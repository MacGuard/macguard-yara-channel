"""The static pages of Subscriptions and Alerts: generated from one table, bilingual, CSP-clean, accessible in structure, and the committed data is what the repository reproduces.
(The behaviour in a real browser is in test_alerts_e2e.py.)"""
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import unittest

from alerts_helpers import ROOT  # noqa: F401
from intel import registry as reg

WEB = pathlib.Path(ROOT) / "web"
DIR = WEB / "intelligence" / "alerts"
PAGES = sorted(DIR.glob("*.html"))
JS = [DIR / "alerts.js", DIR / "filter.js"]


def run(script, *args):
    return subprocess.run([sys.executable, os.path.join(ROOT, "scripts", script), *args], capture_output=True, text=True, timeout=300, cwd=ROOT)


def i18n():
    s = (DIR / "alerts-i18n.js").read_text(encoding="utf-8")
    es_en = json.loads(re.search(r"window\.ALERTS_I18N = (\{.*?\});\nwindow\.ALERTS_TAX", s, re.S).group(1))
    tax = json.loads(re.search(r"window\.ALERTS_TAX = (\{.*?\});\n", s, re.S).group(1))
    return es_en, tax


class GeneratedFiles(unittest.TestCase):
    def test_pages_and_data_equal_what_the_generators_produce(self):
        self.assertEqual(run("gen_alerts_pages.py", "--check").returncode, 0)
        r = run("gen_alerts_site.py", "--check")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_kanban_is_rendered_from_its_source_and_every_card_cites_files_that_exist(self):
        r = run("gen_kanban.py", "--check")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        d = json.load(open(os.path.join(ROOT, "docs", "intelligence", "kanban.json"), encoding="utf-8"))
        self.assertEqual({c["column"] for c in d["cards"]}, {"done", "review", "blocked", "backlog"})
        for c in d["cards"]:
            self.assertTrue(c["es"] and c["en"] and c["evidence"], c)

    def test_the_eight_pages_exist_and_share_one_navigation(self):
        self.assertEqual([p.name for p in PAGES], ["alert.html", "history.html", "index.html", "mine.html", "org.html", "preferences.html", "sources.html", "subscribe.html"])
        navs = set()
        for p in PAGES:
            s = p.read_text(encoding="utf-8")
            navs.add(tuple(re.findall(r"<nav[^>]*>(.*?)</nav>", re.sub(r' aria-current="page"', "", s), re.S)))
            self.assertEqual(len(re.findall(r"<h1\b", s)), 1, p.name)
            self.assertIn('<html lang="es">', s)
            self.assertIn('class="skip"', s)
            self.assertIn('id="main"', s)
            self.assertIn('role="status"', s)
        self.assertEqual(len(navs), 1)


class Bilingual(unittest.TestCase):
    def test_both_languages_have_every_key_and_no_empty_text(self):
        d, tax = i18n()
        self.assertEqual(sorted(d["es"]), sorted(d["en"]))
        for lang in ("es", "en"):
            for k, v in d[lang].items():
                self.assertTrue(v.strip(), f"{lang}:{k}")
        self.assertGreater(len(d["es"]), 300)

    def test_every_key_the_pages_and_the_script_use_exists(self):
        d, _t = i18n()
        used = set()
        for p in PAGES:
            used |= set(re.findall(r'data-t(?:-label)?="([^"]+)"', p.read_text(encoding="utf-8")))
        js = JS[0].read_text(encoding="utf-8")
        used |= set(re.findall(r"\bt\('([a-z0-9_]+)'\)", js))
        used |= set(re.findall(r"'data-t': '([a-z0-9_]+)'", js))
        used |= set(re.findall(r"(?:btn|labelled|checks|tri|text|num|date|group)\('([a-z]{1,3}_[a-z0-9_]+)'", js))
        missing = sorted(k for k in used if k not in d["es"] and not k.endswith("_"))      # 'nk_' + kind is a dynamic prefix: test_dynamic_labels checks every value
        self.assertEqual(missing, [])

    def test_dynamic_labels_exist_for_every_value(self):
        d, tax = i18n()
        for prefix, values in (("tax_sector_", tax["sectors"]), ("tax_region_", tax["regions"]), ("tax_os_", tax["os"]), ("tax_exposure_", tax["exposure"]), ("band_", tax["bands"] + ["unknown"]),
                               ("scope_", ["PERSONAL", "ORGANIZATION", "ORGANIZATION_UNIT", "DEVICE_GROUP", "MSP_CUSTOMER"]), ("freq_", ["immediate", "daily", "weekly"]),
                               ("nk_", ["new", "exploitation_added", "exploitation_source_added", "fix_available", "severity_up", "severity_down", "scope_added", "affected_changed", "mitigation_added"]),
                               ("role_", ["owner", "administrator", "security_manager", "auditor", "operator", "viewer", "msp_administrator"]),
                               ("st_", ["active", "stale", "pending", "blocked", "implemented_no_data", "fresh", "never"]), ("state_", ["active", "suspended", "draft"]),
                               ("dstate_", ["pending", "sent", "retry", "dead", "cancelled", "sending"]), ("mode_", ["immediate", "digest"]), ("kind_", ["new", "update"]),
                               ("type_", ["vulnerability", "advisory", "rule_release"]), ("cat_", ["container_platform", "network_device", "cloud", "service_protocol", "library"])):
            for v in values:
                self.assertIn(prefix + v, d["es"], prefix + v)
                self.assertIn(prefix + v, d["en"], prefix + v)

    def test_taxonomy_labels_come_from_the_versioned_files(self):
        d, tax = i18n()
        for it in json.load(open(os.path.join(ROOT, "config", "alerts", "taxonomies", "sectors.json")))["items"]:
            self.assertTrue(d["es"]["tax_sector_" + it["id"]].startswith(it["es"]))
            self.assertTrue(d["en"]["tax_sector_" + it["id"]].startswith(it["en"]))
        self.assertEqual(tax["taxonomy_versions"]["sectors"], 1)
        nis2 = d["en"]["tax_sector_health"]
        self.assertIn("NIS2 annex I", nis2)


class Csp(unittest.TestCase):
    def test_pages_have_no_inline_script_handler_form_or_external_host(self):
        for p in PAGES:
            s = p.read_text(encoding="utf-8")
            for m in re.finditer(r"<script\b([^>]*)>(.*?)</script[^>]*>", s, re.S | re.I):
                self.assertIn("src=", m.group(1), p.name)
                self.assertEqual(m.group(2).strip(), "")
            self.assertIsNone(re.search(r"\son[a-z]+\s*=", re.sub(r'content="[^"]*"', "", s)), p.name)
            self.assertNotIn("<form", s.lower(), p.name)                                          # the site policy is form-action 'none'
            self.assertIsNone(re.search(r"(https?:)?//[a-z0-9.-]+\.[a-z]{2,}", re.sub(r"<!--.*?-->", "", s)), p.name)
            self.assertIsNone(re.search(r"(href|src|action)\s*=\s*\"\s*javascript:", s, re.I))

    def test_scripts_use_no_dangerous_api_and_only_same_origin_requests(self):
        for p in JS:
            s = p.read_text(encoding="utf-8")
            for bad in ("eval(", "new Function", "innerHTML", "outerHTML", "document.write", "insertAdjacentHTML", "XMLHttpRequest", "sendBeacon", "WebSocket", "sessionStorage", "document.cookie", "importScripts", "postMessage"):
                self.assertNotIn(bad, s, f"{p.name}: {bad}")
            self.assertIsNone(re.search(r"https?://[a-z0-9.-]+\.[a-z]{2,}", s), p.name)
        js = JS[0].read_text(encoding="utf-8")
        self.assertEqual(sorted(set(re.findall(r"fetch\(([^,)]+)", js))), ["path", "url"])
        self.assertEqual(sorted(set(re.findall(r"api\('(?:GET|POST|PATCH|DELETE)', ?'(/api/v1/[a-z/-]+)", js))) , sorted(set(re.findall(r"api\('(?:GET|POST|PATCH|DELETE)', ?'(/api/v1/[a-z/-]+)", js))))
        for path in set(re.findall(r"api\('[A-Z]+', ?'(/[^']+)'", js)):
            self.assertTrue(path.startswith("/api/v1/"), path)
        self.assertEqual(sorted(set(re.findall(r"localStorage\.(\w+)\('(\w+)'", js))), [("getItem", "theme"), ("setItem", "theme")])

    def test_text_is_inserted_as_text_and_links_are_restricted(self):
        js = JS[0].read_text(encoding="utf-8")
        self.assertIn("rel', 'noopener noreferrer'", js)
        self.assertIn("/^https?:\\/\\//", js)
        self.assertNotIn(".href =", js)


class Links(unittest.TestCase):
    def test_every_local_link_resolves(self):
        built = ("docs",)
        for p in PAGES:
            for l in re.findall(r'(?:href|src)="([^"#]+)', p.read_text(encoding="utf-8")):
                if re.match(r"(https?:|mailto:)", l):
                    self.fail(f"{p.name}: external {l}")
                t = (DIR / l.split("?")[0]).resolve()
                rel = os.path.relpath(t, WEB)
                self.assertTrue(t.exists() or rel.split(os.sep)[0] in built, f"{p.name}: {l}")


class Data(unittest.TestCase):
    def test_the_committed_snapshot_holds_only_cleared_data_and_valid_feeds(self):
        from alerts import rss
        registry = reg.load()
        snap = json.load(open(DIR / "data" / "snapshot.json"))
        self.assertEqual(snap["schema"], "macguard.alerts-snapshot/1")
        for a in snap["alerts"]:
            self.assertEqual(a["license"]["redistributable"], True)
            for sid in a["observations"]:
                self.assertTrue(reg.clearance(registry, [sid])[0], sid)
        idx = json.load(open(WEB / "feeds" / "index.json"))
        self.assertGreaterEqual(len(idx["feeds"]), 14)
        for f in idx["feeds"]:
            body = (WEB / f["file"]).read_bytes()
            self.assertEqual(hashlib.sha256(body).hexdigest(), f["sha256"], f["file"])
            self.assertEqual(rss.validate_rss(body), [], f["file"])
            self.assertEqual(body.count(b"<item>"), f["items"])
            if f["items"] == 0:
                self.assertTrue(f["empty_reason"])

    def test_no_third_party_vulnerability_data_is_published_today(self):
        registry = reg.load()
        for sid in ("cisa-kev", "enisa-euvd", "enisa-euvd-exploited", "cert-eu-advisories", "nvd", "osv", "incibe-cert", "ccn-cert"):
            self.assertFalse(reg.clearance(registry, [sid])[0], sid)
        blob = (DIR / "data" / "snapshot.json").read_text() + "".join(p.read_text() for p in (WEB / "feeds" / "public").glob("*.xml"))
        self.assertNotIn("CVE-20", blob)
        self.assertNotIn("EUVD-", blob)

    def test_the_sources_file_never_calls_an_unimplemented_source_active(self):
        src = json.load(open(DIR / "data" / "sources.json"))["sources"]
        by = {s["id"]: s for s in src}
        for sid in ("osv", "nvd", "debian-security-tracker", "ubuntu-security-notices", "redhat-security-data", "sigmahq"):
            self.assertEqual(by[sid]["operational_state"], "pending", sid)
        for sid in ("ccn-cert", "abusech-bulk", "incibe-cert"):
            self.assertEqual(by[sid]["operational_state"], "blocked", sid)
        self.assertEqual(by["macguard-yara-releases"]["operational_state"], "active")
        self.assertTrue(all(s["endpoint"] and s["license"] and s["format"] for s in src))


if __name__ == "__main__":
    unittest.main()
