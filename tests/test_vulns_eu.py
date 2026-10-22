"""Tests for the European/US vulnerability sources: identifiers, versions, the EUVD and CERT-EU parsers, the unified KEV record, the cross-source merge,
distribution-aware assessment, the channel builders (against a LOCAL HTTP server: no network) and the CLI.

Every rule the design makes has a test that fails if the rule is broken. The real upstream APIs were exercised separately by hand (see
docs/intelligence/EU-VULNERABILITIES.md); nothing here talks to the internet."""
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

from intel import catalog, fetch, live, registry as reg, verify  # noqa: E402
from intel.canonical import canonical_bytes, file_sha256  # noqa: E402
from intel.vulns import assess, certeu, euvd, ids, kev, live_eu, merge, records, versions  # noqa: E402
from provenance_schema_check import validate  # noqa: E402
from test_intel import test_registry, slurp  # noqa: E402
from test_intel_live import KEV, Server  # noqa: E402

NOW = datetime(2026, 10, 22, 12, 0, 0, tzinfo=timezone.utc)
SHA = "a" * 64


def schema(name):
    return json.load(open(os.path.join(ROOT, "docs", "intelligence", "schemas", name)))


def ghsa(n):
    """A distinct valid GHSA id per n (the real alphabet has no 0, 1, a, b, d, e, i, k, l, n, o, s, t, u, y, z)."""
    return "GHSA-2g2v-9wf5-" + "".join("23456789"[(n >> (3 * i)) & 7] for i in range(4))


def item(n=1, **over):
    d = {"id": f"EUVD-2026-{1000 + n}", "enisaUuid": f"u{n}", "description": f"Product {n} has a flaw", "datePublished": "Oct 20, 2026, 2:47:26 PM", "dateUpdated": "Oct 21, 2026, 7:00:31 PM",
         "baseScore": 8.4, "baseScoreVersion": "4.0", "baseScoreVector": "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L",
         "references": f"https://vendor.example/advisory/{n}\nnot a url\n", "aliases": f"CVE-2026-{5000 + n}\n{ghsa(n)}\n", "assigner": "cisa-cg", "epss": 0.76,
         "enisaIdProduct": [{"id": "p", "product": {"name": "Widget", "vendor": {"name": "Acme"}}, "product_version": "1.0.0 <1.4.2"}]}
    d.update(over)
    return d


def page(items, total=None):
    return json.dumps({"items": items, "total": len(items) if total is None else total}).encode()


def parse(items, exploited=False, total=None):
    raw = page(items, total)
    return euvd.parse_page(raw, "enisa-euvd", "euvd-page-0000.json", SHA, "2026-10-22T12:00:00Z", NOW, require_exploited=exploited)


def rec(source, rid, cve=(), euvd_ids=(), ghsa=(), asserted=False, since=None, **over):
    r = {"schema": records.SCHEMA_VULN, "source": source, "source_record_id": rid, "ids": {"cve": list(cve), "euvd": list(euvd_ids), "ghsa": list(ghsa)}, "mentions": [],
         "summary": "", "assigner": None, "dates": {"published": "2026-10-01", "updated": None}, "severity": None, "epss": None,
         "exploitation": {"asserted": asserted, "since": since, "basis": "test" if asserted or True else ""}, "affected": [], "fixes": [], "references": [],
         "evidence": {"file": "f", "file_sha256": SHA, "locator": "items[0]", "item_sha256": SHA, "retrieved_at": "2026-10-22T11:00:00Z"}}
    r.update(over)
    return r


class IdTests(unittest.TestCase):
    def test_canonical_spellings(self):
        self.assertEqual(ids.normalise(" cve-2024-0001 "), ("cve", "CVE-2024-0001"))
        self.assertEqual(ids.normalise("euvd-2026-85370"), ("euvd", "EUVD-2026-85370"))
        self.assertEqual(ids.normalise("GHSA-2G2V-9WF5-6M3G"), ("ghsa", "GHSA-2g2v-9wf5-6m3g"))
        self.assertEqual(ids.normalise("ghsa-2g2v-9wf5-6m3g"), ("ghsa", "GHSA-2g2v-9wf5-6m3g"))

    def test_malformed_identifiers_are_refused(self):
        for bad in ("CVE-98-1", "CVE-1998-1234", "CVE-2024-123", "CVE-2024-0001x", "GHSA-2g2v-9wf5-6m3a", "GHSA-2g2v-9wf5", "EUVD-26-1", "PYSEC-2020-1", "", None, 5, "CVE-2024-0001\nCVE-2024-0002", "x" * 80):
            self.assertIsNone(ids.normalise(bad), repr(bad))

    def test_alias_field_splits_on_any_whitespace_dedupes_and_reports_the_rest(self):
        ok, bad = ids.split_aliases("CVE-2026-1111\nGHSA-2g2v-9wf5-6m3g\r\ncve-2026-1111 PYSEC-2020-1,EUVD-2026-0005")
        self.assertEqual(ok, [("cve", "CVE-2026-1111"), ("ghsa", "GHSA-2g2v-9wf5-6m3g"), ("euvd", "EUVD-2026-0005")])
        self.assertEqual(bad, ["PYSEC-2020-1"])
        self.assertEqual(ids.split_aliases(None), ([], []))

    def test_mentions_find_ids_in_prose_but_not_inside_longer_tokens(self):
        txt = "See CVE-2026-44756, cve-2026-58240. NOTCVE-2026-9999 and CVE-2026-12345678901x are not ids; GHSA-2g2v-9wf5-6m3g is."
        self.assertEqual(ids.mentions(txt), [("cve", "CVE-2026-44756"), ("cve", "CVE-2026-58240"), ("ghsa", "GHSA-2g2v-9wf5-6m3g")])
        self.assertEqual(ids.mentions(None), [])


class VersionTests(unittest.TestCase):
    def test_the_shapes_seen_in_the_real_api(self):
        p = versions.parse_affected
        self.assertEqual(p("6.3.9600.0 <6.3.9600.23470")["fixed_in"], "6.3.9600.23470")
        self.assertEqual(p("10.8.0.0 ≤10.8.1.1")["last_affected"], "10.8.1.1")
        self.assertNotIn("fixed_in", p("10.8.0.0 ≤10.8.1.1"))
        self.assertEqual(p("6.1.0 <publication")["upper_bound"], "open")
        self.assertEqual(p("patch: 6.1.177"), {"raw": "patch: 6.1.177", "kind": "fixed-marker", "fixed_in": "6.1.177"})
        self.assertEqual(p("1.7.0")["kind"], "single")
        self.assertIn("does not say", p("1.7.0")["note"])
        for u in ("n/a", "N/A", "unspecified", "", None, 7):
            self.assertEqual(p(u)["kind"], "unspecified", repr(u))

    def test_text_that_is_not_understood_is_kept_not_interpreted(self):
        for odd in ("3.3 Patch 2", "10 Version 1803 for 32-bit Systems", "V3", "all versions before the fix", "5 <3"):
            r = versions.parse_affected(odd)
            self.assertEqual(r["raw"], odd[:200])
            self.assertIn(r["kind"], ("unparsed", "single"), odd)
            self.assertNotIn("fixed_in", r)
            self.assertNotIn("introduced", r)

    def test_range_membership_and_comparison(self):
        r = versions.parse_affected("1.0.0 <1.4.2")
        self.assertIs(versions.in_range("1.4.1", r), True)
        self.assertIs(versions.in_range("1.4.2", r), False)          # the fixed version itself is not affected
        self.assertIs(versions.in_range("0.9", r), False)
        self.assertIs(versions.in_range("1.10", r), False)           # numeric, not text, order: 1.10 > 1.4.2
        self.assertIs(versions.in_range("1.4.2", versions.parse_affected("1.0 ≤1.4.2")), True)
        self.assertIsNone(versions.in_range("1.0", versions.parse_affected("1.0")))
        self.assertEqual(versions.compare("1.0", "1.0.0"), 0)

    def test_debian_order(self):
        c = versions.dpkg_compare
        self.assertEqual(c("1:1.0-1", "2.0-1"), 1)                    # an epoch wins
        self.assertEqual(c("1.0~rc1-1", "1.0-1"), -1)                 # ~ sorts before everything
        self.assertEqual(c("2.4.52-1+deb12u2", "2.4.52-1+deb12u10"), -1)
        self.assertEqual(c("2.4.52-1+deb12u3", "2.4.52-1+deb12u2"), 1)
        self.assertEqual(c("1.0-1", "1.0-1"), 0)
        self.assertEqual(c("1.0a-1", "1.0-1"), 1)
        for bad in ("", "abc", "x:1.0", "-1"):
            with self.assertRaises(ValueError):
                c(bad, "1.0-1")


class EuvdParserTests(unittest.TestCase):
    def test_a_valid_item_becomes_a_record_with_evidence_pointing_back(self):
        recs, rej, meta = parse([item(1), item(2)])
        self.assertEqual((len(recs), rej, meta["input_items"], meta["declared_total"]), (2, {}, 2, 2))
        r = recs[0]
        self.assertEqual(r["ids"], {"cve": ["CVE-2026-5001"], "euvd": ["EUVD-2026-1001"], "ghsa": [ghsa(1)]})
        self.assertEqual(r["dates"], {"published": "2026-10-20", "updated": "2026-10-21"})
        self.assertEqual(r["references"], ["https://vendor.example/advisory/1"])          # the non-URL line is dropped
        self.assertEqual(r["fixes"][0]["fixed_in"], "1.4.2")
        self.assertEqual(r["evidence"]["locator"], "items[0]")
        self.assertEqual(r["evidence"]["file_sha256"], SHA)
        self.assertEqual(validate(r, schema("vuln-record.schema.json")), [])
        canonical_bytes(r)                                                                  # no floats: it can be written canonically

    def test_a_critical_score_is_severity_never_exploitation(self):
        recs, _r, _m = parse([item(1, baseScore=10.0, epss=99.9)])
        self.assertEqual(recs[0]["severity"]["score"], "10.0")
        self.assertFalse(recs[0]["exploitation"]["asserted"])
        self.assertIsNone(recs[0]["exploitation"]["since"])
        self.assertIn("not evidence of exploitation", recs[0]["severity"]["note"])

    def test_exploitedSince_is_the_only_thing_that_asserts_exploitation_and_says_its_limits(self):
        recs, _r, _m = parse([item(1, exploitedSince="Oct 13, 2026, 12:00:00 AM")])
        e = recs[0]["exploitation"]
        self.assertEqual((e["asserted"], e["since"]), (True, "2026-10-13"))
        self.assertIn("does not say who observed", e["basis"])
        self.assertIn("independence from CISA KEV unknown", e["basis"])

    def test_rejections_are_counted_by_reason(self):
        items = [item(1), "text", item(2, id="CVE-2026-1"), item(3, id="EUVD-2026-1003"), item(4, id="EUVD-2026-1003"), item(5, datePublished="yesterday"),
                 item(6, datePublished="Dec 24, 2026, 1:00:00 PM"), item(7, exploitedSince="soon"), item(8, exploitedSince="Dec 24, 2026, 1:00:00 PM")]
        recs, rej, _m = parse(items)
        self.assertEqual([r["source_record_id"] for r in recs], ["EUVD-2026-1001", "EUVD-2026-1003"])
        self.assertEqual(rej, {"duplicate-euvd-id": 1, "exploitedSince-in-the-future": 1, "invalid-date": 1, "invalid-euvd-id": 1, "invalid-exploitedSince": 1,
                               "not-an-object": 1, "published-in-the-future": 1})

    def test_the_exploited_list_rejects_entries_without_exploitedSince(self):
        recs, rej, _m = parse([item(1, exploitedSince="Oct 13, 2026, 12:00:00 AM"), item(2)], exploited=True)
        self.assertEqual([r["source_record_id"] for r in recs], ["EUVD-2026-1001"])
        self.assertEqual(rej, {"exploited-list-entry-without-exploitedSince": 1})

    def test_warnings_for_odd_but_usable_records(self):
        recs, rej, meta = parse([item(1, aliases="CVE-2026-1111 PYSEC-2020-1", dateUpdated="Oct 01, 2026, 1:00:00 PM", baseScore=11)])
        self.assertEqual((len(recs), rej), (1, {}))
        self.assertEqual(meta["warnings"], {"alias-not-an-identifier-dropped": 1, "score-out-of-range-dropped": 1, "updated-before-published": 1})
        self.assertIsNone(recs[0]["severity"])

    def test_answer_shapes_and_errors(self):
        self.assertEqual(euvd.page_items(json.dumps([item(1)]).encode())[1], None)           # the /last, /exploited, /critical endpoints answer a bare list
        for bad in (b"not json", b"{}", b'{"items": 5}', b"\xff\xfe", b"7"):
            with self.assertRaises(fetch.FetchError):
                euvd.page_items(bad)
        self.assertEqual(euvd.page_items(b'{"items": [], "total": true}')[1], None)         # a boolean is not a total

    def test_hostile_record_cannot_inject_through_text_fields(self):
        recs, _r, _m = parse([item(1, references="javascript:alert(1)\nhttps://ok.example/a\nhttp://x.example/\n", description="<script>x</script>" * 100)])
        self.assertEqual(recs[0]["references"], ["https://ok.example/a", "http://x.example/"])          # only http(s) URLs survive; javascript: and prose do not
        self.assertLessEqual(len(recs[0]["summary"]), 280)


FEED = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel><title>t</title>
<item><title>2026-019: Critical Vulnerability in GitLab</title><link>https://cert.europa.eu/publications/security-advisories/2026-019/</link>
<description>GitLab published CVE-2026-44756 and cve-2026-58240. The vendor is aware of active exploitation.&lt;br&gt;Patch now.</description><pubDate>Thu, 22 Oct 2026 11:14:22 +0200</pubDate><guid>a</guid></item>
<item><title>2026-018: Critical Vulnerabilities in PHP</title><link>https://cert.europa.eu/publications/security-advisories/2026-018/</link>
<description>No identifiers here.</description><pubDate>Wed, 21 Oct 2026 17:20:18 +0200</pubDate><guid>b</guid></item>
</channel></rss>"""


def feed(xml=FEED):
    return certeu.parse_feed(xml.encode() if isinstance(xml, str) else xml, "cert-eu-advisories", "f.xml", SHA, "2026-10-22T12:00:00Z", NOW)


class CertEuTests(unittest.TestCase):
    def test_advisories_become_references_with_mentions_not_ids(self):
        recs, rej, meta = feed()
        self.assertEqual((len(recs), rej, meta["input_items"]), (2, {}, 2))
        self.assertEqual([x["source_record_id"] for x in recs], ["CERT-EU-2026-018", "CERT-EU-2026-019"])
        r = recs[1]
        self.assertEqual(r["ids"], {"cve": [], "euvd": [], "ghsa": []})
        self.assertEqual([m["id"] for m in r["mentions"]], ["CVE-2026-44756", "CVE-2026-58240"])
        self.assertEqual(r["references"], ["https://cert.europa.eu/publications/security-advisories/2026-019/"])
        self.assertEqual(validate(r, schema("vuln-record.schema.json")), [])

    def test_prose_about_exploitation_is_never_read_as_an_assertion(self):
        recs, _r, _m = feed()
        for r in recs:
            self.assertFalse(r["exploitation"]["asserted"])
            self.assertIsNone(r["exploitation"]["since"])
        self.assertIn("prose is not read", recs[0]["exploitation"]["basis"])

    def test_bad_items_are_rejected_by_reason(self):
        xml = FEED.replace("</channel>", """<item><title>2026-020: x</title><link>https://cert.europa.eu/publications/security-advisories/2026-021/</link><description>d</description><pubDate>Thu, 22 Oct 2026 11:14:22 +0200</pubDate></item>
<item><title>2026-019: dup</title><link>https://cert.europa.eu/publications/security-advisories/2026-019/</link><description>d</description><pubDate>Thu, 22 Oct 2026 11:14:22 +0200</pubDate></item>
<item><title>2026-022: bad date</title><link>https://cert.europa.eu/publications/security-advisories/2026-022/</link><description>d</description><pubDate>whenever</pubDate></item>
<item><title>2027-001: future</title><link>https://cert.europa.eu/publications/security-advisories/2027-001/</link><description>d</description><pubDate>Fri, 01 Jan 2027 10:00:00 +0100</pubDate></item>
<item><title>2026-023: off site</title><link>https://evil.example/publications/security-advisories/2026-023/</link><description>d</description><pubDate>Thu, 22 Oct 2026 11:14:22 +0200</pubDate></item></channel>""")
        recs, rej, meta = feed(xml)
        self.assertEqual(len(recs), 2)
        self.assertEqual(rej, {"duplicate-advisory": 1, "invalid-pubDate": 1, "published-in-the-future": 1, "title-and-link-do-not-agree-on-the-advisory-number": 2})
        self.assertEqual(meta["input_items"], 7)

    def test_entity_expansion_and_odd_documents_are_refused(self):
        bomb = '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><rss version="2.0"><channel><item><title>&b;</title></channel></rss>'
        late = FEED.replace("<channel>", '<!-- ' + "x" * 6000 + ' --><!DOCTYPE x [<!ENTITY a "b">]><channel>', 1)
        for bad in (bomb, late, FEED.encode("utf-16"), "<html></html>", "<rss", ""):
            with self.assertRaises(fetch.FetchError, msg=str(bad)[:40]):
                feed(bad)


class KevUnifiedTests(unittest.TestCase):
    def test_kev_records_assert_exploitation_with_an_honest_date_meaning(self):
        raw = json.dumps(KEV).encode()
        rs = kev.records(raw, "kev.json", SHA, "2026-10-22T12:00:00Z")
        self.assertEqual([r["source_record_id"] for r in rs], ["CVE-2023-12345", "CVE-2024-0001"])
        r = rs[1]
        self.assertEqual((r["exploitation"]["asserted"], r["exploitation"]["since"]), (True, "2024-01-02"))
        self.assertIn("not when exploitation began", r["exploitation"]["basis"])
        self.assertEqual(r["evidence"]["locator"], "vulnerabilities[0]")
        self.assertEqual(r["kev"]["ransomware_use"], "Known")
        self.assertEqual(r["affected"][0]["version"]["kind"], "unspecified")         # KEV states no versions: none are invented
        self.assertEqual(validate(r, schema("vuln-record.schema.json")), [])

    def test_the_old_kev_index_is_unchanged(self):
        d = tempfile.mkdtemp(prefix="kevcompat-")
        self.addCleanup(shutil.rmtree, d, True)
        registry = test_registry()
        registry["cisa-kev"] = dict(registry["feedA"], id="cisa-kev", default_ttl_days=3650)
        s = Server({"/kev.json": (200, {}, json.dumps(KEV).encode())})
        self.addCleanup(s.close)
        res = live.build_live("cisa-kev", d, 1, registry, NOW, url=s.url("/kev.json"), allow_http_localhost=True)
        names = sorted(os.listdir(res["dir"]))
        for must in ("kev-index.jsonl", "known_exploited_vulnerabilities.json", "build-report.json", "manifest.json", "vuln-records.jsonl"):
            self.assertIn(must, names)
        idx = [json.loads(line) for line in slurp(os.path.join(res["dir"], "kev-index.jsonl")).splitlines()]
        self.assertEqual(sorted(idx[0]), ["cve", "date_added", "name", "product", "ransomware_use", "vendor"])      # the legacy shape
        self.assertEqual(res["stats"]["accepted"], 2)


class MergeTests(unittest.TestCase):
    def test_the_same_cve_from_cisa_and_enisa_is_one_entry_with_both_statements(self):
        k = rec("cisa-kev", "CVE-2026-5001", cve=["CVE-2026-5001"], asserted=True, since="2026-10-01")
        e = rec("enisa-euvd-exploited", "EUVD-2026-1001", cve=["CVE-2026-5001"], euvd_ids=["EUVD-2026-1001"], ghsa=["GHSA-2g2v-9wf5-6m3g"], asserted=True, since="2026-09-20")
        out = merge.merge([e, k])
        self.assertEqual(len(out["entries"]), 1)
        en = out["entries"][0]
        self.assertEqual((en["key"], sorted(en["sources"])), ("CVE-2026-5001", ["cisa-kev", "enisa-euvd-exploited"]))
        self.assertEqual(en["ids"], {"cve": ["CVE-2026-5001"], "euvd": ["EUVD-2026-1001"], "ghsa": ["GHSA-2g2v-9wf5-6m3g"]})
        self.assertEqual(en["exploitation"]["cisa-kev"]["since"], "2026-10-01")             # each source keeps its own date
        self.assertEqual(en["exploitation"]["enisa-euvd-exploited"]["since"], "2026-09-20")
        self.assertEqual(en["exploitation_summary"]["earliest_since"], "2026-09-20")
        self.assertEqual(en["exploitation_summary"]["independent_confirmation"], "unknown")      # two sources are not called independent
        self.assertEqual(out["stats"]["multi_source"], 1)

    def test_a_record_that_only_rates_severity_stays_not_exploited_next_to_a_kev_entry(self):
        k = rec("cisa-kev", "CVE-2026-5001", cve=["CVE-2026-5001"], asserted=True, since="2026-10-01")
        e = rec("enisa-euvd", "EUVD-2026-1001", cve=["CVE-2026-5001"], euvd_ids=["EUVD-2026-1001"], severity={"scheme": "cvss", "score": "10.0"})
        en = merge.merge([k, e])["entries"][0]
        self.assertEqual(en["exploitation_summary"]["asserted_by"], ["cisa-kev"])
        self.assertFalse(en["exploitation"]["enisa-euvd"]["asserted"])
        self.assertEqual(en["exploitation_summary"]["independent_confirmation"], "not-applicable")
        only = merge.merge([e])["entries"][0]
        self.assertEqual(only["exploitation_summary"]["asserted_by"], [])
        self.assertEqual(only["sources"]["enisa-euvd"]["severity"]["score"], "10.0")          # critical stays a severity

    def test_ghsa_joins_records_that_lack_a_cve_but_never_across_two_cves(self):
        a = rec("enisa-euvd", "EUVD-2026-1", cve=["CVE-2026-1"], euvd_ids=["EUVD-2026-1"], ghsa=["GHSA-2g2v-9wf5-6m3g"])
        b = rec("osv", "GHSA-2g2v-9wf5-6m3g", ghsa=["GHSA-2g2v-9wf5-6m3g"])
        out = merge.merge([a, b])
        self.assertEqual([sorted(e["sources"]) for e in out["entries"]], [["enisa-euvd", "osv"]])
        c = rec("osv", "OTHER", cve=["CVE-2026-2"], ghsa=["GHSA-2g2v-9wf5-6m3g"])             # the same GHSA attached to a DIFFERENT cve
        out = merge.merge([a, c])
        self.assertEqual(len(out["entries"]), 2)
        self.assertEqual(len(out["conflicts"]), 1)
        self.assertIn("two different CVEs", out["conflicts"][0]["reason"])
        self.assertTrue(any("alias-conflict-with-another-record" in e["flags"] for e in out["entries"]))

    def test_a_record_naming_two_cves_is_not_merged(self):
        multi = rec("enisa-euvd", "EUVD-2026-9", cve=["CVE-2026-1", "CVE-2026-2"], euvd_ids=["EUVD-2026-9"])
        one = rec("cisa-kev", "CVE-2026-1", cve=["CVE-2026-1"], asserted=True, since="2026-10-01")
        out = merge.merge([multi, one])
        self.assertEqual(len(out["entries"]), 2)
        self.assertEqual(out["conflicts"][0]["ids"], ["CVE-2026-1", "CVE-2026-2"])
        kev_entry = next(e for e in out["entries"] if "cisa-kev" in e["sources"])
        self.assertEqual(sorted(kev_entry["sources"]), ["cisa-kev"])

    def test_text_mentions_and_urls_never_join_records(self):
        k = rec("cisa-kev", "CVE-2026-5001", cve=["CVE-2026-5001"], asserted=True, since="2026-10-01")
        adv = rec("cert-eu-advisories", "CERT-EU-2026-019", mentions=[{"kind": "cve", "id": "CVE-2026-5001"}])
        url = rec("enisa-euvd", "EUVD-2026-7", cve=["CVE-2026-7"], euvd_ids=["EUVD-2026-7"], references=["https://x.example/CVE-2026-5001"])
        out = merge.merge([k, adv, url])
        self.assertEqual(len(out["entries"]), 3)
        kev_entry = next(e for e in out["entries"] if e["key"] == "CVE-2026-5001")
        self.assertEqual(sorted(kev_entry["sources"]), ["cisa-kev"])
        self.assertEqual(kev_entry["mentioned_by"], [{"source": "cert-eu-advisories", "record": "CERT-EU-2026-019"}])
        self.assertIn("no-identifier", next(e for e in out["entries"] if "cert-eu-advisories" in e["sources"])["flags"])

    def test_same_product_name_different_cve_stay_apart(self):
        aff = [{"vendor": "Acme", "product": "Widget", "version": {"raw": "1.0", "kind": "single"}}]
        out = merge.merge([rec("enisa-euvd", "EUVD-2026-1", cve=["CVE-2026-1"], affected=aff), rec("enisa-euvd", "EUVD-2026-2", cve=["CVE-2026-2"], affected=aff)])
        self.assertEqual(len(out["entries"]), 2)

    def test_a_stale_snapshot_keeps_its_assertion_visible_but_not_current(self):
        k = rec("cisa-kev", "CVE-2026-5001", cve=["CVE-2026-5001"], asserted=True, since="2026-10-01")
        e = rec("enisa-euvd-exploited", "EUVD-2026-1001", cve=["CVE-2026-5001"], euvd_ids=["EUVD-2026-1001"], asserted=True, since="2026-09-20")
        snaps = {"cisa-kev": {"retrieved_at": "2026-10-22T10:00:00Z", "max_age_days": 7}, "enisa-euvd-exploited": {"retrieved_at": "2026-10-01T10:00:00Z", "max_age_days": 3}}
        out = merge.merge([k, e], snaps, NOW)
        en = out["entries"][0]
        self.assertEqual(en["exploitation_summary"]["asserted_by"], ["cisa-kev", "enisa-euvd-exploited"])
        self.assertEqual(en["exploitation_summary"]["asserted_by_current"], ["cisa-kev"])
        self.assertTrue(en["exploitation"]["enisa-euvd-exploited"]["stale"])
        self.assertIn("21 days old", out["stale_sources"]["enisa-euvd-exploited"])
        self.assertEqual(out["stats"]["exploited_by_any_source"], 1)
        bad = merge.merge([k], {"cisa-kev": {"retrieved_at": "yesterday", "max_age_days": 7}}, NOW)
        self.assertEqual(bad["stale_sources"], {"cisa-kev": "snapshot date unreadable"})

    def test_two_records_from_one_source_are_flagged_and_invalid_records_are_refused(self):
        a = rec("enisa-euvd", "EUVD-2026-1", cve=["CVE-2026-1"])
        b = rec("enisa-euvd", "EUVD-2026-2", cve=["CVE-2026-1"])
        self.assertIn("two-records-from-enisa-euvd", merge.merge([a, b])["entries"][0]["flags"])
        with self.assertRaises(ValueError):
            merge.merge([rec("x", "y", asserted=True, since=None)])                    # an assertion needs a date
        with self.assertRaises(ValueError):
            merge.merge([rec("x", "y", asserted=False, since="2026-01-01")])           # no assertion, but a date
        with self.assertRaises(ValueError):
            merge.merge([{"schema": "other"}])

    def test_the_result_does_not_depend_on_input_order_and_validates_against_its_schema(self):
        rs = [rec("cisa-kev", "CVE-2026-0001", cve=["CVE-2026-0001"], asserted=True, since="2026-10-01"),
              rec("enisa-euvd", "EUVD-2026-0001", cve=["CVE-2026-0001"], euvd_ids=["EUVD-2026-0001"]), rec("enisa-euvd", "EUVD-2026-0003", euvd_ids=["EUVD-2026-0003"]),
              rec("osv", "GHSA-2g2v-9wf5-6m3g", ghsa=["GHSA-2g2v-9wf5-6m3g"])]
        a = canonical_bytes(merge.merge(rs))
        b = canonical_bytes(merge.merge(list(reversed(rs))))
        self.assertEqual(a, b)
        self.assertEqual(validate(json.loads(a), schema("vuln-merged.schema.json")), [])

    def test_regions_come_from_the_registry(self):
        out = merge.merge([rec("cisa-kev", "CVE-2026-1", cve=["CVE-2026-1"]), rec("enisa-euvd", "EUVD-2026-1", cve=["CVE-2026-1"])],
                          registry={"cisa-kev": {"region": "US"}, "enisa-euvd": {"region": "EU"}})
        self.assertEqual(out["entries"][0]["regions"], ["EU", "US"])


class AssessTests(unittest.TestCase):
    ROWS = [{"distro": "debian", "release": "bookworm", "package": "apache2", "cve": "CVE-2026-5001", "status": "fixed", "fixed_version": "2.4.52-1+deb12u2", "evidence": "https://security-tracker.debian.org/x"},
            {"distro": "debian", "release": "bookworm", "package": "curl", "cve": "CVE-2026-5001", "status": "vulnerable"},
            {"distro": "debian", "release": "bookworm", "package": "zlib", "cve": "CVE-2026-5001", "status": "not-affected"},
            {"distro": "debian", "release": "bookworm", "package": "gnutls", "cve": "CVE-2026-5001", "status": "under-investigation"},
            {"distro": "debian", "release": "bookworm", "package": "dup", "cve": "CVE-2026-5001", "status": "fixed", "fixed_version": "1-1"},
            {"distro": "debian", "release": "bookworm", "package": "dup", "cve": "CVE-2026-5001", "status": "vulnerable"},
            {"distro": "debian", "release": "bookworm", "package": "nover", "cve": "CVE-2026-5001", "status": "fixed"}]

    def a(self, pkg, ver, rows=None, **kw):
        return assess.assess_package("CVE-2026-5001", pkg, ver, kw.get("distro", "debian"), kw.get("release", "bookworm"), self.ROWS if rows is None else rows, kw.get("scheme", "dpkg"))

    def test_no_distribution_row_means_not_assessed_even_if_upstream_says_affected(self):
        r = self.a("apache2", "2.4.50-1", rows=[])
        self.assertEqual(r["verdict"], "NOT_ASSESSED")
        self.assertIn("backported", r["reason"])
        self.assertEqual(self.a("apache2", "2.4.52-1", distro="ubuntu")["verdict"], "NOT_ASSESSED")           # another distribution
        self.assertEqual(self.a("apache2", "2.4.52-1", release="bullseye")["verdict"], "NOT_ASSESSED")        # another release
        self.assertEqual(self.a("unlisted", "1.0")["verdict"], "NOT_ASSESSED")

    def test_a_backported_fix_is_patched_although_the_upstream_version_looks_old(self):
        # upstream says "affected before 2.4.58"; the distribution fixed it in 2.4.52-1+deb12u2, so an installed +deb12u3 is patched
        self.assertEqual(self.a("apache2", "2.4.52-1+deb12u3")["verdict"], "PATCHED")
        self.assertEqual(self.a("apache2", "2.4.52-1+deb12u2")["verdict"], "PATCHED")
        r = self.a("apache2", "2.4.52-1+deb12u1")
        self.assertEqual((r["verdict"], r["fixed_version"]), ("AFFECTED_UNPATCHED", "2.4.52-1+deb12u2"))
        self.assertEqual(r["distro_evidence"], "https://security-tracker.debian.org/x")
        self.assertEqual(self.a("apache2", "1:2.0-1")["verdict"], "PATCHED")                                  # an epoch beats the fixed version

    def test_the_other_statuses(self):
        self.assertEqual(self.a("curl", "8.0")["verdict"], "AFFECTED_UNPATCHED")
        self.assertEqual(self.a("zlib", "1.2")["verdict"], "NOT_AFFECTED")
        self.assertEqual(self.a("gnutls", "3.7")["verdict"], "UNDER_INVESTIGATION")

    def test_contradictions_missing_versions_unknown_schemes_and_bad_versions_are_not_assessed(self):
        self.assertIn("contradicts", self.a("dup", "1-1")["reason"])
        self.assertEqual(self.a("nover", "1.0")["verdict"], "NOT_ASSESSED")
        r = self.a("apache2", "2.4.52-1", scheme="rpm")
        self.assertEqual(r["verdict"], "NOT_ASSESSED")
        self.assertIn("rpm", r["reason"])
        self.assertEqual(self.a("apache2", "not a version")["verdict"], "NOT_ASSESSED")

    def test_the_verdict_never_claims_exploitation_and_demands_a_real_cve(self):
        self.assertTrue(self.a("apache2", "2.4.52-1+deb12u3")["exploited_is_not_decided_here"])
        with self.assertRaises(ValueError):
            assess.assess_package("GHSA-2g2v-9wf5-6m3g", "p", "1", "d", "r", [])

    def test_distro_table_loading_validates_and_matches_its_schema(self):
        doc = {"schema": assess.SCHEMA_DISTRO, "rows": self.ROWS}
        self.assertEqual(validate(doc, schema("distro-fixes.schema.json")), [])
        self.assertEqual(len(assess.load_rows(json.dumps(doc).encode())), 7)
        for bad in ({"schema": "x", "rows": []}, {"schema": assess.SCHEMA_DISTRO, "rows": [{"status": "weird", "cve": "CVE-2026-1"}]},
                    {"schema": assess.SCHEMA_DISTRO, "rows": [{"status": "fixed", "cve": "CVE-1"}]}):
            with self.assertRaises(ValueError):
                assess.load_rows(json.dumps(bad).encode())


def cleared_registry():
    r = test_registry()
    for sid in ("enisa-euvd", "enisa-euvd-exploited", "cert-eu-advisories", "cisa-kev"):
        r[sid] = dict(r["feedA"], id=sid, default_ttl_days=3650)
    r["enisa-euvd-pending"] = dict(r["blocked"], id="enisa-euvd-pending")
    return r


class BuilderTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="eu-build-")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.registry = cleared_registry()

    def serve(self, routes):
        s = Server(routes)
        self.addCleanup(s.close)
        return s

    def routes(self, kind, pages, total, window_days=3):
        out = {}
        for n, items in enumerate(pages):
            out[live_eu._page_url("", kind, n, NOW, window_days)] = (200, {}, page(items, total))
        return out

    def build(self, source, routes, registry=None, **kw):
        s = self.serve(routes)
        return live_eu.build_eu(source, self.d, 1, registry or self.registry, NOW, base_url=s.url(""), allow_http_localhost=True, pause=0, sleep=lambda _x: None, **kw)

    def exploited_items(self, a, b):
        return [item(n, exploitedSince="Oct 13, 2026, 12:00:00 AM") for n in range(a, b)]

    def test_paging_collects_every_page_keeps_every_original_and_is_complete(self):
        pages = [self.exploited_items(1, 101), self.exploited_items(101, 201), self.exploited_items(201, 251)]
        res = self.build("enisa-euvd-exploited", self.routes("euvd-exploited", pages, 250))
        st = res["stats"]
        self.assertEqual((st["accepted"], st["pages"], st["declared_total"], st["complete"], st["input_items"], st["exploitation_asserted"]), (250, 3, 250, True, 250, 250))
        files = sorted(os.listdir(res["dir"]))
        self.assertEqual([f for f in files if f.startswith("euvd-page-") and f.endswith(".json") and ".retrieval" not in f], ["euvd-page-0000.json", "euvd-page-0001.json", "euvd-page-0002.json"])
        m = json.loads(slurp(os.path.join(res["dir"], "manifest.json")))
        origin = {a["path"]: a["origin"] for a in m["artifacts"]}
        self.assertEqual({origin[f"euvd-page-000{i}.json"] for i in range(3)}, {"original"})
        self.assertEqual(origin["vuln-records.jsonl"], "derived")
        recs = live_eu.load_records(res["dir"])
        self.assertEqual(len(recs), 250)
        for r in (recs[0], recs[-1]):                                        # every record points at a kept original and its hash is right
            self.assertEqual(r["evidence"]["file_sha256"], file_sha256(os.path.join(res["dir"], r["evidence"]["file"])))
        self.assertTrue(res["publishable"])                                     # cleared + confirmed + complete

    def test_an_uncleared_source_downloads_but_is_never_publishable(self):
        reg2 = copy.deepcopy(self.registry)
        reg2["enisa-euvd-exploited"] = dict(reg2["enisa-euvd-pending"], id="enisa-euvd-exploited")
        res = self.build("enisa-euvd-exploited", self.routes("euvd-exploited", [self.exploited_items(1, 4)], 3), reg2)
        self.assertFalse(res["publishable"])
        self.assertIn("pending-legal", " ".join(res["blocking_reasons"]))
        reg3 = copy.deepcopy(self.registry)
        reg3["enisa-euvd-exploited"]["owner_confirmed"] = False
        res = live_eu.build_eu("enisa-euvd-exploited", os.path.join(self.d, "b"), 1, reg3, NOW, base_url=self.serve(self.routes("euvd-exploited", [self.exploited_items(1, 4)], 3)).url(""),
                               allow_http_localhost=True, pause=0, sleep=lambda _x: None)
        self.assertFalse(res["publishable"])
        self.assertIn("owner has not confirmed", " ".join(res["blocking_reasons"]))

    def test_stopping_at_the_page_limit_makes_an_incomplete_unpublishable_snapshot(self):
        pages = [self.exploited_items(1, 101), self.exploited_items(101, 201)]
        res = self.build("enisa-euvd-exploited", self.routes("euvd-exploited", pages, 250), max_pages=2)
        self.assertFalse(res["stats"]["complete"])
        self.assertFalse(res["publishable"])
        self.assertIn("incomplete snapshot", " ".join(res["blocking_reasons"]))
        self.assertIn("2-page limit", res["stats"]["incomplete_reason"])

    def test_a_server_that_returns_fewer_records_than_it_declared_is_incomplete(self):
        res = self.build("enisa-euvd-exploited", self.routes("euvd-exploited", [self.exploited_items(1, 51)], 50 + 30))
        self.assertFalse(res["stats"]["complete"])           # one page of 50 against a declared 80
        self.assertIn("declared 80", res["stats"]["incomplete_reason"])
        self.assertFalse(res["publishable"])

    def test_a_page_that_goes_missing_halfway_leaves_nothing_behind(self):
        routes = self.routes("euvd-exploited", [self.exploited_items(1, 101)], 250)
        routes[live_eu._page_url("", "euvd-exploited", 1, NOW, 3)] = (500, {}, b"boom")
        s = self.serve(routes)
        with self.assertRaises(fetch.FetchError) as cm:
            live_eu.build_eu("enisa-euvd-exploited", self.d, 1, self.registry, NOW, base_url=s.url(""), allow_http_localhost=True, pause=0, sleep=lambda _x: None)
        self.assertIn("HTTP 500", str(cm.exception))
        self.assertFalse(os.path.exists(os.path.join(self.d, "vulns-eukev", "1")))          # no half-built channel directory

    def test_malformed_answers_missing_totals_and_rate_limits_are_errors_not_partial_channels(self):
        for name, body, status, why in (("json", b"<html>", 200, "not valid JSON"), ("total", json.dumps([item(1)]).encode(), 200, "does not declare a total"),
                                       ("429", b"slow down", 429, "HTTP 429"), ("empty", b"", 200, "unexpected")):
            d = os.path.join(self.d, name)
            s = self.serve({live_eu._page_url("", "euvd-exploited", 0, NOW, 3): (status, {}, body)})
            with self.assertRaises(fetch.FetchError, msg=name) as cm:
                live_eu.build_eu("enisa-euvd-exploited", d, 1, self.registry, NOW, base_url=s.url(""), allow_http_localhost=True, pause=0, sleep=lambda _x: None)
            self.assertIn(why, str(cm.exception), name)
            self.assertFalse(os.path.exists(os.path.join(d, "vulns-eukev", "1")), name)

    def test_a_record_that_moves_between_pages_is_kept_once_and_counted(self):
        a = item(1, exploitedSince="Oct 13, 2026, 12:00:00 AM", dateUpdated="Oct 20, 2026, 1:00:00 PM")
        b = item(1, exploitedSince="Oct 13, 2026, 12:00:00 AM", dateUpdated="Oct 21, 2026, 1:00:00 PM", baseScore=9.1)
        pages = [[a] + self.exploited_items(2, 101), [b]]
        res = self.build("enisa-euvd-exploited", self.routes("euvd-exploited", pages, 101))
        self.assertEqual(res["stats"]["accepted"], 100)
        self.assertEqual(res["stats"]["rejected_by_reason"], {"duplicate-across-pages": 1})
        kept = next(r for r in live_eu.load_records(res["dir"]) if r["source_record_id"] == "EUVD-2026-1001")
        self.assertEqual(kept["severity"]["score"], "9.1")               # the most recently updated copy wins
        self.assertTrue(res["stats"]["complete"])

    def test_the_window_channel_asserts_no_exploitation_for_critical_items(self):
        pages = [[item(1, baseScore=10.0), item(2, exploitedSince="Oct 13, 2026, 12:00:00 AM")]]
        res = self.build("enisa-euvd", self.routes("euvd-window", pages, 2, 2), window_days=2)
        self.assertEqual((res["channel"], res["stats"]["window_days"], res["stats"]["exploitation_asserted"]), ("vulns-euvd", 2, 1))
        by = {r["source_record_id"]: r for r in live_eu.load_records(res["dir"])}
        self.assertFalse(by["EUVD-2026-1001"]["exploitation"]["asserted"])

    def test_cert_eu_end_to_end_and_a_version_directory_is_never_reused(self):
        res = self.build("cert-eu-advisories", {"/": (200, {}, FEED.encode())})
        self.assertEqual((res["channel"], res["stats"]["accepted"], res["stats"]["exploitation_asserted"]), ("vulns-certeu", 2, 0))
        self.assertEqual(res["retrievals"][0]["bytes"], len(FEED.encode()))
        with self.assertRaises(fetch.FetchError):
            self.build("cert-eu-advisories", {"/": (200, {}, FEED.encode())})
        with self.assertRaises(fetch.FetchError):
            live_eu.build_eu("nope", self.d, 1, self.registry, NOW)
        with self.assertRaises(fetch.FetchError):
            live_eu.build_eu("enisa-euvd", self.d, 1, {}, NOW)

    def test_a_source_that_needs_a_credential_is_refused_before_any_request(self):
        reg2 = copy.deepcopy(self.registry)
        reg2["enisa-euvd"]["access"] = {"credential_required": True}
        with self.assertRaises(fetch.FetchError) as cm:
            live_eu.build_eu("enisa-euvd", self.d, 1, reg2, NOW, base_url="http://127.0.0.1:9", allow_http_localhost=True)
        self.assertIn("credential", str(cm.exception))

    def test_the_channels_are_independent_and_the_catalog_pins_each_exact_version(self):
        k = self.build("enisa-euvd-exploited", self.routes("euvd-exploited", [self.exploited_items(1, 4)], 3))
        c = self.build("cert-eu-advisories", {"/": (200, {}, FEED.encode())})
        refs = []
        for r in (k, c):
            ref = catalog.channel_ref(os.path.join(r["dir"], "manifest.json"))
            ref["manifest"]["path"] = os.path.relpath(os.path.join(r["dir"], "manifest.json"), self.d)
            refs.append(ref)
        doc = catalog.build_catalog(1, "2026-10-22T12:00:00Z", refs, include_draft=True)
        self.assertEqual(sorted(x["id"] for x in doc["channels"]), ["vulns-certeu", "vulns-eukev"])
        for x in doc["channels"]:
            self.assertEqual(x["version"], 1)
            self.assertEqual(len(x["manifest"]["sha256"]), 64)
        out = catalog.write_catalog(doc, os.path.join(self.d, "cat"))
        res = verify.verify_catalog(out, self.d, allow_draft=True)
        self.assertEqual([x for x in res["checks"] if x["status"] == "FAIL"], [])
        self.assertEqual(res["exit_code"], 5)                      # consistent, signature not checked (there is none)
        p = os.path.join(k["dir"], "euvd-page-0000.json")        # tampering with one original page is caught
        with open(p, "ab") as f:
            f.write(b" ")
        res2 = verify.verify_catalog(out, self.d, allow_draft=True)
        self.assertEqual(res2["exit_code"], 1)

    def test_manifest_matches_its_schema_and_carries_no_signature_or_attestation(self):
        res = self.build("enisa-euvd-exploited", self.routes("euvd-exploited", [self.exploited_items(1, 4)], 3))
        m = json.loads(slurp(os.path.join(res["dir"], "manifest.json")))
        self.assertEqual(validate(m, schema("channel-manifest.schema.json")), [])
        self.assertIsNone(m["validation"]["attestation"])
        self.assertFalse(any(a["original_signature"]["present"] for a in m["artifacts"]))


class CardTests(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, os.path.join(ROOT, "scripts"))
        import gen_intel_vulns
        self.gen = gen_intel_vulns
        self.registry = test_registry()
        self.registry["cleared"] = dict(self.registry["feedA"], id="cleared", attribution="credit the cleared source")
        self.registry["notyet"] = dict(self.registry["blocked"], id="notyet")

    def entry(self, srcs):
        rs = [rec(s, f"{s}-1", cve=["CVE-2026-0001"], asserted=(s == "notyet"), since="2026-10-01" if s == "notyet" else None) for s in srcs]
        return merge.merge(rs)["entries"][0]

    def test_nothing_is_published_from_a_source_that_is_not_cleared(self):
        self.assertIsNone(self.gen.card_for(self.entry(["notyet"]), self.registry))
        self.assertIsNone(self.gen.card_for(self.entry(["unknown-source"]), self.registry))

    def test_a_card_drops_the_data_of_uncleared_sources_even_on_the_same_vulnerability(self):
        c = self.gen.card_for(self.entry(["cleared", "notyet"]), self.registry)
        self.assertEqual(sorted(c["sources"]), ["cleared"])
        self.assertEqual(c["exploitation_summary"]["asserted_by"], [])              # the exploitation came only from the uncleared source: it is not published
        self.assertNotIn("notyet", json.dumps(c))
        self.assertEqual(c["withheld_sources"], 1)
        self.assertEqual(c["attribution"], {"cleared": "credit the cleared source"})
        self.assertEqual(validate(c, schema("vuln-card.schema.json")), [])

    def test_the_cli_writes_cards_only_for_cleared_sources(self):
        d = tempfile.mkdtemp(prefix="cards-")
        self.addCleanup(shutil.rmtree, d, True)
        mp, rp = os.path.join(d, "merged.json"), os.path.join(d, "reg.json")
        json.dump(merge.merge([rec("cleared", "c1", cve=["CVE-2026-0001"]), rec("notyet", "n1", cve=["CVE-2026-0002"])]), open(mp, "w"))
        json.dump({"schema": "macguard.source-registry/1", "sources": list(self.registry.values())}, open(rp, "w"))
        self.assertEqual(self.gen.main(["--merged", mp, "--out", os.path.join(d, "out"), "--registry", rp]), 0)
        self.assertEqual(sorted(os.listdir(os.path.join(d, "out"))), ["CVE-2026-0001.json", "index.json"])
        self.assertEqual(json.load(open(os.path.join(d, "out", "index.json")))["skipped_not_cleared"], 1)

    def test_with_the_real_registry_nothing_is_cleared_today(self):
        registry = reg.load()
        for sid in ("cisa-kev", "enisa-euvd", "enisa-euvd-exploited", "cert-eu-advisories", "incibe-cert", "ccn-cert", "nvd", "osv"):
            self.assertFalse(reg.clearance(registry, [sid])[0], sid)


class RegistryTests(unittest.TestCase):
    def test_every_european_source_is_registered_with_region_terms_and_a_reason(self):
        registry = reg.load()
        for sid, region in (("enisa-euvd", "EU"), ("enisa-euvd-exploited", "EU"), ("cert-eu-advisories", "EU"), ("incibe-cert", "ES"), ("ccn-cert", "ES"), ("cisa-kev", "US"), ("nvd", "US")):
            s = registry[sid]
            self.assertEqual(s["region"], region, sid)
            self.assertIn("vulns", s["families"])
            self.assertTrue(s["license"]["name"] and s["status_note"], sid)
            self.assertFalse(s.get("owner_confirmed"), sid)
        self.assertEqual(registry["incibe-cert"]["redistribution_status"], "blocked")
        self.assertEqual(registry["ccn-cert"]["redistribution_status"], "blocked")
        self.assertEqual(registry["enisa-euvd"]["redistribution_status"], "pending-legal")           # no EUVD terms found: not guessed
        self.assertIn("NOT confirmed", registry["enisa-euvd"]["license"]["name"])
        self.assertIn("could not be read", registry["ccn-cert"]["status_note"])

    def test_the_status_table_matches_the_builders(self):
        from intel import status
        by = {c["id"]: c for c in status.CHANNELS}
        for sid, spec in live_eu.SOURCES.items():
            self.assertEqual(by[spec["channel"]]["status"], "experimental")
            self.assertEqual(by[spec["channel"]]["sources"], [sid])
        self.assertEqual(by["vulns"]["sources"], ["cisa-kev"])
        self.assertTrue(all(c["status"] != "operational" for c in status.CHANNELS if c["family"] == "vulns"))


class CliTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="eu-cli-")
        self.addCleanup(shutil.rmtree, self.d, True)

    def run_cli(self, *args):
        p = subprocess.run([sys.executable, "-m", "intel", *args], cwd=ROOT, capture_output=True, text=True, timeout=120, env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": ROOT})
        return p.returncode, p.stdout, p.stderr

    def test_build_merge_lookup_and_assess_through_the_cli(self):
        items = [item(n, exploitedSince="Oct 13, 2026, 12:00:00 AM") for n in range(1, 4)]
        s = Server({live_eu._page_url("", "euvd-exploited", 0, datetime.now(timezone.utc), 3): (200, {}, page(items, 3)), "/": (200, {}, FEED.encode())})
        self.addCleanup(s.close)
        # the CLI uses the real clock, so serve the page for the date it will ask for
        code, out, err = self.run_cli("vulns", "build", "enisa-euvd-exploited", "--out", self.d, "--version", "1", "--url", s.url(""), "--allow-http-localhost", "--pause", "0")
        self.assertEqual(code, 0, err)
        res = json.loads(out)
        self.assertEqual((res["channel"], res["stats"]["accepted"], res["publishable"]), ("vulns-eukev", 3, False))
        code, out, err = self.run_cli("vulns", "build", "cert-eu-advisories", "--out", self.d, "--version", "1", "--url", s.url("/"), "--allow-http-localhost")
        self.assertEqual(code, 0, err)
        code, out, err = self.run_cli("vulns", "merge", "--channel", os.path.join(self.d, "vulns-eukev", "1"), "--channel", os.path.join(self.d, "vulns-certeu", "1"), "--out", self.d, "--version", "1")
        self.assertEqual(code, 0, err)
        mres = json.loads(out)
        self.assertEqual((mres["stats"]["entries"], mres["publishable"], mres["conflicts"]), (5, False, 0))
        self.assertIn("input channels that are not publishable", " ".join(mres["blocking_reasons"]))
        merged = os.path.join(self.d, "vulns-merged", "1", "merged.json")
        code, out, _e = self.run_cli("vulns", "lookup", "cve-2026-5001", "--merged", merged)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["entries"][0]["ids"]["euvd"], ["EUVD-2026-1001"])
        code, out, _e = self.run_cli("vulns", "lookup", ghsa(1).lower(), "--merged", merged)
        self.assertEqual(code, 0)
        self.assertEqual(self.run_cli("vulns", "lookup", "CVE-2099-0001", "--merged", merged)[0], 1)
        self.assertEqual(self.run_cli("vulns", "lookup", "nonsense", "--merged", merged)[0], 3)
        rows = os.path.join(self.d, "rows.json")
        json.dump({"schema": assess.SCHEMA_DISTRO, "rows": AssessTests.ROWS}, open(rows, "w"))
        base = ["vulns", "assess", "CVE-2026-5001", "--package", "apache2", "--distro", "debian", "--release", "bookworm", "--rows", rows]
        self.assertEqual(self.run_cli(*base, "--installed", "2.4.52-1+deb12u3")[0], 0)
        self.assertEqual(self.run_cli(*base, "--installed", "2.4.52-1+deb12u1")[0], 1)
        self.assertEqual(self.run_cli("vulns", "assess", "CVE-2026-5001", "--package", "apache2", "--installed", "1", "--distro", "debian", "--release", "bookworm")[0], 5)      # no data: not assessed

    def test_a_blocked_source_has_no_cli_adapter(self):
        code, _o, err = self.run_cli("vulns", "build", "incibe-cert", "--out", self.d, "--version", "1")
        self.assertNotEqual(code, 0)
        self.assertIn("invalid choice", err)


if __name__ == "__main__":
    unittest.main()
