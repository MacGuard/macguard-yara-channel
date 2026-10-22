"""Tests for the download layer and the two wired real sources. They run against a LOCAL HTTP server (a test double of the upstream feeds);
the real upstream feeds were exercised separately by hand and are recorded in the delivery report, never in a unit test (no network in tests)."""
import hashlib
import http.server
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

from intel import fetch, live, ioc, catalog, verify  # noqa: E402
from test_intel import test_registry, slurp  # noqa: E402

NOW = datetime(2026, 10, 22, 12, 0, 0, tzinfo=timezone.utc)

KEV = {"title": "t", "catalogVersion": "2026.10.21", "dateReleased": "2026-10-21T14:04:39Z", "count": 6, "vulnerabilities": [
    {"cveID": "CVE-2024-0001", "vendorProject": "Acme", "product": "Widget", "vulnerabilityName": "Acme Widget RCE", "dateAdded": "2024-01-02", "dueDate": "2024-01-23", "knownRansomwareCampaignUse": "Known"},
    {"cveID": "cve-2023-12345", "vendorProject": "Beta", "product": "Gadget", "vulnerabilityName": "x", "dateAdded": "2023-05-06"},
    {"cveID": "CVE-2024-0001", "vendorProject": "Acme", "product": "Widget", "vulnerabilityName": "dup", "dateAdded": "2024-01-02"},
    {"cveID": "NOT-A-CVE", "vendorProject": "Acme", "product": "Widget", "dateAdded": "2024-01-02"},
    {"cveID": "CVE-2022-9999", "vendorProject": "Acme", "product": "Widget", "dateAdded": "yesterday"},
    {"cveID": "CVE-2022-8888", "vendorProject": "", "product": "Widget", "dateAdded": "2022-01-01"}]}
FEODO = [{"ip_address": "93.184.216.34", "port": 443, "status": "online", "malware": "QakBot", "first_seen": "2026-10-01 10:00:00", "last_online": "2026-10-20"},
         {"ip_address": "8.8.4.4", "port": 8080, "status": "offline", "malware": "Emotet", "first_seen": "2025-01-01 00:00:00", "last_online": "2026-10-10"},
         {"ip_address": "1.2.3.4", "port": 80, "status": "offline", "malware": "Old", "first_seen": "2022-01-01 00:00:00", "last_online": "2026-03-07"},
         {"ip_address": "10.0.0.9", "port": 80, "status": "online", "malware": "Private", "last_online": "2026-10-21"},
         {"ip_address": "not-an-ip", "port": 80, "status": "online", "malware": "X", "last_online": "2026-10-21"}]


class Server:
    """Serves a dict {path: (status, headers, body)} on 127.0.0.1."""

    def __init__(self, routes):
        outer = routes

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                st, hdr, body = outer.get(self.path, (404, {}, b"not found"))
                self.send_response(st)
                for k, v in hdr.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        self.t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.t.start()

    def url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="intel-live-")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.registry = test_registry()
        self.registry["abusech-feodo"] = dict(self.registry["feedA"], id="abusech-feodo", default_ttl_days=30)
        self.registry["cisa-kev"] = dict(self.registry["feedA"], id="cisa-kev", default_ttl_days=3650)

    def serve(self, routes):
        s = Server(routes)
        self.addCleanup(s.close)
        return s


class FetchTests(Base):
    def test_downloads_keep_the_original_bytes_and_a_retrieval_record(self):
        body = b"hello feed\n"
        s = self.serve({"/f": (200, {"ETag": '"abc"'}, body)})
        rec = fetch.fetch(s.url("/f"), self.d, "f.txt", self.registry["feedA"], allow_http_localhost=True, now="2026-10-22T00:00:00Z")
        self.assertEqual(slurp(os.path.join(self.d, "f.txt"), "rb"), body)
        self.assertEqual((rec["sha256"], rec["bytes"], rec["etag"], rec["status"]), (hashlib.sha256(body).hexdigest(), len(body), '"abc"', 200))
        self.assertEqual(json.loads(slurp(os.path.join(self.d, "f.txt.retrieval.json")))["source_id"], "feedA")

    def test_https_only_no_credentials_and_nothing_overwritten(self):
        for bad in ("http://example.com/x", "ftp://example.com/x", "file:///etc/passwd", "https://user:pw@example.com/x"):
            with self.assertRaises(fetch.FetchError):
                fetch.fetch(bad, self.d, "x", None)
        with self.assertRaises(fetch.FetchError):
            fetch.fetch("http://127.0.0.1:1/x", self.d, "x", None)                     # localhost needs the explicit test flag
        s = self.serve({"/f": (200, {}, b"x")})
        fetch.fetch(s.url("/f"), self.d, "f", None, allow_http_localhost=True)
        with self.assertRaises(fetch.FetchError):
            fetch.fetch(s.url("/f"), self.d, "f", None, allow_http_localhost=True)       # never overwritten
        for name in ("../x", "", ".hidden", "a/b"):
            with self.assertRaises(fetch.FetchError):
                fetch.fetch(s.url("/f"), self.d, name, None, allow_http_localhost=True)

    def test_a_source_that_needs_a_credential_is_never_fetched(self):
        s = self.serve({"/f": (200, {}, b"x")})
        with self.assertRaises(fetch.FetchError) as cm:
            fetch.fetch(s.url("/f"), self.d, "f", self.registry["keyed"], allow_http_localhost=True)
        self.assertIn("credential", str(cm.exception))
        self.assertFalse(os.path.exists(os.path.join(self.d, "f")))

    def test_size_limit_errors_and_redirects(self):
        s = self.serve({"/big": (200, {}, b"x" * 5000), "/empty": (200, {}, b""), "/gone": (410, {}, b"gone"),
                        "/redir": (302, {"Location": "http://evil.invalid/x"}, b"")})
        for path, why in (("/big", "limit"), ("/empty", "unexpected"), ("/gone", "HTTP 410"), ("/redir", "non-HTTPS")):
            with self.assertRaises(fetch.FetchError) as cm:
                fetch.fetch(s.url(path), self.d, "o" + path.strip("/"), None, max_bytes=1000, allow_http_localhost=True)
            self.assertIn(why, str(cm.exception), path)
            self.assertFalse(os.path.exists(os.path.join(self.d, "o" + path.strip("/"))))     # nothing partial is left behind


class LiveKevTests(Base):
    def run_kev(self, doc=None, raw=None, registry=None):
        body = raw if raw is not None else json.dumps(doc or KEV).encode()
        s = self.serve({"/kev.json": (200, {}, body)})
        return live.build_live("cisa-kev", self.d, 1, registry or self.registry, NOW, url=s.url("/kev.json"), allow_http_localhost=True), body

    def test_accepts_valid_records_rejects_the_rest_and_counts_both(self):
        res, body = self.run_kev()
        st = res["stats"]
        self.assertEqual((st["accepted"], st["rejected"]), (2, 4))
        self.assertEqual(st["rejected_by_reason"], {"duplicate-cve-id": 1, "invalid-cve-id": 1, "invalid-date-added": 1, "missing-vendor-or-product": 1})
        self.assertTrue(st["count_matches_declared"])         # the file declares 6 and holds 6 items (a duplicate is a rejection, not a count mismatch)
        self.assertEqual(st["input_items"], 6)
        idx = [json.loads(line) for line in slurp(os.path.join(res["dir"], "kev-index.jsonl")).splitlines()]
        self.assertEqual([r["cve"] for r in idx], ["CVE-2023-12345", "CVE-2024-0001"])         # normalised to upper case, sorted
        self.assertEqual(idx[1]["due_date"], "2024-01-23")

    def test_the_original_is_preserved_byte_for_byte_and_labelled_original(self):
        res, body = self.run_kev()
        m = json.loads(slurp(os.path.join(res["dir"], "manifest.json")))
        by = {a["path"]: a for a in m["artifacts"]}
        self.assertEqual(by["known_exploited_vulnerabilities.json"]["origin"], "original")
        self.assertEqual(by["known_exploited_vulnerabilities.json"]["sha256"], hashlib.sha256(body).hexdigest())
        self.assertEqual(by["kev-index.jsonl"]["origin"], "derived")
        self.assertEqual(by["known_exploited_vulnerabilities.json.retrieval.json"]["origin"], "derived")
        self.assertEqual((m["channel"]["family"], m["channel"]["id"]), ("vulns", "vulns"))

    def test_publication_stays_blocked_until_the_owner_confirms(self):
        reg2 = dict(self.registry)
        reg2["cisa-kev"] = dict(self.registry["cisa-kev"], owner_confirmed=False)
        res, _ = self.run_kev(registry=reg2)
        self.assertFalse(res["publishable"])
        self.assertIn("owner has not confirmed", res["blocking_reasons"][0])
        shutil.rmtree(os.path.join(self.d, "vulns"))
        res, _ = self.run_kev()
        self.assertTrue(res["publishable"])

    def test_garbage_input_is_an_error_not_an_empty_channel(self):
        for raw in (b"not json", b'{"vulnerabilities": 5}', b'{"x": []}', b"[]"):
            shutil.rmtree(os.path.join(self.d, "vulns"), True)
            with self.assertRaises(fetch.FetchError):
                self.run_kev(raw=raw)

    def test_the_built_channel_verifies_through_a_catalog(self):
        res, _ = self.run_kev()
        ref = catalog.channel_ref(os.path.join(res["dir"], "manifest.json"))
        doc = catalog.build_catalog(1, "t", [ref])
        cp = catalog.write_catalog(doc, os.path.join(self.d, "cat"))
        out = verify.verify_catalog(cp, self.d)
        self.assertEqual(out["exit_code"], 5)                      # consistent, unsigned
        self.assertEqual([c for c in out["checks"] if c["status"] == "FAIL"], [])


class LiveFeodoTests(Base):
    def run_feodo(self, rows=None):
        s = self.serve({"/f.json": (200, {}, json.dumps(rows if rows is not None else FEODO).encode())})
        return live.build_live("abusech-feodo", self.d, 1, self.registry, NOW, url=s.url("/f.json"), allow_http_localhost=True)

    def test_global_ips_are_published_with_ttl_private_and_invalid_are_rejected_and_stale_expire(self):
        res = self.run_feodo()
        st = res["stats"]
        self.assertEqual((st["input_items"], st["published"], st["expired"], st["rejected"]), (5, 2, 1, 2))
        self.assertEqual(st["rejected_by_reason"], {"invalid-ip": 1, "non-global-ip": 1})
        recs = [json.loads(line) for line in slurp(os.path.join(res["dir"], "ioc-ipv4.jsonl")).splitlines()]
        self.assertEqual([r["value"] for r in recs], ["8.8.4.4", "93.184.216.34"])
        online = [r for r in recs if r["value"] == "93.184.216.34"][0]
        offline = [r for r in recs if r["value"] == "8.8.4.4"][0]
        self.assertGreater(online["confidence"], offline["confidence"])                     # online C2 is trusted more than offline
        self.assertEqual(online["family"], "QakBot")
        self.assertIn("c2", online["tags"])

    def test_an_all_stale_feed_publishes_nothing_and_says_why(self):
        res = self.run_feodo([FEODO[2]])
        self.assertEqual((res["stats"]["published"], res["stats"]["expired"]), (0, 1))

    def test_only_the_fetch_module_uses_the_network(self):
        banned = re.compile(r"urllib\.request|urllib\.error|\burlopen\b|http\.client|\brequests\b|\bsocket\b|ftplib|smtplib")
        for fn in os.listdir(os.path.join(ROOT, "intel")):
            if fn.endswith(".py") and fn != "fetch.py":
                self.assertIsNone(banned.search(slurp(os.path.join(ROOT, "intel", fn))), fn)


if __name__ == "__main__":
    unittest.main()
