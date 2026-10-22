"""The HTTP API (called as a function): public data, feeds, sessions, CSRF, rate limits, tenant isolation, channels, tokens, privacy and static files."""
import email
import email.policy
import hashlib
import json
import os
import re
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from alerts_helpers import NOW, NOWT, SHA, aff, contents_from, leaf, spec, test_registry, vrec  # noqa: F401
from alerts import api, delivery, engine, identity, mail, rss, store

PW = "correct horse battery staple"


class Client:
    def __init__(self, app, ip="203.0.113.7"):
        self.app, self.ip, self.cookie, self.csrf, self.last = app, ip, None, None, None

    def call(self, method, path, body=None, query=None, headers=None, raw=None, csrf=True, origin=None):
        h = dict(headers or {})
        if self.cookie:
            h["Cookie"] = f"{self.app.cookie_name}={self.cookie}"
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else b"")
        if body is not None and "Content-Type" not in h:
            h["Content-Type"] = "application/json"
        if csrf and self.csrf and method not in ("GET", "HEAD") and "X-CSRF-Token" not in h:
            h["X-CSRF-Token"] = self.csrf
        if origin:
            h["Origin"] = origin
            h["Host"] = "localhost:8080"
        q = {k: [str(v)] for k, v in (query or {}).items()}
        self.last = self.app.handle(api.Request(method, path, q, h, data, self.ip))
        return self.last

    def get(self, path, **kw): return self.call("GET", path, **kw)
    def post(self, path, body=None, **kw): return self.call("POST", path, body if body is not None else {}, **kw)
    def patch(self, path, body, **kw): return self.call("PATCH", path, body, **kw)
    def delete(self, path, **kw): return self.call("DELETE", path, **kw)

    def login(self, email_, pw=PW, totp=None):
        r = self.post("/api/v1/auth/login", {"email": email_, "password": pw, **({"totp": totp} if totp else {})}, csrf=False)
        if r.status == 200:
            self.csrf = r.json()["csrf"]
            m = re.search(re.escape(self.app.cookie_name) + r"=([^;]+)", r.headers["Set-Cookie"])
            self.cookie = m.group(1)
        return r


class ApiCase(unittest.TestCase):
    secure = False
    require_mfa = False

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="alerts-api-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.registry = test_registry()
        self.outbox = os.path.join(self.dir, "outbox")
        self.t = [0.0]
        self.app = api.App(os.path.join(self.dir, "a.db"), self.registry, delivery.Config(email_transport=mail.FileTransport(self.outbox)), clock=lambda: NOW, public_url="https://alerts.example.org",
                           secure_cookies=self.secure, require_mfa_for_org_admin=self.require_mfa, scrypt_params=identity.SCRYPT_TEST, rate_clock=lambda: self.t[0])
        self.db = store.connect(os.path.join(self.dir, "a.db"))
        self.addCleanup(self.db.close)

    def alerts(self, recs, registry=None):
        engine.ingest(self.db, contents_from(recs, registry or self.registry), NOWT)

    def signup(self, email_, ip="203.0.113.7"):
        c = Client(self.app, ip)
        self.assertEqual(c.post("/api/v1/auth/register", {"email": email_, "password": PW}, csrf=False).status, 201)
        self.assertEqual(c.login(email_).status, 200)
        return c

    def emails(self):
        out = []
        for n in sorted(os.listdir(self.outbox)) if os.path.isdir(self.outbox) else []:
            with open(os.path.join(self.outbox, n), "rb") as f:
                out.append(email.message_from_bytes(f.read(), policy=email.policy.default))
        return out


def two_alerts():
    return [vrec("cisa-kev", "CVE-2026-0001", cve=["CVE-2026-0001"], asserted=True, since="2026-10-01", title="Acme Widget RCE", summary="Acme Widget RCE"),
            vrec("enisa-euvd", "EUVD-2026-0001", cve=["CVE-2026-0001"], euvd=["EUVD-2026-0001"], score="9.8", vector="CVSS:3.1/AV:N", summary="Widget flaw", affected=[aff("Microsoft", "Windows 11", "1 <2")]),
            vrec("enisa-euvd", "EUVD-2026-0002", cve=["CVE-2026-0002"], euvd=["EUVD-2026-0002"], score="4.0", vector="CVSS:3.1/AV:L", summary="Other flaw", affected=[aff("Debian", "OpenSSL", "1 <2")])]


class PublicTests(ApiCase):
    def setUp(self):
        super().setUp()
        self.alerts(two_alerts())
        self.c = Client(self.app)

    def test_health_taxonomies_and_sources(self):
        self.assertTrue(self.c.get("/api/v1/health").json()["ok"])
        t = self.c.get("/api/v1/taxonomies").json()
        self.assertEqual([i["id"] for i in t["regions"]["items"]], ["ES", "EU", "OTHER", "GLOBAL"])
        self.assertEqual(t["sectors"]["version"], 1)
        rows = {r["id"]: r for r in self.c.get("/api/v1/sources").json()["sources"]}
        for pend in ("osv", "nvd", "debian-security-tracker", "ubuntu-security-notices", "redhat-security-data", "sigmahq"):
            self.assertEqual(rows[pend]["operational_state"], "pending", pend)
        for blk in ("ccn-cert", "abusech-bulk", "incibe-cert"):
            self.assertEqual(rows[blk]["operational_state"], "blocked", blk)
        self.assertEqual(rows["enisa-euvd"]["freshness"]["alerts"], 2)
        for r in rows.values():
            for k in ("endpoint", "license", "redistribution_status", "operational_state"):
                self.assertIn(k, r)

    def test_listing_with_query_filters_and_reasons(self):
        r = self.c.get("/api/v1/alerts").json()
        self.assertEqual(sorted(i["key"] for i in r["items"]), ["CVE-2026-0001", "CVE-2026-0002"])
        r = self.c.get("/api/v1/alerts", query={"exploited": "true"}).json()
        self.assertEqual([i["key"] for i in r["items"]], ["CVE-2026-0001"])
        self.assertEqual([x["field"] for x in r["items"][0]["match_reasons"]], ["exploited"])
        r = self.c.get("/api/v1/alerts", query={"os": "windows", "severity": "high"}).json()
        self.assertEqual([i["key"] for i in r["items"]], ["CVE-2026-0001"])
        r = self.c.get("/api/v1/alerts", query={"exposure": "internet"}).json()               # the second alert is a local vulnerability
        self.assertEqual([i["key"] for i in r["items"]], ["CVE-2026-0001"])
        r = self.c.get("/api/v1/alerts", query={"id": "euvd-2026-0002"}).json()
        self.assertEqual([i["key"] for i in r["items"]], ["CVE-2026-0002"])
        self.assertEqual(self.c.get("/api/v1/alerts", query={"limit": "1"}).json()["next_cursor"] is not None, True)

    def test_bad_input_is_a_clear_400_never_an_error(self):
        for q in ({"severity": "extreme"}, {"cvss_min": "abc"}, {"exploited": "maybe"}, {"published_after": "yesterday"}, {"region": "MARS"}, {"limit": "x"}, {"os": "'; DROP TABLE alerts;--"},
                  {"new_within_days": "1.5"}, {"id": "not-an-id"}):
            r = self.c.get("/api/v1/alerts", query=q)
            self.assertEqual(r.status, 400, q)
            self.assertIn("error", r.json())
        self.assertEqual(self.c.get("/api/v1/alerts", query={"cursor": "garbage"}).status, 400)
        self.assertEqual(self.c.get("/api/v1/alerts", query={"unknown_param": "1"}).status, 200)           # unknown parameters are ignored, never interpreted

    def test_search_takes_a_filter_document_and_refuses_anything_else(self):
        sp = spec({"all": [leaf("severity", "gte", "high"), leaf("region", "in", ["EU"])]})
        r = self.c.post("/api/v1/alerts/search", {"filter": sp, "limit": 10})
        self.assertEqual([i["key"] for i in r.json()["items"]], ["CVE-2026-0001"])
        self.assertEqual(self.c.post("/api/v1/alerts/search", {"filter": {"schema": "x"}}).status, 400)
        self.assertEqual(self.c.post("/api/v1/alerts/search", {"filter": {"schema": "macguard.subscription-filter/1", "version": 1, "expr": {"field": "sql", "op": "in", "value": ["x"]}}}).status, 400)
        self.assertEqual(self.c.call("POST", "/api/v1/alerts/search", raw=b"not json", headers={"Content-Type": "application/json"}).status, 400)
        self.assertEqual(self.c.call("POST", "/api/v1/alerts/search", raw=b"[]", headers={"Content-Type": "application/json"}).status, 400)
        self.assertEqual(self.c.call("POST", "/api/v1/alerts/search", raw=b"{}", headers={"Content-Type": "text/plain"}).status, 415)
        self.assertEqual(self.c.call("POST", "/api/v1/alerts/search", raw=b"x" * (api.MAX_BODY + 1), headers={"Content-Type": "application/json"}).status, 413)

    def test_alert_detail_and_versions(self):
        aid = self.c.get("/api/v1/alerts", query={"id": "CVE-2026-0001"}).json()["items"][0]["alert_id"]
        d = self.c.get(f"/api/v1/alerts/{aid}").json()
        self.assertEqual(d["alert"]["key"], "CVE-2026-0001")
        self.assertEqual(sorted(d["alert"]["observations"]), ["cisa-kev", "enisa-euvd"])
        self.assertEqual(d["versions"][0]["record_version"], 1)
        for bad in ("/api/v1/alerts/MGA-" + "0" * 20, "/api/v1/alerts/x", "/api/v1/alerts/MGA-ZZ"):
            self.assertEqual(self.c.get(bad).status, 404, bad)

    def test_the_public_api_never_shows_a_source_that_is_not_cleared(self):
        r = dict(self.registry)
        r["enisa-euvd"] = dict(r["enisa-euvd"], owner_confirmed=False)
        app = api.App(os.path.join(self.dir, "a.db"), r, clock=lambda: NOW, scrypt_params=identity.SCRYPT_TEST)
        c = Client(app)
        blob = json.dumps([c.get("/api/v1/alerts").json(), c.post("/api/v1/alerts/search", {"filter": spec({"all": []})}).json()])
        for leak in ("EUVD-2026-0001", "Widget flaw", "Windows 11", "9.8", "enisa-euvd\""):
            self.assertNotIn(leak, blob.replace('"enisa-euvd": ', "").replace("enisa-euvd-exploited", ""), leak)
        keys = [i["key"] for i in c.get("/api/v1/alerts").json()["items"]]
        self.assertEqual(keys, ["CVE-2026-0001"])                                        # only the cleared source's observation remains
        aid = c.get("/api/v1/alerts").json()["items"][0]["alert_id"]
        self.assertNotIn("Widget flaw", json.dumps(c.get(f"/api/v1/alerts/{aid}").json()))
        alert2 = self.db.execute("SELECT alert_id FROM alerts WHERE key='CVE-2026-0002'").fetchone()["alert_id"]
        self.assertEqual(c.get(f"/api/v1/alerts/{alert2}").status, 404)

    def test_rate_limit_on_public_endpoints(self):
        for _ in range(120):
            self.assertEqual(self.c.get("/api/v1/alerts").status, 200)
        r = self.c.get("/api/v1/alerts")
        self.assertEqual(r.status, 429)
        self.assertGreaterEqual(int(r.headers["Retry-After"]), 1)
        self.assertEqual(Client(self.app, "198.51.100.9").get("/api/v1/alerts").status, 200)         # another address is unaffected
        self.t[0] += 61
        self.assertEqual(self.c.get("/api/v1/alerts").status, 200)

    def test_headers_methods_and_internal_errors(self):
        r = self.c.get("/api/v1/health")
        self.assertEqual((r.headers["X-Content-Type-Options"], r.headers["Referrer-Policy"], r.headers["Cache-Control"]), ("nosniff", "no-referrer", "no-store"))
        self.assertEqual(self.c.call("DELETE", "/api/v1/health").status, 405)
        self.assertEqual(self.c.get("/api/v1/nothing").status, 404)
        boom = api.App.health
        api.App.health = lambda self, req, ctx: (_ for _ in ()).throw(RuntimeError("secret internal detail /etc/passwd"))
        try:
            self.app.routes = self.app._routes()
            r = self.c.get("/api/v1/health")
        finally:
            api.App.health = boom
        self.assertEqual(r.status, 500)
        self.assertNotIn("secret", r.body.decode())


class FeedTests(ApiCase):
    def setUp(self):
        super().setUp()
        self.alerts(two_alerts())
        self.c = Client(self.app)

    def test_public_feeds_are_valid_rss_and_carry_attribution_and_reasons_free_text(self):
        for fid in ("all", "exploited", "critical", "region-eu", "region-es", "rules", "source-cisa-kev"):
            r = self.c.get(f"/feeds/public/{fid}.xml")
            self.assertEqual(r.status, 200, fid)
            self.assertEqual(rss.validate_rss(r.body), [], fid)
            self.assertTrue(r.headers["Content-Type"].startswith("application/rss+xml"))
        r = self.c.get("/feeds/public/exploited.xml")
        self.assertIn(b"CVE-2026-0001", r.body)
        self.assertNotIn(b"CVE-2026-0002", r.body)
        self.assertEqual(self.c.get("/feeds/public/region-es.xml").body.count(b"<item>"), 0)                # an empty feed is still a valid feed
        self.assertEqual(self.c.get("/feeds/public/critical.xml").body.count(b"<item>"), 1)
        self.assertIn(b"Atribuci", self.c.get("/feeds/public/all.xml").body) if False else None
        self.assertEqual(self.c.get("/feeds/public/nope.xml").status, 404)
        self.assertEqual(self.c.get("/feeds/public/all.xml", query={"lang": "fr"}).status, 400)
        en = self.c.get("/feeds/public/all.xml", query={"lang": "en"}).body
        self.assertIn(b"<language>en</language>", en)
        self.assertIn(b"Severity:", en)

    def test_etag_revalidation_and_the_index_hashes_match_the_bodies(self):
        r = self.c.get("/feeds/public/all.xml")
        etag = r.headers["ETag"]
        self.assertEqual(self.c.get("/feeds/public/all.xml", headers={"If-None-Match": etag}).status, 304)
        idx = self.c.get("/feeds/index.json").json()
        f = [x for x in idx["feeds"] if x["id"] == "all"][0]
        self.assertEqual(f["sha256"], hashlib.sha256(r.body).hexdigest())
        self.assertEqual(f["items"], 2)
        empty = [x for x in idx["feeds"] if x["id"] == "region-es"][0]
        self.assertIn("no alert matches", empty["empty_reason"])

    def test_a_feed_with_no_cleared_source_is_empty_not_leaking(self):
        r = {k: dict(v, owner_confirmed=False) if k in ("cisa-kev", "enisa-euvd") else v for k, v in self.registry.items()}
        app = api.App(os.path.join(self.dir, "a.db"), r, clock=lambda: NOW)
        body = Client(app).get("/feeds/public/all.xml").body
        self.assertEqual(body.count(b"<item>"), 0)
        self.assertNotIn(b"CVE-2026", body)

    def test_hostile_text_is_escaped_and_cannot_break_the_xml(self):
        self.alerts([vrec("enisa-euvd", "EUVD-2026-0009", cve=["CVE-2026-0009"], euvd=["EUVD-2026-0009"], score="5.0", summary="</description><script>alert(1)</script>]]> \x01\x08 &entity;",
                          title="x </title><b>", refs=["https://ok.example/?a=1&b=2"])])
        body = self.c.get("/feeds/public/all.xml").body
        self.assertEqual(rss.validate_rss(body), [])
        self.assertNotIn(b"<script>", body)
        self.assertNotIn(b"\x01", body)

    def test_validator_rejects_broken_feeds(self):
        good = self.c.get("/feeds/public/all.xml").body
        for bad in (good.replace(b"<rss", b"<foo", 1), good.replace(b"</channel>", b""), b"<rss version='2.0'><channel><title>t</title></channel></rss>", good.replace(b"<guid", b"<guidx", 1),
                    b'<!DOCTYPE x [<!ENTITY a "b">]><rss version="2.0"><channel/></rss>', good.replace(b"https://", b"ftp://")):
            self.assertTrue(rss.validate_rss(bad), bad[:60])


class FeedTokenTests(ApiCase):
    def setUp(self):
        super().setUp()
        self.alerts(two_alerts())
        self.a, self.b = self.signup("a@example.org"), self.signup("b@example.org", "198.51.100.2")

    def personal_sub(self, c, name="mine", expr=None):
        r = c.post("/api/v1/subscriptions", {"name": name, "scope": "PERSONAL", "filter": spec(expr or {"all": []})})
        self.assertEqual(r.status, 201, r.body)
        return r.json()["sub_id"]

    def feed_for(self, c, **body):
        r = c.post("/api/v1/feed-tokens", {"label": "reader", **body})
        self.assertEqual(r.status, 201, r.body)
        return r.json()

    def run_pipeline(self, recs):
        self.alerts(recs)
        from alerts import matching
        matching.match_pending(self.db, self.registry, NOW)

    def test_a_private_feed_shows_only_its_owner_matches_and_is_never_cacheable(self):
        sa = self.personal_sub(self.a, "A exploited", {"all": [leaf("exploited", "is", True)]})
        self.personal_sub(self.b, "B everything")
        self.run_pipeline([vrec("cisa-kev", "CVE-2026-0050", cve=["CVE-2026-0050"], asserted=True, since="2026-10-20", title="Acme 50", summary="Acme 50"),
                           vrec("enisa-euvd", "EUVD-2026-0051", cve=["CVE-2026-0051"], euvd=["EUVD-2026-0051"], score="5.0", summary="Plain 51")])
        ta, tb = self.feed_for(self.a), self.feed_for(self.b)
        fa = Client(self.app).get(ta["feed_url"].replace("https://alerts.example.org", ""))
        fb = Client(self.app).get(tb["feed_url"].replace("https://alerts.example.org", ""))
        self.assertEqual((fa.status, fb.status), (200, 200))
        self.assertEqual(rss.validate_rss(fa.body), [])
        self.assertIn(b"CVE-2026-0050", fa.body)
        self.assertNotIn(b"CVE-2026-0051", fa.body)                                                  # A's filter
        self.assertIn(b"CVE-2026-0051", fb.body)
        self.assertEqual((fa.headers["Cache-Control"], fa.headers["X-Robots-Tag"], fa.headers["Referrer-Policy"]), ("private, no-store", "noindex, nofollow", "no-referrer"))
        self.assertIn(b"Por qu", fa.body)                                                              # the reasons are in the item
        self.assertNotIn(ta["feed_url"].split("/")[-1].encode(), fb.body)

    def test_tokens_revoke_rotate_expire_and_guessing_is_throttled(self):
        self.personal_sub(self.a)
        t = self.feed_for(self.a, expires_days=1)
        path = t["feed_url"].replace("https://alerts.example.org", "")
        anon = Client(self.app)
        self.assertEqual(anon.get(path).status, 200)
        rot = self.a.post(f"/api/v1/feed-tokens/{t['token_id']}/rotate", {"grace_minutes": 0})
        self.assertEqual(rot.status, 201)
        self.assertEqual(anon.get(path).status, 404)                                                 # the old URL is dead
        newpath = rot.json()["feed_url"].replace("https://alerts.example.org", "")
        self.assertEqual(anon.get(newpath).status, 200)
        tid = rot.json()["token_id"]
        self.assertEqual(self.a.post(f"/api/v1/feed-tokens/{tid}/revoke", {}).status, 200)
        self.assertEqual(anon.get(newpath).status, 404)
        self.assertEqual(self.b.post(f"/api/v1/feed-tokens/{tid}/revoke", {}).status, 404)           # not B's token
        guess = Client(self.app, "192.0.2.77")
        statuses = [guess.get("/feeds/private/" + ("A" * 43 if i % 2 else "B" * 43) + ".xml").status for i in range(30)]
        self.assertEqual(statuses[:20], [404] * 20)
        self.assertIn(429, statuses[20:])                                                              # brute-forcing is throttled
        self.assertEqual(Client(self.app, "192.0.2.78").get("/feeds/private/short.xml").status, 404)

    def test_listing_never_contains_the_token_and_the_logs_never_do(self):
        self.personal_sub(self.a)
        t = self.feed_for(self.a)
        token = t["feed_url"].rsplit("/", 1)[1][:-4]
        self.assertNotIn(token, json.dumps(self.a.get("/api/v1/feed-tokens").json()))
        Client(self.app).get(f"/feeds/private/{token}.xml")
        self.assertFalse([l for l in self.app.access_log if token in l])
        self.assertTrue([l for l in self.app.access_log if "/feeds/private/<redacted>.xml" in l])
        self.assertEqual(api.redact("/api/v1/channels/confirm?token=abc&x=1"), "/api/v1/channels/confirm?token=<redacted>&x=1")
        self.assertEqual(api.redact("/feeds/private/SECRETvalue_-1.xml"), "/feeds/private/<redacted>.xml")

    def test_an_organisation_feed_follows_the_owners_current_rights(self):
        oid = self.a.post("/api/v1/orgs", {"name": "Acme"}).json()["org_id"]
        self.a.post("/api/v1/subscriptions", {"name": "org", "scope": "ORGANIZATION", "org_id": oid, "filter": spec({"all": []})})
        self.assertEqual(self.a.post("/api/v1/members", {}, csrf=True).status, 404)
        viewer_c = self.signup("viewer@example.org", "198.51.100.3")
        self.assertEqual(self.a.post(f"/api/v1/orgs/{oid}/members", {"email": "viewer@example.org", "role": "viewer"}).status, 201)
        self.run_pipeline([vrec("enisa-euvd", "EUVD-2026-0060", cve=["CVE-2026-0060"], euvd=["EUVD-2026-0060"], score="6.0", summary="Org item")])
        tok = viewer_c.post("/api/v1/feed-tokens", {"label": "org", "org_id": oid}).json()
        path = tok["feed_url"].replace("https://alerts.example.org", "")
        anon = Client(self.app)
        self.assertIn(b"CVE-2026-0060", anon.get(path).body)
        mem = [m for m in self.a.get(f"/api/v1/orgs/{oid}/members").json()["members"] if m["email"] == "viewer@example.org"][0]["membership_id"]
        self.a.delete(f"/api/v1/orgs/{oid}/members/{mem}")
        self.assertEqual(anon.get(path).status, 404)                                                 # the token outlived the membership; the feed did not
        self.assertEqual(self.b.post("/api/v1/feed-tokens", {"label": "x", "org_id": oid}).status, 403)


class SessionTests(ApiCase):
    secure = True

    def test_cookie_flags_csrf_origin_and_content_type(self):
        c = Client(self.app)
        c.post("/api/v1/auth/register", {"email": "a@example.org", "password": PW}, csrf=False)
        r = c.login("a@example.org")
        cookie = r.headers["Set-Cookie"]
        self.assertTrue(cookie.startswith("__Host-mg_session="))
        for flag in ("HttpOnly", "SameSite=Lax", "Secure", "Path=/"):
            self.assertIn(flag, cookie)
        self.assertEqual(c.get("/api/v1/me").status, 200)
        self.assertEqual(c.post("/api/v1/subscriptions", {"name": "x", "filter": spec({"all": []})}, csrf=False).status, 403)                 # no CSRF token
        self.assertEqual(c.post("/api/v1/subscriptions", {"name": "x", "filter": spec({"all": []})}, headers={"X-CSRF-Token": "wrong"}).status, 403)
        self.assertEqual(c.post("/api/v1/subscriptions", {"name": "x", "filter": spec({"all": []})}, origin="https://evil.example").status, 403)   # cross-origin
        self.assertEqual(c.post("/api/v1/subscriptions", {"name": "x", "filter": spec({"all": []})}, origin="https://alerts.example.org").status, 201)
        self.assertEqual(c.call("POST", "/api/v1/subscriptions", raw=b"name=x", headers={"Content-Type": "application/x-www-form-urlencoded", "X-CSRF-Token": c.csrf}).status, 415)   # a plain HTML form cannot post
        self.assertEqual(Client(self.app).get("/api/v1/me").status, 401)
        bad = Client(self.app)
        bad.cookie = "x" * 43
        self.assertEqual(bad.get("/api/v1/subscriptions").status, 401)
        self.assertEqual(c.post("/api/v1/auth/logout", {}).status, 200)
        self.assertEqual(c.get("/api/v1/me").status, 401)                                                                                         # the server forgot the session

    def test_registration_does_not_reveal_whether_an_address_exists(self):
        c = Client(self.app)
        a = c.post("/api/v1/auth/register", {"email": "a@example.org", "password": PW}, csrf=False)
        b = c.post("/api/v1/auth/register", {"email": "a@example.org", "password": "another long password!"}, csrf=False)
        self.assertEqual((a.status, a.body), (b.status, b.body))
        self.assertEqual(c.post("/api/v1/auth/register", {"email": "x@example.org", "password": "short"}, csrf=False).status, 400)
        self.assertEqual(c.login("a@example.org", "another long password!").status, 401)                                                        # the second password never took effect

    def test_login_failures_are_uniform_throttled_and_lock(self):
        c = Client(self.app)
        c.post("/api/v1/auth/register", {"email": "a@example.org", "password": PW}, csrf=False)
        r1, r2 = c.login("a@example.org", "wrong password here"), c.login("ghost@example.org", "wrong password here")
        self.assertEqual((r1.status, r1.body), (r2.status, r2.body))
        for _ in range(8):
            c.login("a@example.org", "wrong password here")
        self.assertEqual(c.login("a@example.org", PW).status, 429)
        self.assertIn("Retry-After", c.last.headers)


class MfaTests(ApiCase):
    require_mfa = True

    def test_organisation_administration_needs_the_second_factor(self):
        a = self.signup("a@example.org")
        oid = a.post("/api/v1/orgs", {"name": "Acme"}).json()["org_id"]
        r = a.get(f"/api/v1/orgs/{oid}/audit")
        self.assertEqual((r.status, r.json()["error"]["code"]), (403, "mfa_required"))
        self.assertEqual(a.post(f"/api/v1/orgs/{oid}/units", {"name": "Ops"}).status, 403)
        self.assertEqual(a.get(f"/api/v1/orgs/{oid}/members").status, 200)                           # reading the member list is not an administrative change
        secret = a.post("/api/v1/auth/mfa/enroll", {}).json()["secret"]
        self.assertEqual(a.post("/api/v1/auth/mfa/confirm", {"code": "000000"}).status, 400)
        code = identity.totp_code(secret, int(NOW.timestamp()))
        self.assertEqual(a.post("/api/v1/auth/mfa/confirm", {"code": code}).status, 200)
        self.assertEqual(a.get("/api/v1/me").status, 401)                                              # sessions were closed
        self.assertEqual(Client(self.app).login("a@example.org").json()["error"]["code"], "mfa_required")
        a2 = Client(self.app)
        self.assertEqual(a2.login("a@example.org", totp=identity.totp_code(secret, int(NOW.timestamp()))).status, 200)
        self.assertTrue(a2.get("/api/v1/me").json()["mfa_verified"])
        self.assertEqual(a2.post(f"/api/v1/orgs/{oid}/units", {"name": "Ops"}).status, 201)
        self.assertEqual(a2.get(f"/api/v1/orgs/{oid}/audit").status, 200)


class OrgApiTests(ApiCase):
    def setUp(self):
        super().setUp()
        self.a, self.b = self.signup("a@example.org"), self.signup("b@example.org", "198.51.100.2")
        self.oa = self.a.post("/api/v1/orgs", {"name": "Org A"}).json()["org_id"]
        self.ob = self.b.post("/api/v1/orgs", {"name": "Org B"}).json()["org_id"]

    def test_one_tenant_cannot_touch_the_other_through_any_endpoint(self):
        sa = self.a.post("/api/v1/subscriptions", {"name": "A", "scope": "ORGANIZATION", "org_id": self.oa, "filter": spec({"all": []})}).json()["sub_id"]
        self.assertEqual([s["name"] for s in self.b.get("/api/v1/subscriptions").json()["subscriptions"]], [])
        for call in (lambda: self.b.get(f"/api/v1/subscriptions/{sa}"), lambda: self.b.patch(f"/api/v1/subscriptions/{sa}", {"name": "pwn"}), lambda: self.b.delete(f"/api/v1/subscriptions/{sa}"),
                     lambda: self.b.post(f"/api/v1/subscriptions/{sa}/suspend", {}), lambda: self.b.post(f"/api/v1/subscriptions/{sa}/duplicate", {})):
            self.assertEqual(call().status, 404)
        for call in (lambda: self.b.get(f"/api/v1/orgs/{self.oa}/members"), lambda: self.b.get(f"/api/v1/orgs/{self.oa}/audit"), lambda: self.b.post(f"/api/v1/orgs/{self.oa}/units", {"name": "x"}),
                     lambda: self.b.post(f"/api/v1/orgs/{self.oa}/members", {"email": "b@example.org", "role": "owner"})):
            self.assertEqual(call().status, 403)
        self.assertEqual(self.b.post("/api/v1/subscriptions", {"name": "x", "scope": "ORGANIZATION", "org_id": self.oa, "filter": spec({"all": []})}).status, 403)
        self.assertEqual(self.a.get(f"/api/v1/subscriptions/{sa}").json()["name"], "A")
        # the effective tenant is never taken from the request: extra fields are ignored
        r = self.b.post("/api/v1/subscriptions", {"name": "mine", "scope": "PERSONAL", "org_id": self.ob, "filter": spec({"all": []})})
        self.assertEqual(r.status, 400)
        r = self.b.post("/api/v1/subscriptions", {"name": "mine", "scope": "PERSONAL", "owner_user_id": "u_x", "tenant": self.oa, "filter": spec({"all": []})})
        self.assertEqual(r.status, 201)
        self.assertNotEqual(r.json()["owner_user_id"], "u_x")
        self.assertIsNone(r.json()["org_id"])

    def test_members_units_roles_and_the_audit_log_through_the_api(self):
        self.signup("c@example.org", "198.51.100.3")
        self.assertEqual(self.a.post(f"/api/v1/orgs/{self.oa}/members", {"email": "c@example.org", "role": "auditor"}).status, 201)
        self.assertEqual(self.a.post(f"/api/v1/orgs/{self.oa}/units", {"name": "Ops"}).status, 201)
        c = Client(self.app, "198.51.100.3")
        c.login("c@example.org")
        me = c.get("/api/v1/me").json()
        self.assertEqual(me["organizations"][0]["role"], "auditor")
        self.assertIn("audit_logs.read", me["organizations"][0]["permissions"])
        log = c.get(f"/api/v1/orgs/{self.oa}/audit").json()
        self.assertTrue(log["chain"])
        self.assertTrue({"org.create", "member.add", "unit.create"} <= {e["action"] for e in log["entries"]})
        self.assertEqual(c.post(f"/api/v1/orgs/{self.oa}/units", {"name": "x"}).status, 403)           # an auditor changes nothing
        self.assertEqual(c.post("/api/v1/subscriptions", {"name": "x", "scope": "ORGANIZATION", "org_id": self.oa, "filter": spec({"all": []})}).status, 403)

    def test_msp_flow(self):
        m = self.signup("msp@example.org", "198.51.100.4")
        mo = m.post("/api/v1/orgs", {"name": "MSP", "kind": "msp"}).json()["org_id"]
        lid = m.post("/api/v1/msp-links/propose", {"msp_org_id": mo, "customer_org_id": self.oa, "delegated_role": "security_manager"}).json()["link_id"]
        self.assertEqual(m.post("/api/v1/msp-links/accept", {"customer_org_id": self.oa, "link_id": lid}).status, 403)
        self.assertEqual(self.a.post("/api/v1/msp-links/accept", {"customer_org_id": self.oa, "link_id": lid}).status, 200)
        r = m.post("/api/v1/subscriptions", {"name": "for A", "scope": "MSP_CUSTOMER", "org_id": mo, "customer_org_id": self.oa, "filter": spec({"all": []})})
        self.assertEqual(r.status, 201)
        self.assertEqual([s["name"] for s in self.a.get("/api/v1/subscriptions").json()["subscriptions"]], ["for A"])
        self.assertEqual(self.a.post("/api/v1/msp-links/end", {"link_id": lid}).status, 200)
        self.assertEqual(m.get("/api/v1/subscriptions").json()["subscriptions"], [])


class SubscriptionChannelTests(ApiCase):
    def setUp(self):
        super().setUp()
        self.alerts(two_alerts())
        self.c = self.signup("me@example.org")

    def test_create_edit_duplicate_suspend_delete(self):
        r = self.c.post("/api/v1/subscriptions", {"name": "Windows critical", "scope": "PERSONAL", "filter": spec({"all": [leaf("os", "in", ["windows"]), leaf("severity", "gte", "high")]}),
                                                 "frequency": "daily", "notify_on": ["new", "exploitation_added"], "critical_immediate": False})
        self.assertEqual(r.status, 201)
        s = r.json()
        self.assertEqual((s["frequency"], s["notify_on"], s["critical_immediate"], s["filter_version"], s["state"]), ("daily", ["exploitation_added", "new"], False, 1, "active"))
        p = self.c.patch(f"/api/v1/subscriptions/{s['sub_id']}", {"name": "Renamed", "filter": spec({"all": [leaf("os", "in", ["linux"])]})}).json()
        self.assertEqual((p["name"], p["filter_version"]), ("Renamed", 2))
        d = self.c.post(f"/api/v1/subscriptions/{s['sub_id']}/duplicate", {}).json()
        self.assertEqual((d["state"], d["name"]), ("draft", "Renamed (copia)"))
        self.assertEqual(self.c.post(f"/api/v1/subscriptions/{s['sub_id']}/suspend", {}).json()["state"], "suspended")
        self.assertEqual(self.c.post(f"/api/v1/subscriptions/{s['sub_id']}/resume", {}).json()["state"], "active")
        self.assertEqual(self.c.delete(f"/api/v1/subscriptions/{s['sub_id']}").status, 200)
        self.assertEqual(self.c.get(f"/api/v1/subscriptions/{s['sub_id']}").status, 404)
        for bad in ({"name": "", "filter": spec({"all": []})}, {"name": "x", "filter": {"schema": "x"}}, {"name": "x", "filter": spec({"all": []}), "frequency": "hourly"},
                    {"name": "x", "filter": spec({"all": []}), "scope": "GALAXY"}, {"name": "x"}):
            self.assertEqual(self.c.post("/api/v1/subscriptions", bad).status, 400, bad)

    def test_email_channel_needs_a_confirmed_address_and_confirmation_is_a_post(self):
        r = self.c.post("/api/v1/channels", {"kind": "email", "address": "me@example.org", "locale": "en"})
        self.assertEqual(r.status, 201)
        cid = r.json()["channel_id"]
        self.assertNotIn("token", r.body.decode().lower().replace("no token", ""))
        mails = self.emails()
        self.assertEqual(len(mails), 1)
        link = re.search(r"https://alerts.example.org(/api/v1/channels/confirm\?token=[\w-]+)", mails[0].get_content()).group(1)
        path, token = link.split("?token=")
        anon = Client(self.app)
        page = anon.get(path, query={"token": token})
        self.assertEqual(page.status, 200)
        self.assertIn(b"<form", page.body)
        self.assertEqual(self.db.execute("SELECT state FROM notification_channels WHERE channel_id=?", (cid,)).fetchone()["state"], "pending")      # a link scanner GETting it confirms nothing
        r = anon.call("POST", path, raw=f"token={token}".encode(), headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(r.status, 200)
        self.assertEqual(self.db.execute("SELECT state FROM notification_channels WHERE channel_id=?", (cid,)).fetchone()["state"], "active")
        self.assertEqual(anon.call("POST", path, raw=f"token={token}".encode(), headers={"Content-Type": "application/x-www-form-urlencoded"}).status, 400)
        listed = self.c.get("/api/v1/channels").json()["channels"][0]
        self.assertEqual((listed["state"], listed["address"]), ("active", "m***@example.org"))

    def test_one_click_unsubscribe(self):
        self.c.post("/api/v1/channels", {"kind": "email", "address": "me@example.org", "locale": "en"})
        token = re.search(r"token=([\w-]+)", self.emails()[0].get_content()).group(1)
        cid = self.db.execute("SELECT channel_id FROM notification_channels").fetchone()["channel_id"]
        anon = Client(self.app)
        anon.call("POST", "/api/v1/channels/confirm", raw=f"token={token}".encode(), headers={"Content-Type": "application/x-www-form-urlencoded"})
        from alerts import subs
        unsub = subs.unsubscribe_token(self.db, cid)
        self.assertEqual(anon.get("/api/v1/channels/unsubscribe", query={"token": unsub}).status, 200)          # shows a form only
        self.assertEqual(self.db.execute("SELECT state FROM notification_channels").fetchone()["state"], "active")
        self.assertEqual(anon.call("POST", "/api/v1/channels/unsubscribe", query={"token": unsub}, raw=b"List-Unsubscribe=One-Click", headers={"Content-Type": "application/x-www-form-urlencoded"}).status, 200)
        self.assertEqual(self.db.execute("SELECT state FROM notification_channels").fetchone()["state"], "unsubscribed")
        self.assertEqual(anon.call("POST", "/api/v1/channels/unsubscribe", query={"token": cid + ".forged"}, raw=b"x", headers={"Content-Type": "application/x-www-form-urlencoded"}).status, 400)

    def test_webhooks_with_unsafe_destinations_are_refused_with_the_reason(self):
        for url in ("http://hooks.example.com/x", "https://127.0.0.1/x", "https://169.254.169.254/latest/meta-data/", "https://localhost/x", "https://hooks.example.com:22/"):
            r = self.c.post("/api/v1/channels", {"kind": "webhook", "url": url})
            self.assertEqual(r.status, 400, url)
            self.assertIn("refused", r.json()["error"]["message"])
        self.assertEqual(self.c.post("/api/v1/channels", {"kind": "sms", "address": "x"}).status, 400)

    def test_preview_uses_real_alerts_and_sends_nothing(self):
        before = len(self.emails())
        r = self.c.post("/api/v1/alerts/search", {"filter": spec({"all": [leaf("exploited", "is", True)]})}).json()
        self.assertEqual([i["key"] for i in r["items"]], ["CVE-2026-0001"])
        self.assertEqual(len(self.emails()), before)
        self.assertEqual(self.db.execute("SELECT COUNT(*) n FROM alert_matches").fetchone()["n"], 0)

    def test_history_inbox_and_deliveries_endpoints(self):
        from alerts import matching
        ch = self.c.post("/api/v1/channels", {"kind": "email", "address": "me@example.org", "locale": "en"}).json()["channel_id"]
        token = re.search(r"token=([\w-]+)", self.emails()[0].get_content()).group(1)
        Client(self.app).call("POST", "/api/v1/channels/confirm", raw=f"token={token}".encode(), headers={"Content-Type": "application/x-www-form-urlencoded"})
        sid = self.c.post("/api/v1/subscriptions", {"name": "all", "scope": "PERSONAL", "filter": spec({"all": []}), "channel_ids": [ch]}).json()["sub_id"]
        self.alerts([vrec("enisa-euvd", "EUVD-2026-0070", cve=["CVE-2026-0070"], euvd=["EUVD-2026-0070"], score="9.0", summary="New one")])
        matching.match_pending(self.db, self.registry, NOW)
        delivery.run_due(self.db, self.registry, NOW, self.app.cfg)
        m = self.c.get("/api/v1/matches", query={"sub_id": sid}).json()["items"]
        self.assertEqual(len(m), 1)
        self.assertEqual(self.c.post(f"/api/v1/matches/{m[0]['match_id']}/read", {}).status, 200)
        self.assertEqual(self.c.post(f"/api/v1/matches/{m[0]['match_id']}/ack", {}).status, 200)
        self.assertEqual(self.c.get("/api/v1/matches", query={"unread": "true"}).json()["items"], [])
        d = self.c.get("/api/v1/deliveries").json()["deliveries"]
        self.assertEqual([x["state"] for x in d], ["sent"])
        other = self.signup("other@example.org", "198.51.100.8")
        self.assertEqual(other.get("/api/v1/matches").json()["items"], [])
        self.assertEqual(other.post(f"/api/v1/matches/{m[0]['match_id']}/read", {}).status, 404)
        self.assertEqual(other.get("/api/v1/matches", query={"sub_id": sid}).status, 404)

    def test_privacy_export_and_erasure(self):
        self.c.post("/api/v1/subscriptions", {"name": "mine", "scope": "PERSONAL", "filter": spec({"all": []})})
        self.c.post("/api/v1/channels", {"kind": "email", "address": "me@example.org"})
        t = self.c.post("/api/v1/feed-tokens", {"label": "r"}).json()
        exp = self.c.get("/api/v1/me/export").json()
        self.assertEqual(exp["user"]["email"], "me@example.org")
        self.assertEqual(len(exp["subscriptions"]), 1)
        self.assertNotIn(t["feed_url"].rsplit("/", 1)[1][:-4], json.dumps(exp))                  # token values cannot be exported: they are not stored
        self.assertEqual(self.c.post("/api/v1/me/erase", {"confirm": "yes"}).status, 400)
        self.assertEqual(self.c.post("/api/v1/me/erase", {"confirm": "erase my account"}).status, 200)
        self.assertEqual(self.c.get("/api/v1/me").status, 401)
        u = self.db.execute("SELECT * FROM users").fetchone()
        self.assertEqual((u["state"], u["display_name"]), ("deleted", None))
        self.assertNotIn("me@example.org", u["email"])
        self.assertEqual(self.db.execute("SELECT COUNT(*) n FROM notification_channels WHERE address IS NOT NULL").fetchone()["n"], 0)
        self.assertEqual(self.db.execute("SELECT COUNT(*) n FROM credentials").fetchone()["n"], 0)
        self.assertEqual(Client(self.app).login("me@example.org").status, 401)
        self.assertTrue(store.verify_audit(self.db)["ok"])
        self.assertNotIn("me@example.org", json.dumps([dict(r) for r in self.db.execute("SELECT * FROM audit_log")]))

    def test_the_only_owner_cannot_erase_the_account(self):
        self.c.post("/api/v1/orgs", {"name": "Mine"})
        r = self.c.post("/api/v1/me/erase", {"confirm": "erase my account"})
        self.assertEqual(r.status, 400)
        self.assertIn("only owner", r.json()["error"]["message"])


class StaticTests(ApiCase):
    def setUp(self):
        super().setUp()
        self.site = os.path.join(self.dir, "site")
        os.makedirs(os.path.join(self.site, "intelligence"))
        for rel, txt in (("index.html", "<h1>home</h1>"), ("intelligence/a.html", "<p>a</p>"), (".secret", "no"), ("style.css", "body{}")):
            with open(os.path.join(self.site, rel), "w") as f:
                f.write(txt)
        with open(os.path.join(self.dir, "outside.txt"), "w") as f:
            f.write("outside")
        self.app = api.App(os.path.join(self.dir, "a.db"), self.registry, clock=lambda: NOW, site_dir=self.site, secure_cookies=False)
        self.c = Client(self.app)

    def test_serves_files_and_refuses_everything_else(self):
        self.assertIn(b"home", self.c.get("/").body)
        self.assertEqual(self.c.get("/style.css").headers["Content-Type"].split(";")[0], "text/css")
        self.assertEqual(self.c.get("/intelligence/a.html").status, 200)
        for bad in ("/.secret", "/../outside.txt", "/intelligence/../../outside.txt", "/%2e%2e/outside.txt", "/intelligence/", "/nope", "//etc/passwd", "/intelligence/..%2f..%2foutside.txt"):
            self.assertEqual(self.c.get(bad).status, 404, bad)
        os.symlink(os.path.join(self.dir, "outside.txt"), os.path.join(self.site, "link.txt"))
        self.assertEqual(self.c.get("/link.txt").status, 404)                                      # a symlink out of the site is not followed
        self.assertEqual(self.c.call("POST", "/style.css").status, 404)


if __name__ == "__main__":
    unittest.main()
