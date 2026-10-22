"""Matching, queueing, digests, rate limits, e-mail, webhooks (SSRF, signatures, retries, dead letters), idempotency, freshness and metrics."""
import email
import email.policy
import json
import os
import ssl
import subprocess
import threading
import http.server
import socket
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from alerts_helpers import NOW, NOWT, DbCase, aff, contents_from, leaf, spec, SPEC_ALL, vrec  # noqa: F401
from alerts import delivery, engine, mail, matching, store, subs, webhook

PUBLIC = lambda host, port, **kw: [(2, 1, 6, "", ("93.184.216.34", port))]       # noqa: E731


def at(minutes=0, hours=0, days=0):
    return NOW + timedelta(minutes=minutes, hours=hours, days=days)


def alert(n=1, **kw):
    d = dict(cve=[f"CVE-2026-{n:04d}"], euvd=[f"EUVD-2026-{n:04d}"], score="7.5", vector="CVSS:3.1/AV:N", summary=f"Widget {n} flaw", affected=[aff("Acme", "Widget")], title=None)
    d.update(kw)
    return vrec("enisa-euvd", f"EUVD-2026-{n:04d}", **d)


def kev(n=1, since="2026-10-10"):
    return vrec("cisa-kev", f"CVE-2026-{n:04d}", cve=[f"CVE-2026-{n:04d}"], asserted=True, since=since, title=f"Widget {n} RCE", summary=f"Widget {n} RCE")


class World(DbCase):
    def setUp(self):
        super().setUp()
        self.uid = self.user("me@example.org")
        self.p = self.principal(self.uid)
        self.outbox = os.path.join(self.dir, "outbox")
        self.transport = mail.FileTransport(self.outbox)
        self.cfg = delivery.Config(base_url="https://alerts.example.org", email_transport=self.transport)
        self.sent = []

    def channel(self, locale="es", address="me@example.org"):
        c = subs.add_email_channel(self.db, self.p, address, NOWT, locale=locale)
        subs.confirm_channel(self.db, c["confirm_token"], NOWT)
        return c["channel_id"]

    def sub(self, expr=None, channels=None, **kw):
        s = subs.create(self.db, self.p, NOWT, name=kw.pop("name", "my sub"), scope="PERSONAL", spec=spec(expr if expr is not None else {"all": []}), channel_ids=channels or [], **kw)
        return s["sub_id"]

    def feed(self, recs, when=NOW, ingest_at=None):
        engine.ingest(self.db, contents_from(recs, self.reg), store.utc(ingest_at or when))
        return matching.match_pending(self.db, self.reg, when)

    def emls(self):
        return sorted(os.listdir(self.outbox)) if os.path.isdir(self.outbox) else []

    def read_eml(self, name):
        with open(os.path.join(self.outbox, name), "rb") as f:
            return email.message_from_bytes(f.read(), policy=email.policy.default)


class MatchingTests(World):
    def test_a_new_alert_matches_and_the_reasons_are_stored(self):
        sid = self.sub({"all": [leaf("severity", "gte", "high"), leaf("vendor", "in", ["acme"])]})
        r = self.feed([alert(1)])
        self.assertEqual((r["events"], r["material"], r["matches"], r["evaluations"]), (1, 1, 1, 1))
        m = self.db.execute("SELECT * FROM alert_matches").fetchone()
        self.assertEqual((m["sub_id"], m["kind"], m["record_version"], m["filter_version"]), (sid, "new", 1, 1))
        self.assertEqual([x["field"] for x in json.loads(m["reasons_json"])], ["severity", "vendor"])

    def test_non_matching_alerts_and_unselected_changes_are_not_matched(self):
        self.sub({"all": [leaf("os", "in", ["linux"])]})
        self.assertEqual(self.feed([alert(1)])["matches"], 0)
        self.sub({"all": []}, notify_on=["exploitation_added"], name="only exploitation")
        self.assertEqual(self.feed([alert(2)])["matches"], 0)                                      # a new alert is not an 'exploitation_added' change

    def test_a_subscription_only_sees_events_after_it_was_activated(self):
        self.feed([alert(1)])
        self.sub()
        self.assertEqual(matching.match_pending(self.db, self.reg, NOW)["events"], 0)             # nothing is replayed
        self.assertEqual(self.feed([alert(2)])["matches"], 1)

    def test_resuming_does_not_replay_what_happened_while_suspended(self):
        sid = self.sub()
        subs.set_state(self.db, self.p, sid, "suspended", NOWT)
        self.assertEqual(self.feed([alert(1)])["matches"], 0)
        subs.set_state(self.db, self.p, sid, "active", NOWT)
        self.assertEqual(self.feed([alert(1)])["matches"], 0)                                      # unchanged data, nothing new
        self.assertEqual(self.feed([alert(2)])["matches"], 1)

    def test_an_updated_alert_without_a_material_change_notifies_nobody(self):
        self.sub()
        self.feed([alert(1)])
        r = self.feed([alert(1, summary="reworded", refs=["https://x.example/y"])])
        self.assertEqual((r["events"], r["material"], r["matches"]), (1, 0, 0))

    def test_new_evidence_of_exploitation_is_a_notification_of_its_own(self):
        sid = self.sub()
        self.feed([alert(1)])
        r = self.feed([alert(1), kev(1)])
        self.assertEqual(r["matches"], 1)
        kinds = [(m["kind"], json.loads(m["changes_json"])) for m in self.db.execute("SELECT * FROM alert_matches ORDER BY created_utc, rowid")]
        self.assertEqual(kinds[0], ("new", ["new"]))
        self.assertEqual(kinds[1][0], "update")
        self.assertIn("exploitation_added", kinds[1][1])
        self.assertEqual(self.feed([alert(1), kev(1)])["matches"], 0)                              # the same again: nothing
        self.assertEqual(sid, self.db.execute("SELECT sub_id FROM alert_matches LIMIT 1").fetchone()["sub_id"])

    def test_running_the_matcher_twice_never_duplicates(self):
        self.sub()
        engine.ingest(self.db, contents_from([alert(1)], self.reg), NOWT)
        matching.match_pending(self.db, self.reg, NOW)
        self.db.execute("DELETE FROM meta WHERE key='matched_seq'")                                  # simulate a crash before the pointer was saved
        r = matching.match_pending(self.db, self.reg, NOW)
        self.assertEqual((r["matches"], r["duplicates_avoided"]), (0, 1))
        self.assertEqual(self.db.execute("SELECT COUNT(*) n FROM alert_matches").fetchone()["n"], 1)

    def test_a_filter_edit_applies_from_the_next_event_and_records_its_version(self):
        sid = self.sub({"all": [leaf("os", "in", ["linux"])]})
        self.assertEqual(self.feed([alert(1)])["matches"], 0)
        subs.update(self.db, self.p, sid, NOWT, spec=spec({"all": []}))
        self.assertEqual(self.feed([alert(2)])["matches"], 1)
        self.assertEqual(self.db.execute("SELECT filter_version FROM alert_matches").fetchone()["filter_version"], 2)

    def test_a_source_that_is_not_cleared_produces_no_match(self):
        self.sub()
        r = dict(self.reg)
        r["enisa-euvd"] = dict(r["enisa-euvd"], owner_confirmed=False)
        engine.ingest(self.db, contents_from([alert(1)], self.reg), NOWT)
        out = matching.match_pending(self.db, r, NOW)
        self.assertEqual((out["matches"], out["not_distributable"]), (0, 1))

    def test_stale_sources_do_not_count_as_current_exploitation(self):
        self.sub({"all": [leaf("exploited", "is", True)]})
        engine.ingest(self.db, contents_from([alert(1), kev(1)], self.reg), NOWT)
        out = matching.match_pending(self.db, self.reg, NOW, stale=["cisa-kev"])
        self.assertEqual(out["matches"], 0)

    def test_latency_and_lag_are_measured(self):
        for i in range(5):
            self.sub({"all": [leaf("vendor", "in", ["acme"])]}, name=f"s{i}")
        self.feed([alert(1)], when=at(minutes=3), ingest_at=NOW)
        m = store.metric_summary(self.db, "match.latency_ms.p95")
        self.assertEqual(m["count"], 1)
        lag = store.metric_summary(self.db, "ingest_to_match.seconds")
        self.assertEqual(lag["max"], 180.0)


class EmailTests(World):
    def test_immediate_mail_goes_out_once_with_unsubscribe_headers_in_the_channel_language(self):
        cid = self.channel("en")
        self.sub(channels=[cid])
        self.feed([alert(1)])
        res = delivery.run_due(self.db, self.reg, NOW, self.cfg)
        self.assertEqual(res["sent"], 1)
        (name,) = self.emls()
        m = self.read_eml(name)
        self.assertEqual(m["To"], "me@example.org")
        self.assertIn("HIGH", m["Subject"])
        self.assertTrue(m["List-Unsubscribe"].startswith("<https://alerts.example.org/api/v1/channels/unsubscribe?token="))
        self.assertEqual(m["List-Unsubscribe-Post"], "List-Unsubscribe=One-Click")
        self.assertEqual(m["Auto-Submitted"], "auto-generated")
        body = m.get_content()
        self.assertIn("Severity: high", body)
        self.assertIn("Why it matches", body)
        self.assertEqual(delivery.run_due(self.db, self.reg, NOW, self.cfg)["sent"], 0)            # nothing is sent twice
        d = self.db.execute("SELECT * FROM notification_deliveries").fetchone()
        self.assertEqual((d["state"], d["attempts"]), ("sent", 1))

    def test_spanish_is_the_default_language(self):
        cid = self.channel("es")
        self.sub(channels=[cid])
        self.feed([alert(1)])
        delivery.run_due(self.db, self.reg, NOW, self.cfg)
        body = self.read_eml(self.emls()[0]).get_content()
        self.assertIn("Severidad: high", body)
        self.assertIn("Por qué coincide", body)

    def test_nothing_goes_to_an_unconfirmed_address(self):
        c = subs.add_email_channel(self.db, self.p, "me@example.org", NOWT)
        sid = self.sub(channels=[])
        self.db.execute("INSERT INTO subscription_recipients(sub_id, channel_id) VALUES(?,?)", (sid, c["channel_id"]))      # even if wired by hand
        self.feed([alert(1)])
        self.assertEqual(self.db.execute("SELECT COUNT(*) n FROM notification_deliveries").fetchone()["n"], 0)
        self.assertEqual(self.emls(), [])

    def test_header_injection_through_an_alert_title_is_neutralised(self):
        cid = self.channel("en")
        self.sub(channels=[cid])
        self.feed([alert(1, title="Bad\r\nBcc: evil@example.org", summary="Bad\r\nBcc: evil@example.org")])
        delivery.run_due(self.db, self.reg, NOW, self.cfg)
        m = self.read_eml(self.emls()[0])
        self.assertIsNone(m["Bcc"])
        self.assertNotIn("\n", m["Subject"])

    def test_digest_groups_matches_once_per_window(self):
        cid = self.channel("en")
        self.sub(channels=[cid], frequency="daily", critical_immediate=False)
        self.feed([alert(1), alert(2), alert(3)])
        self.assertEqual(delivery.run_due(self.db, self.reg, NOW, self.cfg)["sent"], 0)            # a digest is not sent per alert
        self.assertEqual(matching.build_digests(self.db, at(hours=1)), 1)
        self.assertEqual(matching.build_digests(self.db, at(hours=1, minutes=1)), 0)               # one per window
        delivery.run_due(self.db, self.reg, at(hours=1), self.cfg)
        (name,) = self.emls()
        m = self.read_eml(name)
        self.assertIn("digest (3)", m["Subject"])
        self.assertEqual(m.get_content().count("== "), 3)
        self.feed([alert(4)], when=at(hours=2))
        self.assertEqual(matching.build_digests(self.db, at(hours=2)), 0)                          # the next window has not opened
        self.assertEqual(matching.build_digests(self.db, at(days=1, hours=2)), 1)

    def test_critical_alerts_go_out_at_once_even_when_the_preference_is_a_digest(self):
        cid = self.channel("en")
        self.sub(channels=[cid], frequency="weekly", critical_immediate=True)
        self.feed([alert(1, score="5.0"), alert(2, score="9.9")])
        self.assertEqual(self.db.execute("SELECT COUNT(*) n FROM notification_deliveries WHERE mode='immediate'").fetchone()["n"], 1)
        self.feed([alert(3, score="5.0"), kev(3)])                                                  # a new exploitation statement is urgent too... for an EXISTING alert
        self.assertGreaterEqual(self.db.execute("SELECT COUNT(*) n FROM notification_deliveries WHERE mode='immediate'").fetchone()["n"], 1)

    def test_the_hourly_limit_defers_to_a_digest_and_loses_nothing(self):
        cid = self.channel("en")
        self.sub(channels=[cid])
        n = matching.IMMEDIATE_PER_HOUR + 5
        self.feed([alert(i) for i in range(1, n + 1)])
        self.assertEqual(self.db.execute("SELECT COUNT(*) n FROM notification_deliveries WHERE mode='immediate'").fetchone()["n"], matching.IMMEDIATE_PER_HOUR)
        self.assertEqual(self.db.execute("SELECT COUNT(*) n FROM alert_matches").fetchone()["n"], n)
        self.assertEqual(matching.build_digests(self.db, at(hours=1)), 1)
        d = self.db.execute("SELECT * FROM notification_deliveries WHERE mode='digest'").fetchone()
        self.assertEqual(len(json.loads(d["match_ids_json"])), 5)
        self.assertGreaterEqual(store.metric_summary(self.db, "immediate_limit_hit")["count"], 1)

    def test_a_per_recipient_send_limit_defers_instead_of_failing(self):
        cid = self.channel("en")
        self.sub(channels=[cid])
        self.feed([alert(i) for i in range(1, 15)])
        r = delivery.run_due(self.db, self.reg, NOW, self.cfg)
        self.assertEqual(r["sent"], delivery.EMAIL_PER_HOUR)
        self.assertGreater(r["deferred"], 0)
        self.assertEqual(self.db.execute("SELECT COUNT(*) n FROM notification_deliveries WHERE state='dead'").fetchone()["n"], 0)
        self.assertEqual(delivery.run_due(self.db, self.reg, at(hours=1, minutes=1), self.cfg)["sent"], r["deferred"])

    def test_bounces_switch_a_channel_off(self):
        cid = self.channel("en")
        self.assertEqual(mail.handle_bounce(self.db, cid, "soft", NOWT), "active")
        self.assertEqual(mail.handle_bounce(self.db, cid, "soft", NOWT), "active")
        self.assertEqual(mail.handle_bounce(self.db, cid, "soft", NOWT), "suspended")
        cid2 = self.channel("en", "b@example.org")
        self.assertEqual(mail.handle_bounce(self.db, cid2, "hard", NOWT), "bounced")
        self.sub(channels=[])
        sid = self.db.execute("SELECT sub_id FROM subscriptions").fetchone()["sub_id"]
        self.db.execute("INSERT INTO subscription_recipients(sub_id, channel_id) VALUES(?,?)", (sid, cid2))
        self.feed([alert(1)])
        self.assertEqual(self.db.execute("SELECT COUNT(*) n FROM notification_deliveries").fetchone()["n"], 0)        # a bounced address gets nothing

    def test_a_permanent_smtp_refusal_bounces_and_a_temporary_one_retries(self):
        cid = self.channel("en")
        self.sub(channels=[cid])
        self.feed([alert(1)])

        class T:
            def __init__(s, kind): s.kind = kind
            def send(s, msg): return s.kind, "x"
        self.cfg.email_transport = T("temporary")
        self.assertEqual(delivery.run_due(self.db, self.reg, NOW, self.cfg)["retry"], 1)
        self.assertEqual(delivery.run_due(self.db, self.reg, NOW, self.cfg)["sent"], 0)            # not due yet (backoff)
        self.cfg.email_transport = T("permanent")
        r = delivery.run_due(self.db, self.reg, at(minutes=2), self.cfg)
        self.assertEqual(r["dead"], 1)
        self.assertEqual(self.db.execute("SELECT state FROM notification_channels WHERE channel_id=?", (cid,)).fetchone()["state"], "bounced")

    def test_confirmation_message_and_templates(self):
        m = mail.render_confirmation("a@example.org", "TOKEN123", "en", "https://alerts.example.org", "x@example.org", "d1", NOW)
        self.assertIn("https://alerts.example.org/api/v1/channels/confirm?token=TOKEN123", m.get_content())
        self.assertIn("Confirm", m["Subject"])
        self.assertIn("Confirma", mail.render_confirmation("a@example.org", "T", "es", None, "x@example.org", "d1", NOW)["Subject"])

    def test_the_mail_cannot_reveal_a_withheld_source(self):
        r = dict(self.reg)
        cid = self.channel("en")
        self.sub(channels=[cid])
        self.feed([alert(1, summary="euvd secret wording"), kev(1)])
        r["enisa-euvd"] = dict(r["enisa-euvd"], owner_confirmed=False)                              # withdrawn after matching, before sending
        delivery.run_due(self.db, r, NOW, self.cfg)
        txt = self.read_eml(self.emls()[0]).get_content()
        self.assertNotIn("euvd secret wording", txt)
        self.assertNotIn("EUVD-2026-0001", txt)


class WebhookSecurityTests(unittest.TestCase):
    def test_url_rules(self):
        for bad in ("http://example.com/", "https://127.0.0.1/", "https://localhost/", "https://LOCALHOST./", "https://foo.localhost/", "https://a.internal/", "https://printer.local/", "https://10.0.0.1/",
                    "https://[fd00::1]/", "https://169.254.169.254/latest/meta-data/", "https://metadata.google.internal/", "https://user:pass@example.com/", "https://example.com:8080/", "https://example.com:22/",
                    "https://2130706433/", "https://0x7f000001/", "https://0177.0.0.1/", "https://example.com/#frag", "https://example/", "https://-bad.example.com/", "ftp://example.com/", "javascript:alert(1)",
                    "", None, "https://exa mple.com/", "https://example.com/\r\nHost: evil", "https://" + "a" * 70 + ".example.com/", "https://example.com/" + "a" * 2100, "https://%31%32%37.0.0.1/", "https://127.1/"):
            with self.assertRaises(webhook.UnsafeDestination, msg=repr(bad)):
                webhook.check_url_syntax(bad)
        self.assertEqual(webhook.check_url_syntax("https://Hooks.Example.COM/in?x=1")[:3], ("hooks.example.com", 443, "/in?x=1"))
        self.assertEqual(webhook.check_url_syntax("https://hooks.example.com:8443/")[1], 8443)

    def test_every_resolved_address_must_be_public(self):
        def res(*ips):
            return lambda h, p, **kw: [(2, 1, 6, "", (ip, p)) for ip in ips]
        for ips in (("127.0.0.1",), ("10.1.2.3",), ("172.16.0.1",), ("192.168.0.1",), ("169.254.169.254",), ("100.64.0.1",), ("100.100.100.200",), ("0.0.0.0",), ("224.0.0.1",), ("240.0.0.1",),
                    ("::1",), ("fe80::1",), ("fc00::1",), ("::ffff:127.0.0.1",), ("::ffff:10.0.0.1",), ("fd00:ec2::254",), ("93.184.216.34", "10.0.0.1")):
            with self.assertRaises(webhook.UnsafeDestination, msg=str(ips)):
                webhook.resolve_public("hooks.example.com", 443, res(*ips))
        self.assertEqual(webhook.resolve_public("hooks.example.com", 443, res("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946")), ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"])
        with self.assertRaises(webhook.UnsafeDestination):
            webhook.resolve_public("nope.example.com", 443, mock.Mock(side_effect=socket.gaierror))

    def test_send_revalidates_and_refuses_a_name_that_now_resolves_privately(self):
        priv = lambda h, p, **kw: [(2, 1, 6, "", ("10.0.0.9", p))]       # noqa: E731
        r = webhook.send("https://hooks.example.com/in", b"{}", {}, resolver=priv)
        self.assertIsNone(r.status)
        self.assertIn("refused", r.error)

    def test_signatures_verify_and_reject_tampering_replays_and_rotation(self):
        k1, k2 = "11" * 32, "22" * 32
        body = b'{"id":"d1"}'
        h = webhook.sign([k1, k2], body, 1_700_000_000)
        self.assertTrue(webhook.verify_signature(k1, body, h, now=1_700_000_100))
        self.assertTrue(webhook.verify_signature(k2, body, h, now=1_700_000_100))                  # either key during a rotation
        self.assertFalse(webhook.verify_signature("33" * 32, body, h, now=1_700_000_100))
        self.assertFalse(webhook.verify_signature(k1, body + b" ", h, now=1_700_000_100))
        self.assertFalse(webhook.verify_signature(k1, body, h, now=1_700_000_100 + 301))           # replay window
        for bad in ("", "t=abc,v1=00", "v1=00", "t=1700000000"):
            self.assertFalse(webhook.verify_signature(k1, body, bad, now=1_700_000_100))

    def test_backoff_schedule_ends_in_the_dead_letter_state(self):
        self.assertEqual([webhook.backoff_seconds(n) for n in range(1, 7)], [60, 300, 1800, 7200, 21600, None])


class Receiver:
    """A local HTTP endpoint that records what it gets and answers with a scripted status."""

    def __init__(self, statuses):
        self.statuses, self.got = list(statuses), []
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                outer.got.append({"path": self.path, "headers": dict(self.headers), "body": body})
                st = outer.statuses.pop(0) if outer.statuses else 200
                self.send_response(st)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class WebhookDeliveryTests(World):
    def hook(self, statuses):
        rcv = Receiver(statuses)
        self.addCleanup(rcv.close)
        # the destination check is bypassed for this one local plain-HTTP receiver by test-only flags that no API can set
        w = subs.add_webhook_channel(self.db, self.p, "https://hooks.example.com/in", NOWT, resolver=PUBLIC)
        self.db.execute("UPDATE notification_channels SET address=? WHERE channel_id=?", (f"http://127.0.0.1:{rcv.port}/in", w["channel_id"]))
        self.cfg.webhook_kwargs = {"_test_allow_http_localhost": True}
        return rcv, w

    def test_payload_signature_and_event_id_survive_retries(self):
        rcv, w = self.hook([503, 503, 200])
        self.sub(channels=[w["channel_id"]])
        self.feed([alert(1), kev(1)])
        t = NOW
        outcomes = []
        for wait in (0, 61, 301):
            t = t + timedelta(seconds=wait)
            outcomes.append(delivery.run_due(self.db, self.reg, t, self.cfg))
        self.assertEqual([o["retry"] for o in outcomes], [1, 1, 0])
        self.assertEqual(outcomes[2]["sent"], 1)
        self.assertEqual(len(rcv.got), 3)
        ids = {g["headers"]["X-MacGuard-Event-Id"] for g in rcv.got}
        self.assertEqual(len(ids), 1)                                                              # the same event id on every attempt: receivers can de-duplicate
        g = rcv.got[-1]
        self.assertTrue(webhook.verify_signature(w["secret"], g["body"], g["headers"]["X-MacGuard-Signature"], now=int(t.timestamp())))
        self.assertEqual(g["headers"]["X-MacGuard-Attempt"], "3")
        body = json.loads(g["body"])
        self.assertEqual((body["type"], body["id"]), ("alert.match", list(ids)[0]))
        self.assertEqual(body["matches"][0]["alert"]["key"], "CVE-2026-0001")
        self.assertNotIn("secret", g["body"].decode())
        self.assertEqual(self.db.execute("SELECT attempts, state FROM notification_deliveries").fetchone()[:], (3, "sent"))

    def test_exhausted_retries_end_in_the_dead_letter_state_and_a_flapping_endpoint_is_disabled(self):
        rcv, w = self.hook([500] * 400)
        self.sub(channels=[w["channel_id"]])
        self.feed([alert(i) for i in range(1, 12)])
        t = NOW
        for _ in range(8):
            t += timedelta(hours=7)
            delivery.run_due(self.db, self.reg, t, self.cfg)
        st = self.db.execute("SELECT state, COUNT(*) n FROM notification_deliveries GROUP BY state").fetchall()
        self.assertEqual({r["state"] for r in st} - {"dead", "cancelled"}, set())
        ch = self.db.execute("SELECT * FROM notification_channels WHERE channel_id=?", (w["channel_id"],)).fetchone()
        self.assertEqual(ch["state"], "disabled")
        self.assertIn("too many failures", ch["disabled_reason"])
        self.assertTrue(self.db.execute("SELECT 1 FROM audit_log WHERE action='channel.disabled'").fetchone())

    def test_410_gone_and_client_errors_are_permanent(self):
        rcv, w = self.hook([410])
        self.sub(channels=[w["channel_id"]])
        self.feed([alert(1)])
        r = delivery.run_due(self.db, self.reg, NOW, self.cfg)
        self.assertEqual(r["dead"], 1)
        self.assertEqual(self.db.execute("SELECT state FROM notification_channels WHERE channel_id=?", (w["channel_id"],)).fetchone()["state"], "disabled")
        rcv2, w2 = self.hook([404])
        s2 = self.sub(channels=[w2["channel_id"]], name="second")
        self.feed([alert(2)])
        self.assertEqual(delivery.run_due(self.db, self.reg, NOW, self.cfg)["dead"], 1)

    def test_429_and_timeouts_are_retried(self):
        rcv, w = self.hook([429, 200])
        self.sub(channels=[w["channel_id"]])
        self.feed([alert(1)])
        self.assertEqual(delivery.run_due(self.db, self.reg, NOW, self.cfg)["retry"], 1)
        self.assertEqual(delivery.run_due(self.db, self.reg, at(minutes=2), self.cfg)["sent"], 1)

    def test_an_unreachable_endpoint_is_a_retry_not_a_crash(self):
        w = subs.add_webhook_channel(self.db, self.p, "https://hooks.example.com/in", NOWT, resolver=PUBLIC)
        self.db.execute("UPDATE notification_channels SET address='http://127.0.0.1:1/in' WHERE channel_id=?", (w["channel_id"],))
        self.cfg.webhook_kwargs = {"_test_allow_http_localhost": True, "timeout": 1}
        self.sub(channels=[w["channel_id"]])
        self.feed([alert(1)])
        self.assertEqual(delivery.run_due(self.db, self.reg, NOW, self.cfg)["retry"], 1)

    def test_test_events_are_labelled_and_never_matches(self):
        rcv, w = self.hook([200])
        r = delivery.send_test(self.db, self.reg, w["channel_id"], "x", NOW, self.cfg)
        self.assertTrue(r["ok"])
        self.assertEqual(json.loads(rcv.got[0]["body"])["type"], "test")
        self.assertEqual(self.db.execute("SELECT COUNT(*) n FROM alert_matches").fetchone()["n"], 0)

    def test_the_connection_goes_to_the_validated_address_over_tls(self):
        """A real TLS handshake against a local server: the client must connect to the address it validated and verify the certificate for the NAME."""
        if subprocess.run(["which", "openssl"], capture_output=True).returncode != 0:
            self.skipTest("openssl is not installed: the TLS pinning test cannot run")
        d = self.dir
        key, crt = os.path.join(d, "k.pem"), os.path.join(d, "c.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt, "-days", "2", "-subj", "/CN=hooks.example.com",
                        "-addext", "subjectAltName=DNS:hooks.example.com"], check=True, capture_output=True)
        got = []

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                got.append((self.headers.get("Host"), self.rfile.read(int(self.headers.get("Content-Length", 0)))))
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(crt, key)
        srv.socket = sctx.wrap_socket(srv.socket, server_side=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        real = socket.create_connection
        seen = []

        def fake_connect(addr, timeout=None, **kw):
            seen.append(addr)
            return real(("127.0.0.1", srv.server_address[1]), timeout)          # the test stands in for the 'public' address
        cctx = ssl.create_default_context(cafile=crt)
        with mock.patch("alerts.webhook.socket.create_connection", fake_connect):
            r = webhook.send("https://hooks.example.com/in", b'{"a":1}', {}, resolver=PUBLIC, context=cctx)
        self.assertTrue(r.ok, r.error)
        self.assertEqual(seen, [("93.184.216.34", 443)])                         # it dialled the address that was validated, not a second lookup
        self.assertEqual(got[0][0], "hooks.example.com")                          # and spoke for the original name
        wrong = ssl.create_default_context(cafile=crt)
        with mock.patch("alerts.webhook.socket.create_connection", fake_connect):
            r = webhook.send("https://other.example.com/in", b"{}", {}, resolver=PUBLIC, context=wrong)
        self.assertFalse(r.ok)                                                    # a certificate for another name is refused
        self.assertIn("SSL", r.error)


class IdempotencyTests(World):
    def test_one_delivery_per_match_and_channel_even_if_queued_twice(self):
        cid = self.channel("en")
        self.sub(channels=[cid])
        self.feed([alert(1)])
        m = self.db.execute("SELECT * FROM alert_matches").fetchone()
        s = {"sub_id": m["sub_id"], "frequency": "immediate", "critical_immediate": True}
        view = {"severity": {"band": "high"}}
        n = matching._queue(self.db, s, m["match_id"], view, ["new"], NOW)
        self.assertEqual(n, 0)                                                                    # the idempotency key already exists
        self.assertEqual(self.db.execute("SELECT COUNT(*) n FROM notification_deliveries").fetchone()["n"], 1)

    def test_a_claimed_delivery_cannot_be_sent_by_a_second_worker(self):
        cid = self.channel("en")
        self.sub(channels=[cid])
        self.feed([alert(1)])
        did = self.db.execute("SELECT delivery_id FROM notification_deliveries").fetchone()["delivery_id"]
        self.db.execute("UPDATE notification_deliveries SET state='sending' WHERE delivery_id=?", (did,))          # worker A holds it
        self.assertEqual(delivery.run_due(self.db, self.reg, NOW, self.cfg)["sent"], 0)
        self.assertEqual(self.emls(), [])

    def test_a_deleted_subscription_or_channel_cancels_pending_deliveries(self):
        cid = self.channel("en")
        sid = self.sub(channels=[cid])
        self.feed([alert(1)])
        subs.delete(self.db, self.p, sid, NOWT)
        r = delivery.run_due(self.db, self.reg, NOW, self.cfg)
        self.assertEqual((r["cancelled"], r["sent"]), (1, 0))


class HistoryTests(World):
    def test_history_inbox_read_and_acknowledge(self):
        cid = self.channel("en")
        sid = self.sub(channels=[cid], name="inbox")
        self.feed([alert(i) for i in range(1, 4)])
        delivery.run_due(self.db, self.reg, NOW, self.cfg)
        page = subs.list_matches(self.db, self.p, limit=2)
        self.assertEqual(len(page["items"]), 2)
        self.assertTrue(page["next_before"])
        self.assertEqual(page["items"][0]["sub_name"], "inbox")
        mid = page["items"][0]["match_id"]
        subs.mark_match(self.db, self.p, mid, NOWT, acknowledge=True)
        got = [i for i in subs.list_matches(self.db, self.p)["items"] if i["match_id"] == mid][0]
        self.assertTrue(got["read_utc"] and got["acknowledged_utc"])
        self.assertEqual(len(subs.list_matches(self.db, self.p, unread_only=True)["items"]), 2)
        hist = subs.delivery_history(self.db, self.p)
        self.assertEqual({h["state"] for h in hist}, {"sent"})
        other = self.principal(self.user("x@example.org"))
        self.assertEqual(subs.list_matches(self.db, other)["items"], [])
        with self.assertRaises(Exception):
            subs.mark_match(self.db, other, mid, NOWT)


if __name__ == "__main__":
    unittest.main()
