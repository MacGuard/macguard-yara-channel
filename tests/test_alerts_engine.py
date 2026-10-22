"""Normalisation, deduplication, versioning, material changes, distribution gating, queries and freshness."""
import copy
import json
import os
import unittest
from datetime import datetime, timedelta, timezone

from alerts_helpers import ROOT, NOW, NOWT, DbCase, aff, contents_from, leaf, spec, vrec, test_registry  # noqa: F401
from alerts import engine, filters, model, sources, store
from intel import registry as reg

G1 = "GHSA-2g2v-9wf5-6m3g"


class ModelTests(DbCase):
    def two_sources(self):
        k = vrec("cisa-kev", "CVE-2026-0001", cve=["CVE-2026-0001"], asserted=True, since="2026-10-01", title="Acme Widget RCE", summary="Acme Widget RCE", published=None,
                 affected=[aff("Acme", "Widget", "unspecified")])
        e = vrec("enisa-euvd", "EUVD-2026-0001", cve=["CVE-2026-0001"], euvd=["EUVD-2026-0001"], ghsa=[G1], score="9.8", vector="CVSS:3.1/AV:N/AC:L/PR:N", summary="Widget has a flaw",
                 affected=[aff("Acme", "Widget", "1.0 <1.4.2")], fixes=[{"vendor": "Acme", "product": "Widget", "fixed_in": "1.4.2", "basis": "b"}], published="2026-09-20", refs=["https://acme.example/adv"])
        return [k, e]

    def test_one_alert_from_cve_euvd_and_ghsa_keeps_every_observation(self):
        c = contents_from(self.two_sources(), self.reg)
        self.assertEqual(len(c), 1)
        a = c[0]
        self.assertEqual(a["ids"], {"cve": ["CVE-2026-0001"], "euvd": ["EUVD-2026-0001"], "ghsa": [G1]})
        self.assertEqual(sorted(a["observations"]), ["cisa-kev", "enisa-euvd"])
        self.assertEqual(a["observations"]["enisa-euvd"]["evidence"]["file"], "f.json")
        self.assertEqual(a["title"].split(":")[0], "CVE-2026-0001")
        self.assertIn("Acme Widget RCE", a["title"])                           # CISA names it first
        self.assertEqual(a["severity"]["band"], "critical")
        self.assertEqual(a["severity"]["rated_by"], ["enisa-euvd"])
        self.assertEqual(a["attack_vector"], "network")
        self.assertEqual(a["exploitation"]["status"], "exploited")
        self.assertEqual(a["exploitation"]["asserted_by"], ["cisa-kev"])
        self.assertEqual(a["exploitation"]["per_source"]["enisa-euvd"]["asserted"], False)       # EUVD only rates it
        self.assertEqual(a["fix"]["available"], True)
        self.assertEqual([r["region"] for r in a["region_scope"]], ["country:US", "EU"])
        self.assertEqual(a["validation"], {"state": "validated", "problems": []})
        self.assertEqual(a["dates"]["published"], "2026-09-20")
        self.assertEqual(a["license"]["redistributable"], True)

    def test_a_critical_score_alone_is_not_exploitation(self):
        a = contents_from([vrec("enisa-euvd", "EUVD-2026-0001", cve=["CVE-2026-0001"], euvd=["EUVD-2026-0001"], score="10.0")], self.reg)[0]
        self.assertEqual(a["severity"]["band"], "critical")
        self.assertEqual(a["exploitation"]["status"], "not-asserted")
        self.assertEqual(a["exploitation"]["asserted_by"], [])

    def test_discrepancies_between_sources_are_reported_not_hidden(self):
        r1 = vrec("enisa-euvd", "EUVD-2026-0001", cve=["CVE-2026-0001"], score="7.0", published="2026-09-20")
        r2 = vrec("cisa-kev", "CVE-2026-0001", cve=["CVE-2026-0001"], asserted=True, since="2026-10-01", published="2026-09-25")
        r3 = vrec("cert-eu-advisories", "X", cve=["CVE-2026-0001"], score="9.0", published="2026-09-20")
        a = contents_from([r1, r2, r3], self.reg)[0]
        fields = {d["field"]: d["values"] for d in a["discrepancies"]}
        self.assertEqual(fields["severity.score"], {"cert-eu-advisories": "9.0", "enisa-euvd": "7.0"})
        self.assertEqual(fields["dates.published"], {"cert-eu-advisories": "2026-09-20", "cisa-kev": "2026-09-25", "enisa-euvd": "2026-09-20"})
        self.assertEqual(a["severity"]["score"], "9.0")

    def test_similar_titles_never_merge_records(self):
        a = vrec("enisa-euvd", "EUVD-2026-0001", cve=["CVE-2026-0001"], title="Acme Widget RCE", summary="Acme Widget RCE")
        b = vrec("cisa-kev", "CVE-2026-0002", cve=["CVE-2026-0002"], title="Acme Widget RCE", summary="Acme Widget RCE")
        self.assertEqual(len(contents_from([a, b], self.reg)), 2)

    def test_the_hash_ignores_staleness_and_changes_with_content(self):
        recs = self.two_sources()
        fresh = contents_from(recs, self.reg, {"cisa-kev": {"retrieved_at": "2026-10-22T10:00:00Z", "max_age_days": 7}})[0]
        stale = contents_from(recs, self.reg, {"cisa-kev": {"retrieved_at": "2026-09-01T10:00:00Z", "max_age_days": 7}})[0]
        self.assertEqual(model.content_hash(fresh), model.content_hash(stale))
        recs[1]["severity"]["score"] = "5.0"
        self.assertNotEqual(model.content_hash(contents_from(recs, self.reg)[0]), model.content_hash(fresh))

    def test_the_alert_id_comes_from_the_first_key_and_looks_random(self):
        c = contents_from(self.two_sources(), self.reg)[0]
        a1, a2 = model.new_alert_id(c), model.alert_id_for("CVE-2026-0002")
        self.assertRegex(a1, r"^MGA-[0-9a-f]{20}$")
        self.assertNotEqual(a1, a2)

    def test_incomplete_evidence_makes_the_validation_partial(self):
        r = vrec("enisa-euvd", "EUVD-2026-0001", cve=["CVE-2026-0001"])
        r["evidence"]["file_sha256"] = ""
        a = contents_from([r], self.reg)[0]
        self.assertEqual(a["validation"]["state"], "partial")
        self.assertIn("no evidence reference", a["validation"]["problems"][0])


class IngestTests(DbCase):
    def base(self, **kw):
        d = dict(cve=["CVE-2026-0001"], euvd=["EUVD-2026-0001"], score="7.5", vector="CVSS:3.1/AV:N", summary="s", affected=[aff("Acme", "Widget")])
        d.update(kw)
        return vrec("enisa-euvd", "EUVD-2026-0001", **d)

    def alert(self):
        return engine.load_alert(self.db, self.db.execute("SELECT alert_id FROM alerts").fetchone()["alert_id"])

    def events(self):
        return [dict(r) for r in self.db.execute("SELECT * FROM alert_events ORDER BY seq")]

    def test_first_sight_is_new_the_same_data_again_is_nothing(self):
        r = self.ingest([self.base()])
        self.assertEqual((r["new"], r["unchanged"]), (1, 0))
        r = self.ingest([self.base()])
        self.assertEqual((r["new"], r["unchanged"], r["updated_material"]), (0, 1, 0))
        self.assertEqual(len(self.events()), 1)
        self.assertEqual(self.alert()["record_version"], 1)

    def test_an_update_is_a_new_version_of_the_same_alert_not_a_new_alert(self):
        self.ingest([self.base()])
        aid = self.alert()["alert_id"]
        self.ingest([self.base(score="9.9")])
        a = self.alert()
        self.assertEqual((a["alert_id"], a["record_version"]), (aid, 2))
        self.assertEqual(self.db.execute("SELECT COUNT(*) n FROM alerts").fetchone()["n"], 1)
        self.assertEqual(self.db.execute("SELECT COUNT(*) n FROM alert_versions").fetchone()["n"], 2)
        e = self.events()[-1]
        self.assertEqual((e["kind"], json.loads(e["changes_json"]), e["material"]), ("update", ["severity_up"], 1))

    def test_material_changes_are_named(self):
        self.ingest([self.base()])
        cases = [
            ("exploitation_added", [vrec("enisa-euvd", "EUVD-2026-0001", cve=["CVE-2026-0001"], euvd=["EUVD-2026-0001"], score="7.5", vector="CVSS:3.1/AV:N", summary="s", affected=[aff("Acme", "Widget")], asserted=True, since="2026-10-10")]),
            ("exploitation_source_added", [vrec("enisa-euvd", "EUVD-2026-0001", cve=["CVE-2026-0001"], euvd=["EUVD-2026-0001"], score="7.5", vector="CVSS:3.1/AV:N", summary="s", affected=[aff("Acme", "Widget")], asserted=True, since="2026-10-10"),
                                           vrec("cisa-kev", "CVE-2026-0001", cve=["CVE-2026-0001"], asserted=True, since="2026-10-11")]),
        ]
        names = []
        for name, recs in cases:
            self.ingest(recs)
            names.append(json.loads(self.events()[-1]["changes_json"]))
        self.assertEqual(names[0], ["exploitation_added"])
        self.assertEqual(names[1], ["exploitation_source_added", "scope_added"])
        self.ingest([self.base(fixes=[{"vendor": "Acme", "product": "Widget", "fixed_in": "2.0", "basis": "b"}], asserted=True, since="2026-10-10"), cases[1][1][1]])
        self.assertEqual(json.loads(self.events()[-1]["changes_json"]), ["fix_available"])
        self.ingest([self.base(score="3.0", fixes=[{"vendor": "Acme", "product": "Widget", "fixed_in": "2.0", "basis": "b"}], asserted=True, since="2026-10-10"), cases[1][1][1]])
        self.assertEqual(json.loads(self.events()[-1]["changes_json"]), ["severity_down"])
        self.ingest([self.base(score="3.0", fixes=[{"vendor": "Acme", "product": "Widget", "fixed_in": "2.0", "basis": "b"}], asserted=True, since="2026-10-10", affected=[aff("Acme", "Widget"), aff("Acme", "Gadget")]), cases[1][1][1]])
        self.assertEqual(json.loads(self.events()[-1]["changes_json"]), ["affected_changed"])

    def test_wording_and_references_bump_the_version_but_are_not_material(self):
        self.ingest([self.base()])
        self.ingest([self.base(summary="a better description", refs=["https://x.example/y"])])
        e = self.events()[-1]
        self.assertEqual((e["kind"], json.loads(e["changes_json"]), e["material"]), ("update", ["other"], 0))
        self.assertEqual(self.alert()["record_version"], 2)

    def test_a_later_identifier_joins_the_same_alert(self):
        self.ingest([vrec("enisa-euvd", "EUVD-2026-0001", euvd=["EUVD-2026-0001"], score="7.5")])
        aid = self.alert()["alert_id"]
        self.assertEqual(self.alert()["key"], "EUVD-2026-0001")
        self.ingest([vrec("enisa-euvd", "EUVD-2026-0001", cve=["CVE-2026-0001"], euvd=["EUVD-2026-0001"], score="7.5")])
        a = self.alert()
        self.assertEqual((a["alert_id"], a["key"]), (aid, "CVE-2026-0001"))                 # the id never changes; the key may
        self.assertEqual(self.db.execute("SELECT COUNT(*) n FROM alerts").fetchone()["n"], 1)
        self.assertEqual(self.db.execute("SELECT alert_id FROM alert_identifiers WHERE identifier='CVE-2026-0001'").fetchone()["alert_id"], aid)

    def test_identifiers_of_two_alerts_in_one_record_are_a_conflict_nothing_is_merged(self):
        self.ingest([vrec("enisa-euvd", "EUVD-2026-0001", cve=["CVE-2026-0001"], euvd=["EUVD-2026-0001"]), vrec("enisa-euvd", "EUVD-2026-0002", cve=["CVE-2026-0002"], euvd=["EUVD-2026-0002"])])
        bad = contents_from([vrec("osv", "z", cve=["CVE-2026-0001"], euvd=["EUVD-2026-0002"])], self.reg)[0]
        r = engine.ingest(self.db, [bad], NOWT)
        self.assertEqual((r["conflicts"], r["new"]), (1, 0))
        self.assertEqual(self.db.execute("SELECT COUNT(*) n FROM alerts").fetchone()["n"], 2)
        self.assertEqual(self.db.execute("SELECT COUNT(*) n FROM audit_log WHERE action='alert.identifier_conflict'").fetchone()["n"], 1)

    def test_a_vulnerability_without_an_identifier_is_refused(self):
        c = contents_from([vrec("enisa-euvd", "EUVD-2026-0001", cve=["CVE-2026-0001"])], self.reg)[0]
        c["ids"] = {"cve": [], "euvd": [], "ghsa": []}
        r = engine.ingest(self.db, [c], NOWT)
        self.assertEqual((r["refused"], r["new"]), (1, 0))

    def test_the_whole_batch_is_one_transaction_and_the_audit_chain_holds(self):
        self.ingest([self.base()])
        self.ingest([self.base(score="9.0")])
        self.assertTrue(store.verify_audit(self.db)["ok"])
        self.db.execute("UPDATE audit_log SET action='x' WHERE seq=1")
        self.assertFalse(store.verify_audit(self.db)["ok"])

    def test_advisories_without_identifiers_are_kept_by_key(self):
        r = vrec("cert-eu-advisories", "CERT-EU-2026-019", title="2026-019: GitLab", summary="d")
        r["mentions"] = [{"kind": "cve", "id": "CVE-2026-44756"}]
        self.ingest([r])
        a = self.alert()
        self.assertEqual((a["alert_type"], a["key"]), ("advisory", "CERT-EU-2026-019"))
        self.ingest([r])
        self.assertEqual(self.db.execute("SELECT COUNT(*) n FROM alerts").fetchone()["n"], 1)


class DistributionTests(DbCase):
    def setUp(self):
        super().setUp()
        self.registry = test_registry()
        self.registry["enisa-euvd"] = dict(self.registry["enisa-euvd"], redistribution_status="pending-legal", owner_confirmed=False)        # NOT cleared
        recs = [vrec("cisa-kev", "CVE-2026-0001", cve=["CVE-2026-0001"], asserted=True, since="2026-10-01", title="Acme RCE", summary="kev text", refs=["https://cisa.example/k"]),
                vrec("enisa-euvd", "EUVD-2026-0001", cve=["CVE-2026-0001"], euvd=["EUVD-2026-0001"], ghsa=[G1], score="9.9", vector="CVSS:3.1/AV:N", summary="euvd secret text",
                     affected=[aff("Acme", "Widget", "1.0 <2.0")], refs=["https://enisa.example/e"], published="2026-09-01")]
        engine.ingest(self.db, contents_from(recs, self.registry), NOWT)
        self.alert = engine.load_alert(self.db, self.db.execute("SELECT alert_id FROM alerts").fetchone()["alert_id"])

    def test_the_view_contains_nothing_from_a_source_that_is_not_cleared(self):
        v = model.publish_view(self.alert, self.registry)
        blob = json.dumps(v)
        for leak in ("euvd secret text", "EUVD-2026-0001", G1, "enisa.example", "enisa-euvd", "9.9", "Widget"):
            self.assertNotIn(leak, blob, leak)
        self.assertEqual(sorted(v["observations"]), ["cisa-kev"])
        self.assertEqual(v["severity"]["band"], "unknown")                           # the only score came from the withheld source
        self.assertEqual(v["license"]["withheld_sources"], 1)
        self.assertEqual(v["ids"], {"cve": ["CVE-2026-0001"], "euvd": [], "ghsa": []})
        self.assertEqual(v["exploitation"]["asserted_by"], ["cisa-kev"])
        self.assertEqual(v["validation"]["state"], "validated")
        self.assertEqual(v["dates"]["published"], "2026-10-01")                       # CISA's date, not the withheld source's 2026-09-01

    def test_the_stored_alert_still_has_everything(self):
        self.assertEqual(sorted(self.alert["observations"]), ["cisa-kev", "enisa-euvd"])
        self.assertEqual(self.alert["severity"]["band"], "critical")

    def test_no_cleared_source_means_no_view_at_all(self):
        r = dict(self.registry)
        r["cisa-kev"] = dict(r["cisa-kev"], owner_confirmed=False)
        self.assertIsNone(model.publish_view(self.alert, r))

    def test_query_filters_the_view_not_the_stored_alert(self):
        sp = spec(leaf("severity", "gte", "high"))
        self.assertEqual(engine.query(self.db, self.registry, sp, NOW)["items"], [])           # the critical score belongs to a withheld source
        sp2 = spec(leaf("exploited", "is", True))
        items = engine.query(self.db, self.registry, sp2, NOW)["items"]
        self.assertEqual([i["key"] for i in items], ["CVE-2026-0001"])
        self.assertNotIn("euvd secret text", json.dumps(items))
        r = dict(self.registry)
        r["cisa-kev"] = dict(r["cisa-kev"], owner_confirmed=False)
        self.assertEqual(engine.query(self.db, r, sp2, NOW)["items"], [])


class QueryTests(DbCase):
    def test_keyset_pagination_visits_every_alert_once_in_order(self):
        recs = [vrec("enisa-euvd", f"EUVD-2026-{i:04d}", cve=[f"CVE-2026-{i:04d}"], euvd=[f"EUVD-2026-{i:04d}"], score="5.0") for i in range(1, 8)]
        for i, r in enumerate(recs):
            engine.ingest(self.db, contents_from([r], self.reg), store.utc(NOW + timedelta(minutes=i)))
        seen, cur = [], None
        for _ in range(10):
            page = engine.query(self.db, self.reg, spec({"all": []}), NOW, limit=3, cursor=cur)
            seen += [i["key"] for i in page["items"]]
            cur = page["next_cursor"]
            if not cur:
                break
        self.assertEqual(seen, [f"CVE-2026-{i:04d}" for i in range(7, 0, -1)])
        with self.assertRaises(ValueError):
            engine.query(self.db, self.reg, spec({"all": []}), NOW, cursor="nonsense")

    def test_an_invalid_filter_never_reaches_the_database(self):
        with self.assertRaises(filters.FilterError):
            engine.query(self.db, self.reg, {"schema": "x"}, NOW)

    def test_matches_carry_their_reasons(self):
        self.ingest([vrec("enisa-euvd", "EUVD-2026-0001", cve=["CVE-2026-0001"], euvd=["EUVD-2026-0001"], score="8.0", affected=[aff("Microsoft", "Windows 11", "1 <2")])])
        sp = spec({"all": [leaf("os", "in", ["windows"]), leaf("severity", "gte", "high")]})
        it = engine.query(self.db, self.reg, sp, NOW)["items"][0]
        self.assertEqual([r["field"] for r in it["match_reasons"]], ["os", "severity"])
        self.assertEqual(it["match_reasons"][0]["basis"], "curated-mapping:technology-map@1")


class FreshnessTests(DbCase):
    def test_source_status_reports_age_staleness_and_failures(self):
        recs = [vrec("cisa-kev", "CVE-2026-0001", cve=["CVE-2026-0001"], asserted=True, since="2026-10-01")]
        engine.ingest(self.db, contents_from(recs, self.reg), NOWT, [{"source_id": "cisa-kev", "retrieved_utc": "2026-10-20T00:00:00Z", "status": "ok", "records_in": 1, "accepted": 1}])
        st = engine.source_status(self.db, self.reg, NOW)
        self.assertEqual((st["cisa-kev"]["state"], st["cisa-kev"]["alerts"]), ("fresh", 1))
        self.assertEqual(st["enisa-euvd"]["state"], "never-imported")
        later = NOW + timedelta(days=9)
        self.assertEqual(engine.source_status(self.db, self.reg, later)["cisa-kev"]["state"], "stale")
        self.assertEqual(engine.stale_sources(engine.source_status(self.db, self.reg, later)), ["cisa-kev"])
        engine.ingest(self.db, [], store.utc(NOW + timedelta(hours=1)), [{"source_id": "cisa-kev", "status": "error", "error": "HTTP 500"}])
        self.assertEqual(engine.source_status(self.db, self.reg, NOW)["cisa-kev"]["failed_runs_since_last_ok"], 1)

    def test_the_source_catalog_never_calls_an_unimplemented_source_active(self):
        st = engine.source_status(self.db, self.reg, NOW)
        rows = {r["id"]: r for r in sources.source_catalog(self.reg, st)}
        for sid in ("osv", "nvd", "debian-security-tracker", "ubuntu-security-notices", "redhat-security-data", "sigmahq"):
            self.assertEqual(rows[sid]["operational_state"], "pending", sid)
        for sid in ("ccn-cert", "abusech-bulk", "incibe-cert"):
            self.assertEqual(rows[sid]["operational_state"], "blocked", sid)
        self.assertEqual(rows["cisa-kev"]["operational_state"], "implemented-no-data")


class ViewCacheTests(DbCase):
    def test_warm_builds_once_and_a_clearance_change_invalidates(self):
        self.ingest([vrec("cisa-kev", "CVE-2026-0001", cve=["CVE-2026-0001"], asserted=True, since="2026-10-01"), vrec("enisa-euvd", "EUVD-2026-0002", cve=["CVE-2026-0002"], euvd=["EUVD-2026-0002"], score="5.0")])
        self.assertEqual(engine.warm_views(self.db, self.reg), 2)
        self.assertEqual(engine.warm_views(self.db, self.reg), 0)                                   # cached
        r = dict(self.reg)
        r["enisa-euvd"] = dict(r["enisa-euvd"], owner_confirmed=False)
        self.assertNotEqual(engine.clearance_key(r), engine.clearance_key(self.reg))
        self.assertEqual(engine.warm_views(self.db, r), 2)                                          # a different clearance has its own views
        self.assertEqual([i["key"] for i in engine.query(self.db, r, spec({"all": []}), NOW)["items"]], ["CVE-2026-0001"])          # and never reuses the permissive ones
        self.assertEqual(len(engine.query(self.db, self.reg, spec({"all": []}), NOW)["items"]), 2)
        self.ingest([vrec("enisa-euvd", "EUVD-2026-0002", cve=["CVE-2026-0002"], euvd=["EUVD-2026-0002"], score="9.5")])       # a new version needs a new view
        self.assertEqual(engine.warm_views(self.db, self.reg), 1)
        self.assertEqual(engine.query(self.db, self.reg, spec(leaf("severity", "gte", "critical")), NOW)["items"][0]["key"], "CVE-2026-0002")


class YaraReleaseTests(DbCase):
    def test_the_real_release_log_becomes_first_party_alerts(self):
        contents, runs = sources.yara_release_contents(os.path.join(ROOT, "logs", "log.jsonl"), self.reg)
        self.assertGreaterEqual(len(contents), 3)
        c = contents[0]
        self.assertEqual((c["alert_type"], c["validation"]["state"], c["exploitation"]["status"]), ("rule-release", "validated", "not-asserted"))
        self.assertTrue(c["key"].startswith("YARA-rules-"))
        engine.ingest(self.db, contents, NOWT, runs)
        items = engine.query(self.db, self.reg, spec(leaf("alert_type", "in", ["rule-release"])), NOW)["items"]
        self.assertEqual(len(items), len(contents))
        self.assertEqual(items[0]["region_scope"][0]["region"], "GLOBAL")

    def test_it_is_not_distributable_when_the_owner_withdraws_the_flag(self):
        contents, _runs = sources.yara_release_contents(os.path.join(ROOT, "logs", "log.jsonl"), self.reg)
        engine.ingest(self.db, contents, NOWT)
        r = dict(self.reg)
        r["macguard-yara-releases"] = dict(r["macguard-yara-releases"], owner_confirmed=False)
        self.assertEqual(engine.query(self.db, r, spec({"all": []}), NOW)["items"], [])


if __name__ == "__main__":
    unittest.main()
