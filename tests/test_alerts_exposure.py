"""AssetExposureMatch v1: states, invariants, backports, name-only coincidences and fleet summaries. (The contract is executable here; MacGuard Cloud does not exist.)"""
import json
import unittest

from alerts_helpers import DbCase, aff, contents_from, vrec, SHA  # noqa: F401
from alerts import engine, exposure, model
from provenance_schema_check import validate
from alerts_helpers import ROOT
import os


def schema(n):
    return json.load(open(os.path.join(ROOT, "docs", "intelligence", "schemas", n)))


class ExposureTests(DbCase):
    def view(self, affected, cve="CVE-2026-0100"):
        c = contents_from([vrec("enisa-euvd", "EUVD-2026-0100", cve=[cve], euvd=["EUVD-2026-0100"], score="8.0", affected=affected)], self.reg)[0]
        engine.ingest(self.db, [c], "2026-10-22T12:00:00Z")
        return engine.view_of(self.db, self.db.execute("SELECT alert_id, record_version FROM alerts").fetchone()["alert_id"], 1, self.reg, engine.clearance_key(self.reg))

    def ev(self, view, packages, **kw):
        m = exposure.evaluate_asset(view, dict({"asset_id": "a1", "packages": packages}, **kw), kw.pop("rows", None) if False else kw.get("rows"))
        self.assertEqual(exposure.validate_match(m), [], m)
        self.assertEqual(validate(m, schema("asset-exposure-match.schema.json")), [])
        return m

    def test_exact_vendor_product_and_range_is_confirmed_outside_is_not_affected(self):
        v = self.view([aff("Acme", "Widget", "1.0 <2.0")])
        self.assertEqual(self.ev(v, [{"vendor": "Acme", "name": "Widget", "version": "1.5", "source": "vendor"}])["state"], "CONFIRMED_AFFECTED")
        self.assertEqual(self.ev(v, [{"vendor": "Acme", "name": "Widget", "version": "2.0", "source": "vendor"}])["state"], "NOT_AFFECTED")
        self.assertEqual(self.ev(v, [{"vendor": "Acme", "name": "Widget", "version": "0.9", "source": "vendor"}])["state"], "NOT_AFFECTED")

    def test_a_similar_name_is_never_a_match(self):
        v = self.view([aff("Acme", "Widget", "1.0 <2.0")])
        m = self.ev(v, [{"vendor": "Other Corp", "name": "Widget", "version": "1.5", "source": "vendor"}])
        self.assertEqual((m["state"], m["evidence"][0]["kind"]), ("UNKNOWN", "name-only"))
        m = self.ev(v, [{"name": "Widget", "version": "1.5", "source": "vendor"}])                 # no vendor stated
        self.assertEqual(m["state"], "UNKNOWN")
        self.assertEqual(self.ev(v, [{"vendor": "Acme", "name": "Widgets", "version": "1.5", "source": "vendor"}])["state"], "UNKNOWN")       # different product
        self.assertEqual(self.ev(v, [])["state"], "UNKNOWN")

    def test_missing_versions_open_ranges_and_single_versions_are_not_decisive(self):
        v = self.view([aff("Acme", "Widget", "1.0 <publication"), aff("Acme", "Gadget", "3.1"), aff("Acme", "Thing", "n/a")])
        self.assertEqual(self.ev(v, [{"vendor": "Acme", "name": "Widget", "version": "1.5", "source": "vendor"}])["state"], "POTENTIALLY_AFFECTED")
        self.assertEqual(self.ev(v, [{"vendor": "Acme", "name": "Gadget", "version": "3.1", "source": "vendor"}])["state"], "POTENTIALLY_AFFECTED")
        self.assertEqual(self.ev(v, [{"vendor": "Acme", "name": "Thing", "version": "1", "source": "vendor"}])["state"], "UNKNOWN")
        self.assertEqual(self.ev(v, [{"vendor": "Acme", "name": "Widget", "version": None, "source": "vendor"}])["state"], "UNKNOWN")

    def test_linux_packages_follow_the_distribution_not_the_upstream_range(self):
        v = self.view([aff("Apache", "Apache HTTP Server", "2.4.0 <2.4.58")])
        pkg = [{"name": "Apache HTTP Server", "version": "2.4.52-1+deb12u3", "source": "distribution"}]
        distro = {"id": "debian", "release": "bookworm", "scheme": "dpkg"}
        m = self.ev(v, pkg, distro=distro)
        self.assertEqual((m["state"], m["evidence"][0]["kind"]), ("POTENTIALLY_AFFECTED", "no-distribution-data"))      # never CONFIRMED from the upstream range
        rows = [{"distro": "debian", "release": "bookworm", "package": "Apache HTTP Server", "cve": "CVE-2026-0100", "status": "fixed", "fixed_version": "2.4.52-1+deb12u2"}]
        self.assertEqual(self.ev(v, pkg, distro=distro, rows=rows)["state"], "NOT_AFFECTED")                           # the backported fix is in
        old = [{"name": "Apache HTTP Server", "version": "2.4.52-1+deb12u1", "source": "distribution"}]
        m = self.ev(v, old, distro=distro, rows=rows)
        self.assertEqual((m["state"], m["evidence"][0]["kind"]), ("CONFIRMED_AFFECTED", "distribution-advisory"))
        self.assertEqual(self.ev(v, pkg, distro={"id": "ubuntu", "release": "jammy", "scheme": "dpkg"}, rows=rows)["state"], "UNKNOWN")      # another distribution: no data

    def test_not_evaluated_is_not_unaffected(self):
        v = self.view([aff("Acme", "Widget", "1.0 <2.0")])
        m = exposure.evaluate_asset(v, {"asset_id": "a9", "evaluated": False, "packages": []})
        self.assertEqual((m["state"], exposure.validate_match(m)), ("NOT_EVALUATED", []))
        rule = dict(v, alert_type="rule-release")
        self.assertEqual(exposure.evaluate_asset(rule, {"asset_id": "a1", "packages": []})["state"], "NOT_EVALUATED")

    def test_the_best_evidence_across_packages_wins(self):
        v = self.view([aff("Acme", "Widget", "1.0 <2.0")])
        m = self.ev(v, [{"vendor": "Acme", "name": "Widget", "version": "3.0", "source": "vendor"}, {"vendor": "Acme", "name": "Widget", "version": "1.2", "source": "vendor"}])
        self.assertEqual(m["state"], "CONFIRMED_AFFECTED")

    def test_validator_refuses_a_producer_that_breaks_the_rules(self):
        base = {"schema": "macguard.asset-exposure-match/1", "alert_id": "x", "asset_id": "y", "reason": "r"}
        self.assertTrue(exposure.validate_match(dict(base, state="CONFIRMED_AFFECTED", evidence=[{"kind": "name-only"}])))
        self.assertTrue(exposure.validate_match(dict(base, state="CONFIRMED_AFFECTED", evidence=[])))
        self.assertTrue(exposure.validate_match(dict(base, state="NOT_AFFECTED", evidence=[])))
        self.assertTrue(exposure.validate_match(dict(base, state="NOT_EVALUATED", evidence=[{"kind": "vendor-version-range"}])))
        self.assertTrue(exposure.validate_match(dict(base, state="CONFIRMED_AFFECTED", evidence=[{"kind": "made-up"}])))
        self.assertTrue(exposure.validate_match({"state": "CONFIRMED_AFFECTED"}))

    def test_fleet_summary_never_hides_what_was_not_evaluated(self):
        v = self.view([aff("Acme", "Widget", "1.0 <2.0")])
        ms = [exposure.evaluate_asset(v, {"asset_id": "a1", "packages": [{"vendor": "Acme", "name": "Widget", "version": "1.5", "source": "vendor"}]}),
              exposure.evaluate_asset(v, {"asset_id": "a2", "packages": [{"vendor": "Acme", "name": "Widget", "version": "3.0", "source": "vendor"}]}),
              exposure.evaluate_asset(v, {"asset_id": "a3", "packages": []}), exposure.evaluate_asset(v, {"asset_id": "a4", "evaluated": False, "packages": []})]
        s = exposure.fleet_summary(ms, 10)
        self.assertEqual((s["assets_total"], s["assets_evaluated"], s["not_evaluated"], s["insufficient_information"]), (10, 3, 7, 1))
        self.assertEqual(s["counts"], {"CONFIRMED_AFFECTED": 1, "POTENTIALLY_AFFECTED": 0, "NOT_AFFECTED": 1, "UNKNOWN": 1, "NOT_EVALUATED": 1})


if __name__ == "__main__":
    unittest.main()
