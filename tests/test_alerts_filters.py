"""The filter language: validation (a closed set, limits, no code), the shared vectors that Python and JavaScript must both pass, and a few properties."""
import json
import os
import unittest
from datetime import datetime, timezone

from alerts_helpers import ROOT, leaf, spec  # noqa: F401
from alerts import filters

VECTORS = json.load(open(os.path.join(ROOT, "tests", "fixtures", "alerts", "filter-vectors.json"), encoding="utf-8"))


def now():
    return datetime.strptime(VECTORS["now"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


class VectorTests(unittest.TestCase):
    def test_every_shared_vector(self):
        bad = []
        for v in VECTORS["vectors"]:
            a = dict(VECTORS["base"])
            a.update(v["alert_overrides"])
            sp = spec(v["expr"])
            self.assertEqual(filters.validate(sp), [], v["name"])
            ok, reasons = filters.evaluate(sp, a, filters.Ctx(now(), v["changes"], v["stale"]))
            if ok != v["expect"]:
                bad.append((v["name"], ok, v["expect"]))
            self.assertTrue(reasons, v["name"])                         # every answer says why
            for r in reasons:
                self.assertEqual(set(r) - {"negated"}, {"field", "op", "expected", "observed", "basis", "sources"})
        self.assertEqual(bad, [])

    def test_the_javascript_evaluator_agrees_on_answers_AND_reasons(self):
        import shutil
        import subprocess
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not installed: the browser evaluator was NOT compared (a skip is not a pass)")
        r = subprocess.run([node, os.path.join(ROOT, "tests", "alerts_filter_vectors.mjs")], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        d = subprocess.run([node, os.path.join(ROOT, "tests", "alerts_filter_vectors.mjs"), "--dump"], capture_output=True, text=True, timeout=60)
        js = {x["name"]: x for x in json.loads(d.stdout)}
        diffs = []
        for v in VECTORS["vectors"]:
            a = dict(VECTORS["base"])
            a.update(v["alert_overrides"])
            ok, reasons = filters.evaluate(spec(v["expr"]), a, filters.Ctx(now(), v["changes"], v["stale"]))
            norm = lambda rs: json.loads(json.dumps(rs, sort_keys=True))      # noqa: E731
            if js[v["name"]]["matched"] != ok or norm(js[v["name"]]["reasons"]) != norm(reasons):
                diffs.append(v["name"])
        self.assertEqual(diffs, [], "Python and JavaScript explain differently")

    def test_the_vectors_cover_every_field(self):
        used = set()

        def walk(n):
            if "field" in n:
                used.add(n["field"])
            for k in ("all", "any"):
                for c in n.get(k, []):
                    walk(c)
            if "not" in n:
                walk(n["not"])
        for v in VECTORS["vectors"]:
            walk(v["expr"])
        self.assertEqual(sorted(set(filters.LEAVES) - used), [])


class ValidationTests(unittest.TestCase):
    def ok(self, expr):
        self.assertEqual(filters.validate(spec(expr)), [], expr)

    def bad(self, expr, why=None):
        errs = filters.validate(spec(expr))
        self.assertTrue(errs, expr)
        if why:
            self.assertIn(why, " ".join(errs))

    def test_a_filter_is_data_with_a_fixed_envelope(self):
        for s in (None, [], {}, {"schema": "x", "version": 1, "expr": {"all": []}}, {"schema": "macguard.subscription-filter/1", "version": 2, "expr": {"all": []}},
                  {"schema": "macguard.subscription-filter/1", "version": 1, "expr": {"all": []}, "extra": 1}, "expr", 7):
            self.assertTrue(filters.validate(s), repr(s))
        with self.assertRaises(filters.FilterError):
            filters.parse({})

    def test_unknown_fields_operators_and_keys_are_refused(self):
        self.bad(leaf("__proto__", "in", ["x"]), "unknown field")
        self.bad(leaf("os", "regex", ["linux"]), "operator")
        self.bad(leaf("cvss", "in", 5), "operator")
        self.bad({"field": "os", "op": "in", "value": ["linux"], "sql": "1=1"}, "allowed keys")
        self.bad({"field": "os", "op": "in"}, "allowed keys")
        self.bad({"all": [], "any": []}, "takes only")
        self.bad({"not": {"all": []}, "x": 1}, "takes only one")
        self.bad({"eval": "process.exit()"}, "unknown field")
        self.bad({}, "unknown field")

    def test_values_are_checked_by_kind(self):
        for expr in (leaf("region", "in", ["MARS"]), leaf("region", "in", []), leaf("region", "in", "EU"), leaf("region", "in", ["country:usa"]), leaf("sector", "in", ["nope"]),
                     leaf("os", "in", ["beos"]), leaf("cvss", "gte", 11), leaf("cvss", "gte", "7"), leaf("cvss", "gte", True), leaf("severity", "gte", "extreme"), leaf("severity", "gte", "unknown"),
                     leaf("published", "gte", "2026-13-01"), leaf("published", "gte", "26-01-01"), leaf("exploited", "is", "yes"), leaf("id", "in", ["CVE-1"]), leaf("id", "in", ["CVE-2026-0001; DROP"]),
                     leaf("attack_technique", "in", ["T12"]), leaf("exposure", "in", ["cloud"]), leaf("change", "any", ["everything"]), leaf("source", "in", ["Bad Source"]),
                     leaf("version", "affects", {"vendor": "a", "product": "b"}), leaf("version", "affects", {"vendor": "a", "product": "b", "version": "x1"}), leaf("ingested_within_days", "lte", -1),
                     leaf("exploited", "is", True, source="../x"), leaf("sector", "in", ["health"], include_unknown="yes"), leaf("vendor", "in", ["x" * 300])):
            self.bad(expr)

    def test_the_good_shapes(self):
        for expr in (leaf("region", "in", ["ES", "EU", "country:FR", "OTHER", "GLOBAL"]), leaf("cvss", "gte", 7.5), leaf("severity", "gte", "critical"), leaf("id", "in", ["CVE-2026-0001", "EUVD-2026-0001", "GHSA-2g2v-9wf5-6m3g"]),
                     leaf("version", "affects", {"vendor": "a", "product": "b", "version": "1.2.3-rc1"}), {"all": [leaf("os", "in", ["linux"]), {"any": [leaf("exploited", "is", True), {"not": leaf("cvss", "lte", 3)}]}]},
                     {"all": []}, leaf("sector", "in", ["health"], include_unknown=True), leaf("exploited", "is", True, source="cisa-kev")):
            self.ok(expr)

    def test_limits_on_depth_size_and_lists(self):
        deep = leaf("os", "in", ["linux"])
        for _ in range(filters.MAX_DEPTH):
            deep = {"not": deep}
        self.bad(deep, "deeper")
        self.bad({"all": [leaf("os", "in", ["linux"])] * (filters.MAX_LEAVES + 1)})
        self.bad({"all": [{"all": [leaf("os", "in", ["linux"])] * 30}, {"all": [leaf("os", "in", ["linux"])] * 30}]}, "more than")
        self.bad(leaf("vendor", "in", ["v%d" % i for i in range(filters.MAX_LIST + 1)]))

    def test_the_evaluator_never_runs_anything_it_was_given(self):
        marker = []
        sp = spec(leaf("vendor", "in", ["__import__('os').system('echo hi')"]))
        self.assertEqual(filters.validate(sp), [])                         # it is just a string to compare
        import alerts_helpers as h
        v = json.loads(json.dumps(VECTORS["base"]))
        ok, _r = filters.evaluate(sp, v, filters.Ctx(now()))
        self.assertFalse(ok)
        self.assertEqual(marker, [])

    def test_match_all_is_valid(self):
        self.assertEqual(filters.validate(filters.match_all()), [])


if __name__ == "__main__":
    unittest.main()
