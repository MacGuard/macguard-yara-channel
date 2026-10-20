"""The pipeline side of the dependency scenarios shared with the quarantine panel (tests/fixtures/dependency_scenarios.json).

decide.py is the authority on what is published: a file whose dependency is not published is left out, whatever its own state and whatever a reviewer
approved. The panel computes the same thing in admin/worker/src/core.js (dependencyEffect) so a reviewer sees whether an approval will take effect; the
Worker suite runs the same scenarios and asserts the panel never says an approval is effective when this suite shows decide.py leaves the file out."""
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import decide  # noqa: E402

SCENARIOS = json.loads((pathlib.Path(__file__).resolve().parent / "fixtures" / "dependency_scenarios.json").read_text())["scenarios"]


def sha(path):
    return path.ljust(64, "0")[:64].replace("/", "0")


def classified(scenario):
    return [{"path": f["path"], "sha256": sha(f["path"]), "bytes": 10, "source": "community", "state": f["state"], "depends_on": f.get("deps", []),
             "reasons": [{"code": c, "severity": sev, "detail": c} for c, sev in f.get("reasons", [])]} for f in scenario["files"]]


def decisions(approve):
    return {sha(p): {"state": "APPROVED_PENDING_VALIDATION", "by": "reviewer"} for p in approve}


class DependencyScenarios(unittest.TestCase):
    def test_every_case_publishes_exactly_what_the_scenario_says(self):
        n = 0
        for sc in SCENARIOS:
            for case in sc["cases"]:
                res = decide.decide(classified(sc), None, decisions(case["approve"]), None, None, False)
                self.assertEqual(sorted(a["path"] for a in res["approved"]), sorted(case["included"]), f'{sc["name"]} / approve {case["approve"]}')
                n += 1
        self.assertGreaterEqual(n, 15)

    def test_the_panel_rows_of_the_fixture_are_what_the_pipeline_really_submits(self):
        for sc in SCENARIOS:
            res = decide.decide(classified(sc), None, {}, None, None, False)
            submitted = {s["path"]: sorted(s["reasons"]) for s in res["submissions"]}
            for row in sc["panel"]:
                self.assertEqual(sorted(row["reasons"]), submitted.get(row["path"]), f'{sc["name"]}: {row["path"]}')
            self.assertEqual(sorted(r["path"] for r in sc["panel"]), sorted(submitted), f'{sc["name"]}: the panel holds exactly the submitted files (rejected ones never reach it)')

    def test_an_approval_never_publishes_a_file_whose_dependency_stays_out(self):
        for sc in SCENARIOS:
            for case in sc["cases"]:
                res = decide.decide(classified(sc), None, decisions(case["approve"]), None, None, False)
                published = {a["path"] for a in res["approved"]}
                for f in sc["files"]:
                    if f["path"] in published:
                        self.assertTrue(all(d in published for d in f.get("deps", [])), f'{sc["name"]}: {f["path"]} is published without something it needs')


if __name__ == "__main__":
    unittest.main()
