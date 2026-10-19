"""Failures of the GitHub release step, run against the REAL `run:` script of publish.yml with a fake `gh` on PATH.

The fake records every call and fails on demand (release creation, an asset upload, too few assets, publishing, a killed process).
The invariant under test: a release becomes public (`gh release edit --draft=false`) only after it was created as a draft, every asset is
attached and the asset count was checked; any failure before that leaves nothing public and the step exits non-zero.
This is a mock of GitHub, so it proves the script's ordering and exit handling, not GitHub's own behaviour (see docs/audit/TEST-MATRIX.md)."""
import json
import os
import re
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

WF = Path(__file__).resolve().parent.parent / ".github" / "workflows"

FAKE_GH = r'''#!/usr/bin/env bash
echo "$*" >> "$GH_LOG"
case "$1 $2" in
  "release create") [ "$FAIL" = create ] && { echo "HTTP 502" >&2; exit 1; }; [ "$FAIL" = killed ] && kill -9 $$; exit 0;;
  "release upload") [ "$FAIL" = upload ] && { echo "HTTP 500" >&2; exit 1; }; exit 0;;
  "release view")   echo "${ASSETS:-10}"; exit 0;;
  "release edit")   [ "$FAIL" = edit ] && { echo "HTTP 503" >&2; exit 1; }; exit 0;;
esac
exit 0
'''


def step_script(workflow, name_prefix):
    lines = (WF / workflow).read_text().splitlines()
    start = next(i for i, l in enumerate(lines) if re.match(rf"\s+- name: {re.escape(name_prefix)}", l))
    run = next(i for i in range(start, len(lines)) if re.match(r"\s+run: \|\s*$", lines[i]))
    indent = len(lines[run + 1]) - len(lines[run + 1].lstrip())
    body = []
    for l in lines[run + 1:]:
        if l.strip() and len(l) - len(l.lstrip()) < indent:
            break
        body.append(l[indent:])
    return "\n".join(body)


class PublishStep(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = step_script("publish.yml", "Publish release")

    def run_step(self, fail=None, assets=10, consistency=True):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "bin").mkdir(); gh = d / "bin" / "gh"; gh.write_text(FAKE_GH); gh.chmod(gh.stat().st_mode | stat.S_IEXEC)
            (d / "release-meta").mkdir(); (d / "dist").mkdir()
            (d / "release-meta" / "release.json").write_text(json.dumps({"files": 3, "yara_rules": 7, "package_bytes": 10, "package_sha256": "ab" * 32, "changes": {"added": 1, "modified": 0, "removed": 0}}))
            if consistency: (d / "release-meta" / "consistency.json").write_text("{}")
            (d / "run.sh").write_text(self.script)
            env = {**os.environ, "PATH": f"{d / 'bin'}:{os.environ['PATH']}", "GH_LOG": str(d / "calls.log"), "TAG": "rules-test", "FAIL": fail or "", "ASSETS": str(assets)}
            p = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "run.sh"], cwd=d, env=env, capture_output=True, text=True)
            calls = (d / "calls.log").read_text().splitlines() if (d / "calls.log").exists() else []
            return p.returncode, calls

    @staticmethod
    def published(calls):
        return any(c.startswith("release edit") and "--draft=false" in c for c in calls)

    def test_success_creates_a_draft_checks_the_count_and_only_then_publishes(self):
        rc, calls = self.run_step()
        self.assertEqual(rc, 0)
        kinds = [c.split()[1] for c in calls]
        self.assertEqual(kinds, ["create", "upload", "view", "edit"])
        self.assertIn("--draft", calls[0]); self.assertNotIn("--draft=false", calls[0])
        self.assertIn("--draft=false --latest", calls[-1])

    def test_each_failure_leaves_nothing_public(self):
        for fail in ["create", "upload", "killed", "edit"]:
            rc, calls = self.run_step(fail=fail)
            self.assertNotEqual(rc, 0, fail)
            if fail != "edit":
                self.assertFalse(self.published(calls), f"{fail}: published after a failure: {calls}")
            else:   # the publish call itself failed: it was attempted last and the step still failed
                self.assertEqual(calls[-1].split()[1], "edit")

    def test_too_few_assets_never_publishes(self):
        for n in [0, 5, 8]:
            rc, calls = self.run_step(assets=n)
            self.assertNotEqual(rc, 0, n); self.assertFalse(self.published(calls), n)

    def test_release_without_consistency_proof_is_still_complete_at_nine_assets(self):
        rc, calls = self.run_step(consistency=False, assets=9)   # the first release has no predecessor
        self.assertEqual(rc, 0); self.assertTrue(self.published(calls))
        self.assertNotIn("upload", [c.split()[1] for c in calls])


class PublishWorkflowShape(unittest.TestCase):
    """Order and conditions that cannot be seen in the step alone."""
    text = (WF / "publish.yml").read_text()

    def idx(self, s): 
        i = self.text.find(s); self.assertGreaterEqual(i, 0, s); return i

    def test_signing_and_verification_come_before_the_release_step(self):
        for earlier in ["Write and sign the manifest", "Check the artifacts before anything becomes public", "Re-verify the final set before signing"]:
            self.assertLess(self.idx(earlier), self.idx("Publish release (draft first"), earlier)

    def test_marking_rules_released_only_after_success_and_the_record_step_always_runs(self):
        i = self.idx("Tell the quarantine service which approved rules were released")
        self.assertIn("if: success()", self.text[i:i + 200])
        j = self.idx("Record result and commit the log")
        self.assertIn("if: always()", self.text[j:j + 200])

    def test_releases_are_serialised_and_never_cancelled(self):
        self.assertRegex(self.text, r"concurrency:\s*\n\s+group: macguard-log\s*\n\s+cancel-in-progress: false")

    def test_site_runs_do_not_share_the_publish_group_except_for_the_short_record_job(self):
        site = (WF / "site.yml").read_text()
        self.assertIn("group: site-deploy", site)
        self.assertEqual(site.count("macguard-log"), 1, "only the record job may take the log group")


if __name__ == "__main__":
    unittest.main()
