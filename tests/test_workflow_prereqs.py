"""Regression for FA-31: the first *scheduled* daily run failed because the suite needs `cosign`
(tests/test_verify_public_release.py verifies the real release) and the runner did not have it.
A dispatched run later passed, which proves nothing about the cron; this test pins the cause: any
workflow job that runs the Python suite must install cosign in an earlier step of the same job."""
import re
import unittest
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"


def jobs(text):
    """Split a workflow into {job_name: [step_text, ...]} without a YAML dependency."""
    out, job, in_jobs = {}, None, False
    for line in text.splitlines():
        if re.match(r"^jobs:\s*$", line):
            in_jobs = True
        elif in_jobs and (m := re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)):
            job = m.group(1)
            out[job] = [""]
        elif job and re.match(r"^      - ", line):
            out[job].append(line + "\n")
        elif job:
            out[job][-1] += line + "\n"
    return out


class WorkflowPrerequisites(unittest.TestCase):
    def test_every_job_running_the_suite_installs_cosign_first(self):
        seen = 0
        for wf in sorted(WORKFLOWS.glob("*.yml")):
            for name, steps in jobs(wf.read_text()).items():
                run_at = next((i for i, s in enumerate(steps) if "unittest discover" in s), None)
                if run_at is None:
                    continue
                seen += 1
                installed = any("sigstore/cosign-installer@" in s for s in steps[:run_at])
                self.assertTrue(installed, f"{wf.name}:{name} runs the suite without installing cosign first")
        self.assertGreaterEqual(seen, 1, "expected daily.yml to run the full suite")

    def test_cosign_installer_is_pinned_by_sha(self):
        for wf in WORKFLOWS.glob("*.yml"):
            for m in re.finditer(r"sigstore/cosign-installer@(\S+)", wf.read_text()):
                self.assertRegex(m.group(1), r"^[0-9a-f]{40}$", f"{wf.name} must pin the installer by SHA")

    def test_workers_and_d1_credentials_never_live_in_a_workflow(self):
        """Least privilege: the only Cloudflare secret in CI is the Pages token (site.yml). Deploying or changing the
        private service needs Workers Scripts/D1 edit rights, which stay with a person and never reach CI."""
        # The ONE owner-approved exception (decision of 2026-10-25, recorded in the pull request): backup.yml holds the credentials of the encrypted-backup copy (D1 export token, one object-store key per provider) in
        # the environment macguard-backup-production. It may export and copy; it may never deploy or migrate (the first assertion still applies to it), and no other workflow gains any secret.
        backup_secrets = {"CLOUDFLARE_API_TOKEN", "MG_B2_KEY_ID", "MG_B2_SECRET", "MG_SCW_KEY_ID", "MG_SCW_SECRET", "MG_R2_KEY_ID", "MG_R2_SECRET"}
        for wf in WORKFLOWS.glob("*.yml"):
            t = wf.read_text()
            self.assertNotRegex(t, r"wrangler[^\n]*\b(deploy|d1)\b", f"{wf.name} deploys or migrates the private service from CI")
            allowed = {"CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID", "GITHUB_TOKEN"} | (backup_secrets if wf.name == "backup.yml" else set())
            for name in re.findall(r"secrets\.([A-Z0-9_]+)", t):
                self.assertIn(name, allowed, f"{wf.name}: unexpected secret {name}")
        self.assertNotIn("secrets.", (WORKFLOWS / "daily.yml").read_text().replace("secrets.GITHUB_TOKEN", ""))


if __name__ == "__main__":
    unittest.main()
