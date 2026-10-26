"""The guard that refuses to deploy the quarantine Worker with a placeholder, a wrong host or incomplete bindings (scripts/check_worker_config.py).

The 2026-10-21 deploy went out with PUBLIC_URL and OIDC_AUDIENCE still set to REPLACE-WITH-ADMIN-HOSTNAME: the OAuth redirect and the audience of the
pipeline callbacks were wrong until a corrective deploy. Each way of getting a config wrong has a test that must be refused."""
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts" / "check_worker_config.py"
TEMPLATE = (ROOT / "admin" / "worker" / "wrangler.toml").read_text()
D1 = "4c9f258a-8dd3-41eb-a840-2d0ff84c238d"
INTEL = "663fa259-cf0f-4224-9892-ed585c6ac560"


def deployable():
    return (TEMPLATE.replace("REPLACE-WITH-INTEL-D1-ID", INTEL).replace("REPLACE-WITH-D1-ID", D1).replace("REPLACE-WITH-ADMIN-HOSTNAME", "panel.mac-guard.com")
            .replace("workers_dev = false\n", 'workers_dev = false\nroutes = [{ pattern = "panel.mac-guard.com", custom_domain = true }]\n', 1))


def run(mode, text):
    with tempfile.TemporaryDirectory() as d:
        p = pathlib.Path(d) / "wrangler.toml"
        p.write_text(text)
        r = subprocess.run([sys.executable, str(GUARD), mode, str(p)], capture_output=True, text=True)
    return r.returncode, r.stdout


class WorkerConfigGuard(unittest.TestCase):
    def refused(self, text, expect):
        code, out = run("--config", text)
        self.assertEqual(code, 1, out)
        self.assertIn(expect, out)

    def test_the_tracked_template_keeps_only_the_known_placeholders(self):
        self.assertEqual(run("--template", TEMPLATE)[0], 0)

    def test_the_tracked_template_is_never_deployable_as_it_is(self):
        self.assertEqual(run("--config", TEMPLATE)[0], 1)

    def test_a_complete_config_is_deployable(self):
        code, out = run("--config", deployable())
        self.assertEqual(code, 0, out)
        self.assertTrue(out.startswith("OK: "), out)

    def test_the_placeholder_host_is_refused(self):
        self.refused(deployable().replace('PUBLIC_URL = "https://panel.mac-guard.com"', 'PUBLIC_URL = "https://REPLACE-WITH-ADMIN-HOSTNAME"'), "PUBLIC_URL")
        self.refused(deployable().replace('OIDC_AUDIENCE = "https://panel.mac-guard.com"', 'OIDC_AUDIENCE = "https://REPLACE-WITH-ADMIN-HOSTNAME"'), "OIDC_AUDIENCE")

    def test_the_host_must_be_exact(self):
        for wrong in ("https://panel.mac-guard.com/", "http://panel.mac-guard.com", "https://example.com", "panel.mac-guard.com"):
            self.refused(deployable().replace('PUBLIC_URL = "https://panel.mac-guard.com"', f'PUBLIC_URL = "{wrong}"'), "PUBLIC_URL must be exactly")
            self.refused(deployable().replace('OIDC_AUDIENCE = "https://panel.mac-guard.com"', f'OIDC_AUDIENCE = "{wrong}"'), "OIDC_AUDIENCE must be exactly")

    def test_the_custom_domain_is_required(self):
        self.refused(deployable().replace('routes = [{ pattern = "panel.mac-guard.com", custom_domain = true }]\n', ""), "custom domain")
        self.refused(deployable().replace("custom_domain = true", "custom_domain = false"), "custom domain")

    def test_the_d1_binding_must_be_complete(self):
        self.refused(deployable().replace(D1, "REPLACE-WITH-D1-ID"), "placeholder")
        self.refused(deployable().replace(D1, "not-a-uuid"), "not a UUID")
        self.refused(deployable().replace('binding = "DB"', 'binding = "OTHER"'), "binding named DB")
        self.refused(deployable().replace('database_name = "macguard-quarantine"', 'database_name = "other"'), "database_name")

    def test_the_intel_binding_is_required_complete_and_separate_from_the_panel_database(self):
        self.refused(deployable().replace(INTEL, "REPLACE-WITH-INTEL-D1-ID"), "placeholder")
        self.refused(deployable().replace(INTEL, "not-a-uuid"), "INTEL database_id is not a UUID")
        self.refused(deployable().replace('binding = "INTEL"', 'binding = "OTHER"'), "binding named INTEL")
        self.refused(deployable().replace('database_name = "macguard-intel"', 'database_name = "other"'), "INTEL database_name")
        self.refused(deployable().replace(INTEL, D1), "different database")

    def test_the_assets_binding_and_the_pipeline_variables_are_required(self):
        self.refused(deployable().replace('binding = "ASSETS"', 'binding = "OTHER"'), "ASSETS")
        self.refused(deployable().replace('PIPELINE_WORKFLOWS = "daily.yml,publish.yml"', 'PIPELINE_WORKFLOWS = "daily.yml"'), "PIPELINE_WORKFLOWS")
        self.refused(deployable().replace('REPO = "MacGuard/macguard-yara-channel"', 'REPO = "someone/else"'), "REPO")

    def test_a_public_workers_dev_url_is_refused(self):
        self.refused(deployable().replace("workers_dev = false", "workers_dev = true"), "workers_dev")

    def test_any_example_looking_value_is_refused(self):
        self.refused(deployable() + '\n[vars.extra]\nX = "example-value"\n', "placeholder")

    def test_an_unreadable_config_is_a_usage_error_not_a_pass(self):
        self.assertEqual(run("--config", "this is not toml [")[0], 2)
        r = subprocess.run([sys.executable, str(GUARD), "--config", "/nonexistent/wrangler.toml"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
