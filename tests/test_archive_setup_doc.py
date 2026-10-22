"""The owner's archive setup guide must stay consistent with archive.yml and with the decisions taken: no Compliance by default,
no administrative credential in GitHub, and the Object Lock facts corrected on 2026-10-22."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = (ROOT / "docs" / "OPERATIONS-archive-setup.md").read_text()
WORKFLOW = (ROOT / ".github" / "workflows" / "archive.yml").read_text()


class ArchiveSetupGuide(unittest.TestCase):
    def test_secret_names_in_the_guide_are_exactly_those_the_workflow_reads(self):
        used = set(re.findall(r"secrets\.([A-Z_]+)", WORKFLOW))
        self.assertEqual(used, {"ARCHIVE_ACCESS_KEY_ID", "ARCHIVE_SECRET_ACCESS_KEY"})
        for name in used:
            self.assertIn(name, DOC)
        for env in ("r2", "b2", "scaleway"):
            for kind in ("write", "read"):
                self.assertIn(f"archive-{env}-{kind}", DOC)

    def test_the_guide_does_not_instruct_compliance_or_a_permanent_lock(self):
        section2 = DOC.split("## 2. Un proveedor tras otro")[1].split("### 2.4")[0]
        self.assertIn("Governance", section2)
        self.assertIn("**No usar «indefinida»**", section2)
        for line in section2.splitlines():
            if re.search(r"compliance|cumplimiento", line, re.I):
                self.assertTrue(re.search(r"autorizaci|no equivalen|no es compliance|solo compliance|Compliance \(", line, re.I), f"Compliance presented as a default: {line[:120]}")

    def test_object_lock_facts_are_the_corrected_ones(self):
        self.assertNotIn("no se puede activar ni desactivar después", DOC)
        self.assertNotIn("activados en la creación**", DOC)
        self.assertIn("se puede activar en un bucket existente", DOC.replace("**Object Lock se puede activar en un bucket existente**", "se puede activar en un bucket existente"))
        self.assertIn("no se puede deshabilitar", DOC)
        self.assertIn("no equivalen a un Compliance inmutable", DOC.replace("**", ""))
        self.assertIn("no protege frente a identidades autorizadas", DOC)

    def test_administrative_credentials_never_go_to_github_and_are_not_created(self):
        for needle in ("`macguard-b2-admin`", "Solo en el llavero del propietario, nunca en GitHub"):
            self.assertIn(needle, DOC)
        self.assertIn("**no se crean**, y no entran en GitHub", DOC)

    def test_scaleway_free_offer_is_a_90_day_trial_and_the_negative_tests_are_listed(self):
        self.assertIn("**90 días**", DOC)
        self.assertIn("no es una franquicia permanente", DOC)
        for needle in ("Borrado normal", "Sobrescritura", "Acortar o quitar la retención", "Bypass autorizado"):
            self.assertIn(needle, DOC)
        self.assertIn("NO está verificada hasta pasarlas", DOC)

    def test_write_keys_are_never_granted_delete_or_retention_capabilities(self):
        m = re.search(r"`macguard-b2-write`[^\n]*", DOC)
        self.assertIsNotNone(m)
        b2 = m.group(0) if m else ""
        self.assertIn("**Sin** `deleteFiles`, `writeFileRetentions` ni `bypassGovernance`", b2)
        m = re.search(r"`macguard-scw-write-policy`[^\n]*", DOC)
        self.assertIsNotNone(m)
        scw = m.group(0) if m else ""
        self.assertIn("Nunca `ObjectStorageObjectsDelete`", scw)
        self.assertIn("PutObjectRetention", scw)


if __name__ == "__main__":
    unittest.main()
