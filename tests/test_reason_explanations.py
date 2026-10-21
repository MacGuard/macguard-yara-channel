"""The panel explains every finding the pipeline can emit, and says whether it blocks exactly as the contract does.

A finding without an explanation would show a person a bare code on a rule they cannot approve. The explanations live in admin/worker/public/i18n.js
(rx_<code>: what the control checks, rf_<code>: what would have to happen, rk_<code>: block | review); the set of findings a person may accept is WAIVABLE in
admin/worker/src/core.js, which tests/test_decide.py keeps equal to decide.py."""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
I18N = (ROOT / "admin" / "worker" / "public" / "i18n.js").read_text()
CORE = (ROOT / "admin" / "worker" / "src" / "core.js").read_text()
EMITTED = set()
for name in ("rulecheck.py", "decide.py"):
    EMITTED |= set(re.findall(r"""finding\('([a-z0-9-]+)',""", (ROOT / "scripts" / name).read_text()))
    EMITTED |= set(re.findall(r"""'code': '([a-z0-9-]+)'""", (ROOT / "scripts" / name).read_text()))
EMITTED -= {"waived-by-review"}   # informative, not a finding a person decides on
WAIVABLE = set(re.findall(r"'([a-z-]+)'", re.search(r"WAIVABLE = new Set\(\[([^\]]*)\]", CORE).group(1)))
KEY = lambda code: re.sub(r"[^a-z0-9]+", "_", code)


def keys(lang):
    start = I18N.index(f"  {lang}: {{")
    end = I18N.index("\n  },", start) if lang == "es" else len(I18N)
    return I18N[start:end]


class ReasonExplanations(unittest.TestCase):
    def test_the_pipeline_emits_what_we_think_it_emits(self):
        self.assertGreaterEqual(len(EMITTED), 20, EMITTED)
        self.assertTrue(WAIVABLE <= EMITTED | {"unknown-module"}, WAIVABLE - EMITTED)

    def test_every_emitted_finding_is_explained_in_both_languages(self):
        for lang in ("es", "en"):
            block = keys(lang)
            for code in sorted(EMITTED | {"synthetic-test"}):
                for prefix in ("rx_", "rf_", "rk_"):
                    self.assertIn(f"{prefix}{KEY(code)}:", block, f"{lang}: {prefix}{KEY(code)}")

    def test_a_finding_blocks_exactly_when_it_is_not_waivable(self):
        for lang in ("es", "en"):
            block = keys(lang)
            for code in sorted(EMITTED | {"synthetic-test"}):
                kind = re.search(rf"rk_{KEY(code)}: '([a-z]+)'", block).group(1)
                self.assertEqual(kind, "review" if code in WAIVABLE else "block", f"{lang}: {code}")

    def test_the_fix_never_promises_that_approval_overrides_a_blocking_control(self):
        for lang in ("es", "en"):
            block = keys(lang)
            for code in sorted(EMITTED | {"synthetic-test"}):
                if code in WAIVABLE:
                    continue
                fix = re.search(rf"rf_{KEY(code)}: '([^']*)'", block).group(1).lower()
                self.assertNotIn("al aprobar", fix, f"{lang}: {code}")
                self.assertNotIn("by approving", fix, f"{lang}: {code}")


if __name__ == "__main__":
    unittest.main()
