"""The rules_root vectors shared with the quarantine Worker (tests/fixtures/rules_root_vectors.json).

The Worker recomputes the rules_root of a release manifest before it accepts it as evidence of publication, so its implementation (JavaScript, in
admin/worker/src/core.js) must stay identical to scripts/tlog.py. This test keeps the fixture honest against the Python reference; the Worker suite
asserts its own implementation against the same file."""
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import tlog  # noqa: E402

VECTORS = json.loads((pathlib.Path(__file__).resolve().parent / "fixtures" / "rules_root_vectors.json").read_text())["vectors"]


class RulesRootVectors(unittest.TestCase):
    def test_the_fixture_is_what_tlog_computes(self):
        for v in VECTORS:
            self.assertEqual(tlog.rules_root(v["files"]), v["rules_root"], f'n={v["n"]}')

    def test_the_order_of_the_list_does_not_matter(self):
        for v in VECTORS:
            self.assertEqual(tlog.rules_root(list(reversed(v["files"]))), v["rules_root"], f'n={v["n"]}')

    def test_the_vectors_cover_empty_single_odd_and_power_of_two_sizes(self):
        self.assertEqual({v["n"] for v in VECTORS} >= {0, 1, 2, 3, 5, 8, 13, 100}, True)


if __name__ == "__main__":
    unittest.main()
