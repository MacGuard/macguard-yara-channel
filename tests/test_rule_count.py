"""stats.yara_rules counts the rules YARA compiles: declarations inside comments or string literals are not rules.

catalog.count_rules (used by seal.py and build_site.py) and the copy embedded in the standalone verify_public_release.py must agree,
and the verifier must still accept the historical signed value of releases sealed with the old line count."""
import json, pathlib, re, shutil, sys, tarfile, tempfile, unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import catalog, verify_public_release as V

QA_RELEASE = pathlib.Path('/home/dmuino/.local/state/macguard/qa/a11y-20261101/build-c13/release')
OLD_RE = re.compile(r'^\s*(?:(?:global|private)\s+)*rule\s+\w+', re.M)

MIXED = r'''
import "pe"
/*
rule Disabled_Block { condition: true }
   private rule Disabled_Private { condition: false }
*/
// rule Disabled_Line { condition: true }
rule Real_One : tag1 tag2 {
    meta:
        description = "matches rule Fake_In_Meta { condition: true }"
        note = "escaped \" quote then rule Fake_After_Escape {"
    strings:
        $a = "rule Fake_In_String {"
        $b = { 4D 5A /* } rule Fake_In_Hex_Comment { */ 90 // rule Fake_In_Hex_Line {
               00 }
        $c = /rule Fake_In_Regex \{ [}]/ nocase
    condition:
        $a or $b or $c and filesize / 2 > 10 // rule Fake_After_Condition {
}
private rule Real_Two { condition: true } global rule Real_Three { condition: true }
global private rule Real_Four
{
    condition: Real_Two
}
/* unterminated comment with
rule Fake_In_Unterminated { condition: true }
'''


class CountRules(unittest.TestCase):
    def both(self, text, expected):
        self.assertEqual(catalog.count_rules(text), expected, 'catalog.count_rules')
        self.assertEqual(V.count_rules(text), expected, 'verify_public_release.count_rules')

    def test_rule_inside_block_comment_is_not_counted(self):
        self.both('/*\nrule A { condition: true }\n*/\nrule B { condition: true }\n', 1)

    def test_rule_inside_line_comment_is_not_counted(self):
        self.both('//rule A { condition: true }\n  // rule B { condition: true }\nrule C { condition: true }\n', 1)

    def test_rule_inside_string_literal_is_not_counted(self):
        self.both('rule A {\n strings:\n  $s = "x\nrule B { condition: true }"\n condition: $s }\n', 1)
        self.both('rule A {\n meta:\n  d = "rule B {"\n condition: true }\n', 1)
        self.both('include "rule B {"\nrule A { condition: true }\n', 1)

    def test_rule_inside_hex_string_comment_is_not_counted(self):
        self.both('rule A {\n strings:\n  $h = { 4D 5A /* }\nrule B { condition: true }\n*/ 00 }\n condition: $h }\n', 1)
        self.both('rule A {\n strings:\n  $h = { 4D 5A // }\nrule B { condition: true }\n 00 }\n condition: $h }\n', 1)

    def test_nested_looking_comments(self):
        # YARA comments do not nest: the first */ ends the comment, so Inner is commented out but After is a real rule.
        self.both('/* outer /* inner\nrule Inner { condition: true }\n*/\nrule After { condition: true }\n', 1)
        self.both('/* a */ rule A { condition: true } /* rule B { condition: true } */ // */ rule C { condition: true }\n', 1)

    def test_private_and_global_rules_are_counted(self):
        self.both('private rule A { condition: true }\nglobal rule B { condition: true }\nglobal private rule C { condition: true }\n'
                  'private global rule D : t { condition: true }\n', 4)

    def test_real_world_like_mix(self):
        self.both(MIXED, 4)

    def test_regex_in_strings_is_skipped(self):
        self.both('rule A {\n strings:\n  $r = /rule B \\{/\n condition: $r }\nrule C { condition: true }\n', 2)

    def test_previous_behaviour_kept(self):
        t = 'import "pe"\nrule A { condition: true }\nprivate rule B { condition: true }\nglobal private rule C { condition: true }\n// rule D\n  rule E{condition:true}'
        self.both(t, 4); self.both('include "x.yar"', 0); self.both('', 0)

    def test_malformed_input_never_raises(self):
        for t in ('rule', 'rule A', 'rule A {', 'rule A { strings: $a = "unterminated', 'rule A { strings: $h = { 4D', '/*', '"', 'private', 'rule A : {'):
            catalog.count_rules(t); V.count_rules(t)

    def test_old_line_regex_overcounts_these_cases(self):
        # Documents the bug: the line regex counted declarations inside comments and strings.
        self.assertGreater(len(OLD_RE.findall(MIXED)), catalog.count_rules(MIXED))


class VerifierAcceptance(unittest.TestCase):
    TEXTS = ['/*\nrule Old { condition: true }\n*/\nrule A { condition: true }\n', 'private rule B { condition: true }\n']

    def test_current_count_passes(self):
        self.assertEqual(V.check_yara_rules(2, self.TEXTS), (2, 'current'))

    def test_historical_line_count_still_passes(self):
        self.assertEqual(V.check_yara_rules(3, self.TEXTS), (2, 'legacy'))

    def test_any_other_value_fails(self):
        for bad in (1, 4, None, '2'):
            with self.assertRaises(V.Fail) as e: V.check_yara_rules(bad, self.TEXTS)
            self.assertEqual(e.exception.code, 1)


class RealRelease(unittest.TestCase):
    """The release whose signed stats.yara_rules (10021) included 82 commented-out declarations."""

    @classmethod
    def setUpClass(cls):
        tar, man = QA_RELEASE / 'rules-release.tar.gz', QA_RELEASE / 'manifest.json'
        if not (tar.is_file() and man.is_file()): raise unittest.SkipTest(f'QA release copy not available at {QA_RELEASE} (local fixture, not in the repository)')
        cls.tmp = pathlib.Path(tempfile.mkdtemp(prefix='rule-count-release-'))
        with tarfile.open(tar) as t: t.extractall(cls.tmp, filter='data')
        cls.manifest = json.loads(man.read_text())
        cls.texts = [(cls.tmp / f['path']).read_text(errors='replace') for f in cls.manifest['files']]

    @classmethod
    def tearDownClass(cls): shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_count_is_9939_and_historical_value_still_verifies(self):
        signed = self.manifest['stats']['yara_rules']
        self.assertEqual(signed, 10021)
        self.assertEqual(sum(catalog.count_rules(t) for t in self.texts), 9939)
        self.assertEqual(sum(V.count_rules(t) for t in self.texts), 9939)
        self.assertEqual(V.check_yara_rules(signed, self.texts), (9939, 'legacy'))
        self.assertEqual(V.check_yara_rules(9939, self.texts), (9939, 'current'))


if __name__ == '__main__':
    unittest.main()
