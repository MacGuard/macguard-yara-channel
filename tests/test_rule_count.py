"""Rule counts of a release.

stats.yara_rules keeps its signed, historical meaning (rule declarations matched line-wise, commented-out ones included) so that
verify_public_release.py 1.0.0, already in users' hands, keeps passing. stats.yara_rules_compiled (additive) counts the rules YARA
compiles: declarations inside comments or string literals are not rules. catalog.count_compiled_rules and the copy embedded in the
standalone verifier must agree."""
import importlib.util, json, pathlib, re, shutil, subprocess, sys, tarfile, tempfile, unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import catalog, portal, verify_public_release as V

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
        self.assertEqual(catalog.count_compiled_rules(text), expected, 'catalog.count_compiled_rules')
        self.assertEqual(V.count_compiled_rules(text), expected, 'verify_public_release.count_compiled_rules')

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
            catalog.count_compiled_rules(t); V.count_compiled_rules(t)

    def test_old_line_regex_overcounts_these_cases(self):
        # Documents the bug: the line regex counted declarations inside comments and strings.
        self.assertGreater(len(OLD_RE.findall(MIXED)), catalog.count_compiled_rules(MIXED))


def write_files(folder, texts):
    files = []
    for k, x in enumerate(texts):
        p = pathlib.Path(folder) / 'rules' / f'f{k}.yar'; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(x)
        files.append({'path': f'rules/f{k}.yar', 'bytes': len(x.encode())})
    return files


def verifier_1_0_0():
    """verify_public_release.py 1.0.0 as published (main at 8a38beb), imported from git; None when the object is not available."""
    r = subprocess.run(['git', '-C', str(ROOT), 'show', '8a38beb:scripts/verify_public_release.py'], capture_output=True)
    if r.returncode != 0: return None
    d = pathlib.Path(tempfile.mkdtemp(prefix='verifier-1.0.0-')); f = d / 'verify_public_release_1_0_0.py'; f.write_bytes(r.stdout)
    spec = importlib.util.spec_from_file_location('verify_public_release_1_0_0', f); mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    shutil.rmtree(d, ignore_errors=True)
    return mod


def old_counts_check(rule_re, st, files, texts):
    """The counts check of verifier 1.0.0, verbatim in substance: files, expanded bytes, and a RULE_RE recount of yara_rules."""
    assert st.get('files') == len(files), 'stats.files'
    assert st.get('expanded_bytes') == sum(f['bytes'] for f in files), 'stats.expanded_bytes'
    n = sum(len(rule_re.findall(x)) for x in texts)
    assert st.get('yara_rules') == n, f"stats.yara_rules {st.get('yara_rules')} != {n}"


class SignedStats(unittest.TestCase):
    TEXTS = ['/*\nrule Old { condition: true }\n*/\nrule A { condition: true }\n', 'private rule B { condition: true }\n', MIXED]

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix='rule-stats-')); self.files = write_files(self.tmp, self.TEXTS)
        self.st = catalog.release_stats(self.tmp, self.files)
    def tearDown(self): shutil.rmtree(self.tmp, ignore_errors=True)

    def test_new_field_is_additive(self):
        self.assertEqual(self.st['yara_rules'], sum(len(OLD_RE.findall(x)) for x in self.TEXTS))   # unchanged meaning
        self.assertEqual(self.st['yara_rules_compiled'], 1 + 1 + 4)
        self.assertEqual((self.st['files'], self.st['expanded_bytes']), (3, sum(f['bytes'] for f in self.files)))
        self.assertIn('catalog.release_stats(folder', (ROOT / 'scripts/seal.py').read_text(), 'seal.py must sign these stats')

    def test_verifier_1_0_0_accepts_stats_of_the_new_seal(self):
        old = verifier_1_0_0()
        rule_re = old.RULE_RE if old else OLD_RE
        if old: self.assertEqual(old.VERSION, '1.0.0')
        self.assertEqual(rule_re.pattern, V.RULE_RE.pattern); self.assertEqual(rule_re.flags, V.RULE_RE.flags)
        old_counts_check(rule_re, self.st, self.files, self.TEXTS)
        if old is None: self.skipTest('git object 8a38beb not available: checked against the embedded 1.0.0 regex only')

    def test_current_verifier_checks_both_fields(self):
        n, c, detail = V.check_rule_counts(self.st, self.TEXTS)
        self.assertEqual((n, c), (self.st['yara_rules'], 6)); self.assertIn('stats.yara_rules_compiled', detail)

    def test_wrong_compiled_count_fails(self):
        for bad in (self.st['yara_rules'], 5, 7, None):
            with self.assertRaises(V.Fail) as e: V.check_rule_counts(dict(self.st, yara_rules_compiled=bad), self.TEXTS)
            self.assertEqual(e.exception.code, 1); self.assertIn('yara_rules_compiled', e.exception.message)

    def test_wrong_line_count_still_fails(self):
        for bad in (self.st['yara_rules_compiled'], self.st['yara_rules'] + 1):
            with self.assertRaises(V.Fail) as e: V.check_rule_counts(dict(self.st, yara_rules=bad), self.TEXTS)
            self.assertIn('stats.yara_rules ', e.exception.message)

    def test_historical_manifest_without_the_field_verifies(self):
        st = {k: v for k, v in self.st.items() if k != 'yara_rules_compiled'}
        n, c, detail = V.check_rule_counts(st, self.TEXTS)
        self.assertEqual((n, c), (self.st['yara_rules'], 6)); self.assertIn('not checked', detail)

    def test_display_prefers_compiled_and_falls_back(self):
        self.assertEqual(portal.yara_counts({'yara_rules': 10021, 'yara_rules_compiled': 9939})['yara_rules'], 9939)
        old = portal.yara_counts({'yara_rules': 10021})
        self.assertEqual(old['yara_rules'], 10021); self.assertTrue(old['yara_rules_basis'].startswith('declarations'))
        self.assertEqual(V.rule_count_text({'yara_rules': 10021, 'yara_rules_compiled': 9939}), '9939 (10021 declarations incl. commented-out)')
        self.assertEqual(V.rule_count_text({'yara_rules': 10021}), '10021')


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

    def test_counts_10021_declarations_9939_compiled_and_historical_manifest_verifies(self):
        signed = self.manifest['stats']
        self.assertEqual(signed['yara_rules'], 10021); self.assertNotIn('yara_rules_compiled', signed)
        self.assertEqual(sum(catalog.count_compiled_rules(t) for t in self.texts), 9939)
        self.assertEqual(sum(V.count_compiled_rules(t) for t in self.texts), 9939)
        st = catalog.release_stats(self.tmp, self.manifest['files'])
        self.assertEqual((st['yara_rules'], st['yara_rules_compiled'], st['files'], st['expanded_bytes']),
                         (10021, 9939, signed['files'], signed['expanded_bytes']))
        n, c, detail = V.check_rule_counts(signed, self.texts)        # historical signed manifest, no new field
        self.assertEqual((n, c), (10021, 9939)); self.assertIn('not checked', detail)
        self.assertEqual(V.check_rule_counts(st, self.texts)[:2], (10021, 9939))   # what a new seal would sign
        old_counts_check(OLD_RE, st, self.manifest['files'], self.texts)


if __name__ == '__main__':
    unittest.main()
