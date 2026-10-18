import json, pathlib, shutil, subprocess, sys, tempfile, unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import rulecheck as rc

POLICY = json.loads((pathlib.Path(__file__).resolve().parents[1] / 'config/policy.json').read_text())
GOOD = 'import "pe"\nrule Good { strings: $a = "abc" $b = { 4D 5A } condition: $a or $b }\n'
YARAC = shutil.which('yarac')

def codes(text): return {f['code'] for f in rc.analyse_text(text, POLICY)['findings']}
def sev(text): return {f['severity'] for f in rc.analyse_text(text, POLICY)['findings']}

class StaticTests(unittest.TestCase):
    def test_a_good_file_has_no_findings(self):
        self.assertEqual(rc.analyse_text(GOOD, POLICY)['findings'], [])
    def test_truncated_in_the_middle_of_a_rule(self):
        t = GOOD[:GOOD.index('condition') + 12]
        self.assertIn('unclosed-rule', codes(t)); self.assertIn('truncated', sev(t))
    def test_truncated_inside_a_string(self):
        self.assertIn('unterminated-string', codes('rule A { strings: $a = "abc'))
    def test_truncated_inside_a_comment_and_a_regex(self):
        self.assertIn('unterminated-comment', codes(GOOD + '/* the rest is missing'))
        self.assertIn('unterminated-regex', codes('rule A { strings: $a = /ab+c'))
    def test_comment_and_string_contents_do_not_confuse_the_brace_count(self):
        t = 'rule A { // a } in a comment\n strings: $a = "}}}" condition: $a }\n'
        self.assertEqual(rc.analyse_text(t, POLICY)['findings'], [])
    def test_hex_strings_use_braces_and_stay_balanced(self):
        self.assertEqual(rc.analyse_text('rule H { strings: $h = { 41 [2-4] 42 } condition: $h }', POLICY)['findings'], [])
    def test_corrupt_bytes_and_missing_condition(self):
        self.assertIn('corrupt-encoding', codes(GOOD + '�'))
        self.assertIn('no-condition', codes('rule A { strings: $a = "x" }'))
    def test_file_without_rules_is_rejected(self):
        self.assertIn('reject', sev('// only a comment\n'))
    def test_modules_policy(self):
        self.assertIn('blocked-module', codes('import "cuckoo"\nrule A { condition: true }'))
        self.assertIn('unknown-module', codes('import "weird"\nrule A { condition: true }'))
        self.assertNotIn('unknown-module', codes(GOOD))
    def test_costly_regexes_are_flagged_but_ordinary_ones_are_not(self):
        self.assertIn('costly-regex', codes('rule A { strings: $a = /(a+)+b/ condition: $a }'))
        self.assertIn('costly-regex', codes('rule A { strings: $a = /x.{0,5000}y.*z.*w/ condition: $a }'))
        self.assertNotIn('costly-regex', codes('rule A { strings: $a = /[a-z]{3,8}\\.exe/ condition: $a }'))
        self.assertNotIn('costly-regex', codes('rule A { strings: $a = /abc.{0,100}def/ condition: $a }'))
    def test_whole_file_loops_are_flagged(self):
        self.assertIn('filesize-loop', codes('rule A { condition: for any i in (0..filesize) : ( uint8(i) == 0x41 ) }'))
    def test_deprecated_metadata_is_read(self):
        self.assertTrue(rc.analyse_text('rule A { meta: deprecated = true condition: true }', POLICY)['deprecated'])
    def test_rule_names_and_includes_are_extracted(self):
        a = rc.analyse_text('include "other.yar"\nprivate rule P { condition: true }\nrule Q { condition: P }', POLICY)
        self.assertEqual(a['rules'], ['P', 'Q']); self.assertEqual(a['includes'], ['other.yar'])

@unittest.skipUnless(YARAC, 'yarac is not installed; the compile tests need the real compiler (a skipped test is not a pass)')
class CompileTests(unittest.TestCase):
    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp()); self.engines = rc.find_engines([YARAC])
    def tearDown(self): shutil.rmtree(self.d, ignore_errors=True)
    def run_set(self, files, rejected=None):
        entries = []
        for name, text in files.items():
            (self.d / name).parent.mkdir(parents=True, exist_ok=True); data = text.encode() if isinstance(text, str) else text
            (self.d / name).write_bytes(data)
            entries.append({'path': name, 'source': 'community', 'sha256': rc.sha256(data), 'bytes': len(data)})
        res = rc.classify(entries, self.d, POLICY, self.engines, {}, rejected or set())
        return {r['path']: r for r in res}
    def test_valid_file_is_validated(self):
        self.assertEqual(self.run_set({'a.yar': GOOD})['a.yar']['state'], rc.VALIDATED)
    def test_syntax_error_is_quarantined_with_the_compiler_message(self):
        r = self.run_set({'a.yar': 'rule A { condition: $nope }'})['a.yar']
        self.assertEqual(r['state'], rc.QUARANTINED); self.assertTrue(any(f['code'] in ('compile-error', 'compile-dependency') for f in r['reasons']))
    def test_truncated_file_is_quarantined_not_published(self):
        r = self.run_set({'a.yar': GOOD[:-5]})['a.yar']
        self.assertEqual(r['state'], rc.QUARANTINED)
    def test_binary_content_is_rejected(self):
        self.assertEqual(self.run_set({'a.yar': b'rule A { condition: true }\x00\x01\x02'})['a.yar']['state'], rc.REJECTED)
    def test_same_content_rejected_before_stays_rejected(self):
        data = GOOD.encode()
        self.assertEqual(self.run_set({'a.yar': GOOD}, rejected={rc.sha256(data)})['a.yar']['state'], rc.REJECTED)
    def test_changed_content_of_a_rejected_rule_is_a_new_candidate(self):
        self.assertEqual(self.run_set({'a.yar': GOOD + '// edited\n'}, rejected={rc.sha256(GOOD.encode())})['a.yar']['state'], rc.VALIDATED)
    def test_dependency_across_files_is_resolved_and_tracked(self):
        r = self.run_set({'base.yar': 'private rule IsPE { condition: uint16(0) == 0x5A4D }', 'use.yar': 'rule Uses { condition: IsPE }'})
        self.assertEqual(r['use.yar']['state'], rc.VALIDATED); self.assertIn('base.yar', r['use.yar']['depends_on'])
    def test_dependent_of_a_quarantined_file_is_quarantined_too(self):
        r = self.run_set({'base.yar': 'private rule IsPE { condition: uint16(0) == 0x5A4D ', 'use.yar': 'rule Uses { condition: IsPE }'})
        self.assertEqual(r['base.yar']['state'], rc.QUARANTINED); self.assertEqual(r['use.yar']['state'], rc.QUARANTINED)
    def test_license_that_changed_quarantines_the_whole_source(self):
        (self.d / 'a.yar').write_text(GOOD); data = GOOD.encode()
        e = [{'path': 'a.yar', 'source': 'community', 'sha256': rc.sha256(data), 'bytes': len(data)}]
        r = rc.classify(e, self.d, POLICY, self.engines, {'community': {'license_check': {'ok': False, 'detail': 'LICENSE text changed'}}})
        self.assertEqual(r[0]['state'], rc.QUARANTINED)
    def test_without_a_compiler_nothing_is_validated(self):
        (self.d / 'a.yar').write_text(GOOD); data = GOOD.encode()
        r = rc.classify([{'path': 'a.yar', 'source': 'community', 'sha256': rc.sha256(data), 'bytes': len(data)}], self.d, POLICY, [])
        self.assertEqual(r[0]['state'], rc.QUARANTINED)
if __name__ == '__main__': unittest.main()
