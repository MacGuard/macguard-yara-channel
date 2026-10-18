import json, pathlib, shutil, sys, tempfile, unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import decide, dynamic_gate, rulecheck as rc

ROOT = pathlib.Path(__file__).resolve().parents[1]
POLICY = json.loads((ROOT / 'config/policy.json').read_text())
POLICY['dynamic']['runs'] = 3
YARA, YARAC = shutil.which('yara'), shutil.which('yarac')
GOOD = 'rule G%d { strings: $a = "needle%d" condition: $a }'
SLOW = 'rule SLOW { condition: for any i in (0..filesize-1) : ( for any j in (0..filesize-1) : ( i != j and uint8(i) == 1 and uint8(j) == 2 and false ) ) }'
GENERIC = 'rule GENERIC { strings: $a = "the" condition: $a }'     # matches the text files of the clean corpus

@unittest.skipUnless(YARA and YARAC, 'yara is not installed; the dynamic gate needs the real engine (a skipped test is not a pass)')
class GateTests(unittest.TestCase):
    def setUp(self): self.d = pathlib.Path(tempfile.mkdtemp()); self.p = pathlib.Path(tempfile.mkdtemp())
    def tearDown(self): shutil.rmtree(self.d, ignore_errors=True); shutil.rmtree(self.p, ignore_errors=True)
    def write(self, root, files):
        out = []
        for name, text in files.items():
            (root / name).write_text(text); data = text.encode()
            out.append({'path': name, 'source': 'community', 'sha256': rc.sha256(data), 'bytes': len(data), 'state': 'VALIDATED', 'reasons': [], 'depends_on': [], 'rules': __import__('re').findall(r'rule\s+(\w+)', text)})
        return out
    def previous(self, files):
        entries = self.write(self.p, files); (self.p / 'manifest.json').write_text(json.dumps({'files': [{'path': e['path'], 'sha256': e['sha256']} for e in entries]})); return entries
    def run_gate(self, files, prev=None):
        cls = self.write(self.d, files)
        policy = json.loads(json.dumps(POLICY)); policy['dynamic']['absolute']['max_scan_p95_s'] = 2.0
        return dynamic_gate.run(self.d, cls, self.p if prev else None, policy, None, YARA, YARAC, max_iter=3, timeout_file=1)

    def test_a_good_set_passes_and_the_result_belongs_to_exactly_that_set(self):
        files = {f'g{i}.yar': GOOD % (i, i) for i in range(4)}
        final, dyn = self.run_gate(files)
        self.assertTrue(final['publishable'], final['blockers']); self.assertEqual(dyn['set_root'], final['rules_root']); self.assertEqual(dyn['canaries_detected'], dyn['canaries_expected'])
    def test_a_rule_that_blocks_the_engine_is_isolated_and_the_rest_is_published(self):
        files = {f'g{i}.yar': GOOD % (i, i) for i in range(5)}; files['slow.yar'] = SLOW
        final, dyn = self.run_gate(files)
        self.assertEqual(dyn['culprits'], ['slow.yar']); self.assertNotIn('slow.yar', [f['path'] for f in final['approved']]); self.assertEqual(len(final['approved']), 5)
        self.assertTrue(final['publishable'], final['blockers']); self.assertEqual(dyn['set_root'], final['rules_root'])
        self.assertTrue(any(s['path'] == 'slow.yar' for s in final['submissions'])); self.assertGreaterEqual(len(dyn['iterations']), 2)
    def test_a_new_blocking_rule_on_top_of_a_good_baseline_is_isolated(self):
        base = {f'g{i}.yar': GOOD % (i, i) for i in range(4)}; self.previous(base)
        files = dict(base); files['slow.yar'] = SLOW; files['extra.yar'] = GOOD % (9, 9)
        final, dyn = self.run_gate(files, prev=True)
        self.assertEqual(dyn['culprits'], ['slow.yar']); self.assertEqual(sorted(f['path'] for f in final['approved']), sorted(list(base) + ['extra.yar'])); self.assertTrue(final['publishable'], final['blockers'])
    def test_a_baseline_comparison_does_not_flag_an_unchanged_set(self):
        base = {f'g{i}.yar': GOOD % (i, i) for i in range(4)}; self.previous(base); files = dict(base); files['new.yar'] = GOOD % (7, 7)
        final, dyn = self.run_gate(files, prev=True)
        self.assertTrue(final['publishable'], (final['blockers'], dyn.get('reasons'))); self.assertEqual(dyn['verdict'], 'ok')
    def test_a_rule_that_matches_a_lot_of_clean_files_is_quarantined_and_the_set_is_remeasured(self):
        files = {'a.yar': GOOD % (1, 1), 'generic.yar': GENERIC}
        final, dyn = self.run_gate(files)
        self.assertNotIn('generic.yar', [f['path'] for f in final['approved']]); self.assertTrue(final['publishable'], final['blockers']); self.assertEqual(dyn['set_root'], final['rules_root'])
        self.assertTrue(any(s['path'] == 'generic.yar' for s in final['submissions']))
    def test_if_everything_blocks_the_engine_nothing_is_published(self):
        final, dyn = self.run_gate({'slow.yar': SLOW})
        self.assertFalse(final['publishable'])
if __name__ == '__main__': unittest.main()
