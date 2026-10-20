import json, pathlib, shutil, sys, tempfile, unittest
from unittest import mock
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

@unittest.skipUnless(YARA and YARAC, 'yara is not installed (a skipped test is not a pass)')
class VerifyOnlyTests(unittest.TestCase):
    def test_a_platform_check_loads_the_dependencies_the_candidate_declares(self):
        d = pathlib.Path(tempfile.mkdtemp())
        try:
            (d / 'rules').mkdir(); (d / 'rules/base.yar').write_text('private rule Base { strings: $a = "x" condition: $a }'); (d / 'rules/use.yar').write_text('rule Use { condition: Base }')
            files = [{'path': 'rules/base.yar', 'sha256': 'a' * 64, 'bytes': 10}, {'path': 'rules/use.yar', 'sha256': 'b' * 64, 'bytes': 10, 'depends_on': ['rules/base.yar']}]
            (d / 'candidate.json').write_text(json.dumps({'files': files}))
            doc = dynamic_gate.verify_only(d, None, json.loads(json.dumps(POLICY)), YARA, YARAC, str(d / 'out.json'))
            self.assertIn(doc['verdict'], ('ok', 'no-baseline'), doc['reasons']); self.assertEqual(doc['canaries_detected'], doc['canaries_expected'])
        finally: shutil.rmtree(d, ignore_errors=True)

@unittest.skipUnless(YARA and YARAC, 'yara is not installed; the dynamic gate needs the real engine (a skipped test is not a pass)')
class BenignHitRateTests(unittest.TestCase):
    """The benign-corpus hit rate counts distinct clean files per logical rule (reproduced on the runner image: one benign binary matched a rule file that
    three others depend on, so it was compiled in four namespaces and counted four times, 4/58 > 5%, and the file and its three dependents were quarantined)."""
    def setUp(self): self.d = pathlib.Path(tempfile.mkdtemp())
    def tearDown(self): shutil.rmtree(self.d, ignore_errors=True)
    def gate(self, files, deps, marks):
        """marks: {marker text: number of extra clean-corpus files containing it}. Returns (final decision, dynamic result)."""
        cls = []
        for name, text in files.items():
            (self.d / name).write_text(text); data = text.encode()
            cls.append({'path': name, 'source': 'community', 'sha256': rc.sha256(data), 'bytes': len(data), 'state': 'VALIDATED', 'reasons': [], 'depends_on': deps.get(name, []), 'rules': __import__('re').findall(r'rule\s+(\w+)', text)})
        build = dynamic_gate.bench.build_corpus
        def with_marked_files(dest, **kw):
            corpus, canaries = build(dest, **kw)
            for marker, n in marks.items():
                for i in range(n): q = dest / f'benign_{abs(hash(marker)) % 9999}_{i}.txt'; q.write_text(f'a harmless file that happens to contain {marker}'); corpus.append(q)
            return corpus, canaries
        policy = json.loads(json.dumps(POLICY)); policy['dynamic']['absolute']['max_scan_p95_s'] = 2.0
        with mock.patch.object(dynamic_gate.bench, 'build_corpus', with_marked_files):
            return dynamic_gate.run(self.d, cls, None, policy, None, YARA, YARAC, max_iter=3, timeout_file=2)
    CAP = {'cap.yar': 'rule CAP { strings: $a = "SHARED-BENIGN-MARK" condition: $a }', **{f'dep{i}.yar': f'rule DEP{i} {{ strings: $a = "only-dep-{i}" condition: $a }}' for i in (1, 2, 3)}}
    DEPS = {f'dep{i}.yar': ['cap.yar'] for i in (1, 2, 3)}

    def test_one_benign_file_matched_through_four_namespaces_does_not_make_a_rule_generic(self):
        final, dyn = self.gate(self.CAP, self.DEPS, {'SHARED-BENIGN-MARK': 1})
        self.assertEqual(sorted(f['path'] for f in final['approved']), sorted(self.CAP), 'the rule file and its three dependents stay in the set')
        self.assertEqual(dyn['benign_hits_by_file'].get('cap.yar'), 1); self.assertTrue(final['publishable'], final['blockers'])
        self.assertEqual(dyn['canaries_detected'], dyn['canaries_expected'])
    def test_the_five_percent_limit_still_applies_to_distinct_files_through_every_namespace(self):
        final, dyn = self.gate({**self.CAP, **{f'g{i}.yar': GOOD % (i, i) for i in range(4)}}, self.DEPS, {'SHARED-BENIGN-MARK': 4})          # 4 of 62 distinct files = 6.5%
        self.assertEqual(dyn['benign_hits_by_file'].get('cap.yar'), 4, 'four files, not sixteen')
        self.assertNotIn('cap.yar', [f['path'] for f in final['approved']]); self.assertTrue(any(s['path'] == 'cap.yar' and 'matches-benign-corpus' in s['reasons'] for s in final['submissions']))
        self.assertTrue(all(d not in [f['path'] for f in final['approved']] for d in self.DEPS), 'its dependents cannot ship without it')
    def test_three_distinct_files_stay_under_the_limit_exactly_as_the_arithmetic_says(self):
        final, dyn = self.gate(self.CAP, self.DEPS, {'SHARED-BENIGN-MARK': 3})          # 3 of 61 = 4.9%
        self.assertEqual(dyn['benign_hits_by_file'].get('cap.yar'), 3); self.assertIn('cap.yar', [f['path'] for f in final['approved']])
    def test_a_generic_rule_cannot_hide_behind_a_same_named_rule_in_another_file(self):
        files = {'generic.yar': 'rule SAME { strings: $a = "the" condition: $a }', 'quiet.yar': 'rule SAME { strings: $a = "never-in-the-corpus" condition: $a }'}   # same name, listed so that the quiet one is last
        final, dyn = self.gate(files, {}, {})
        self.assertNotIn('generic.yar', [f['path'] for f in final['approved']], 'matches the ten text files of the clean corpus')
        self.assertIn('quiet.yar', [f['path'] for f in final['approved']]); self.assertGreaterEqual(dyn['benign_hits_by_file']['generic.yar'], 10)
        self.assertNotIn('quiet.yar', dyn['benign_hits_by_file'])
if __name__ == '__main__': unittest.main()
