import json, pathlib, sys, tempfile, unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import decide, make_public_candidate as mpc, tlog

class PublicCandidateTests(unittest.TestCase):
    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp()); (self.d / 'rules/c').mkdir(parents=True)
        self.files = []
        for name in ('good', 'secretly_quarantined_name'):
            (self.d / f'rules/c/{name}.yar').write_text(f'rule {name} {{ condition: true }}'); self.files.append({'path': f'rules/c/{name}.yar', 'sha256': (name[0] * 64), 'bytes': 30, 'source': 'community', 'state': 'VALIDATED', 'reasons': [], 'depends_on': [], 'rules': [name]})
        self.files[1]['state'] = 'QUARANTINED'; self.files[1]['reasons'] = [{'code': 'costly-regex', 'severity': 'review', 'detail': 'compiler output about secretly_quarantined_name'}]
        self.dec = decide.decide(self.files, dynamic={'verdict': 'ok', 'set_root': decide.set_root(self.files[:1]), 'canaries_detected': 5, 'canaries_expected': 5})
        (self.d / 'decision.json').write_text(json.dumps(self.dec))
        (self.d / 'candidate.json').write_text(json.dumps({'sources': [{'id': 'community', 'repository': 'r/r', 'commit': 'c' * 40, 'kind': 'rules'}], 'files': self.files, 'rejected': [{'path': 'rules/c/secretly_quarantined_name.yar'}]}))
        (self.d / 'dynamic.json').write_text(json.dumps({'verdict': 'ok', 'set_root': self.dec['rules_root'], 'culprits': ['rules/c/secretly_quarantined_name.yar'], 'benign_hits_by_file': {'rules/c/secretly_quarantined_name.yar': 9},
                                                         'iterations': [{'culprits': ['secretly_quarantined_name']}], 'metrics': {'scan_p95_s': {'baseline': 0.02, 'candidate': 0.02, 'regressed': False, 'noise_mad': 0.0}}, 'canaries_detected': 5, 'canaries_expected': 5}))
        self.out = self.d / 'pub'; self.pub = mpc.build(self.d, self.out)
    def test_only_approved_files_and_nothing_about_the_others_leaves_the_job(self):
        blob = ''.join(p.read_text() for p in self.out.rglob('*') if p.is_file())
        self.assertNotIn('secretly_quarantined_name', blob); self.assertTrue((self.out / 'rules/c/good.yar').exists()); self.assertFalse((self.out / 'rules/c/secretly_quarantined_name.yar').exists())
        d = json.loads((self.out / 'dynamic.json').read_text()); self.assertNotIn('culprits', d); self.assertNotIn('benign_hits_by_file', d); self.assertNotIn('iterations', d)
    def test_public_stats_are_counts(self):
        self.assertEqual(json.loads((self.out / 'public_stats.json').read_text())['quarantined'], 1)
    def test_the_set_root_of_the_artifact_matches_the_dynamic_result(self):
        pub = json.loads((self.out / 'candidate.json').read_text()); self.assertEqual(tlog.rules_root(pub['files']), json.loads((self.out / 'dynamic.json').read_text())['set_root'])
    def test_log_events_hold_counts_only(self):
        evs = tlog.events_for_decision(json.loads((self.d / 'candidate.json').read_text()), self.dec, '1', '2026-10-18T00:00:00Z')
        self.assertNotIn('secretly_quarantined_name', json.dumps(evs)); self.assertIn('candidate.classified', [e['event'] for e in evs]); acc = [e for e in evs if e['event'] == 'candidate.accepted'][0]
        self.assertEqual((acc['details']['file_count'], acc['details']['quarantined']), (1, 1))
    def test_a_non_publishable_run_is_logged_with_its_blockers(self):
        dec = decide.decide(self.files, dynamic=None)
        evs = tlog.events_for_decision(json.loads((self.d / 'candidate.json').read_text()), dec, '1', 't'); self.assertEqual(evs[-1]['event'], 'candidate.not_publishable')
if __name__ == '__main__': unittest.main()
