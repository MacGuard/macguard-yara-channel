import pathlib, sys, unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import decide

def f(path, state='VALIDATED', sha=None, reasons=None, deps=None, source='nextron'):
    return {'path': path, 'sha256': sha or path.ljust(64, '0')[:64].replace('/', '0'), 'bytes': 10, 'source': source, 'state': state, 'reasons': reasons or [], 'depends_on': deps or []}
def r(code, sev): return {'code': code, 'severity': sev, 'detail': code}
def ok_dyn(files, **kw):
    d = {'verdict': 'ok', 'set_root': decide.set_root(files), 'canaries_detected': 5, 'canaries_expected': 5}; d.update(kw); return d
def approve(sha, by='alice'): return {sha: {'state': 'APPROVED_PENDING_VALIDATION', 'by': by}}

class DecideTests(unittest.TestCase):
    def test_a_valid_rule_is_published_automatically(self):
        files = [f('rules/a.yar')]; res = decide.decide(files, dynamic=ok_dyn(files))
        self.assertTrue(res['publishable']); self.assertEqual([a['path'] for a in res['approved']], ['rules/a.yar'])
    def test_a_corrupt_rule_is_never_published_and_the_rest_still_is(self):
        files = [f('rules/a.yar'), f('rules/bad.yar', 'QUARANTINED', reasons=[r('compile-error', 'corrupt')])]
        res = decide.decide(files, dynamic=ok_dyn([files[0]]))
        self.assertEqual([a['path'] for a in res['approved']], ['rules/a.yar']); self.assertEqual(res['excluded'][0]['path'], 'rules/bad.yar'); self.assertTrue(res['publishable'])
    def test_a_truncated_rule_goes_to_quarantine_submissions(self):
        files = [f('rules/a.yar'), f('rules/t.yar', 'QUARANTINED', reasons=[r('unclosed-rule', 'truncated')])]
        res = decide.decide(files, dynamic=ok_dyn([files[0]]))
        self.assertEqual([s['path'] for s in res['submissions']], ['rules/t.yar']); self.assertIn('unclosed-rule', res['submissions'][0]['reasons'])
    def test_hard_failures_are_rejected_and_remembered_by_hash(self):
        files = [f('rules/e.yar', 'REJECTED', reasons=[r('no-rules', 'reject')])]
        self.assertEqual(decide.decide(files, dynamic=None, dynamic_required=False)['new_rejected_hashes'], [files[0]['sha256']])
    def test_rejected_content_is_not_reincorporated_but_edited_content_is_a_new_candidate(self):
        old = f('rules/r.yar', sha='a' * 64)
        res = decide.decide([old], dynamic_required=False, previously_rejected=['a' * 64])
        self.assertEqual(res['approved'], []); self.assertEqual(res['excluded'][0]['state'], 'REJECTED')
        edited = f('rules/r.yar', sha='b' * 64)
        self.assertEqual([a['path'] for a in decide.decide([edited], dynamic_required=False, previously_rejected=['a' * 64])['approved']], ['rules/r.yar'])
    def test_a_reviewer_rejection_blocks_even_a_validated_file(self):
        files = [f('rules/a.yar', sha='c' * 64)]
        res = decide.decide(files, decisions={'c' * 64: {'state': 'REJECTED', 'reason': 'too noisy'}}, dynamic_required=False)
        self.assertEqual(res['approved'], [])
    def test_approval_waives_a_judgement_finding_but_the_file_still_has_to_pass_the_technical_checks(self):
        q = f('rules/slow.yar', 'QUARANTINED', sha='d' * 64, reasons=[r('costly-regex', 'review')])
        res = decide.decide([q], decisions=approve('d' * 64), dynamic=ok_dyn([{**q, 'state': 'VALIDATED'}]))
        self.assertEqual([a['path'] for a in res['approved']], ['rules/slow.yar']); self.assertTrue(any(x['code'] == 'waived-by-review' for x in res['approved'][0]['reasons']))
    def test_approval_cannot_skip_a_compile_error_truncation_or_corruption(self):
        for code, sev in (('compile-error', 'corrupt'), ('unclosed-rule', 'truncated'), ('corrupt-encoding', 'corrupt')):
            q = f('rules/x.yar', 'QUARANTINED', sha='e' * 64, reasons=[r(code, sev)])
            self.assertEqual(decide.decide([q], decisions=approve('e' * 64), dynamic_required=False)['approved'], [], code)
    def test_approval_cannot_skip_a_dynamic_failure(self):
        q = f('rules/x.yar', sha='f' * 64)
        res = decide.decide([q], decisions=approve('f' * 64), dynamic={'culprits': ['rules/x.yar'], 'verdict': 'ok'}, dynamic_required=False)
        self.assertEqual(res['approved'], []); self.assertTrue(any(r_['code'] == 'dynamic-failure' for r_ in res['excluded'][0]['reasons']))
    def test_approval_cannot_override_a_changed_license(self):
        q = f('rules/x.yar', 'QUARANTINED', sha='1' * 64, reasons=[r('license-changed', 'review')])
        self.assertEqual(decide.decide([q], decisions=approve('1' * 64), dynamic_required=False)['approved'], [])
    def test_approval_for_a_different_hash_does_nothing(self):
        q = f('rules/x.yar', 'QUARANTINED', sha='2' * 64, reasons=[r('costly-regex', 'review')])
        self.assertEqual(decide.decide([q], decisions=approve('3' * 64), dynamic_required=False)['approved'], [])
    def test_batch_approval_affects_only_the_selected_hashes(self):
        qs = [f(f'rules/q{i}.yar', 'QUARANTINED', sha=str(i) * 64, reasons=[r('costly-regex', 'review')]) for i in range(1, 5)]
        res = decide.decide(qs, decisions={**approve('1' * 64), **approve('3' * 64)}, dynamic_required=False)
        self.assertEqual(sorted(a['path'] for a in res['approved']), ['rules/q1.yar', 'rules/q3.yar'])
    def test_without_the_quarantine_store_the_safe_default_applies(self):
        q = f('rules/x.yar', 'QUARANTINED', reasons=[r('costly-regex', 'review')])
        res = decide.decide([f('rules/a.yar'), q], decisions=None, dynamic=ok_dyn([f('rules/a.yar')]))
        self.assertEqual([a['path'] for a in res['approved']], ['rules/a.yar']); self.assertTrue(res['publishable'])
    def test_a_dependent_of_an_excluded_file_is_excluded_too(self):
        base = f('rules/base.yar', 'QUARANTINED', reasons=[r('compile-error', 'corrupt')]); use = f('rules/use.yar', deps=['rules/base.yar'])
        self.assertEqual(decide.decide([base, use], dynamic_required=False)['approved'], [])
    def test_a_previously_published_rule_that_now_fails_is_withheld_and_flagged(self):
        prev = {'files': [{'path': 'rules/old.yar', 'sha256': '9' * 64}]}
        now = f('rules/old.yar', 'QUARANTINED', sha='8' * 64, reasons=[r('compile-error', 'corrupt')])
        res = decide.decide([now, f('rules/new.yar')], previous=prev, dynamic_required=False)
        self.assertEqual([p['path'] for p in res['previously_published_failing']], ['rules/old.yar']); self.assertEqual([a['path'] for a in res['approved']], ['rules/new.yar'])
    def test_rules_gone_upstream_are_retired(self):
        res = decide.decide([f('rules/a.yar')], previous={'files': [{'path': 'rules/gone.yar', 'sha256': '7' * 64}, {'path': 'rules/a.yar', 'sha256': 'a'.ljust(64, '0')}]}, dynamic_required=False)
        self.assertEqual([x['path'] for x in res['retired']], ['rules/gone.yar'])
    def test_no_effective_change_is_not_publishable(self):
        a = f('rules/a.yar'); res = decide.decide([a], previous={'files': [{'path': 'rules/a.yar', 'sha256': a['sha256']}]}, dynamic=ok_dyn([a]))
        self.assertFalse(res['publishable']); self.assertIn('no effective change', res['blockers'][0])
    def test_dynamic_result_for_another_set_blocks_publication(self):
        files = [f('rules/a.yar'), f('rules/b.yar')]
        self.assertFalse(decide.decide(files, dynamic=ok_dyn([files[0]]))['publishable'])
    def test_missing_or_failed_dynamic_validation_blocks_publication(self):
        files = [f('rules/a.yar')]
        self.assertFalse(decide.decide(files, dynamic=None)['publishable'])
        self.assertFalse(decide.decide(files, dynamic=ok_dyn(files, verdict='regression'))['publishable'])
        self.assertFalse(decide.decide(files, dynamic=ok_dyn(files, verdict='inconclusive'))['publishable'])
    def test_detection_must_be_demonstrated_by_canaries(self):
        files = [f('rules/a.yar')]; self.assertFalse(decide.decide(files, dynamic=ok_dyn(files, canaries_detected=2))['publishable'])
    def test_generic_rules_matching_the_clean_corpus_are_quarantined(self):
        files = [f('rules/g.yar'), f('rules/a.yar')]
        res = decide.decide(files, dynamic_required=False, benign_hits={'rules/g.yar': 20}, corpus_size=58)
        self.assertEqual([a['path'] for a in res['approved']], ['rules/a.yar'])
    def test_public_stats_hold_only_counts(self):
        files = [f('rules/a.yar'), f('rules/q.yar', 'QUARANTINED', reasons=[r('costly-regex', 'review')])]
        s = decide.decide(files, dynamic_required=False)['public_stats']
        self.assertEqual({k: v for k, v in s.items() if k != 'ledger_root'}, {'examined': 2, 'accepted': 1, 'quarantined': 1, 'rejected': 0, 'deprecated': 0, 'retired': 0, 'previously_published_failing': 0})
        self.assertRegex(s['ledger_root'], '^[0-9a-f]{64}$')

ANOMALY = {'max_removed_fraction': 0.15, 'max_changed_fraction': 0.40}
class AnomalyTests(unittest.TestCase):
    def prev(self, n): return {'files': [{'path': f'rules/p{i}.yar', 'sha256': str(i % 10) * 64} for i in range(n)]}
    def test_a_mass_removal_is_not_published_automatically(self):
        kept = [f(f'rules/p{i}.yar', sha=str(i % 10) * 64) for i in range(50)]          # 50 of 100 survive: an upstream wipe
        res = decide.decide(kept, previous=self.prev(100), dynamic=ok_dyn(kept), anomaly=ANOMALY)
        self.assertFalse(res['publishable']); self.assertIn('unusually large change', res['blockers'][0]); self.assertEqual(res['change_fractions']['removed'], 0.5)
    def test_a_person_can_allow_it_after_looking(self):
        kept = [f(f'rules/p{i}.yar', sha=str(i % 10) * 64) for i in range(50)]
        self.assertTrue(decide.decide(kept, previous=self.prev(100), dynamic=ok_dyn(kept), anomaly=ANOMALY, allow_large_change=True)['publishable'])
    def test_an_ordinary_daily_change_goes_through(self):
        kept = [f(f'rules/p{i}.yar', sha=str(i % 10) * 64) for i in range(98)] + [f('rules/new.yar')]
        self.assertTrue(decide.decide(kept, previous=self.prev(100), dynamic=ok_dyn(kept), anomaly=ANOMALY)['publishable'])
    def test_rewriting_most_files_counts_as_a_large_change_too(self):
        edited = [f(f'rules/p{i}.yar', sha='f' * 64) for i in range(100)]
        self.assertFalse(decide.decide(edited, previous=self.prev(100), dynamic=ok_dyn(edited), anomaly=ANOMALY)['publishable'])
if __name__ == '__main__': unittest.main()
