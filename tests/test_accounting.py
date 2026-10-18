import json, pathlib, sys, unittest
from datetime import date
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import accounting, decide, stats, tlog

def f(path, state='VALIDATED', sha=None, source='nextron', reasons=None, deps=None):
    return {'path': path, 'sha256': sha or (path.encode().hex() * 8)[:64].ljust(64, '0'), 'bytes': 5, 'source': source, 'state': state, 'reasons': reasons or [], 'depends_on': deps or []}
def r(code, sev): return {'code': code, 'severity': sev, 'detail': ''}
def acc(run, time, **d): return {'run_id': run, 'time': time, 'event': 'candidate.accepted', 'details': d}

class InvariantTests(unittest.TestCase):
    def test_every_examined_file_ends_in_exactly_one_explicit_state(self):
        files = [f('a'), f('b'), f('q', 'QUARANTINED', reasons=[r('costly-regex', 'review')]), f('x', 'REJECTED', reasons=[r('no-rules', 'reject')]), f('d', 'DEPRECATED')]
        res = decide.decide(files, dynamic_required=False); s = res['public_stats']
        self.assertEqual((s['examined'], s['accepted'], s['quarantined'], s['rejected'], s['deprecated']), (5, 2, 1, 1, 1)); self.assertEqual(accounting.violations(s), [])
        self.assertEqual(len(res['ledger']), 5); self.assertEqual({e['state'] for e in res['ledger']}, {'accepted', 'quarantined', 'rejected', 'deprecated'})
        self.assertTrue(all({'id', 'sha256', 'source', 'path', 'state'} <= set(e) for e in res['ledger'])); self.assertEqual(len({e['id'] for e in res['ledger']}), 5)
    def test_the_six_missing_files_scenario_adds_up_with_quarantine_shown(self):
        files = [f(f'ok{i}') for i in range(1174)] + [f(f'q{i}', 'QUARANTINED', reasons=[r('compile-dependency', 'review')]) for i in range(6)] + [f(f'r{i}', 'REJECTED', reasons=[r('no-rules', 'reject')]) for i in range(4)]
        s = decide.decide(files, dynamic_required=False)['public_stats']
        self.assertEqual((s['examined'], s['accepted'], s['quarantined'], s['rejected']), (1184, 1174, 6, 4)); accounting.require(s)
    def test_a_dependent_of_a_quarantined_file_is_counted_once_as_quarantined(self):
        files = [f('base', 'QUARANTINED', reasons=[r('compile-error', 'corrupt')]), f('use', deps=['base'])]
        s = decide.decide(files, dynamic_required=False)['public_stats']; self.assertEqual((s['examined'], s['accepted'], s['quarantined']), (2, 0, 2)); accounting.require(s)
    def test_duplicated_content_in_different_files_is_counted_per_file(self):
        same = 'a' * 64; files = [f('rules/x/one.yar', sha=same), f('rules/x/two.yar', sha=same), f('rules/y/three.yar', sha=same, source='community')]
        res = decide.decide(files, dynamic_required=False); self.assertEqual(res['public_stats']['examined'], 3); self.assertEqual(len({e['id'] for e in res['ledger']}), 3)
    def test_the_same_file_listed_twice_is_refused(self):
        with self.assertRaises(ValueError): accounting.build_ledger([f('a'), f('a')], [])
    def test_retired_files_are_a_different_unit_and_do_not_enter_the_sum(self):
        prev = {'files': [{'path': 'gone', 'sha256': 'e' * 64}, {'path': 'a', 'sha256': f('a')['sha256']}]}
        s = decide.decide([f('a')], previous=prev, dynamic_required=False)['public_stats']; self.assertEqual((s['examined'], s['accepted'], s['retired']), (1, 1, 1)); accounting.require(s)
    def test_a_violating_record_is_detected_and_blocks_publication(self):
        bad = {'examined': 10, 'accepted': 5, 'quarantined': 2, 'rejected': 2, 'deprecated': 0}
        self.assertIn('examined 10', accounting.violations(bad)[0])
        with self.assertRaises(ValueError): accounting.require(bad)
        self.assertTrue(accounting.violations({'examined': 'x'}))
    def test_logging_refuses_statistics_that_break_the_invariant(self):
        files = [f('a')]; res = decide.decide(files, dynamic_required=False); res['public_stats']['quarantined'] = 3
        with self.assertRaises(ValueError): tlog.events_for_decision({'sources': []}, res, '1', 't')
    def test_the_ledger_root_changes_when_any_state_changes_and_ignores_order(self):
        a = accounting.build_ledger([f('a'), f('b')], [f('q', 'QUARANTINED')]); b = accounting.build_ledger([f('b'), f('a')], [f('q', 'QUARANTINED')]); c = accounting.build_ledger([f('a')], [f('b', 'QUARANTINED'), f('q', 'QUARANTINED')])
        self.assertEqual(accounting.ledger_root(a), accounting.ledger_root(b)); self.assertNotEqual(accounting.ledger_root(a), accounting.ledger_root(c))

class StatsAccountingTests(unittest.TestCase):
    def day(self, log, d='2026-10-18'): return {x['date']: x for x in stats.daily(log, date.fromisoformat(d))}[d]
    def test_one_run_is_never_mixed_with_another_on_the_same_day(self):
        log = [acc('1', '2026-10-18T03:00:00Z', file_count=100, examined=110, quarantined=8, rejected=2, deprecated=0), acc('2', '2026-10-18T15:00:00Z', file_count=120, examined=130, quarantined=6, rejected=4, deprecated=0)]
        d = self.day(log); self.assertEqual((d['examined'], d['accepted'], d['quarantined'], d['rejected']), (130, 120, 6, 4)); self.assertTrue(d['accounting_ok'])
    def test_a_day_without_a_run_has_no_numbers_and_no_invariant(self):
        d = self.day([]); self.assertFalse(d['observed']); self.assertIsNone(d['quarantined']); self.assertIsNone(d['accounting_ok'])
    def test_legacy_runs_without_a_breakdown_are_marked_as_such_not_forced_to_balance(self):
        d = self.day([acc('1', '2026-10-18T03:00:00Z', file_count=50)]); self.assertIsNone(d['quarantined']); self.assertIsNone(d['accounting_ok'])
    def test_publishing_statistics_that_violate_the_invariant_fails_the_build(self):
        import tempfile
        log = [acc('1', '2026-10-18T03:00:00Z', file_count=100, examined=110, quarantined=1, rejected=2, deprecated=0)]
        with tempfile.TemporaryDirectory() as td:
            lf = pathlib.Path(td) / 'log.jsonl'; lf.write_text('\n'.join(json.dumps(e) for e in log) + '\n')
            with self.assertRaises(ValueError): stats.build(lf, pathlib.Path(td) / 'stats.json')
            self.assertFalse((pathlib.Path(td) / 'stats.json').exists())
    def test_a_quarantine_only_run_balances(self):
        d = self.day([acc('1', '2026-10-18T03:00:00Z', file_count=0, examined=5, quarantined=5, rejected=0, deprecated=0)]); self.assertTrue(d['accounting_ok']); self.assertEqual(d['accepted'], 0)
    def test_changes_come_from_releases_not_from_the_analysis_and_are_labelled_by_release(self):
        rel = [{'published_at': '2026-10-17T06:00:00Z', 'added': 1184, 'modified': 0, 'removed': 0, 'tag': 'rules-1'}]
        d = {x['date']: x for x in stats.daily([acc('2', '2026-10-18T03:00:00Z', file_count=1174, examined=1184, quarantined=6, rejected=4, deprecated=0)], date(2026, 10, 18), releases=rel)}
        self.assertIsNone(d['2026-10-18']['new']); self.assertEqual(d['2026-10-17']['new'], 1184)
if __name__ == '__main__': unittest.main()
