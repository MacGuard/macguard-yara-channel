import pathlib, sys, unittest
from datetime import date
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import stats

def acc(run, time, n): return {'run_id': run, 'time': time, 'event': 'candidate.accepted', 'details': {'file_count': n}}
def rej(run, time, n): return {'run_id': run, 'time': time, 'event': 'candidate.rejected', 'details': {'file_count': n}}
def bad(run, time): return {'run_id': run, 'time': time, 'event': 'rule.rejected'}

class StatsTests(unittest.TestCase):
    def test_window_is_30_days_ending_today_and_unobserved_days_are_not_zero(self):
        d = stats.daily([], date(2026, 10, 18))
        self.assertEqual(len(d), 30); self.assertEqual(d[-1]['date'], '2026-10-18'); self.assertEqual(d[0]['date'], '2026-09-19')
        self.assertTrue(all(x['observed'] is False and x['examined'] is None for x in d))
    def test_last_run_of_the_day_wins_and_rejections_are_counted(self):
        log = [acc('1', '2026-10-17T03:00:00Z', 100), bad('2', '2026-10-17T05:00:00Z'), bad('2', '2026-10-17T05:00:01Z'), rej('2', '2026-10-17T05:00:02Z', 120),
               acc('3', '2026-10-18T03:00:00Z', 130)]
        d = {x['date']: x for x in stats.daily(log, date(2026, 10, 18))}
        self.assertEqual(d['2026-10-17'], {'date': '2026-10-17', 'observed': True, 'examined': 120, 'accepted': 118, 'rejected': 2, 'new': None, 'modified': None, 'removed': None})
        self.assertEqual(d['2026-10-18'], {'date': '2026-10-18', 'observed': True, 'examined': 130, 'accepted': 130, 'rejected': 0, 'new': None, 'modified': None, 'removed': None})
    def test_days_older_than_a_month_drop_out(self):
        d = stats.daily([acc('1', '2026-08-01T00:00:00Z', 50)], date(2026, 10, 18))
        self.assertEqual(sum(x['examined'] or 0 for x in d), 0)
    def test_events_without_run_or_time_are_ignored(self):
        d = stats.daily([{'event': 'candidate.accepted', 'details': {'file_count': 9}}], date(2026, 10, 18))
        self.assertEqual(sum(x['examined'] or 0 for x in d), 0)
    def test_release_changes_land_on_their_day_and_do_not_fake_observation(self):
        rel = [{'published_at': '2026-10-17T06:00:00Z', 'added': 5, 'modified': 2, 'removed': 1}]
        d = {x['date']: x for x in stats.daily([], date(2026, 10, 18), releases=rel)}
        self.assertEqual((d['2026-10-17']['new'], d['2026-10-17']['modified'], d['2026-10-17']['removed']), (5, 2, 1))
        self.assertFalse(d['2026-10-17']['observed']); self.assertIsNone(d['2026-10-16']['new'])
    def test_a_run_that_found_zero_rules_is_observed_not_missing(self):
        d = {x['date']: x for x in stats.daily([acc('1', '2026-10-18T03:00:00Z', 0)], date(2026, 10, 18))}
        self.assertTrue(d['2026-10-18']['observed']); self.assertEqual(d['2026-10-18']['examined'], 0)

if __name__ == '__main__': unittest.main()

class AutonomousFlowStats(unittest.TestCase):
    def test_counts_come_from_the_classification_event_not_from_per_rule_events(self):
        e = {'run_id': '1', 'time': '2026-10-18T03:00:00Z', 'event': 'candidate.accepted', 'details': {'file_count': 1150, 'examined': 1184, 'quarantined': 30, 'rejected': 4}}
        d = {x['date']: x for x in stats.daily([e], date(2026, 10, 18))}['2026-10-18']
        self.assertEqual((d['examined'], d['accepted'], d['rejected']), (1184, 1150, 34))
