import pathlib, sys, unittest
from datetime import date
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import stats

def acc(run, time, n): return {'run_id': run, 'time': time, 'event': 'candidate.accepted', 'details': {'file_count': n}}
def rej(run, time, n): return {'run_id': run, 'time': time, 'event': 'candidate.rejected', 'details': {'file_count': n}}
def bad(run, time): return {'run_id': run, 'time': time, 'event': 'rule.rejected'}

class StatsTests(unittest.TestCase):
    def test_window_is_30_days_ending_today_with_zero_fill(self):
        d = stats.daily([], date(2026, 10, 18))
        self.assertEqual(len(d), 30); self.assertEqual(d[-1]['date'], '2026-10-18'); self.assertEqual(d[0]['date'], '2026-09-19')
        self.assertTrue(all(x['downloaded'] == 0 for x in d))
    def test_last_run_of_the_day_wins_and_rejections_are_counted(self):
        log = [acc('1', '2026-10-17T03:00:00Z', 100), bad('2', '2026-10-17T05:00:00Z'), bad('2', '2026-10-17T05:00:01Z'), rej('2', '2026-10-17T05:00:02Z', 120),
               acc('3', '2026-10-18T03:00:00Z', 130)]
        d = {x['date']: x for x in stats.daily(log, date(2026, 10, 18))}
        self.assertEqual(d['2026-10-17'], {'date': '2026-10-17', 'downloaded': 120, 'accepted': 118, 'rejected': 2})
        self.assertEqual(d['2026-10-18'], {'date': '2026-10-18', 'downloaded': 130, 'accepted': 130, 'rejected': 0})
    def test_days_older_than_a_month_drop_out(self):
        d = stats.daily([acc('1', '2026-08-01T00:00:00Z', 50)], date(2026, 10, 18))
        self.assertEqual(sum(x['downloaded'] for x in d), 0)
    def test_events_without_run_or_time_are_ignored(self):
        d = stats.daily([{'event': 'candidate.accepted', 'details': {'file_count': 9}}], date(2026, 10, 18))
        self.assertEqual(sum(x['downloaded'] for x in d), 0)

if __name__ == '__main__': unittest.main()
