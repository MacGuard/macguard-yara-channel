import json, pathlib, shutil, sys, tempfile, unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import bench

THR = json.loads((pathlib.Path(__file__).resolve().parents[1] / 'config/policy.json').read_text())['dynamic']['regression']
YARA, YARAC = shutil.which('yara'), shutil.which('yarac')

def run(compile_wall=0.8, compile_rss=9.0, p95=0.026, cpu=0.6, rss=1.0, bad=0, err=''):
    return {'files': 1, 'compile': {'wall': compile_wall, 'cpu': 0.02, 'rss_mb': compile_rss, 'code': 0}, 'compile_error': err,
            'scan': {'samples': 63, 'wall_p50': 0.02, 'wall_p95': p95, 'wall_p99': 0.03, 'cpu_total': cpu, 'rss_peak_mb': rss, 'errors': 0, 'timeouts': bad, 'crashes': 0}}

class StatsTests(unittest.TestCase):
    def test_percentiles(self):
        v = list(range(1, 101)); self.assertAlmostEqual(bench.percentile(v, 50), 50.5); self.assertAlmostEqual(bench.percentile(v, 99), 99.01)
        self.assertIsNone(bench.percentile([], 50))
    def test_groups_join_dependent_files(self):
        g = bench.groups(['a', 'b', 'c', 'd'], {'b': ['a'], 'c': ['b']}); self.assertIn(['a', 'b', 'c'], [sorted(x) for x in g]); self.assertIn(['d'], g)

class CompareTests(unittest.TestCase):
    def runs(self, n, **kw): return [run(**{k: v * (1 + 0.01 * i) if isinstance(v, float) else v for k, v in kw.items()}) for i in range(n)]
    def test_identical_sets_with_ordinary_noise_pass(self):
        self.assertEqual(bench.compare(self.runs(5), self.runs(5, p95=0.027), THR)['verdict'], 'ok')
    def test_large_memory_regression_is_detected(self):
        r = bench.compare(self.runs(5), self.runs(5, compile_rss=300.0, rss=250.0), THR)
        self.assertEqual(r['verdict'], 'regression'); self.assertTrue(r['metrics']['compile_rss_mb']['regressed'])
    def test_large_cpu_regression_is_detected(self):
        r = bench.compare(self.runs(5), self.runs(5, cpu=40.0, p95=2.0), THR)
        self.assertEqual(r['verdict'], 'regression'); self.assertTrue(r['metrics']['scan_cpu_total_s']['regressed'])
    def test_a_small_rise_inside_the_noise_floor_is_not_flagged(self):
        self.assertEqual(bench.compare(self.runs(5), self.runs(5, rss=1.5, cpu=0.7), THR)['verdict'], 'ok')
    def test_too_few_runs_is_inconclusive_not_ok(self):
        self.assertEqual(bench.compare(self.runs(2), self.runs(2), THR)['verdict'], 'inconclusive')
    def test_new_timeouts_are_a_regression_even_if_times_look_fine(self):
        self.assertEqual(bench.compare(self.runs(4), self.runs(4, bad=5), THR)['verdict'], 'regression')
    def test_a_set_that_does_not_compile_as_a_whole_is_a_regression(self):
        c = self.runs(4); c[0]['compile_error'] = 'duplicated identifier'
        self.assertEqual(bench.compare(self.runs(4), c, THR)['verdict'], 'regression')
    def test_one_noisy_baseline_sample_does_not_hide_a_real_regression(self):
        b = self.runs(5, cpu=0.6); b[2] = run(cpu=3.0)          # one outlier: MAD ignores it
        self.assertEqual(bench.compare(b, self.runs(5, cpu=40.0), THR)['verdict'], 'regression')

class IsolationTests(unittest.TestCase):
    def test_ddmin_finds_the_single_culprit(self):
        items = list(range(40)); self.assertEqual(bench.ddmin(items, lambda s: 17 in s), [17])
    def test_ddmin_finds_an_interacting_pair(self):
        self.assertEqual(sorted(bench.ddmin(list(range(30)), lambda s: 3 in s and 21 in s)), [3, 21])
    def test_ddmin_with_nothing_failing_returns_empty(self):
        self.assertEqual(bench.ddmin([1, 2, 3], lambda s: False), [])
    def test_ddmin_respects_its_budget(self):
        calls = []
        bench.ddmin(list(range(200)), lambda s: calls.append(1) or (5 in s), budget=15); self.assertLessEqual(len(calls), 18)

@unittest.skipUnless(YARA and YARAC, 'yara is not installed; engine tests cannot run (a skipped test is not a pass)')
class EngineTests(unittest.TestCase):
    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp()); self.corpus, self.canaries = bench.build_corpus(self.d / 'corpus')
    def tearDown(self): shutil.rmtree(self.d, ignore_errors=True)
    def measure(self, name, text, timeout_file=1):
        (self.d / f'{name}.yar').write_text(text); w = self.d / f'w_{name}'; shutil.rmtree(w, ignore_errors=True); w.mkdir()
        return bench.measure_set(YARA, YARAC, self.d, [f'{name}.yar'], {}, self.corpus[:12] if timeout_file < 5 else self.corpus, self.canaries, w, timeout_file=timeout_file)
    def test_a_valid_rule_measures_cleanly(self):
        r = self.measure('good', 'rule G { strings: $a = "needle" condition: $a }', timeout_file=10)
        self.assertEqual((r['scan']['errors'], r['scan']['timeouts'], r['scan']['crashes']), (0, 0, 0)); self.assertGreaterEqual(r['scan']['samples'], 12)
        self.assertGreater(r['scan']['rss_peak_mb'], 0); self.assertGreater(r['compiled_bytes'], 0)
    def test_a_rule_that_blocks_the_engine_is_seen_as_timeouts(self):
        r = self.measure('slow', 'rule S { condition: for any i in (0..filesize-1) : ( for any j in (0..filesize-1) : ( i != j and uint8(i) == 1 and uint8(j) == 2 and false ) ) }')
        self.assertGreaterEqual(r['scan']['timeouts'], 3); self.assertTrue(r['scan']['aborted_early'])
    def test_a_blocking_rule_makes_the_candidate_a_regression_against_a_good_baseline(self):
        base = [self.measure('good', 'rule G { strings: $a = "needle" condition: $a }') for _ in range(3)]
        cand = [self.measure('slow', 'rule S { condition: for any i in (0..filesize-1) : ( for any j in (0..filesize-1) : ( i != j and uint8(i) == 1 and uint8(j) == 2 and false ) ) }', timeout_file=1) for _ in range(3)]
        self.assertEqual(bench.compare(base, cand, THR)['verdict'], 'regression')
    def test_culprit_isolation_with_the_real_engine(self):
        slow = 'rule S%d { condition: for any i in (0..filesize-1) : ( for any j in (0..filesize-1) : ( i != j and uint8(i) == 1 and uint8(j) == 2 and false ) ) }'
        files = {f'ok{i}.yar': f'rule OK{i} {{ strings: $a = "n{i}" condition: $a }}' for i in range(7)}; files['bad.yar'] = slow % 1
        for n, t in files.items(): (self.d / n).write_text(t)
        def fails(names):
            w = self.d / 'iso'; shutil.rmtree(w, ignore_errors=True); w.mkdir()
            r = bench.measure_set(YARA, YARAC, self.d, list(names), {}, self.corpus[:4], self.canaries[:1], w, timeout_file=1)
            return bool(r['scan'] and r['scan']['timeouts'])
        self.assertEqual(bench.ddmin(sorted(files), fails, budget=20), ['bad.yar'])
    def test_canaries_prove_detection_works(self):
        (self.d / 'c.yar').write_text(bench.CANARY_RULES)
        comp = self.d / 'c.yarc'; self.assertEqual(__import__('subprocess').run([YARAC, str(self.d / 'c.yar'), str(comp)]).returncode, 0)
        clean, fired = bench.detections(YARA, comp, self.corpus, self.canaries)
        self.assertEqual(fired, 5); self.assertEqual(clean, {})
if __name__ == '__main__': unittest.main()
