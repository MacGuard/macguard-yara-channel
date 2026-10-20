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
    def test_closure_lists_dependencies_first_and_survives_cycles(self):
        self.assertEqual(bench.closure('c', {'c': ['b'], 'b': ['a']}), ['a', 'b', 'c']); self.assertEqual(bench.closure('d', {}), ['d'])
        self.assertEqual(sorted(bench.closure('a', {'a': ['b'], 'b': ['a']})), ['a', 'b'])

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
    def test_the_same_rule_name_in_two_files_is_loadable_in_one_set(self):
        d = pathlib.Path(tempfile.mkdtemp()); (d / 'a.yar').write_text('rule SAME { strings: $a = "x" condition: $a }'); (d / 'b.yar').write_text('rule SAME { strings: $a = "y" condition: $a }')
        out = d / 'o.yarc'; r = bench.compile_set(YARAC, d, ['a.yar', 'b.yar'], {}, out); self.assertEqual(r['code'], 0, r['stderr'])
    def test_a_dependency_is_copied_into_the_namespace_of_each_dependent(self):
        d = pathlib.Path(tempfile.mkdtemp()); (d / 'base.yar').write_text('private rule Base { condition: true }'); (d / 'u1.yar').write_text('rule U { condition: Base }'); (d / 'u2.yar').write_text('rule U { condition: Base }')
        out = d / 'o.yarc'; r = bench.compile_set(YARAC, d, ['u1.yar', 'u2.yar'], {'u1.yar': ['base.yar'], 'u2.yar': ['base.yar']}, out); self.assertEqual(r['code'], 0, r['stderr'])
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

class HitCountingUnitTests(unittest.TestCase):
    def test_match_lines_keep_namespace_and_rule(self):
        out = 'ns3:ldpreload /tmp/c/sys_awk\ndefault:plain_rule /tmp/c/x\nbare_rule /tmp/c/z\n\nns12:Same_Name /tmp/c/y\n'
        self.assertEqual(bench.parse_matches(out), [('ns3', 'ldpreload'), (None, 'plain_rule'), (None, 'bare_rule'), ('ns12', 'Same_Name')])
    def test_owners_place_each_rule_in_every_namespace_that_holds_a_copy_of_its_file(self):
        o = bench.rule_owners(['cap.yar', 'd1.yar', 'x.yar'], {'d1.yar': ['cap.yar']}, {'cap.yar': ['cap'], 'd1.yar': ['dep'], 'x.yar': ['cap']})
        self.assertEqual(o, {'ns0': {'cap': 'cap.yar'}, 'ns1': {'cap': 'cap.yar', 'dep': 'd1.yar'}, 'ns2': {'cap': 'x.yar'}})   # same name, different files: kept apart per namespace
    def test_hits_per_file_are_the_most_distinct_corpus_files_any_one_rule_matched(self):
        clean = {'a.yar::r1': ['f1', 'f2'], 'a.yar::r2': ['f3'], 'b.yar::r1': ['f1']}
        self.assertEqual(bench.benign_hits_by_file(clean, {}), {'a.yar': 2, 'b.yar': 1})
    def test_a_match_that_owners_cannot_place_credits_every_file_defining_that_rule_name(self):
        clean = {'?::dup': ['f1', 'f2', 'f3']}
        self.assertEqual(bench.benign_hits_by_file(clean, {'a.yar': ['dup'], 'b.yar': ['dup', 'z'], 'c.yar': ['other']}), {'a.yar': 3, 'b.yar': 3})

@unittest.skipUnless(YARA and YARAC, 'yara is not installed; counting matches needs the real engine (a skipped test is not a pass)')
class HitCountingEngineTests(unittest.TestCase):
    """The reproduced defect: a rule file that other files depend on is compiled once per namespace, and one benign file used to be counted once per copy."""
    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp()); self.corpus = []
        for i in range(8):
            q = self.d / f'clean{i}.txt'; q.write_text(f'nothing to see {i}'); self.corpus.append(q)
    def tearDown(self): shutil.rmtree(self.d, ignore_errors=True)
    def build(self, files, deps, marked=()):
        for name, text in files.items(): (self.d / name).write_text(text)
        for i in marked: self.corpus[i].write_text('LD_PRELOAD-style benign text')
        comp = self.d / 'all.yarc'; names = sorted(files)
        self.assertEqual(bench.compile_set(YARAC, self.d, names, deps, comp)['code'], 0)
        rules = {n: __import__('re').findall(r'rule\s+(\w+)', t) for n, t in files.items()}
        return comp, names, bench.rule_owners(names, deps, rules), rules
    CAP = 'rule ldpreload { strings: $a = "LD_PRELOAD" condition: $a }'
    DEPS = {'d1.yar': ['cap.yar'], 'd2.yar': ['cap.yar'], 'd3.yar': ['cap.yar']}
    def files(self): return {'cap.yar': self.CAP, **{f'd{i}.yar': f'rule dep{i} {{ strings: $a = "dep-only-{i}" condition: $a }}' for i in (1, 2, 3)}}
    def raw_lines(self, comp, f): return len(bench.parse_matches(__import__('subprocess').run([YARA, '-p', '1', '-e', '-C', str(comp), str(f)], capture_output=True, text=True).stdout))

    def test_four_output_lines_for_one_benign_file_are_one_match(self):
        comp, names, owners, rules = self.build(self.files(), self.DEPS, marked=[0])
        self.assertEqual(self.raw_lines(comp, self.corpus[0]), 4, 'the engine really prints one line per namespace copy: this is the reproduction')
        clean, _ = bench.detections(YARA, comp, self.corpus, [], owners)
        self.assertEqual(clean, {'cap.yar::ldpreload': ['clean0.txt']})
        self.assertEqual(bench.benign_hits_by_file(clean, rules), {'cap.yar': 1})
        self.assertEqual(bench.detections(YARA, comp, self.corpus, [])[0], {'ldpreload': ['clean0.txt']}, 'even without owners the same file is not repeated')
    def test_distinct_files_are_still_counted_one_each_across_every_namespace(self):
        comp, names, owners, rules = self.build(self.files(), self.DEPS, marked=[0, 1, 2])
        clean, _ = bench.detections(YARA, comp, self.corpus, [], owners)
        self.assertEqual(clean, {'cap.yar::ldpreload': ['clean0.txt', 'clean1.txt', 'clean2.txt']})   # three files, not twelve and not one
        self.assertEqual(bench.benign_hits_by_file(clean, rules), {'cap.yar': 3})
    def test_the_same_rule_name_in_different_files_is_not_merged(self):
        files = {'x.yar': 'rule Same { strings: $a = "AAA" condition: $a }', 'y.yar': 'rule Same { strings: $a = "BBB" condition: $a }'}
        comp, names, owners, rules = self.build(files, {})
        self.corpus[0].write_text('AAA'); self.corpus[1].write_text('BBB'); self.corpus[2].write_text('AAA and BBB')
        clean, _ = bench.detections(YARA, comp, self.corpus, [], owners)
        self.assertEqual(clean, {'x.yar::Same': ['clean0.txt', 'clean2.txt'], 'y.yar::Same': ['clean1.txt', 'clean2.txt']})
        self.assertEqual(bench.benign_hits_by_file(clean, rules), {'x.yar': 2, 'y.yar': 2})
        self.assertEqual(bench.detections(YARA, comp, self.corpus, [])[0], {'Same': ['clean0.txt', 'clean1.txt', 'clean2.txt']}, 'what the old keys did: two different rules became one')
    def test_canaries_are_still_found_through_the_parsed_output(self):
        (self.d / 'c.yar').write_text(bench.CANARY_RULES); comp = self.d / 'c.yarc'; self.assertEqual(__import__('subprocess').run([YARAC, str(self.d / 'c.yar'), str(comp)]).returncode, 0)
        canaries = []
        for i in range(5): q = self.d / f'can{i}'; q.write_text(f'MACGUARD-CANARY-{i}-DETECT-ME'); canaries.append(q)
        self.assertEqual(bench.detections(YARA, comp, self.corpus, canaries)[1], 5)

if __name__ == '__main__': unittest.main()
