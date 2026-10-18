#!/usr/bin/env python3
"""Dynamic validation of a rule set with the real YARA engine: compile cost, load + scan latency, CPU, peak memory,
crashes and timeouts, detection of known-benign canaries, and benign-corpus hit rate.

Everything runs with child processes measured through wait4(2) rusage, so CPU time and peak resident memory are per
process, not guessed. Nothing from the rules is executed except by the YARA engine itself, on safe files only.

Statistics: each condition (baseline = last approved set, candidate) is measured `runs` times interleaved (A B A B ...)
under identical conditions on the same machine; the verdict compares medians against the baseline's own noise (MAD),
never a single sample and never a fixed percentage alone."""
import argparse, json, os, pathlib, random, shutil, signal, statistics, subprocess, sys, tempfile, time

def run_measured(cmd, timeout=60, stdout=None):
    """Run cmd, return dict(status, wall, cpu, rss_mb, timed_out, crashed)."""
    t0 = time.monotonic()
    p = subprocess.Popen(cmd, stdout=stdout or subprocess.DEVNULL, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
    ru, status, timed_out = None, None, False
    while True:
        pid, st, ru_ = os.wait4(p.pid, os.WNOHANG)
        if pid:
            status, ru = st, ru_; break
        if time.monotonic() - t0 > timeout:
            timed_out = True; p.kill(); _, status, ru = os.wait4(p.pid, 0); break
        time.sleep(0.005)
    err = p.stderr.read().decode('utf-8', 'replace') if p.stderr else ''; p.stderr.close()
    wall = time.monotonic() - t0
    code = os.waitstatus_to_exitcode(status); p.returncode = code   # reaped by wait4: tell Popen so it does not warn
    rss = ru.ru_maxrss / (1024 * 1024 if sys.platform == 'darwin' else 1024)   # macOS: bytes, Linux: KiB
    return {'code': code, 'wall': wall, 'cpu': ru.ru_utime + ru.ru_stime, 'rss_mb': rss, 'timed_out': timed_out, 'crashed': code < 0 and not timed_out, 'stderr': err[-300:]}

def percentile(values, q):
    if not values: return None
    v = sorted(values); k = (len(v) - 1) * q / 100; f = int(k); c = min(f + 1, len(v) - 1)
    return v[f] + (v[c] - v[f]) * (k - f)

def closure(path, deps, seen=None, visiting=None):
    """A file and every file it needs, dependencies first (cycles are tolerated)."""
    seen = seen if seen is not None else []; visiting = visiting if visiting is not None else set()
    if path in seen or path in visiting: return seen
    visiting.add(path)
    for d in deps.get(path, []): closure(d, deps, seen, visiting)
    visiting.discard(path); seen.append(path)
    return seen

def compile_set(yarac, root, files, deps, out_path, timeout=300):
    """One YARA namespace per rule file, containing a copy of the files it depends on. Upstream sources define the same rule name
    in several files (hundreds of overlaps between Nextron and Yara-Rules), so loading everything into one namespace cannot work."""
    args = [yarac, '-w', '-d', 'filepath=', '-d', 'filename=', '-d', 'extension=', '-d', 'filetype=', '-d', 'owner=', '-d', 'md5=']
    for i, f in enumerate(files):
        for p in closure(f, deps): args.append(f'ns{i}:{root / p}')
    args.append(str(out_path))
    return run_measured(args, timeout=timeout)

def build_corpus(dest: pathlib.Path, seed=1234, n_random=40, extra_dirs=()):
    """Deterministic safe corpus: random bytes, text, repeated patterns, plus real system binaries; and canary files."""
    dest.mkdir(parents=True, exist_ok=True); rng = random.Random(seed); files = []
    for i in range(n_random):
        p = dest / f'rand{i:03d}.bin'; p.write_bytes(bytes(rng.getrandbits(8) for _ in range(rng.choice([512, 4096, 65536, 262144]))))
        files.append(p)
    for i in range(10):
        p = dest / f'text{i:02d}.txt'; p.write_text(('The quick brown fox jumps over the lazy dog. ' * rng.randint(20, 4000))); files.append(p)
    for cand in ('/bin/ls', '/bin/cat', '/bin/echo', '/usr/bin/env', '/bin/sh', '/usr/bin/awk', '/usr/bin/sort', '/usr/bin/grep'):
        if os.path.isfile(cand): q = dest / ('sys_' + os.path.basename(cand)); shutil.copy(cand, q); files.append(q)
    for d in extra_dirs:
        for p in sorted(pathlib.Path(d).glob('*'))[:20]:
            if p.is_file() and p.stat().st_size < 5_000_000: q = dest / ('x_' + p.name); shutil.copy(p, q); files.append(q)
    canaries = []
    for i in range(5):
        p = dest / f'canary{i}.dat'; p.write_text(f'harmless test file\nMACGUARD-CANARY-{i}-DETECT-ME\n'); canaries.append(p)
    return files, canaries

CANARY_RULES = '\n'.join(f'rule MacGuard_Canary_{i} {{ strings: $a = "MACGUARD-CANARY-{i}-DETECT-ME" condition: $a }}' for i in range(5)) + '\n'

def measure_set(yara, yarac, root, files, deps, corpus, canaries, workdir, timeout_file=10, max_failures=3):
    """One measurement of one rule set."""
    compiled = workdir / 'rules.yarc'
    comp = compile_set(yarac, root, files, deps, compiled)
    res = {'files': len(files), 'compile': {k: comp[k] for k in ('wall', 'cpu', 'rss_mb', 'code', 'timed_out', 'crashed')}, 'compile_error': comp['stderr'] if comp['code'] else ''}
    if comp['code'] != 0: res['scan'] = None; return res
    res['compiled_bytes'] = compiled.stat().st_size
    lat, cpu, rss, errors, timeouts, crashes, hits, aborted = [], [], [], 0, 0, 0, {}, False
    for f in corpus + canaries:
        m = run_measured([yara, '-p', '1', '-C', str(compiled), str(f)], timeout=timeout_file, stdout=subprocess.PIPE)
        lat.append(m['wall']); cpu.append(m['cpu']); rss.append(m['rss_mb'])
        if m['timed_out']: timeouts += 1
        elif m['crashed']: crashes += 1
        elif m['code'] not in (0,): errors += 1
        if timeouts + crashes + errors >= max_failures: aborted = True; break   # the verdict is clear; do not burn minutes on a rule that blocks the engine
    res['scan'] = {'samples': len(lat), 'wall_p50': percentile(lat, 50), 'wall_p95': percentile(lat, 95), 'wall_p99': percentile(lat, 99), 'cpu_total': sum(cpu), 'rss_peak_mb': max(rss) if rss else 0,
                   'errors': errors, 'timeouts': timeouts, 'crashes': crashes, 'aborted_early': aborted}
    return res

def detections(yara, compiled, corpus, canaries):
    """Rule matches on the clean corpus (possible false positives) and on the canaries (must all fire)."""
    def scan(f):
        r = subprocess.run([yara, '-p', '1', '-C', str(compiled), str(f)], capture_output=True, text=True, timeout=30)
        return [l.split()[0].split(':')[-1] for l in r.stdout.splitlines() if l.strip()]
    clean = {}
    for f in corpus:
        for rule in scan(f): clean.setdefault(rule, []).append(f.name)
    fired = sum(1 for f in canaries if any(r.startswith('MacGuard_Canary_') for r in scan(f)))
    return clean, fired

def mad(xs):
    m = statistics.median(xs); return statistics.median([abs(x - m) for x in xs])

def compare(baseline_runs, candidate_runs, thresholds, min_runs=3):
    """baseline_runs / candidate_runs: lists of measure_set() results. Returns {'verdict': 'ok'|'regression'|'inconclusive', 'metrics': {...}}."""
    cfg = thresholds
    out = {'verdict': 'ok', 'metrics': {}, 'reasons': []}
    if min(len(baseline_runs), len(candidate_runs)) < min_runs:
        out['verdict'] = 'inconclusive'; out['reasons'].append(f'fewer than {min_runs} runs per side'); return out
    def series(runs, getter): return [getter(r) for r in runs if r.get('scan')]
    metrics = {'compile_wall_s': (lambda r: r['compile']['wall'], 0.5, None), 'compile_rss_mb': (lambda r: r['compile']['rss_mb'], None, cfg['min_absolute_rss_mb']),
               'scan_p95_s': (lambda r: r['scan']['wall_p95'], 0.05, None), 'scan_cpu_total_s': (lambda r: r['scan']['cpu_total'], None, cfg['min_absolute_cpu_seconds']),
               'scan_rss_peak_mb': (lambda r: r['scan']['rss_peak_mb'], None, cfg['min_absolute_rss_mb'])}
    for name, (getter, abs_wall, abs_floor) in metrics.items():
        b, c = series(baseline_runs, getter), series(candidate_runs, getter)
        if len(b) < min_runs or len(c) < min_runs: out['verdict'] = 'inconclusive'; out['reasons'].append(f'{name}: runs without a result'); continue
        bm, cm = statistics.median(b), statistics.median(c); noise = mad(b)
        floor = max(cfg['metric_noise_multiplier'] * noise, cfg['min_relative_increase'] * bm, abs_floor or 0, abs_wall or 0)
        delta = cm - bm
        out['metrics'][name] = {'baseline': bm, 'candidate': cm, 'delta': delta, 'noise_mad': noise, 'threshold': floor, 'regressed': delta > floor}
        if delta > floor: out['verdict'] = 'regression' if out['verdict'] != 'inconclusive' else out['verdict']; out['reasons'].append(f'{name} rose from {bm:.3f} to {cm:.3f} (allowed +{floor:.3f})')
    for side, runs in (('candidate', candidate_runs), ('baseline', baseline_runs)):
        bad = sum((r.get('scan') or {}).get('crashes', 0) + (r.get('scan') or {}).get('timeouts', 0) + (r.get('scan') or {}).get('errors', 0) for r in runs)
        if side == 'candidate' and bad and not sum((r.get('scan') or {}).get('crashes', 0) + (r.get('scan') or {}).get('timeouts', 0) + (r.get('scan') or {}).get('errors', 0) for r in baseline_runs):
            out['verdict'] = 'regression'; out['reasons'].append(f'{bad} crashes, timeouts or errors that the baseline does not have')
        if side == 'candidate' and any(r.get('compile_error') for r in runs): out['verdict'] = 'regression'; out['reasons'].append('the candidate set does not compile as a whole')
    return out

def ddmin(items, fails, budget=60):
    """Smallest subset of `items` that still makes fails(subset) true (Zeller's delta debugging); budget bounds the test calls."""
    n, calls = 2, 0; items = list(items)
    if not fails(items): return []
    while len(items) >= 2 and calls < budget:
        size = max(1, len(items) // n); chunks = [items[i:i + size] for i in range(0, len(items), size)]; reduced = False
        for ch in chunks:
            calls += 1
            if calls > budget: break
            if fails(ch): items, n, reduced = ch, 2, True; break
        if not reduced:
            for i in range(len(chunks)):
                comp = [x for j, c in enumerate(chunks) if j != i for x in c]
                calls += 1
                if calls > budget: break
                if comp and fails(comp): items, n, reduced = comp, max(n - 1, 2), True; break
        if not reduced:
            if n >= len(items): break
            n = min(len(items), n * 2)
    return items

def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--dist', default='dist'); ap.add_argument('--baseline', help='directory with the last approved rules (same layout as dist, with candidate.json-like files list in baseline.json)')
    ap.add_argument('--approved', default='dist/approved.json'); ap.add_argument('--policy', default='config/policy.json'); ap.add_argument('--out', default='dist/dynamic.json'); ap.add_argument('--runs', type=int)
    ap.add_argument('--yara', default='yara'); ap.add_argument('--yarac', default='yarac')
    a = ap.parse_args(); policy = json.loads(pathlib.Path(a.policy).read_text())['dynamic']; runs = a.runs or policy['runs']
    dist = pathlib.Path(a.dist); approved = json.loads(pathlib.Path(a.approved).read_text())
    yara, yarac = shutil.which(a.yara), shutil.which(a.yarac)
    if not yara or not yarac: sys.exit('yara and yarac are required for the dynamic stage')
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td); corpus, canaries = build_corpus(td / 'corpus')
        canary_dir = td / 'canary'; canary_dir.mkdir(); (canary_dir / 'canary.yar').write_text(CANARY_RULES)
        def prep(files_root, files, tag):
            w = td / tag; w.mkdir(); return w
        cand_files = [f['path'] for f in approved['files']]; deps = {f['path']: f.get('depends_on', []) for f in approved['files']}
        base_files, base_root = [], None
        if a.baseline and (pathlib.Path(a.baseline) / 'baseline.json').exists():
            bj = json.loads((pathlib.Path(a.baseline) / 'baseline.json').read_text()); base_files = [f['path'] for f in bj['files']]; base_root = pathlib.Path(a.baseline)
        cand_runs, base_runs = [], []
        for i in range(runs):
            w = td / f'c{i}'; w.mkdir(); cand_runs.append(measure_set(yara, yarac, dist, cand_files, deps, corpus, canaries, w))
            if base_root:
                w = td / f'b{i}'; w.mkdir(); base_runs.append(measure_set(yara, yarac, base_root, base_files, {}, corpus, canaries, w))
        # detection on the candidate set (+ canary rules compiled alongside)
        w = td / 'det'; w.mkdir(); comp = w / 'rules.yarc'
        compile_set(yarac, dist, cand_files, deps, comp)
        clean, fired = detections(yara, comp, corpus, canaries) if comp.exists() else ({}, 0)
        canary_ok = subprocess.run([yarac, str(canary_dir / 'canary.yar'), str(w / 'canary.yarc')], capture_output=True).returncode == 0
        canary_fired = 0
        if canary_ok:
            for f in canaries:
                r = subprocess.run([yara, '-p', '1', '-C', str(w / 'canary.yarc'), str(f)], capture_output=True, text=True); canary_fired += 1 if 'MacGuard_Canary_' in r.stdout else 0
        verdict = compare(base_runs, cand_runs, json.loads(pathlib.Path(a.policy).read_text())['dynamic']['regression']) if base_runs else {'verdict': 'no-baseline', 'metrics': {}, 'reasons': ['no previous approved set to compare with']}
        doc = {'schema': 1, 'platform': sys.platform, 'engine': subprocess.run([yara, '--version'], capture_output=True, text=True).stdout.strip(), 'runs': runs, 'corpus': {'clean_files': len(corpus), 'canaries': len(canaries)},
               'candidate_runs': cand_runs, 'baseline_runs': base_runs, 'comparison': verdict, 'canaries_detected': canary_fired, 'clean_corpus_hits': {k: v for k, v in clean.items()},
               'percentiles_reported': len(corpus) + len(canaries) >= policy['min_samples_for_percentiles']}
    pathlib.Path(a.out).write_text(json.dumps(doc, indent=1) + '\n'); print(json.dumps({'comparison': verdict['verdict'], 'canaries': canary_fired}), file=sys.stderr)

if __name__ == '__main__': main()
