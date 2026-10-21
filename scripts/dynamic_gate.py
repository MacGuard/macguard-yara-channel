#!/usr/bin/env python3
"""Dynamic gate: measure the approved candidate set against the last approved one under identical conditions, isolate the
rules responsible for a failure, quarantine only those, rebuild the set, and measure again until the final set passes.

A set is never published unless the measurement that passed was taken on exactly that set (decide.py checks set_root)."""
import argparse, json, pathlib, shutil, subprocess, sys, tempfile
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import admission, bench, decide, rulecheck

def absolute_ok(run, cfg):
    s, c = run.get('scan'), run['compile']
    if run.get('compile_error') or not s: return ['the set does not compile as a whole']
    why = []
    if s['crashes'] or s['timeouts'] or s['errors']: why.append(f"{s['crashes']} crashes, {s['timeouts']} timeouts, {s['errors']} errors while scanning")
    if s['wall_p95'] > cfg['max_scan_p95_s']: why.append(f"scan p95 {s['wall_p95']:.2f}s exceeds {cfg['max_scan_p95_s']}s")
    if s['rss_peak_mb'] > cfg['max_scan_rss_mb']: why.append(f"scan RSS {s['rss_peak_mb']:.0f} MB exceeds {cfg['max_scan_rss_mb']} MB")
    if c['rss_mb'] > cfg['max_compile_rss_mb'] or c['wall'] > cfg['max_compile_wall_s']: why.append('compile cost exceeds the sanity limits')
    return why

class Gate:
    def __init__(self, yara, yarac, policy, workdir, corpus, canaries, timeout_file=10):
        self.yara, self.yarac, self.cfg, self.work, self.corpus, self.canaries, self.timeout_file = yara, yarac, policy['dynamic'], workdir, corpus, canaries, timeout_file
        self.n = 0
    def measure(self, root, files, deps, runs=1):
        out = []
        for _ in range(runs):
            self.n += 1; w = self.work / f'm{self.n}'; w.mkdir()
            out.append(bench.measure_set(self.yara, self.yarac, root, files, deps, self.corpus, self.canaries, w, self.timeout_file))
        return out
    def verdict(self, base, cand):
        """base: (root, files) or None."""
        runs = self.cfg['runs']
        c = self.measure(cand['root'], cand['files'], cand['deps'], runs)
        if base:
            b = self.measure(base['root'], base['files'], base.get('deps', {}), runs)
            if any(r.get('scan') for r in b):
                return bench.compare(b, c, self.cfg['regression']), b, c
            # the previous set no longer loads on this engine: a comparison is impossible, fall back to the absolute limits and say so
            note = 'the previous release does not compile as a whole on this engine; absolute limits applied'
            bad = [w for r in c for w in absolute_ok(r, self.cfg['absolute'])]
            return {'verdict': 'no-baseline' if not bad else 'regression', 'metrics': {}, 'reasons': [note] + bad}, b, c
        bad = [w for r in c for w in absolute_ok(r, self.cfg['absolute'])]
        return {'verdict': 'no-baseline' if not bad else 'regression', 'metrics': {}, 'reasons': bad or ['no previous approved set to compare with; sanity limits held']}, [], c

    def culprits(self, base, cand, budget=40):
        """Smallest set of NEW or CHANGED files that reproduces the failure on top of the baseline (or alone, without baseline)."""
        suspects = [f for f in cand['files'] if f in cand.get('new_or_changed', cand['files'])]
        def fails(subset):
            files = list(subset) + (base['files'] if base else [])
            roots_ok = True
            if base:   # baseline files live under base root, candidate under cand root: measure them in two roots by copying into a scratch root
                scratch = self.work / f'iso{self.n + 1}'; scratch.mkdir()
                for f in base['files']:
                    t = scratch / f; t.parent.mkdir(parents=True, exist_ok=True); shutil.copy(base['root'] / f, t)
                for f in subset:
                    t = scratch / f; t.parent.mkdir(parents=True, exist_ok=True); shutil.copy(cand['root'] / f, t)
                root = scratch
            else: root = cand['root']
            runs = 3 if base else 1
            c = self.measure(root, files, {**(base.get('deps', {}) if base else {}), **cand['deps']}, runs)
            if base:
                b = self.measure(base['root'], base['files'], {}, runs)
                return bench.compare(b, c, self.cfg['regression'])['verdict'] == 'regression'
            return bool(absolute_ok(c[0], self.cfg['absolute']))
        return bench.ddmin(suspects, fails, budget=budget)

def run(dist, classification, previous_dir, policy, decisions, yara, yarac, max_iter=3, previously_rejected=None, timeout_file=10, allow_large_change=False, sources=None):
    dist = pathlib.Path(dist); prev_manifest = None; base = None
    if previous_dir and (pathlib.Path(previous_dir) / 'manifest.json').exists():
        prev_manifest = json.loads((pathlib.Path(previous_dir) / 'manifest.json').read_text())
        base = {'root': pathlib.Path(previous_dir), 'files': [f['path'] for f in prev_manifest['files']]}
        base['deps'] = rulecheck.infer_deps(base['root'], base['files'], policy)
    log, culprits, hits_known = [], set(), {}
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td); corpus, canaries = bench.build_corpus(td / 'corpus'); work = td / 'work'; work.mkdir()
        gate = Gate(yara, yarac, policy, work, corpus, canaries, timeout_file)
        def decide_now(dyn=None, required=False):
            return decide.decide(classification, prev_manifest, decisions, dyn if dyn is not None else {'culprits': sorted(culprits)}, hits_known, required, corpus_size=len(corpus), previously_rejected=previously_rejected, anomaly=policy.get('anomaly'), allow_large_change=allow_large_change, sources=sources)
        for it in range(1, max_iter + 1):
            dec = decide_now(); approved = dec['approved']
            cand = {'root': dist, 'files': [f['path'] for f in approved], 'deps': {f['path']: f.get('depends_on', []) for f in approved}}
            prev_hashes = {f['path']: f['sha256'] for f in (prev_manifest or {}).get('files', [])}
            cand['new_or_changed'] = [f['path'] for f in approved if prev_hashes.get(f['path']) != f['sha256']]
            if not approved: log.append({'iteration': it, 'result': 'empty set'}); break
            cmp_, b, c = gate.verdict(base, cand)
            entry = {'iteration': it, 'files': len(approved), 'verdict': cmp_['verdict'], 'reasons': cmp_['reasons']}; log.append(entry)
            if cmp_['verdict'] in ('ok', 'no-baseline'):
                # detection and benign-corpus hit rate, measured on exactly this set
                w = work / f'final{it}'; w.mkdir(); comp = w / 'rules.yarc'; bench.compile_set(yarac, dist, cand['files'], cand['deps'], comp)
                rules_by_file = {f['path']: f.get('rules', []) for f in approved}
                clean, _ = bench.detections(yara, comp, corpus, canaries, bench.rule_owners(cand['files'], cand['deps'], rules_by_file)) if comp.exists() else ({}, 0)
                (w / 'c.yar').write_text(bench.CANARY_RULES); subprocess.run([yarac, str(w / 'c.yar'), str(w / 'c.yarc')], capture_output=True)
                fired = sum(1 for f in canaries if 'MacGuard_Canary_' in subprocess.run([yara, '-p', '1', '-C', str(w / 'c.yarc'), str(f)], capture_output=True, text=True).stdout) if (w / 'c.yarc').exists() else 0
                for p, n in bench.benign_hits_by_file(clean, rules_by_file).items(): hits_known[p] = max(hits_known.get(p, 0), n)
                dyn = {'schema': 1, 'platform': sys.platform, 'engine': subprocess.run([yara, '--version'], capture_output=True, text=True).stdout.strip(), 'verdict': cmp_['verdict'], 'reasons': cmp_['reasons'], 'metrics': cmp_['metrics'],
                       'set_root': decide.set_root(approved), 'canaries_detected': fired, 'canaries_expected': len(canaries), 'culprits': sorted(culprits), 'corpus': {'clean_files': len(corpus), 'canaries': len(canaries)},
                       'benign_hits_by_file': hits_known, 'runs': policy['dynamic']['runs'], 'iterations': log, 'baseline': bool(base), 'candidate_runs': c, 'baseline_runs': b,
                       'not_run': ['independent-macos-vm'], 'percentiles_reported': len(corpus) + len(canaries) >= policy['dynamic']['min_samples_for_percentiles']}
                final = decide_now(dyn, True)
                if {f['path'] for f in final['approved']} != set(cand['files']):
                    entry['rebuilt_without'] = sorted(set(cand['files']) - {f['path'] for f in final['approved']}); continue   # too-generic files left the set: measure the new set
                return final, dyn
            bad = gate.culprits(base, cand); entry['culprits'] = bad
            if not bad: entry['isolation'] = 'could not isolate a single cause'; break
            culprits |= set(bad)
        dec = decide_now({'culprits': sorted(culprits), 'verdict': 'failed', 'set_root': None}, True)
        dec['blockers'].append('the dynamic gate did not converge on a passing set'); dec['publishable'] = False
        return dec, {'verdict': 'failed', 'iterations': log, 'culprits': sorted(culprits)}

def verify_only(dist, previous_dir, policy, yara, yarac, out):
    """Measure a set that is already decided (the public candidate) without changing it. Used on other platforms."""
    dist = pathlib.Path(dist); cand_json = json.loads((dist / 'candidate.json').read_text())
    files = [f['path'] for f in cand_json['files']]; base = None
    if previous_dir and (pathlib.Path(previous_dir) / 'manifest.json').exists():
        pm = json.loads((pathlib.Path(previous_dir) / 'manifest.json').read_text()); base = {'root': pathlib.Path(previous_dir), 'files': [f['path'] for f in pm['files']]}; base['deps'] = rulecheck.infer_deps(base['root'], base['files'], policy)
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td); corpus, canaries = bench.build_corpus(td / 'corpus'); work = td / 'work'; work.mkdir()
        gate = Gate(yara, yarac, policy, work, corpus, canaries)
        cmp_, b, c = gate.verdict(base, {'root': dist, 'files': files, 'deps': {f['path']: f.get('depends_on', []) for f in cand_json['files']}})   # dependencies travel with the candidate
        w = work / 'canary'; w.mkdir(); (w / 'c.yar').write_text(bench.CANARY_RULES); subprocess.run([yarac, str(w / 'c.yar'), str(w / 'c.yarc')], capture_output=True)
        fired = sum(1 for f in canaries if 'MacGuard_Canary_' in subprocess.run([yara, '-p', '1', '-C', str(w / 'c.yarc'), str(f)], capture_output=True, text=True).stdout)
    doc = {'schema': 1, 'platform': sys.platform, 'engine': subprocess.run([yara, '--version'], capture_output=True, text=True).stdout.strip(), 'verdict': cmp_['verdict'], 'reasons': cmp_['reasons'], 'metrics': cmp_['metrics'],
           'set_root': tlog_root(cand_json['files']), 'canaries_detected': fired, 'canaries_expected': len(canaries), 'baseline': bool(base), 'runs': policy['dynamic']['runs']}
    pathlib.Path(out).write_text(json.dumps(doc, indent=1) + '\n'); return doc

def tlog_root(files): return decide.set_root(files)

if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('--verify-only', action='store_true', help='measure the candidate in --dist as it is (platform check)'); ap.add_argument('--allow-large-change', action='store_true', help='a person has looked at an unusually large change'); ap.add_argument('--dist', default='dist'); ap.add_argument('--classification', default='dist/classification.json'); ap.add_argument('--previous'); ap.add_argument('--decisions')
    ap.add_argument('--policy', default='config/policy.json'); ap.add_argument('--sources', default='config/sources.json', help='turns on the new-source hold (scripts/admission.py)'); ap.add_argument('--rejected'); ap.add_argument('--out', default='dist/decision.json'); ap.add_argument('--dynamic-out', default='dist/dynamic.json'); ap.add_argument('--approved-out', default='dist/approved.json')
    a = ap.parse_args(); load = lambda p: json.loads(pathlib.Path(p).read_text()) if p and pathlib.Path(p).exists() else None
    yara, yarac = shutil.which('yara'), shutil.which('yarac')
    if not yara or not yarac: sys.exit('yara and yarac are required for the dynamic gate')
    if a.verify_only:
        yd = verify_only(a.dist, a.previous, json.loads(pathlib.Path(a.policy).read_text()), yara, yarac, a.dynamic_out)
        print(f"verdict={yd['verdict']}"); print(json.dumps(yd['reasons']), file=sys.stderr); sys.exit(0 if yd['verdict'] in ('ok', 'no-baseline') and yd['canaries_detected'] == yd['canaries_expected'] else 1)
    cls = json.loads(pathlib.Path(a.classification).read_text())['files']
    final, dyn = run(a.dist, cls, a.previous, json.loads(pathlib.Path(a.policy).read_text()), load(a.decisions), yara, yarac, previously_rejected=load(a.rejected), sources=admission.load_sources(a.sources))
    pathlib.Path(a.out).write_text(json.dumps(final, indent=1) + '\n'); pathlib.Path(a.dynamic_out).write_text(json.dumps(dyn, indent=1) + '\n')
    pathlib.Path(a.approved_out).write_text(json.dumps({'files': final['approved'], 'rules_root': final['rules_root']}, indent=1) + '\n')
    print(f"publishable={'true' if final['publishable'] else 'false'}"); print(json.dumps(final['public_stats']) + ' blockers=' + json.dumps(final['blockers']), file=sys.stderr)
    sys.exit(0)
