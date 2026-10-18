#!/usr/bin/env python3
"""Run the real MacGuard CLI over the safe corpus and report crashes, timeouts, errors, wall-time percentiles and peak memory.
This exercises the audit engine (not YARA, which the app does not bundle yet) on the platform where it runs.

usage: macguard_smoke.py /path/to/macguard-audit --out result.json [--rules-from dist-public]

With --rules-from the candidate rules are installed into a private data directory (MACGUARD_DATA_DIR) together with the detection canary
rules, so MacGuard itself runs the shipped YARA engine over the corpus and must report every canary."""
import argparse, json, os, pathlib, shutil, sys, tempfile
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import bench

def main():
    ap = argparse.ArgumentParser(); ap.add_argument('binary'); ap.add_argument('--out', required=True); ap.add_argument('--timeout', type=int, default=60); ap.add_argument('--rules-from')
    a = ap.parse_args()
    with tempfile.TemporaryDirectory() as td:
        if a.rules_from:
            src = pathlib.Path(a.rules_from); live = pathlib.Path(td) / 'data/YARARules/community'; (live / '.release').mkdir(parents=True)
            cand = json.loads((src / 'candidate.json').read_text())
            for f in cand['files']:
                dst = live / f['path'].removeprefix('rules/'); dst.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(src / f['path'], dst)
            (live / 'macguard-canary.yar').write_text(bench.CANARY_RULES)
            (live / '.release/manifest.json').write_text(json.dumps({'rules_root': 'smoke', 'files': cand['files']}))
            os.environ['MACGUARD_DATA_DIR'] = str(pathlib.Path(td) / 'data')
        files, canaries = bench.build_corpus(pathlib.Path(td) / 'corpus'); targets = files + canaries
        # a few bundles and archives, built with the system tools, so more than one format is exercised
        extra = pathlib.Path(td) / 'extra'; extra.mkdir()
        import subprocess
        app = extra / 'Smoke.app/Contents/MacOS'; app.mkdir(parents=True); shutil.copy('/bin/echo', app / 'tool')
        (extra / 'Smoke.app/Contents/Info.plist').write_text('<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleExecutable</key><string>tool</string><key>CFBundleIdentifier</key><string>x.smoke</string></dict></plist>')
        subprocess.run(['/usr/bin/tar', '-czf', str(extra / 'a.tgz'), '-C', str(extra), 'Smoke.app'], check=False)
        subprocess.run(['/usr/bin/zip', '-qr', str(extra / 'a.zip'), 'Smoke.app'], cwd=extra, check=False)
        targets += [extra / 'Smoke.app', extra / 'a.tgz', extra / 'a.zip']
        results = []
        for t in targets:
            m = bench.run_measured([a.binary, 'scan', str(t), '--format', 'json'], timeout=a.timeout, stdout=__import__('subprocess').PIPE)
            r = {'name': t.name, 'code': m['code'], 'wall': m['wall'], 'rss_mb': m['rss_mb'], 'cpu': m['cpu'], 'timed_out': m['timed_out'], 'crashed': m['crashed']}
            if a.rules_from and t in canaries:
                out = subprocess.run([a.binary, 'scan', str(t), '--format', 'json'], capture_output=True, text=True, timeout=a.timeout).stdout
                try: r['canary_detected'] = any(f['title'].startswith('YARA match: MacGuard_Canary_') for f in json.loads(out)['results'][0]['findings'])
                except Exception: r['canary_detected'] = False
            results.append(r)
    walls = [r['wall'] for r in results]
    doc = {'schema': 1, 'platform': sys.platform, 'targets': len(results), 'crashes': sum(r['crashed'] for r in results), 'timeouts': sum(r['timed_out'] for r in results),
           'tool_errors': sum(1 for r in results if r['code'] not in (0, 2) and not r['timed_out'] and not r['crashed']), 'wall_p50': bench.percentile(walls, 50), 'wall_p95': bench.percentile(walls, 95), 'wall_p99': bench.percentile(walls, 99),
           'rss_peak_mb': max(r['rss_mb'] for r in results), 'cpu_total': sum(r['cpu'] for r in results), 'percentiles_reported': len(results) >= 50,
           'yara_in_macguard': bool(a.rules_from), 'canaries_detected_by_macguard': sum(1 for r in results if r.get('canary_detected')), 'canaries_expected': len(canaries) if a.rules_from else 0}
    pathlib.Path(a.out).write_text(json.dumps(doc, indent=1) + '\n'); print(json.dumps(doc))
    sys.exit(1 if doc['crashes'] or doc['timeouts'] or doc['tool_errors'] or doc['canaries_detected_by_macguard'] < doc['canaries_expected'] else 0)

if __name__ == '__main__': main()
