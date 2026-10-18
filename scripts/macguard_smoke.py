#!/usr/bin/env python3
"""Run the real MacGuard CLI over the safe corpus and report crashes, timeouts, errors, wall-time percentiles and peak memory.
This exercises the audit engine (not YARA, which the app does not bundle yet) on the platform where it runs.

usage: macguard_smoke.py /path/to/macguard-audit --out result.json"""
import argparse, json, pathlib, sys, tempfile
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import bench

def main():
    ap = argparse.ArgumentParser(); ap.add_argument('binary'); ap.add_argument('--out', required=True); ap.add_argument('--timeout', type=int, default=60)
    a = ap.parse_args()
    with tempfile.TemporaryDirectory() as td:
        files, canaries = bench.build_corpus(pathlib.Path(td) / 'corpus'); targets = files + canaries
        # a few bundles and archives, built with the system tools, so more than one format is exercised
        extra = pathlib.Path(td) / 'extra'; extra.mkdir()
        import subprocess, shutil
        app = extra / 'Smoke.app/Contents/MacOS'; app.mkdir(parents=True); shutil.copy('/bin/echo', app / 'tool')
        (extra / 'Smoke.app/Contents/Info.plist').write_text('<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleExecutable</key><string>tool</string><key>CFBundleIdentifier</key><string>x.smoke</string></dict></plist>')
        subprocess.run(['/usr/bin/tar', '-czf', str(extra / 'a.tgz'), '-C', str(extra), 'Smoke.app'], check=False)
        subprocess.run(['/usr/bin/zip', '-qr', str(extra / 'a.zip'), 'Smoke.app'], cwd=extra, check=False)
        targets += [extra / 'Smoke.app', extra / 'a.tgz', extra / 'a.zip']
        results = []
        for t in targets:
            m = bench.run_measured([a.binary, 'scan', str(t), '--format', 'json'], timeout=a.timeout, stdout=__import__('subprocess').PIPE)
            results.append({'name': t.name, 'code': m['code'], 'wall': m['wall'], 'rss_mb': m['rss_mb'], 'cpu': m['cpu'], 'timed_out': m['timed_out'], 'crashed': m['crashed']})
    walls = [r['wall'] for r in results]
    doc = {'schema': 1, 'platform': sys.platform, 'targets': len(results), 'crashes': sum(r['crashed'] for r in results), 'timeouts': sum(r['timed_out'] for r in results),
           'tool_errors': sum(1 for r in results if r['code'] not in (0, 2) and not r['timed_out'] and not r['crashed']), 'wall_p50': bench.percentile(walls, 50), 'wall_p95': bench.percentile(walls, 95), 'wall_p99': bench.percentile(walls, 99),
           'rss_peak_mb': max(r['rss_mb'] for r in results), 'cpu_total': sum(r['cpu'] for r in results), 'percentiles_reported': len(results) >= 50}
    pathlib.Path(a.out).write_text(json.dumps(doc, indent=1) + '\n'); print(json.dumps(doc))
    sys.exit(1 if doc['crashes'] or doc['timeouts'] or doc['tool_errors'] else 0)

if __name__ == '__main__': main()
