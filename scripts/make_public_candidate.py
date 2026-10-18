#!/usr/bin/env python3
"""Build the only thing that leaves the private job: the approved rule set and aggregate numbers.

GitHub Actions artifacts of a public repository are public, so anything about quarantined or rejected rules (names,
findings, compiler output, culprits, per-rule hit counts) is dropped here. Those details go to the private quarantine
service only.

usage: make_public_candidate.py --dist dist --out dist-public [--previous previous/manifest.json]"""
import argparse, json, pathlib, shutil, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import changes

PUBLIC_DYNAMIC = ('schema', 'platform', 'engine', 'verdict', 'set_root', 'canaries_detected', 'canaries_expected', 'corpus', 'runs', 'baseline', 'percentiles_reported', 'not_run')

def build(dist: pathlib.Path, out: pathlib.Path, previous: dict = None) -> dict:
    decision = json.loads((dist / 'decision.json').read_text()); cand = json.loads((dist / 'candidate.json').read_text())
    dyn = json.loads((dist / 'dynamic.json').read_text()) if (dist / 'dynamic.json').exists() else {}
    shutil.rmtree(out, ignore_errors=True); out.mkdir(parents=True)
    files = []
    for f in decision['approved']:
        dst = out / f['path']; dst.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(dist / f['path'], dst)
        files.append({'source': f['source'], 'path': f['path'], 'sha256': f['sha256'], 'bytes': f['bytes']})
    public = {k: v for k, v in cand.items() if k not in ('files', 'rejected')}; public['files'] = files; public['rejected'] = []
    (out / 'candidate.json').write_text(json.dumps(public, indent=2, sort_keys=True) + '\n')
    (out / 'validation.json').write_text(json.dumps({'engine': 'yara', 'checked': len(files), 'failures': []}, indent=2) + '\n')
    (out / 'changes.json').write_text(json.dumps(changes.compute(public, previous), indent=1) + '\n')
    pd = {k: dyn[k] for k in PUBLIC_DYNAMIC if k in dyn}
    pd['aggregate'] = {k: {'baseline': v['baseline'], 'candidate': v['candidate'], 'regressed': v['regressed']} for k, v in (dyn.get('metrics') or {}).items()}
    (out / 'dynamic.json').write_text(json.dumps(pd, indent=1) + '\n')
    (out / 'public_stats.json').write_text(json.dumps(decision['public_stats'], indent=1) + '\n')
    return public

if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('--dist', default='dist'); ap.add_argument('--out', default='dist-public'); ap.add_argument('--previous')
    a = ap.parse_args(); prev = json.loads(pathlib.Path(a.previous).read_text()) if a.previous and pathlib.Path(a.previous).exists() else None
    pub = build(pathlib.Path(a.dist), pathlib.Path(a.out), prev); print(f"public candidate: {len(pub['files'])} files")
