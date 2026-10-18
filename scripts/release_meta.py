#!/usr/bin/env python3
"""Release metadata published next to the signed artifacts: release.json, changes.json, CHANGELOG.md and, when a previous
release exists, consistency.json (RFC 9162 proof from the previous log head to this one).

usage: release_meta.py --dist dist --tarball rules-release.tar.gz --tag TAG --run-url URL --out OUT [--previous prev/manifest.json]"""
import argparse, hashlib, json, pathlib, sys
from datetime import datetime, timezone
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import catalog, changes

def changelog(tag: str, doc: dict, limit: int = 300) -> str:
    c = doc['counts']
    out = [f'# {tag}', '', f"{c['total']} rule files in this release: {c['added']} added, {c['modified']} modified, {c['removed']} removed, {c['unchanged']} unchanged.", '',
           'This is the complete current rule set, not a delta: any release installs on its own.', '']
    for title, key in (('Added', 'added'), ('Modified', 'modified'), ('Removed', 'removed')):
        items = doc[key]
        if not items: continue
        out += [f'## {title} ({len(items)})', ''] + [f'- `{p}`' for p in items[:limit]]
        if len(items) > limit: out.append(f'- … and {len(items) - limit} more (see changes.json)')
        out.append('')
    return '\n'.join(out)

def build(dist: pathlib.Path, tarball: pathlib.Path, tag: str, run_url: str, out: pathlib.Path, previous: dict = None, log_lines: list = None, now: str = None) -> dict:
    manifest = json.loads((dist / 'manifest.json').read_text())
    doc = changes.compute(manifest, previous)
    out.mkdir(parents=True, exist_ok=True)
    pkg = tarball.read_bytes()
    stats = manifest.get('stats') or {}
    release = {'schema': 1, 'tag': tag, 'created_at': now or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), 'workflow_run': run_url,
               'rules_root': manifest['rules_root'], 'log': manifest.get('log'), 'files': len(manifest['files']), 'yara_rules': stats.get('yara_rules'),
               'expanded_bytes': stats.get('expanded_bytes'), 'package': 'rules-release.tar.gz', 'package_bytes': len(pkg), 'package_sha256': hashlib.sha256(pkg).hexdigest(),
               'previous_rules_root': doc['previous_rules_root'], 'changes': doc['counts'],
               'sources': manifest.get('sources'), 'complete_release': True}
    (out / 'release.json').write_text(json.dumps(release, indent=1) + '\n')
    (out / 'changes.json').write_text(json.dumps(doc, indent=1) + '\n')
    (out / 'CHANGELOG.md').write_text(changelog(tag, doc))
    if previous and previous.get('log') and log_lines is not None:
        cons = catalog.consistency_doc(log_lines, previous['log'], manifest.get('log'))
        if cons: (out / 'consistency.json').write_text(json.dumps(cons, indent=1) + '\n')
    return release

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    for k in ('--dist', '--tarball', '--tag', '--run-url', '--out'): ap.add_argument(k, required=True)
    ap.add_argument('--previous'); ap.add_argument('--log', default='logs/log.jsonl')
    a = ap.parse_args()
    prev = json.loads(pathlib.Path(a.previous).read_text()) if a.previous and pathlib.Path(a.previous).exists() else None
    lines = [l for l in pathlib.Path(a.log).read_bytes().split(b'\n') if l] if pathlib.Path(a.log).exists() else []
    r = build(pathlib.Path(a.dist), pathlib.Path(a.tarball), a.tag, a.run_url, pathlib.Path(a.out), prev, lines)
    print(json.dumps({k: r[k] for k in ('tag', 'files', 'yara_rules', 'package_bytes', 'changes')}))
