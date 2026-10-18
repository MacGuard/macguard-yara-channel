#!/usr/bin/env python3
"""Compare a candidate with the latest published release and decide whether a new release is warranted.

A release is warranted when rule content differs: a file added, modified (hash changed) or removed. A change of
upstream commit alone, with byte-identical rules, is not an effective change. The first release always is.

usage: changes.py --dist dist [--previous previous/manifest.json] [--out dist/changes.json]
Prints `changed=true|false` (append it to $GITHUB_OUTPUT)."""
import argparse, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import catalog

def compute(candidate: dict, previous: dict = None) -> dict:
    d = catalog.diff(previous, candidate)
    total = len(candidate.get('files', []))
    unchanged = total - len(d['added']) - len(d['modified'])
    return {'schema': 1, 'changed': bool(previous is None or d['added'] or d['modified'] or d['removed']),
            'previous_rules_root': previous.get('rules_root') if previous else None,
            'counts': {'added': len(d['added']), 'modified': len(d['modified']), 'removed': len(d['removed']), 'unchanged': unchanged, 'total': total},
            'added': d['added'], 'modified': d['modified'], 'removed': d['removed']}

if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('--dist', default='dist'); ap.add_argument('--previous'); ap.add_argument('--out')
    a = ap.parse_args(); dist = pathlib.Path(a.dist)
    cand = json.loads((dist / 'candidate.json').read_text())
    prev = json.loads(pathlib.Path(a.previous).read_text()) if a.previous and pathlib.Path(a.previous).exists() else None
    doc = compute(cand, prev)
    pathlib.Path(a.out or dist / 'changes.json').write_text(json.dumps(doc, indent=1) + '\n')
    c = doc['counts']
    print(f"changed={'true' if doc['changed'] else 'false'}")
    print(f"+{c['added']} ~{c['modified']} -{c['removed']} ={c['unchanged']} of {c['total']}", file=sys.stderr)
