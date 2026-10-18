#!/usr/bin/env python3
"""Check that two hosts of the site offer the same release.

usage: compare_mirrors.py BASE_URL_A BASE_URL_B

Each host is verified on its own by verify_live.py (signatures, hashes, proofs). This answers a different question: do they serve the SAME
release? A mirror that failed to deploy keeps serving an older, still valid, release; that is safe but must be reported, not hidden.
Exit 0: identical. Exit 3: they differ (details on stdout). Exit 2: a host could not be read."""
import json, sys, urllib.error, urllib.request

FIELDS = ('manifest_sha256', 'package_sha256', 'package_bytes', 'rules_root', 'stats')

def latest(base):
    req = urllib.request.Request(base.rstrip('/') + '/latest.json', headers={'User-Agent': 'macguard-compare-mirrors/1', 'Cache-Control': 'no-cache'})
    with urllib.request.urlopen(req, timeout=40) as r: doc = json.load(r)
    return {**{k: doc.get(k) for k in FIELDS}, 'log_size': (doc.get('log') or {}).get('size'), 'log_root': (doc.get('log') or {}).get('root')}

def compare(a, b):
    return [f'{k}: {a[k]!r} != {b[k]!r}' for k in a if a[k] != b[k]]

def main(argv):
    if len(argv) != 2: sys.exit(__doc__)
    try: docs = [latest(u) for u in argv]
    except (urllib.error.URLError, OSError, ValueError) as e:
        print(f'UNREADABLE: {e}'); return 2
    diff = compare(*docs)
    if diff:
        print('DIFFERENT releases are served:'); [print('  ' + d) for d in diff]; return 3
    print(f"identical: manifest {docs[0]['manifest_sha256'][:16]}..., rules_root {str(docs[0]['rules_root'])[:16]}..., log {docs[0]['log_size']} entries")
    return 0

if __name__ == '__main__': sys.exit(main(sys.argv[1:]))
