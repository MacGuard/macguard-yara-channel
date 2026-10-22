#!/usr/bin/env python3
"""TEST DOUBLE of `wrangler d1 execute <db> --remote --json --command <sql>` for the two read-only queries used by scripts/archive/monthly.py.
Data comes from the JSON file named by $FAKE_D1: {"audit": [...rows...], "anchors": [...] or null (null = table does not exist)}."""
import json, os, re, sys

a = sys.argv[1:]
sql = a[a.index('--command') + 1]
assert '--remote' in a and '--json' in a and a[:2] == ['d1', 'execute']
data = json.load(open(os.environ['FAKE_D1']))
if m := re.match(r'SELECT .* FROM audit WHERE seq > (\d+) ORDER BY seq ASC LIMIT (\d+)$', sql):
    res = [r for r in data['audit'] if r['seq'] > int(m[1])][:int(m[2])]
elif sql.startswith('SELECT seq, hash, rows, seal_sha256 FROM audit_anchor'):
    if data['anchors'] is None: sys.stderr.write('D1_ERROR: no such table: audit_anchor'); sys.exit(1)
    res = data['anchors']
else:
    sys.stderr.write('unexpected query'); sys.exit(2)
print(json.dumps([{'results': res, 'success': True, 'meta': {}}]))
