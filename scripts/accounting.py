#!/usr/bin/env python3
"""Exact accounting of one analysis run.

Unit of counting: a RULE FILE examined by one run (not individual YARA rules, not downloads). Every examined file ends in exactly
one explicit final state:

  accepted     passed every mandatory check and is in the candidate release
  quarantined  held for human review (or excluded because something it needs is)
  rejected     refused outright by a hard criterion or a reviewer
  deprecated   marked deprecated by its own metadata, not distributed

Invariant, per run:   examined = accepted + quarantined + rejected + deprecated
There is no catch-all state. 'retired' (files of the previous release that upstream no longer has) is NOT part of this sum: those
files were not examined by this run; they are counted separately because they are a different unit.

The ledger gives each examined file a unique id (SHA-256 of source, path and content hash), its hash, source and final state. The
public side publishes only the counts and `ledger_root`, a Merkle root over (id, state) so the private ledger can later be shown to
match what was announced without naming quarantined files."""
import hashlib, sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import tlog

FINAL_STATES = ('accepted', 'quarantined', 'rejected', 'deprecated')
_MAP = {'QUARANTINED': 'quarantined', 'REJECTED': 'rejected', 'DEPRECATED': 'deprecated', 'VALIDATED': 'accepted'}

def entry_id(source: str, path: str, sha256: str) -> str:
    return hashlib.sha256(f'{source}\0{path}\0{sha256}'.encode()).hexdigest()

def build_ledger(approved: list, excluded: list) -> list:
    """approved/excluded: dicts with path, sha256, source (and state for excluded). Raises if a file is listed twice."""
    out, seen = [], set()
    for f, final in [(f, 'accepted') for f in approved] + [(f, _MAP[f['state']]) for f in excluded]:
        i = entry_id(f.get('source', ''), f['path'], f['sha256'])
        if i in seen: raise ValueError(f"file counted twice in one run: {f['path']}")
        seen.add(i); out.append({'id': i, 'sha256': f['sha256'], 'source': f.get('source', ''), 'path': f['path'], 'state': final})
    return sorted(out, key=lambda e: e['id'])

def ledger_root(ledger: list) -> str:
    """Merkle root (the log's RFC 6962 hashing) over `id NUL state` leaves ordered by id."""
    leaves = [tlog.leaf_hash(f"{e['id']}\0{e['state']}".encode()) for e in sorted(ledger, key=lambda e: e['id'])]
    return tlog.mth(leaves).hex()

def counts(ledger: list) -> dict:
    c = {s: 0 for s in FINAL_STATES}
    for e in ledger: c[e['state']] += 1
    return c

def violations(stats: dict) -> list:
    """Problems in a stats record (examined/accepted/quarantined/rejected/deprecated). Empty list = consistent."""
    bad = []
    for k in ('examined', 'accepted', 'quarantined', 'rejected'):
        if not isinstance(stats.get(k), int) or stats[k] < 0: bad.append(f'{k} must be a non-negative integer')
    if bad: return bad
    total = stats['accepted'] + stats['quarantined'] + stats['rejected'] + int(stats.get('deprecated', 0) or 0)
    if total != stats['examined']:
        bad.append(f"examined {stats['examined']} != accepted {stats['accepted']} + quarantined {stats['quarantined']} + rejected {stats['rejected']} + deprecated {int(stats.get('deprecated', 0) or 0)} = {total}")
    return bad

def require(stats: dict):
    v = violations(stats)
    if v: raise ValueError('accounting invariant violated: ' + '; '.join(v))
