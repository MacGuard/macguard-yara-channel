#!/usr/bin/env python3
"""Catalog, release history and consistency evidence for the public site.

Everything here is derived from signed manifests and the append-only log; nothing is typed in by hand.

catalog.json   one row per rule file of the latest release (path, source, category, upstream repo + commit, sha256, bytes,
               validation, first release it appeared in, release that last changed it)
releases.json  one row per published release, with added/modified/removed computed by comparing manifests path by path
               and hash by hash (never by comparing totals)
consistency.json  RFC 9162 consistency proof from the previous release's log head to the latest one
"""
import json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import tlog

NEXTRON_PREFIXES = {'apt', 'mal', 'gen', 'expl', 'vuln', 'susp', 'hktl', 'webshell', 'yara', 'cloud', 'general', 'thor', 'configured'}

import re
RULE_RE = re.compile(r'^\s*(?:(?:global|private)\s+)*rule\s+\w+', re.M)

def count_rules(text: str) -> int:
    """Individual YARA rule declarations in a file (a file may hold many, or none)."""
    return len(RULE_RE.findall(text))

def category(path: str, source: str) -> str:
    """Directory under the source when there is one; for flat Nextron files, the file-name prefix. Derived, not upstream metadata."""
    parts = path.split('/')                      # rules/<source>/<dir>/.../<file>
    inner = parts[2:] if len(parts) > 2 and parts[1] == source else parts[1:]
    if len(inner) > 1 and inner[0] not in ('yara',): return inner[0]
    name = inner[-1]
    head = name.split('_', 1)[0].lower()
    return head if head in NEXTRON_PREFIXES and '_' in name else (inner[0] if len(inner) > 1 else 'general')

def file_map(manifest: dict) -> dict:
    return {f['path']: f['sha256'] for f in manifest.get('files', [])}

def diff(old: dict, new: dict) -> dict:
    """added / modified / removed between two manifests, by path and hash."""
    a, b = file_map(old) if old else {}, file_map(new)
    return {'added': sorted(p for p in b if p not in a),
            'modified': sorted(p for p in b if p in a and a[p] != b[p]),
            'removed': sorted(p for p in a if p not in b)}

def history(releases: list) -> list:
    """releases: [{tag, published_at, url, manifest(dict), verification(dict|None)}] in any order -> rows, oldest first."""
    rows, prev = [], None
    for r in sorted(releases, key=lambda r: (r['published_at'], r['tag'])):
        m = r['manifest']; d = diff(prev, m)
        rows.append({'tag': r['tag'], 'published_at': r['published_at'], 'url': r['url'],
                     'total': len(m.get('files', [])), 'added': len(d['added']), 'modified': len(d['modified']), 'removed': len(d['removed']),
                     'rules_root': m.get('rules_root'), 'log': m.get('log'), 'stats': m.get('stats'),
                     'package_bytes': r.get('package_bytes'),
                     'verification': r.get('verification') or {'checked': False},
                     # only assets this release really has: older releases lack checkpoint/metadata files, and a dead link is worse than none
                     'assets': {n: f"{r['url'].rstrip('/').replace('/tag/', '/download/')}/{n}" for n in (r.get('asset_names') or ('rules-release.tar.gz', 'manifest.json', 'manifest.sigstore.json', 'inclusion-proof.json'))},
                     '_diff': d})
        prev = m
    return rows

def first_seen(rows_with_manifests: list) -> dict:
    """path -> (first tag, tag of the last change)."""
    seen, last, prev = {}, {}, {}
    for tag, m in rows_with_manifests:
        for p, h in file_map(m).items():
            if p not in prev: seen.setdefault(p, tag); last[p] = tag
            elif prev[p] != h: last[p] = tag
        prev = file_map(m)
    return {p: (seen.get(p), last.get(p)) for p in prev}

def build_catalog(manifest: dict, seen: dict, tag: str) -> dict:
    sources = {s['id']: s for s in manifest.get('sources', [])}
    ok = manifest.get('validation', {})
    validated = ok.get('engine') and ok.get('checked') == len(manifest.get('files', []))
    out = []
    for f in sorted(manifest['files'], key=lambda f: f['path']):
        s = sources.get(f.get('source'), {})
        fs = seen.get(f['path'], (tag, tag))
        out.append({'path': f['path'], 'name': f['path'].rsplit('/', 1)[-1], 'category': category(f['path'], f.get('source', '')),
                    'source': f.get('source'), 'repository': s.get('repository'), 'commit': s.get('commit'),
                    'sha256': f['sha256'], 'bytes': f['bytes'],
                    'validation': 'compiled' if validated else 'unchecked',
                    'first_release': fs[0], 'changed_in': fs[1]})
    return {'schema': 1, 'release': tag, 'rules_root': manifest.get('rules_root'), 'count': len(out),
            'validation_note': 'compiled = accepted by the YARA compiler in the publishing workflow; it says nothing about detection quality or safety',
            'category_note': 'category is derived from the directory or file-name prefix, not from upstream metadata',
            'files': out}

def consistency_doc(log_lines: list, old_head: dict, new_head: dict):
    """Proof that the log of new_head.size entries extends the log of old_head.size entries (None when not applicable)."""
    if not old_head or not new_head or old_head['size'] >= new_head['size'] or new_head['size'] > len(log_lines): return None
    leaves = [tlog.leaf_hash(l) for l in log_lines[:new_head['size']]]
    old_root, new_root = tlog.mth(leaves[:old_head['size']]), tlog.mth(leaves)
    if old_root.hex() != old_head['root'] or new_root.hex() != new_head['root']: return None
    proof = tlog.consistency_proof(old_head['size'], leaves)
    assert tlog.verify_consistency(old_head['size'], new_head['size'], old_root, new_root, proof)
    return {'schema': 1, 'origin': tlog.ORIGIN if hasattr(tlog, 'ORIGIN') else 'macguard-rules-log v1', 'first_size': old_head['size'], 'first_root': old_head['root'],
            'second_size': new_head['size'], 'second_root': new_head['root'], 'proof': [p.hex() for p in proof]}

def public_rows(rows: list) -> list:
    return [{k: v for k, v in r.items() if not k.startswith('_')} for r in rows]
