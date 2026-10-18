#!/usr/bin/env python3
"""Licence evidence for a rules source. The policy says what each source is expected to be licensed under; if what GitHub
reports and what the LICENSE text says stops matching, every file of that source is quarantined until a person decides."""
import base64, hashlib, json, re, urllib.request

def verdict(rule: dict, reported_spdx: str, text: str) -> dict:
    """rule: policy['licenses'][repo]. Pure function, unit tested."""
    digest = hashlib.sha256(text.encode('utf-8', 'replace')).hexdigest() if text else ''
    if not rule: return {'ok': False, 'detail': 'no licence policy for this source', 'sha256': digest, 'spdx_reported': reported_spdx}
    if not text: return {'ok': False, 'detail': 'no LICENSE text could be read', 'sha256': digest, 'spdx_reported': reported_spdx}
    if rule.get('expected_spdx') and reported_spdx != rule['expected_spdx']:
        return {'ok': False, 'detail': f"GitHub reports {reported_spdx or 'no licence'}, policy expects {rule['expected_spdx']}", 'sha256': digest, 'spdx_reported': reported_spdx}
    if rule.get('expected_marker') and rule['expected_marker'].lower() not in text.lower():
        return {'ok': False, 'detail': f"LICENSE text no longer contains \"{rule['expected_marker']}\"", 'sha256': digest, 'spdx_reported': reported_spdx}
    if rule.get('sha256') and rule['sha256'] != digest:
        return {'ok': False, 'detail': 'LICENSE text changed since it was reviewed', 'sha256': digest, 'spdx_reported': reported_spdx}
    return {'ok': True, 'detail': f"{rule['spdx']}: {rule['redistribution']}", 'sha256': digest, 'spdx_reported': reported_spdx, 'redistribution': rule['redistribution']}

def fetch(repo: str, token: str = '') -> tuple:
    req = urllib.request.Request(f'https://api.github.com/repos/{repo}/license', headers={'User-Agent': 'MacGuard-YARA-Channel/0.2', 'Accept': 'application/vnd.github+json', **({'Authorization': f'Bearer {token}'} if token else {})})
    with urllib.request.urlopen(req, timeout=25) as r: d = json.load(r)
    return (d.get('license') or {}).get('spdx_id', ''), base64.b64decode(d.get('content', '')).decode('utf-8', 'replace')
