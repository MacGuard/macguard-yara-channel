#!/usr/bin/env python3
"""Build-time data of the multi-family portal pages (catalog.html, packages.html): derived ONLY from files the site build already has.

families.json  every family the portal names, with its REAL state. The YARA Community family takes its numbers from latest.json (counted by the site
               build from the verified release); every other family comes from config/intel-families.json and carries NO count and NO package: a
               family that is not published is shown as such, never with a number or a download. Families the owner listed for the portal but
               that no configuration describes are NOT_CONFIGURED.
packages.json  only packages that really exist: today the signed YARA Community releases (releases.json rows). Every number names its source.

Each numeric field sits in an object with a `source` field (tests/test_portal.py enforces it)."""
import json, pathlib

SCHEMA_FAMILIES, SCHEMA_PACKAGES = 'macguard.portal-families/1', 'macguard.portal-packages/1'
# config/intel-families.json `publication` -> portal state. Anything unknown is NOT_PUBLISHED (never optimistic).
STATE = {'RETENIDA': 'RETAINED', 'NO_DATA': 'NO_DATA', 'BLOCKED': 'BLOCKED', 'NOT_APPLICABLE': 'ENGINE_ONLY', 'PUBLISHED': 'PUBLISHED'}
# The portal tier of each family follows the owner's Freemium decision (2026-11-01): YARA Community and public vulnerability data are FREE;
# other rule engines, indicators and correlation are PREMIUM. A tier says how it WILL be offered; the state says whether it exists today.
TIER = {'detections': 'PREMIUM', 'indicators': 'PREMIUM', 'vulnerabilities': 'FREE', 'context': 'FREE'}
# Families the portal must name even though no configuration describes them yet (owner mandates of 2026-11-01).
EXPECTED = [('clamav', 'detections', 'ClamAV'), ('ghsa', 'vulnerabilities', 'GHSA (GitHub Security Advisories)'),
            ('gcve', 'vulnerabilities', 'GCVE'), ('cwe', 'vulnerabilities', 'CWE (MITRE)'), ('cvss', 'vulnerabilities', 'CVSS (scores per source)')]


def families(config: dict, latest: dict | None) -> dict:
    out = []
    yara = {'id': 'yara_community', 'group': 'detections', 'name': 'YARA Community', 'tier': 'FREE', 'engine': 'YARA',
            'state': 'PUBLISHED' if latest else 'NOT_PUBLISHED', 'config_source': None, 'package': None}
    if latest:
        s = latest.get('stats') or {}
        yara['package'] = {'files': s.get('files'), 'yara_rules': s.get('yara_rules'), 'package_bytes': latest.get('package_bytes'),
                           'manifest': latest.get('manifest'), 'signature': latest.get('signature'), 'inclusion_proof': latest.get('inclusion_proof'),
                           'manifest_sha256': latest.get('manifest_sha256'), 'source': 'latest.json (counted by the site build from the verified release)'}
    out.append(yara)
    seen = set()
    for f in config.get('families', []):
        seen.add(f['id'])
        state = STATE.get(f.get('publication'), 'NOT_PUBLISHED')
        if f.get('integration') == 'NOT_INTEGRATED': state = 'NOT_INTEGRATED'
        out.append({'id': f['id'], 'group': f['group'], 'name': f['name'], 'tier': TIER.get(f['group'], 'PREMIUM'),
                    'engine': 'YARA-X' if f['id'] == 'yara_x' else None, 'state': state,
                    'upstream': f.get('source'), 'causes': list(f.get('causes') or [])[:6],
                    'config_source': 'config/intel-families.json', 'package': None})
    for fid, group, name in EXPECTED:
        if fid not in seen:
            out.append({'id': fid, 'group': group, 'name': name, 'tier': TIER[group], 'engine': None, 'state': 'NOT_CONFIGURED',
                        'upstream': None, 'causes': [], 'config_source': None, 'package': None})
    return {'schema': SCHEMA_FAMILIES, 'as_of': config.get('as_of'), 'source': 'config/intel-families.json + latest.json', 'families': out,
            'note': 'Only YARA Community is published today. Other families are listed with their real state and no counts or downloads.'}


def packages(rows: list, latest: dict | None) -> dict:
    """rows: catalog.public_rows(history) oldest first. Newest first in the output. Only YARA Community exists today."""
    out = []
    for r in reversed(rows):
        st = r.get('stats') or {}
        out.append({'family': 'yara_community', 'name': 'YARA Community', 'tier': 'FREE', 'engine': 'YARA', 'format': 'tar.gz (rules/ + manifest.json)',
                    'tag': r['tag'], 'published_at': r['published_at'], 'url': r['url'],
                    'size': {'package_bytes': r.get('package_bytes'), 'source': 'release metadata (history/<tag>/meta.json)'},
                    'items': {'files': r.get('total'), 'yara_rules': st.get('yara_rules'), 'source': 'signed manifest of the release'},
                    'changes': {'added': r.get('added'), 'modified': r.get('modified'), 'removed': r.get('removed'), 'source': 'signed manifests compared path by path'},
                    'rules_root': r.get('rules_root'), 'verification': r.get('verification') or {'checked': False}, 'assets': r.get('assets') or {}})
    current = None
    if latest:
        current = {'package': latest.get('package'), 'package_sha256': latest.get('package_sha256'), 'manifest': latest.get('manifest'),
                   'manifest_sha256': latest.get('manifest_sha256'), 'signature': latest.get('signature'), 'inclusion_proof': latest.get('inclusion_proof'),
                   'checkpoint': latest.get('checkpoint'), 'checkpoint_signature': latest.get('checkpoint_signature'), 'source': 'latest.json'}
    return {'schema': SCHEMA_PACKAGES, 'source': 'releases.json + latest.json', 'current': current, 'packages': out,
            'premium': {'available': [], 'note': 'Premium packages are not published yet. They will be served only behind server-side authorisation; PoC and exploit code is never part of any package.'}}


def write(site: pathlib.Path, root: pathlib.Path, rows: list) -> None:
    cfg_file = root / 'config' / 'intel-families.json'
    config = json.loads(cfg_file.read_text()) if cfg_file.exists() else {'families': []}
    latest = json.loads((site / 'latest.json').read_text()) if (site / 'latest.json').exists() else None
    (site / 'families.json').write_text(json.dumps(families(config, latest), indent=1, sort_keys=True) + '\n')
    (site / 'packages.json').write_text(json.dumps(packages(rows, latest), indent=1, sort_keys=True) + '\n')
