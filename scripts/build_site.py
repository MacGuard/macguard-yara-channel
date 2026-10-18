#!/usr/bin/env python3
"""Assemble the static site: web/ + latest signed release + transparency log + latest.json."""
import hashlib, json, pathlib, shutil, sys, tarfile
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import catalog, tlog, stats
root = pathlib.Path(__file__).resolve().parents[1]
site = root / 'site'; release = root / 'release'
shutil.rmtree(site, ignore_errors=True)
shutil.copytree(root / 'web', site)
if (release / 'manifest.json').exists():
    for name in ('manifest.json', 'manifest.sigstore.json', 'inclusion-proof.json'): shutil.copy(release / name, site / name)
    with tarfile.open(release / 'rules-release.tar.gz') as t:
        t.extractall(site, filter='data')
    shutil.copy(release / 'rules-release.tar.gz', site / 'rules-release.tar.gz')
    body = (release / 'manifest.json').read_bytes(); manifest = json.loads(body)
    (site / 'latest.json').write_text(json.dumps({
        'schema': 1, 'manifest': 'manifest.json', 'signature': 'manifest.sigstore.json', 'inclusion_proof': 'inclusion-proof.json', 'checkpoint': 'logs/checkpoint.txt', 'checkpoint_signature': 'logs/checkpoint.sigstore.json', 'manifest_sha256': hashlib.sha256(body).hexdigest(),
        'rules_root': manifest.get('rules_root'), 'log': manifest.get('log')}, indent=2, sort_keys=True) + '\n')
    print('Site includes the latest signed release')
else:
    print('No release yet: publishing the web only')
if (root / 'logs').exists(): shutil.copytree(root / 'logs', site / 'logs')

# --- release history, catalog and consistency evidence, all derived from signed manifests ---
hist_dir = root / 'history'          # history/<tag>/{meta.json, manifest.json, verification.json?} written by the workflow
releases = []
for d in sorted(hist_dir.glob('*/')) if hist_dir.exists() else []:
    if not (d / 'manifest.json').exists() or not (d / 'meta.json').exists(): continue
    meta = json.loads((d / 'meta.json').read_text())
    ver = json.loads((d / 'verification.json').read_text()) if (d / 'verification.json').exists() else None
    releases.append({'tag': meta['tag'], 'published_at': meta['published_at'], 'url': meta['url'], 'manifest': json.loads((d / 'manifest.json').read_text()), 'verification': ver})
rows = catalog.history(releases)
(site / 'releases.json').write_text(json.dumps({'schema': 1, 'releases': catalog.public_rows(rows),
    'note': 'added/modified/removed compare the signed manifests path by path and hash by hash. GitHub Releases are the canonical archive.'}, indent=1) + '\n')
if (site / 'manifest.json').exists():
    manifest = json.loads((site / 'manifest.json').read_text())
    tag = rows[-1]['tag'] if rows else 'latest'
    seen = catalog.first_seen([(r['tag'], r['manifest']) for r in sorted(releases, key=lambda r: (r['published_at'], r['tag']))])
    (site / 'catalog.json').write_text(json.dumps(catalog.build_catalog(manifest, seen, tag), separators=(',', ':')) + '\n')
    log_lines = (root / 'logs' / 'log.jsonl').read_bytes().split(b'\n') if (root / 'logs' / 'log.jsonl').exists() else []
    log_lines = [l for l in log_lines if l]
    if len(rows) >= 2 and rows[-2].get('log'):
        doc = catalog.consistency_doc(log_lines, rows[-2]['log'], manifest.get('log'))
        if doc: (site / 'consistency.json').write_text(json.dumps(doc, indent=1) + '\n'); print('Consistency proof published')
stats.build(root / 'logs' / 'log.jsonl', site / 'stats.json', releases=catalog.public_rows(rows))   # recomputed on every deploy; keeps the last 30 days
print(f'Site assembled in {site}')
