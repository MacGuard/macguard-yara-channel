#!/usr/bin/env python3
"""Assemble the static site: web/ + latest signed release + transparency log + latest.json."""
import hashlib, json, pathlib, shutil, sys, tarfile
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import catalog, tlog, stats
root = pathlib.Path(__file__).resolve().parents[1]
site = root / 'site'; release = root / 'release'
import html
def plain_list(c):
    """Static fallback of the catalog for browsers without JavaScript."""
    rows = ''.join('<tr><td><a href="%s">%s</a></td><td>%s</td><td>%s</td><td>%s</td><td><code>%s</code></td><td>%d</td></tr>' % (
        html.escape(f['path']), html.escape(f['name']), html.escape(f['category']), html.escape(f['source'] or ''), html.escape((f['commit'] or '')[:10]), f['sha256'], f['bytes']) for f in c['files'])
    return ('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>YARA rules (plain list) · MacGuard YARA Channel</title>'
            '<link rel="stylesheet" href="style.css"><main><h1>YARA rules (plain list)</h1><p>%d files from release %s, generated from the signed manifest. A matching SHA-256 shows the file is the published one; it is not an individual signature. '
            '<a href="./">Back</a> · <a href="manifest.json">manifest.json</a> · <a href="manifest.sigstore.json">manifest.sigstore.json</a></p><div class="tablewrap"><table><caption class="sr">Rules</caption><thead><tr><th scope="col">File</th><th scope="col">Category</th><th scope="col">Source</th><th scope="col">Commit</th><th scope="col">SHA-256</th><th scope="col">Bytes</th></tr></thead><tbody>%s</tbody></table></div></main></html>') % (c['count'], html.escape(str(c['release'])), rows)
shutil.rmtree(site, ignore_errors=True)
shutil.copytree(root / 'web', site)
if (release / 'manifest.json').exists():
    for name in ('manifest.json', 'manifest.sigstore.json', 'inclusion-proof.json'): shutil.copy(release / name, site / name)
    with tarfile.open(release / 'rules-release.tar.gz') as t:
        t.extractall(site, filter='data')
    shutil.copy(release / 'rules-release.tar.gz', site / 'rules-release.tar.gz')
    body = (release / 'manifest.json').read_bytes(); manifest = json.loads(body)
    exp = sum(f['bytes'] for f in manifest['files'])
    yara_rules = sum(catalog.count_rules((site / f['path']).read_text(errors='replace')) for f in manifest['files'])
    (site / 'latest.json').write_text(json.dumps({'stats': {'files': len(manifest['files']), 'yara_rules': yara_rules, 'expanded_bytes': exp, 'package_bytes': (release / 'rules-release.tar.gz').stat().st_size,
        'source': 'counted by the site build from the files that passed verification'},
        'schema': 1, 'manifest': 'manifest.json', 'signature': 'manifest.sigstore.json', 'inclusion_proof': 'inclusion-proof.json', 'checkpoint': 'logs/checkpoint.txt', 'checkpoint_signature': 'logs/checkpoint.sigstore.json', 'manifest_sha256': hashlib.sha256(body).hexdigest(), 'package': 'rules-release.tar.gz', 'package_sha256': hashlib.sha256((release / 'rules-release.tar.gz').read_bytes()).hexdigest(), 'package_bytes': (release / 'rules-release.tar.gz').stat().st_size,
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
    releases.append({'tag': meta['tag'], 'published_at': meta['published_at'], 'url': meta['url'], 'package_bytes': meta.get('package_bytes'), 'asset_names': meta.get('asset_names'), 'manifest': json.loads((d / 'manifest.json').read_text()), 'verification': ver})
rows = catalog.history(releases)
(site / 'releases.json').write_text(json.dumps({'schema': 1, 'releases': catalog.public_rows(rows),
    'note': 'added/modified/removed compare the signed manifests path by path and hash by hash. GitHub Releases are the canonical archive.'}, indent=1) + '\n')
if (site / 'manifest.json').exists():
    manifest = json.loads((site / 'manifest.json').read_text())
    tag = rows[-1]['tag'] if rows else 'latest'
    seen = catalog.first_seen([(r['tag'], r['manifest']) for r in sorted(releases, key=lambda r: (r['published_at'], r['tag']))])
    (site / 'catalog.json').write_text(json.dumps(catalog.build_catalog(manifest, seen, tag, platform_of=lambda p: catalog.platforms((site / p).read_text(errors='replace'))), separators=(',', ':')) + '\n')
    (site / 'rules-list.html').write_text(plain_list(json.loads((site / 'catalog.json').read_text())))
    log_lines = (root / 'logs' / 'log.jsonl').read_bytes().split(b'\n') if (root / 'logs' / 'log.jsonl').exists() else []
    log_lines = [l for l in log_lines if l]
    if len(rows) >= 2 and rows[-2].get('log'):
        doc = catalog.consistency_doc(log_lines, rows[-2]['log'], manifest.get('log'))
        if doc: (site / 'consistency.json').write_text(json.dumps(doc, indent=1) + '\n'); print('Consistency proof published')
stats.build(root / 'logs' / 'log.jsonl', site / 'stats.json', releases=catalog.public_rows(rows))
# --- multi-family portal data (catalog.html, packages.html): real states only, no invented counts or downloads ---
import portal
portal.write(site, root, catalog.public_rows(rows))
# --- Threat Intelligence Hub: hub.json, sources.json, and intel packages / the static KEV index ONLY from packages verified in this build ---
import portal_hub
_hub = portal_hub.write(site, root, catalog.public_rows(rows))
print('Hub data written:', 'static KEV index from a verified package' if _hub['kev_static'] else 'no verified KEV package (KEV shown as unavailable)')
# --- the independent verifier, with its hash (same-origin copies are a convenience, not a root of trust: see the Verification page) ---
shutil.copy(root / 'scripts' / 'verify_public_release.py', site / 'verify_public_release.py')
(site / 'verify_public_release.py.sha256').write_text(hashlib.sha256((site / 'verify_public_release.py').read_bytes()).hexdigest() + '  verify_public_release.py\n')
# --- documentation (Markdown in docs-src/, numbers read from the files published above); a build error stops the site build ---
import build_docs
report = build_docs.build(site / 'docs', site)
print(f"Documentation built: {report['pages']} pages")   # recomputed on every deploy; keeps the last 30 days
import csp
print(f'Vulnerability API: {portal_hub.inject_api(site, csp.api_base()) or "not configured (static KEV search only)"}')
print(f'Content Security Policy written to {csp.inject(site)} pages')   # GitHub Pages cannot send headers, so the policy travels in each page
print(f'Site assembled in {site}')
