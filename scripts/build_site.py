#!/usr/bin/env python3
"""Assemble the static site: web/ + latest signed release + transparency log + latest.json."""
import hashlib, json, pathlib, shutil, sys, tarfile
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import tlog
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
print(f'Site assembled in {site}')
