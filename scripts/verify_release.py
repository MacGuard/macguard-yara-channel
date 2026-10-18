#!/usr/bin/env python3
"""Verify a published release the way a client must: signatures, file hashes, rules root and log inclusion.

usage: verify_release.py DIR --identity WORKFLOW_IDENTITY --repo OWNER/NAME
DIR holds manifest.json, manifest.sigstore.json, inclusion-proof.json, rules/ and logs/ (checkpoint + bundle)."""
import argparse, hashlib, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import tlog
ap=argparse.ArgumentParser(); ap.add_argument('dir'); ap.add_argument('--identity',required=True); ap.add_argument('--repo',required=True)
a=ap.parse_args(); d=pathlib.Path(a.dir); verify=tlog.cosign_verifier(a.identity,a.repo)
def fail(msg): sys.exit(f'VERIFY FAILED: {msg}')
manifest_path=d/'manifest.json'
err=verify(manifest_path,d/'manifest.sigstore.json')
if err: fail(f'manifest signature: {err}')
m=json.loads(manifest_path.read_text())
for f in m['files']:
    p=d/f['path']
    if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=f['sha256']: fail(f"{f['path']} does not match the manifest")
if tlog.rules_root(m['files'])!=m['rules_root']: fail('rules_root does not match the file list')
cp=d/'logs'/'checkpoint.txt'; body=cp.read_bytes()
err=verify(cp,d/'logs'/'checkpoint.sigstore.json')
if err: fail(f'checkpoint signature: {err}')
size,root=tlog.Log.parse_checkpoint(body)
if m['log']['size']!=size or m['log']['root']!=root.hex(): fail('manifest log head differs from the signed checkpoint')
err=tlog.check_inclusion_proof(json.loads((d/'inclusion-proof.json').read_text()),body,m['rules_root'])
if err: fail(err)
print(f"release OK: {len(m['files'])} files, rules_root {m['rules_root'][:16]}..., included in log of {size} entries")
