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
bad=tlog.check_inventory(m.get('files'))
if bad: fail(f'manifest inventory: {bad}')
for f in m['files']:
    p=d/f['path']
    if f.get('bytes') is not None and p.is_file() and p.stat().st_size!=f['bytes']: fail(f"{f['path']} has a different size than the manifest")
    if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=f['sha256']: fail(f"{f['path']} does not match the manifest")
listed={f['path'] for f in m['files']}
extra=sorted(str(q.relative_to(d)) for q in (d/'rules').rglob('*') if q.is_file() and str(q.relative_to(d)) not in listed) if (d/'rules').is_dir() else []
if extra: fail(f'files in the package that the signed manifest does not list: {extra[:3]}')
st=m.get('stats') or {}
if st and (st.get('files')!=len(m['files']) or st.get('expanded_bytes')!=sum(f['bytes'] for f in m['files'])): fail('manifest stats do not match the file list')
if tlog.rules_root(m['files'])!=m['rules_root']: fail('rules_root does not match the file list')
cp=d/'logs'/'checkpoint.txt'; body=cp.read_bytes()
err=verify(cp,d/'logs'/'checkpoint.sigstore.json')
if err: fail(f'checkpoint signature: {err}')
size,root=tlog.Log.parse_checkpoint(body)
if m['log']['size']!=size or m['log']['root']!=root.hex(): fail('manifest log head differs from the signed checkpoint')
err=tlog.check_inclusion_proof(json.loads((d/'inclusion-proof.json').read_text()),body,m['rules_root'])
if err: fail(err)
ev=m.get('evidence')
if ev is not None:   # releases made after the evidence field was introduced must carry consistent evidence; older ones simply do not have it
    dyn=ev.get('dynamic') or {}
    if dyn.get('set_root')!=m['rules_root']: fail('evidence: the dynamic measurement belongs to a different rule set')
    if dyn.get('verdict') not in ('ok','no-baseline') or dyn.get('canaries_detected')!=dyn.get('canaries_expected'): fail('evidence: the dynamic measurement does not pass')
print(f"release OK: {len(m['files'])} files, rules_root {m['rules_root'][:16]}..., included in log of {size} entries")
