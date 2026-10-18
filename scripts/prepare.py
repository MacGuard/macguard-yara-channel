#!/usr/bin/env python3
"""Fetch pinned GitHub commit snapshots, normalize inventory without changing rule semantics."""
import hashlib, json, os, pathlib, re, shutil, subprocess, tarfile, tempfile, urllib.request
from datetime import datetime, timezone
ROOT=pathlib.Path(__file__).resolve().parents[1]
OUT=ROOT/'dist'; OUT.mkdir(exist_ok=True)
CFG=json.loads((ROOT/'config/sources.json').read_text())
MAX_DOWNLOAD=90_000_000
POLICY=json.loads((ROOT/'config/policy.json').read_text())
sys_path=__import__('sys').path; sys_path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import licensing

def request(url):
    req=urllib.request.Request(url,headers={'User-Agent':'MacGuard-YARA-Channel/0.1','Accept':'application/vnd.github+json'})
    with urllib.request.urlopen(req,timeout=25) as r:
        data=r.read(MAX_DOWNLOAD+1)
    if len(data)>MAX_DOWNLOAD: raise RuntimeError('Download exceeds limit')
    return data

def sha(data): return hashlib.sha256(data).hexdigest()

def extract_safe(data, destination):
    import io
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as t:
        members=t.getmembers()
        if len(members)>25000: raise RuntimeError('Too many archive entries')
        for m in members:
            pp=pathlib.PurePosixPath(m.name)
            if m.issym() or m.islnk() or m.isdev() or m.isfifo() or pp.is_absolute() or '..' in pp.parts:
                raise RuntimeError('Unsafe archive member')
        t.extractall(destination,filter='data')

inventory=[]; sources=[]; rejected=[]
with tempfile.TemporaryDirectory() as td:
    for source in CFG['sources']:
        repo=source['repo']; org,name=repo.split('/')
        meta=json.loads(request(f'https://api.github.com/repos/{repo}/commits/HEAD'))
        commit=meta['sha']
        record={'id':source['id'],'repository':repo,'commit':commit,'kind':source['kind']}
        if source['kind']=='rules':
            try: spdx,text=licensing.fetch(repo,os.environ.get('GITHUB_TOKEN') or os.environ.get('GH_TOKEN',''))
            except Exception as e: spdx,text='',''
            record['license_check']=licensing.verdict(POLICY['licenses'].get(repo),spdx,text)
        sources.append(record)
        if source['kind']!='rules': continue
        archive=request(f'https://api.github.com/repos/{repo}/tarball/{commit}')
        folder=pathlib.Path(td)/source['id'];folder.mkdir()
        extract_safe(archive,folder)
        top=next(folder.iterdir())
        for path in sorted(top.rglob('*')):
            if not path.is_file() or path.suffix.lower() not in ('.yar','.yara'): continue
            rel=path.relative_to(top)
            if not any(str(rel)==prefix or str(rel).startswith(prefix+'/') for prefix in source['paths']): continue
            raw=path.read_bytes()
            if len(raw)>1_000_000 or b'\x00' in raw:
                rejected.append({'source':source['id'],'path':str(rel),'reason':'size-or-binary'});continue
            target=OUT/'rules'/source['id']/rel
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(raw)
            inventory.append({'source':source['id'],'path':str(target.relative_to(OUT)), 'sha256':sha(raw),'bytes':len(raw)})
manifest={'schema':1,'created_at':datetime.now(timezone.utc).isoformat(),'sources':sources,'files':inventory,'rejected':rejected,'status':'UNSIGNED_CANDIDATE'}
(OUT/'candidate.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
print(f'Prepared {len(inventory)} rules; {len(rejected)} rejected. Unsigned candidate only.')
