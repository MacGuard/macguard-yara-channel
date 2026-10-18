#!/usr/bin/env python3
"""Fail closed on syntax errors. This checks parsing, not detection efficacy."""
import json, pathlib, shutil, subprocess, sys
root=pathlib.Path(__file__).resolve().parents[1]
manifest=json.loads((root/'dist/candidate.json').read_text())
engine=shutil.which('yara')
if not engine: sys.exit('ERROR: YARA compiler missing in CI')
fail=[]
for item in manifest['files']:
    p=root/'dist'/item['path']
    try:
        cp=subprocess.run([engine,'-w',str(p),str(p)],capture_output=True,text=True,timeout=8)
        if cp.returncode: fail.append({'file':item['path'],'error':cp.stderr[-400:]})
    except subprocess.TimeoutExpired: fail.append({'file':item['path'],'error':'timeout'})
(root/'dist/validation.json').write_text(json.dumps({'engine':'yara','checked':len(manifest['files']),'failures':fail},indent=2))
if fail: sys.exit(f'Validation failed for {len(fail)} rules; no release')
print('All selected rules parsed successfully')
