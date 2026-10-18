#!/usr/bin/env python3
"""Fail closed on syntax errors. This checks parsing, not detection efficacy."""
import json, os, pathlib, shutil, subprocess, sys
root=pathlib.Path(__file__).resolve().parents[1]
manifest=json.loads((root/'dist/candidate.json').read_text())
engine=shutil.which('yarac')
if not engine: sys.exit('ERROR: YARA compiler (yarac) missing in CI')
# External variables the rule sets expect the scanner to supply (signature-base, Yara-Rules).
# Compilation only needs them declared; the scanning host must provide real values.
EXTERNALS=['-d','filepath=','-d','filename=','-d','extension=','-d','filetype=','-d','owner=','-d','md5=','-d','is__elf=false']
fail=[]
for item in manifest['files']:
    p=root/'dist'/item['path']
    try:
        cp=subprocess.run([engine,'-w',*EXTERNALS,str(p),os.devnull],capture_output=True,text=True,timeout=8)
        if cp.returncode: fail.append({'file':item['path'],'error':cp.stderr[-400:]})
    except subprocess.TimeoutExpired: fail.append({'file':item['path'],'error':'timeout'})
(root/'dist/validation.json').write_text(json.dumps({'engine':'yara','checked':len(manifest['files']),'failures':fail},indent=2))
if fail: sys.exit(f'Validation failed for {len(fail)} rules; no release')
print('All selected rules parsed successfully')
