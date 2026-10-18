#!/usr/bin/env python3
"""Fail closed on syntax errors. This checks parsing, not detection efficacy."""
import json, os, pathlib, re, shutil, subprocess, sys
root=pathlib.Path(__file__).resolve().parents[1]
manifest=json.loads((root/'dist/candidate.json').read_text())
engine=shutil.which('yarac')
if not engine: sys.exit('ERROR: YARA compiler (yarac) missing in CI')
# External variables the rule sets expect the scanner to supply (signature-base, Yara-Rules).
# Compilation only needs them declared; the scanning host must provide real values.
EXTERNALS=['-d','filepath=','-d','filename=','-d','extension=','-d','filetype=','-d','owner=','-d','md5=']
fail=[]
# Some rule files depend on rules defined in other files (e.g. global private "is__elf").
# Index rule names so a file can be compiled together with the files it needs.
DEFINES={}
for item in manifest['files']:
    text=(root/'dist'/item['path']).read_text(errors='replace')
    for name in re.findall(r'^\s*(?:(?:global|private)\s+)*rule\s+(\w+)',text,re.M): DEFINES.setdefault(name,item['path'])
def compile_set(paths):
    return subprocess.run([engine,'-w',*EXTERNALS,*[str(root/'dist'/q) for q in paths],os.devnull],capture_output=True,text=True,timeout=8)
for item in manifest['files']:
    paths=[item['path']]
    try:
        for _ in range(5):
            cp=compile_set(paths)
            missing=re.findall(r'undefined identifier "(\w+)"',cp.stderr)
            extra=[DEFINES[m] for m in dict.fromkeys(missing) if m in DEFINES and DEFINES[m] not in paths]
            if cp.returncode and extra: paths+=extra; continue
            break
        if cp.returncode: fail.append({'file':item['path'],'error':cp.stderr[-400:]})
    except subprocess.TimeoutExpired: fail.append({'file':item['path'],'error':'timeout'})
(root/'dist/validation.json').write_text(json.dumps({'engine':'yara','checked':len(manifest['files']),'failures':fail},indent=2))
if fail: sys.exit(f'Validation failed for {len(fail)} rules; no release')
print('All selected rules parsed successfully')
