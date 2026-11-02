#!/usr/bin/env python3
"""Write the canonical manifest of a validated candidate. The workflow signs it afterwards with Sigstore (cosign)."""
import json, os, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import catalog, tlog
root=pathlib.Path(__file__).resolve().parents[1]
folder=root/'dist'
manifest=json.loads((folder/'candidate.json').read_text())
validation=json.loads((folder/'validation.json').read_text())
if validation['failures']: sys.exit('Unvalidated rules cannot be published')
head=root/'logs'/'checkpoint.txt'
if not head.exists(): sys.exit('No log checkpoint; run tlog.py checkpoint before sealing')
log_size,log_root=tlog.Log.parse_checkpoint(head.read_bytes())
bad=tlog.check_inventory(manifest['files'])
if bad: sys.exit(f'The inventory cannot be sealed: {bad}')
manifest['rules_root']=tlog.rules_root(manifest['files'])
manifest['log']={'origin':tlog.ORIGIN,'size':log_size,'root':log_root.hex()}
# Counts derived from the files themselves; they are signed with the manifest. Old clients ignore unknown fields.
# yara_rules: rule declarations matched line-wise, including commented-out ones (kept for verifier compatibility);
# yara_rules_compiled: rules outside comments and strings, the ones YARA compiles. See catalog.release_stats.
manifest['stats']=catalog.release_stats(folder,manifest['files'])
manifest['status']='PUBLISHED';manifest['validation']={'checked':validation['checked'],'engine':validation['engine']}
# Evidence that the set published is the set that was tested. It is signed with the manifest, so a client can see which review run, which
# commit of the workflows and which dynamic measurement the signature covers. It is the publishing workflow's statement, not an independent attestation.
dyn_path=folder/'dynamic.json'
if not dyn_path.exists(): sys.exit('No dynamic evidence for this candidate; it cannot be sealed')
dyn=json.loads(dyn_path.read_text())
if dyn.get('set_root')!=manifest['rules_root']: sys.exit('The dynamic evidence belongs to a different rule set; it cannot be sealed')
if dyn.get('verdict') not in ('ok','no-baseline') or dyn.get('canaries_detected')!=dyn.get('canaries_expected'): sys.exit('The dynamic evidence does not pass; it cannot be sealed')
manifest['evidence']={'candidate_run_id':os.environ.get('RUN_ID',''),'candidate_workflow_sha':os.environ.get('CANDIDATE_SHA',''),'publish_run_url':os.environ.get('RUN_URL',''),
    'dynamic':{k:dyn.get(k) for k in ('set_root','verdict','engine','platform','canaries_detected','canaries_expected')},'dynamic_corpus':dyn.get('corpus')}
(folder/'manifest.json').write_bytes(json.dumps(manifest,sort_keys=True,separators=(',',':')).encode())
print('Manifest written; it must now be signed with cosign.')
