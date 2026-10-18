#!/usr/bin/env python3
"""Write the canonical manifest of a validated candidate. The workflow signs it afterwards with Sigstore (cosign)."""
import json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import tlog
root=pathlib.Path(__file__).resolve().parents[1]
folder=root/'dist'
manifest=json.loads((folder/'candidate.json').read_text())
validation=json.loads((folder/'validation.json').read_text())
if validation['failures']: sys.exit('Unvalidated rules cannot be published')
head=root/'logs'/'checkpoint.txt'
if not head.exists(): sys.exit('No log checkpoint; run tlog.py checkpoint before sealing')
log_size,log_root=tlog.Log.parse_checkpoint(head.read_bytes())
manifest['rules_root']=tlog.rules_root(manifest['files'])
manifest['log']={'origin':tlog.ORIGIN,'size':log_size,'root':log_root.hex()}
manifest['status']='PUBLISHED';manifest['validation']={'checked':validation['checked'],'engine':validation['engine']}
(folder/'manifest.json').write_bytes(json.dumps(manifest,sort_keys=True,separators=(',',':')).encode())
print('Manifest written; it must now be signed with cosign.')
