#!/usr/bin/env python3
"""Sign canonical manifest using Ed25519 private key provided by protected signing job."""
import base64, hashlib, json, os, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import tlog
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
root=pathlib.Path(__file__).resolve().parents[1]
folder=root/'dist'
manifest=json.loads((folder/'candidate.json').read_text())
validation=json.loads((folder/'validation.json').read_text())
if validation['failures']: sys.exit('Unvalidated rules cannot be signed')
key=os.getenv('MACGUARD_ED25519_PRIVATE_KEY_B64')
if not key: sys.exit('Missing signing key; cannot publish')
head=root/'logs'/'checkpoint.txt'
if not head.exists(): sys.exit('No signed log checkpoint; run tlog.py checkpoint before signing')
log_size,log_root=tlog.Log.parse_checkpoint(head.read_bytes())
manifest['rules_root']=tlog.rules_root(manifest['files'])
manifest['log']={'origin':tlog.ORIGIN,'size':log_size,'root':log_root.hex()}
manifest['status']='PUBLISHED';manifest['validation']={'checked':validation['checked'],'engine':validation['engine']}
body=json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()
(folder/'manifest.json').write_bytes(body)
sig=Ed25519PrivateKey.from_private_bytes(base64.b64decode(key,validate=True)).sign(body)
(folder/'manifest.sig').write_text(base64.b64encode(sig).decode()+'\n')
print('Manifest signed (Ed25519). Public key must be pinned in the macOS client.')
