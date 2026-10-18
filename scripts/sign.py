#!/usr/bin/env python3
"""Sign canonical manifest using Ed25519 private key provided by protected signing job."""
import base64, hashlib, json, os, pathlib, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
root=pathlib.Path(__file__).resolve().parents[1]
folder=root/'dist'
manifest=json.loads((folder/'candidate.json').read_text())
validation=json.loads((folder/'validation.json').read_text())
if validation['failures']: sys.exit('Unvalidated rules cannot be signed')
key=os.getenv('MACGUARD_ED25519_PRIVATE_KEY_B64')
if not key: sys.exit('Missing signing key; cannot publish')
manifest['status']='PUBLISHED';manifest['validation']={'checked':validation['checked'],'engine':validation['engine']}
body=json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()
(folder/'manifest.json').write_bytes(body)
sig=Ed25519PrivateKey.from_private_bytes(base64.b64decode(key,validate=True)).sign(body)
(folder/'manifest.sig').write_text(base64.b64encode(sig).decode()+'\n')
print('Manifest signed (Ed25519). Public key must be pinned in the macOS client.')
