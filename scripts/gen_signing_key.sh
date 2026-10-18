#!/usr/bin/env bash
# Run once, locally: creates the Ed25519 signing key, stores the private half only as a GitHub
# environment secret (never written to disk) and writes the public half to config/signing_pubkey.b64.
set -euo pipefail
REPO="${1:-MacGuard/macguard-yara-channel}"
cd "$(dirname "$0")/.."
VENV="$(mktemp -d)"
trap 'rm -rf "$VENV"' EXIT
python3 -m venv "$VENV"
"$VENV/bin/pip" install -q 'cryptography==44.0.2'
"$VENV/bin/python" - "$REPO" <<'PY'
import base64, subprocess, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as s
k = Ed25519PrivateKey.generate()
priv = base64.b64encode(k.private_bytes(s.Encoding.Raw, s.PrivateFormat.Raw, s.NoEncryption()))
pub = base64.b64encode(k.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)).decode()
subprocess.run(['gh', 'secret', 'set', 'MACGUARD_ED25519_PRIVATE_KEY_B64', '-R', sys.argv[1], '--env', 'stable-signing'], input=priv, check=True)
open('config/signing_pubkey.b64', 'w').write(pub + '\n')
print('Public key (pin it in the app):', pub)
PY
