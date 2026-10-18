#!/usr/bin/env bash
# Fetches the current Sigstore public-good trusted root through TUF and prints its SHA-256 for pinning.
set -euo pipefail
out="$(dirname "$0")/../Resources/sigstore/trusted_root.json"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
COSIGN_ROOT="$tmp" cosign initialize --mirror https://tuf-repo-cdn.sigstore.dev --root-checksum "" >/dev/null 2>&1 || cosign initialize >/dev/null
src="${HOME}/.sigstore/root/tuf-repo-cdn.sigstore.dev/targets/trusted_root.json"
cp "$src" "$out"; shasum -a 256 "$out"
echo "Add this hash to SigstoreVerifier.pinnedTrustedRoots, review the diff, then ship an app update."
