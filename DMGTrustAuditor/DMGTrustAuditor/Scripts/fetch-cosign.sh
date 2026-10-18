#!/usr/bin/env bash
# Downloads the pinned official cosign release binary for an architecture, verifies it against its own Sigstore bundle,
# checks the SHA-256 against the pins in Core/SigstoreVerifier.swift, and installs it as Helpers/cosign for packaging.
# usage: Scripts/fetch-cosign.sh arm64|amd64 DEST_DIR      (needs gh and a trusted cosign to verify with)
set -euo pipefail
arch="$1"; dest="$2"; version=v3.1.1
declare -A pin=( [arm64]=94b42a9e697be95675f6160ab031a9a5f1ec1e646d6f648d7b2f5cd59ececbc5 [amd64]=14d2678dfbfde18798151e86fbd91ebdadbb7424b18412a42a155dd8a2df4c7a )
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
gh release download "$version" -R sigstore/cosign -p "cosign-darwin-$arch" -p "cosign-darwin-$arch.sigstore.json" -D "$tmp"
cosign verify-blob --bundle "$tmp/cosign-darwin-$arch.sigstore.json" --certificate-identity keyless@projectsigstore.iam.gserviceaccount.com --certificate-oidc-issuer https://accounts.google.com "$tmp/cosign-darwin-$arch"
got="$(shasum -a 256 "$tmp/cosign-darwin-$arch" | cut -d' ' -f1)"
[ "$got" = "${pin[$arch]}" ] || { echo "hash $got does not match the pin ${pin[$arch]}" >&2; exit 1; }
mkdir -p "$dest"; install -m 0755 "$tmp/cosign-darwin-$arch" "$dest/cosign"; echo "cosign $version ($arch) installed and verified in $dest"
