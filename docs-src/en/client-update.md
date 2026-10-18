---
title: Update in MacGuard
summary: How the app downloads, verifies and installs the rules.
---
## Normal flow

{{diagram:client-update}}

The app does not update on its own without consent. It downloads into a private staging folder with per-file size limits, extracts with limits (no links or paths outside the directory) and only activates the rules when **every** check has passed.

## What it checks

- Sigstore signature of the manifest and the checkpoint with the expected identity and issuer.
- SHA-256 of every file against the signed manifest, and that none is extra or missing.
- `rules_root`, the inclusion proof and that the checkpoint matches the log head in the manifest.
- Consistency with the saved trusted checkpoint (rollback and fork protection).

## Origins

The app downloads from GitHub Pages first (`https://macguard.github.io/macguard-yara-channel/`) and, only if that origin does not answer, from the Cloudflare Pages mirror (`https://macguard-rules.pages.dev/`). Each attempt installs from **one** origin end to end; it never mixes files from the two. Both serve the same signed bytes and the release is verified the same way in both cases. A verification failure does not fall through to the next origin.

## YARA engine

MacGuard ships its own YARA engine {{tool.yara}} (with OpenSSL {{tool.openssl}}) as a universal Intel/ARM build. Before using the engine it checks the hashes of its manifest, its code signature, its version, its architecture and a self-test. Every rule file is loaded in its own namespace with the signed dependencies.

> **LIMIT** Developer ID signing and notarization of the app, the engine and the bundled `cosign` are app release steps that are still pending.

## Atomic install

{{diagram:client-atomic-install}}
