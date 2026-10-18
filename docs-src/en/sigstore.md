---
title: Sigstore signatures
summary: Keyless signing with the workflow identity, and what exactly is verified.
---
## How signing works

There is no private key stored anywhere. During `publish.yml`, `cosign sign-blob` asks GitHub for an OIDC token naming the workflow, Fulcio issues a short-lived certificate bound to that identity, the signature is recorded in Rekor and everything is stored in a `.sigstore.json` bundle.

{{diagram:sigstore-sequence}}

## What is signed and with which identity

| Artifact | Bundle |
|---|---|
| `manifest.json` | `manifest.sigstore.json` |
| `checkpoint.txt` | `checkpoint.sigstore.json` |

- Certificate identity: `{{identity}}`.
- OIDC issuer: `{{issuer}}`.
- Workflow repository: `{{repo}}` (`--certificate-github-workflow-repository`).

The package `rules-release.tar.gz` is **not** signed separately: it is covered because the signed manifest contains the SHA-256 of each file and `rules_root`, and the package is checked to contain exactly those files.

## In MacGuard

The app ships a pinned `cosign` ({{tool.cosign}}, SHA-256 checked) and a pinned `trusted_root.json` trust root; it verifies offline with `--trusted-root`. There is no maintained Swift Sigstore library, which is why cosign is used (see `DMGTrustAuditor/DMGTrustAuditor/docs/ADR-0001-sigstore-verification.md`).

> **LIMIT** **There are no SLSA or in-toto attestations.** Only two blobs are signed with Sigstore. That proves which workflow signed those bytes; by itself it does not prove the build process was the expected one beyond the workflow identity.

> **PROPOSED** Adding provenance attestations (SLSA) would be a design change; it is not implemented or scheduled in this repository.
