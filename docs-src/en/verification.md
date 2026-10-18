---
title: Verifying rules, signatures and transparency
summary: How to check a release yourself without trusting this site: commands, real URLs and how to read the results.
---
## A. What you will check

A release is valid if (1) the manifest and the checkpoint are signed by the expected workflow identity, (2) every package file matches the SHA-256 in the signed manifest, (3) the recomputed Merkle root equals `rules_root`, and (4) the checkpoint contains the release entry and extends the one you already knew.

> **LIMIT** A valid signature and matching hashes prove **who** published exactly **those bytes**. They do not prove the rules are good or that scanned files are safe.

## B. Requirements

- `cosign` ({{tool.cosign}} or later), installed from its official source.
- Python 3 for the verifier and the Merkle recomputation; nothing beyond the standard library.
- `shasum` (macOS) or `sha256sum` (Linux).

## C. Artifacts of the latest release

Release [`{{release.tag}}`]({{release.url}}). The mandatory artifacts download from this path:

```
{{release.download}}/rules-release.tar.gz
{{release.download}}/manifest.json
{{release.download}}/manifest.sigstore.json
{{release.download}}/inclusion-proof.json
{{release.download}}/checkpoint.txt
{{release.download}}/checkpoint.sigstore.json
```

Optional: `release.json`, `changes.json`, `CHANGELOG.md` and `consistency.json` (the latter proves the log extends the previous release log). To download them all:

```bash
mkdir verify && cd verify
gh release download {{release.tag}} --repo {{repo}}
```

## D. Verify the signature with cosign

Minimal example with the expected identity and issuer:

```bash
cosign verify-blob manifest.json \
  --bundle manifest.sigstore.json \
  --certificate-identity "{{identity}}" \
  --certificate-oidc-issuer "{{issuer}}"
```

Full version, which also requires the certificate to name this repository, for the manifest and for the checkpoint:

```bash
cosign verify-blob manifest.json \
  --bundle manifest.sigstore.json \
  --certificate-identity "{{identity}}" \
  --certificate-oidc-issuer "{{issuer}}" \
  --certificate-github-workflow-repository "{{repo}}"

cosign verify-blob checkpoint.txt \
  --bundle checkpoint.sigstore.json \
  --certificate-identity "{{identity}}" \
  --certificate-oidc-issuer "{{issuer}}" \
  --certificate-github-workflow-repository "{{repo}}"
```

Correct result: `Verified OK`. If the identity or issuer do not match, cosign fails; do not run anything from that release.

## E. Verify the package hashes

SHA-256 of the package (must be `{{release.package_sha256}}` for this release) and of the manifest (`{{release.manifest_sha256}}`):

```bash
# macOS
shasum -a 256 rules-release.tar.gz manifest.json
# Linux
sha256sum rules-release.tar.gz manifest.json
```

The package hash is **not** signed separately; what ties it to the signature is that every extracted file has the SHA-256 listed in `manifest.json`. The verifier does it for you (section G).

## F. Recompute `rules_root` and inclusion

The manual recomputation of `rules_root` is in [Merkle trees](page:merkle). The inclusion proof (`inclusion-proof.json`) is checked by the verifier: it carries the release log entry up to the checkpoint root and checks that this entry names the signed `rules_root`.

## G. Public verifier

The `verify_public_release.py` script does all of the above in one go (Python standard library and `cosign`). Download it **to a file**, read it and run it; do not pipe it into an interpreter.

```bash
curl -fsSLo verify_public_release.py https://raw.githubusercontent.com/{{repo}}/main/scripts/verify_public_release.py
less verify_public_release.py
python3 verify_public_release.py --latest
```

Options: `--latest`, `--tag TAG`, `--directory DIR` (already downloaded artifacts), `--json`, `--previous-checkpoint FILE` or `--trust-state FILE` (rollback protection), `--token` or the `GITHUB_TOKEN` variable (only to avoid the anonymous GitHub API limit, which returns HTTP 403 when exhausted). Real output, abridged, on the latest release:

```
MacGuard release verification — PASS (exit 0)

Release        {{release.tag}}  (latest)
Files          {{release.files}}   individual YARA rules: {{release.yara_rules}}
rules_root     {{release.rules_root}}

  [PASS] signature.manifest
  [PASS] signature.checkpoint
  [PASS] files.sha256
  [PASS] merkle.rules_root
  [PASS] merkle.inclusion
  [n/a ] consistency: no previous checkpoint was given
```

> **CURRENT** Without `--previous-checkpoint` or `--trust-state` the verifier says so explicitly: it is a first verification and **rollback protection is NOT established** by that run.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | All mandatory checks done and passed. |
| 1 | Integrity: a hash does not match. |
| 2 | Invalid signature or identity. |
| 3 | Merkle, inclusion or consistency. |
| 4 | Incomplete download or network error. |
| 5 | A dependency is missing (`cosign`). |
| 6 | Invalid format or incomplete set. |

If there are several failures the report lists them all and the exit code is the first by this precedence: 5, 4, 6, 2, 1, 3.

{{diagram:verifier-flow}}

## H. How to know the verifier itself is the right one

The verifier is code you run: read it (about 400 lines) and compare the commit on GitHub. Downloading it from the same site that hosts the rules is not an independent root of trust.

> **PROPOSED** Signing `verify_public_release.py` with Sigstore in `publish.yml` and attaching it to every release is a **proposed** improvement: it does not exist yet, so current releases carry no signed copy of the verifier.

## I. What to do if it fails

- Do not install or use the rules from that release.
- Repeat with `--output-dir DIR` and compare the artifacts with those on GitHub Releases (the canonical archive).
- Open an issue on the repository with the full `--json` output; it contains no secrets.
