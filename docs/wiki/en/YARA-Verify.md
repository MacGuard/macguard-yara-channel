# Verify a release

[Home](EN-Home) · [Quarantine](EN-YARA-Quarantine) · [Publishing](EN-YARA-Publishing) · [Transparency](EN-YARA-Transparency) · [Verify](EN-YARA-Verify)

## In 30 seconds

You do not have to trust us: you can check a release yourself in four steps. (1) Hashes: the files are the ones the manifest lists. (2) Signature: the manifest was signed by the `publish.yml` workflow of this repository. (3) Merkle root: the file list produces the signed `rules_root`. (4) Log: the publication is in the transparency log and extends the one you already knew. A public script does it all in one go. {{ev:EV-YC-53}}

## An everyday example

A parcel arrives by courier. You check the seal is unbroken (hashes), the sender is who they claim to be (signature and identity), the delivery note matches what is inside (root) and the shipment number is later than the last one you received (log). A genuine, unopened parcel can still contain something unsuitable: verification does not judge the content.

{{diagram:verifier-flow}}

## Step by step

Requirements: `cosign` installed from its official source, Python 3 (standard library only) and `shasum` or `sha256sum`.

1. Download the verifier **to a file**, read it and run it; do not pipe it into an interpreter:

```bash
curl -fsSLo verify_public_release.py https://raw.githubusercontent.com/MacGuard/macguard-yara-channel/main/scripts/verify_public_release.py
less verify_public_release.py
python3 -I verify_public_release.py --latest --trust-state ~/.macguard-trust.json
```

2. Read the report. Each line is `[PASS]`, `[FAIL]` or `[n/a ]`. The exit code summarises the failure (table in "Under the hood").
3. To do it by hand, download the artifacts and check each layer:

```bash
gh release download <TAG> --repo MacGuard/macguard-yara-channel
cosign verify-blob manifest.json --bundle manifest.sigstore.json \
  --certificate-identity "https://github.com/MacGuard/macguard-yara-channel/.github/workflows/publish.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-github-workflow-repository "MacGuard/macguard-yara-channel"
shasum -a 256 rules-release.tar.gz manifest.json
```

Do the same with `checkpoint.txt` and `checkpoint.sigstore.json`. Correct result: `Verified OK`. To recompute `rules_root` by hand, use the script in [merkle.md](https://github.com/MacGuard/macguard-yara-channel/blob/main/docs-src/en/merkle.md).

## Under the hood

The verifier resolves the release **once** and downloads everything from that tag. It checks, without trusting any command's text (only return codes and data): artifacts present, signature of the manifest and the checkpoint, safe package extraction (no links or paths outside the directory, with limits), SHA-256 of each file, `rules_root`, counts, that the checkpoint matches the manifest `log`, the inclusion proof and, if you give it a previous checkpoint, consistency. Default identity and issuer: those in [Publishing](EN-YARA-Publishing). Code: `scripts/verify_public_release.py`. {{ev:EV-YC-53}}

Real output, abridged, of the latest release on 2026-10-22 (run for this page):

```
MacGuard release verification — PASS (exit 0)
Release   rules-20261021-39541028283  (latest)
Files     1178   individual YARA rules: 10021
  [PASS] signature.manifest
  [PASS] signature.checkpoint
  [PASS] files.sha256: 1178 files match the signed manifest byte for byte
  [PASS] merkle.rules_root
  [PASS] merkle.inclusion: entry 177 of 180 is in the checkpoint ...
  [n/a ] consistency: no previous checkpoint was given ...
```

| Code | Meaning |
|---|---|
| 0 | All mandatory checks done and passed. |
| 1 | Integrity: a hash does not match. |
| 2 | Invalid signature or identity. |
| 3 | Merkle, inclusion or consistency. |
| 4 | Incomplete download or network error. |
| 5 | A dependency is missing (`cosign`). |
| 6 | Invalid format or incomplete set. |

If several fail, the report lists them all and the code is the first by the precedence 5, 4, 6, 2, 1, 3. {{ev:EV-YC-55}}

**Recognising a legitimate new version (anti-rollback).** With `--trust-state FILE` (or `--previous-checkpoint FILE`) the verifier compares against the last checkpoint you verified: a smaller size fails with `ROLLBACK`; the same size with a different root fails with `FORK`; a larger size requires `consistency.json` and a valid proof that starts exactly at your checkpoint. The state file is written only after a full pass. Tested: a first run with `--trust-state` says "n/a"; a second run on the same release gives `[PASS] consistency: same checkpoint as the trusted one (180 entries)`. A different identity fails with exit 2 (tested with a fake identity). {{ev:EV-YC-54}}

**If verification fails** (the same criterion the app follows): nothing new is installed, the rules already installed keep working and the reason is explained. Do not use the rules of that release; repeat with `--output-dir DIR` and compare with the GitHub Releases artifacts; open an issue with the `--json` output (it holds no secrets). The app saves the trust state in a file with 0600 permissions before activating the rules. {{ev:EV-YC-56}}

## Check it yourself

The commands above are the repository's own. Run on 2026-10-22: `--latest` (PASS, exit 0), the manual `cosign verify-blob` check (`Verified OK`) and `shasum`, the second pass with `--trust-state`, and an attempt with a fake identity (FAIL, exit 2). Verifier tests: `python3 -m unittest tests.test_verify_public_release` (passed). Without a GitHub token the anonymous API allows 60 requests per hour per IP; the verifier says so and uses the `github.com` redirect. More: [verification.md](https://github.com/MacGuard/macguard-yara-channel/blob/main/docs-src/en/verification.md), [client-failures.md](https://github.com/MacGuard/macguard-yara-channel/blob/main/docs-src/en/client-failures.md).

{{diagram:client-update}}

## Limits

- Without `--previous-checkpoint` or `--trust-state`, a first run does **not** establish rollback protection. {{ev:EV-YC-54}}
- The verifier is code you run: read it. Downloading it from the same site that hosts the rules is not an independent root of trust. Signing it with Sigstore and attaching it to every release is a proposal; it does not exist yet. {{ev:EV-YC-57}}
- A valid signature and matching hashes prove who published those bytes, not that the rules are good or that scanned files are safe.
- There is no end-to-end performance test between the channel and Installer Auditor. {{ev:EV-YC-10}}

## State

| Capability | State |
|---|---|
| Independent public verifier with tests | operational {{ev:EV-YC-53}} |
| Anti-rollback protection with local state | operational {{ev:EV-YC-54}} |
| Verifier signed and attached to each release | not implemented (proposal) {{ev:EV-YC-57}} |
