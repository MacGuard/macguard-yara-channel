# Publishing and signing

[Home](EN-Home) · [Quarantine](EN-YARA-Quarantine) · [Publishing](EN-YARA-Publishing) · [Transparency](EN-YARA-Transparency) · [Verify](EN-YARA-Verify)

## In 30 seconds

Each release is a complete package (`rules-release.tar.gz`) holding the rules and a signed list (`manifest.json`) that gives the SHA-256 of every file. A GitHub workflow, `publish.yml`, signs that list with Sigstore without storing any private key. Whoever downloads it can check which workflow identity published and that the **bytes** are the signed ones, within Sigstore's trust model. That does not show that MacGuard wrote every rule or that they are harmless. {{ev:EV-YC-45}} {{ev:EV-YC-46}}

> The signature shows the verifiable identity of the publishing workflow and the integrity of the signed artifact, within Sigstore's trust model. It does not show who wrote the rules, that MacGuard wrote them, or that all are harmless.

## An everyday example

A bookshop sells a book with the distributor's stamp and a numbered seal. The author is somebody else; the stamp says who distributes it; the seal says nobody changed the pages since sealing; and none of that guarantees the book's content is correct or harmless. It is the same here: original author, distributor, signer, integrity and content safety are five different things.

{{diagram:trust-questions}}

| Question | What answers it | Where to see it |
|---|---|---|
| Original author of a rule | The upstream repository and its license (two rule sources) | `sources` in the manifest {{ev:EV-YC-49}} |
| Distributor of the package | The MacGuard channel, as a GitHub release | The repository and the release |
| Signer identity | The `publish.yml` workflow of this repository (branch `main`) | Sigstore certificate |
| Integrity of the bytes | SHA-256 of each file and `rules_root` | The signed `manifest.json` |
| Safety of the content | **Not** proven by anything above | Static and dynamic tests, with their limits |

## Step by step

{{diagram:release-sequence}}

The daily review requests this workflow only when the set is publishable, it changed and the macOS measurement job succeeded. {{ev:EV-YC-89}}

1. `precheck` compares the candidate with the latest release; if identical it asks for no approval and publishes nothing.
2. `publish` re-verifies the final set: static classification and dynamic evidence. Publication runs through a protected, reproducible workflow; the identity and technical checks are the same whichever approval mode is configured.
3. It signs the log checkpoint, writes the manifest (`scripts/seal.py`), signs it and generates the inclusion proof.
4. It packages: `tar -czf rules-release.tar.gz -C dist rules manifest.json`.
5. It checks the exact artifacts, creates the release as a **draft**, attaches every file and only then makes it public. {{ev:EV-YC-45}}

## Under the hood

**`manifest.json`.** Real keys of the latest release read: `created_at`, `evidence`, `files`, `log`, `rejected`, `rules_root`, `schema`, `sources`, `stats`, `status`, `validation`. `files` gives `path`, `sha256` and `bytes` per file; `rules_root` is the Merkle root of that list (see [Transparency](EN-YARA-Transparency)); `log` copies the origin, size and root of the log (`macguard-rules-log v1`); `stats` are counts derived from the files themselves. It is written with sorted keys and no spaces. `seal.py` refuses to seal if dynamic evidence is missing or belongs to another set. {{ev:EV-YC-45}}

**What is signed, and with what.** `cosign sign-blob --yes --bundle` signs two files: `manifest.json` and `checkpoint.txt`. No stored key: GitHub issues an OIDC token naming the workflow, Fulcio issues a short-lived certificate bound to that identity, and the signature is recorded in Rekor, Sigstore's public log. Expected identity: `https://github.com/MacGuard/macguard-yara-channel/.github/workflows/publish.yml@refs/heads/main`; issuer `https://token.actions.githubusercontent.com`. The package is not signed separately: the signed manifest covers it because it lists the SHA-256 of every file. {{ev:EV-YC-46}}

{{diagram:sigstore-sequence}}

**Do attestations exist?** An *attestation* in the GitHub/SLSA sense is a signed statement about **how** an artifact was built (in-toto). This repository **does not produce them**: `.github/workflows/` has no attestation step, and the site documentation states it as a limit. What exists instead: (1) Sigstore signatures of two blobs; (2) the `evidence` field inside the signed manifest (`candidate_run_id`, `candidate_workflow_sha`, `publish_run_url` and the dynamic measurement), which `seal.py` describes as the workflow's own statement, "not an independent attestation". Adding SLSA attestations would be a design change and a possible future step. {{ev:EV-YC-47}}

**Link to commit and run.** The tag is `rules-YYYYMMDD-<run id>`; the id is the `publish.yml` run. The signed manifest includes `evidence.publish_run_url` (that run), `candidate_run_id` (the daily run that produced the candidate) and `candidate_workflow_sha` (commit of the candidate's workflow). The certificate identity names the workflow and branch. {{ev:EV-YC-48}}

**Four mechanisms that are not interchangeable.**

| Mechanism | What it proves | What it does NOT prove |
|---|---|---|
| Hashes (SHA-256) | That some bytes are the listed ones | Who listed them |
| Sigstore (cosign) | Which workflow identity signed those bytes, and when (within Sigstore's trust model) | That the build process was the expected one, or that the content is good |
| Attestation (SLSA/in-toto) | How it was built (does not exist here) | n/a: not produced |
| Our own transparency log | That a publication is in an append-only log and was not rewritten | That the rule is harmless; it is not Rekor |

## Check it yourself

```bash
python3 -I scripts/verify_public_release.py --latest
```

Details and real output in [Verify](EN-YARA-Verify). Code: [publish.yml](https://github.com/MacGuard/macguard-yara-channel/blob/main/.github/workflows/publish.yml), [seal.py](https://github.com/MacGuard/macguard-yara-channel/blob/main/scripts/seal.py), [release.md](https://github.com/MacGuard/macguard-yara-channel/blob/main/docs-src/en/release.md).

## Limits

- A valid signature and matching hashes prove which workflow identity published exactly **those bytes**. They do not prove who wrote the rules or that the rules are good.
- Each release is the complete set; a correction is a new release and by convention, tags are not reused.
- Further hardening of release immutability is planned. {{ev:EV-YC-59}}
- `release.json` is unsigned metadata; the verifier cross-checks it against the signed values.

## State

| Capability | State |
|---|---|
| Complete release with manifest and log signed with Sigstore | published {{ev:EV-YC-03}} |
| Release-to-workflow-run link inside the manifest | operational {{ev:EV-YC-48}} |
| GitHub/SLSA attestations | not implemented (possible future step) {{ev:EV-YC-47}} |
| Release immutability hardening | planned {{ev:EV-YC-59}} |
