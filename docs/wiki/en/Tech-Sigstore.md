# Technology: Sigstore

[Home](EN-Home) · [Limits](EN-YARA-Limits) · [Technology: YARA](EN-Tech-YARA) · [Technology: Merkle](EN-Tech-Merkle) · [Historical archive](EN-YARA-Archive)

## In 30 seconds

Sigstore is an open source project for signing files (releases, binaries, images) so anyone can verify the signature; signing events are recorded in a public, auditable log {{ev:EV-YC-73}}. Here it is used to check that a rule bundle was signed by the `publish.yml` workflow and not by something else.

## An everyday example

It is like a wax seal that exists for only a moment: the user proves who they are with an ID, receives a valid seal for a few minutes, then destroys it. Later, anyone can check a public ledger to see that the seal was used and who asked for it. It does not say whether what was sealed is good.

{{diagram:sigstore-sequence}}

## Step by step

1. The `publish.yml` workflow asks GitHub for an OIDC token that names the workflow itself.
2. **Fulcio** (the certificate authority) issues a short-lived certificate binding that identity to an ephemeral key.
3. `cosign` signs the file and the signature is recorded in **Rekor** (the transparency log); everything is stored in a `.sigstore.json` bundle {{ev:EV-YC-73}}.
4. The client verifies the bundle against the Sigstore trust root and **checks identity and issuer**.

## Under the hood

"Keyless" means nobody holds a long-lived signing key: the key pair is discarded after signing and verification relies on the log {{ev:EV-YC-73}}. In the project, `publish.yml` signs the log checkpoint and `dist/manifest.json` with `cosign sign-blob --bundle`; `scripts/tlog.py` (`cosign_verifier`) verifies with `cosign verify-blob --bundle`, requiring the certificate identity, the OIDC issuer and the workflow repository {{ev:EV-YC-69}} {{ev:EV-YC-03}}.

- **Detects:** a file altered after signing, or signed by another identity.
- **Does not prevent:** the publishing workflow itself, if compromised, signing bad content with a valid signature.
- **Cost:** a network call to Sigstore services when signing; local verification with the bundle.

## Who else uses it

No row implies that these organisations use MacGuard.

| Who | Classification | Source |
|---|---|---|
| Kubernetes: its release process signs binary artifacts (tarballs, SPDX files, binaries) with cosign keyless signing | uses the same technology | {{ev:EV-YC-75}} |
| npm: packages published with provenance are signed by Sigstore public good servers and logged in a public ledger | uses the same technology | {{ev:EV-YC-74}} |

## Check it yourself

```
python3 -m unittest tests.test_seal_evidence tests.test_verify_public_release
python3 scripts/tlog.py verify --identity "<publish workflow ref>" --repo MacGuard/macguard-yara-channel
```

The second command needs `cosign` installed and the exact workflow identity.

## Limits

The signature proves origin and integrity, not rule quality. `manifest.evidence` is a statement by the publishing workflow, not an independent attestation {{ev:EV-YC-66}}. The in-browser verifier is served from the same origin as the package (RR-07).

## State

| Capability | State |
|---|---|
| Keyless signing of checkpoints and manifests in each release | operational {{ev:EV-YC-03}} |
| Sigstore signature of the historical archive manifest | planned (the archive is not operational) {{ev:EV-YC-60}} |
