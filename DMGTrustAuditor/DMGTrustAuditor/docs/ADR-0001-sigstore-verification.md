# ADR-0001 — Sigstore verification in the shipping app

Status: accepted (2026-10-18). Reviewed by: pending human review.

## Context
The rules channel is signed with Sigstore keyless (GitHub OIDC, Fulcio certificate, Rekor entry). The app must verify
that before installing rules, on machines that have no developer tools, and must fail closed.

## Options evaluated
| Option | Result |
|---|---|
| Swift Sigstore library | None maintained was found (searches return Go, Rust, JS, Dart clients only). |
| Re-implement in Swift | Needs X.509 chain building to Fulcio, SCT and Rekor signed-entry-timestamp checks, bundle parsing, TUF. That is home-grown cryptography; rejected. |
| Link the Go/Rust verifier through FFI | Large build burden; same trust as shipping the binary but harder to audit. |
| **Ship the official `cosign` as a helper** | Chosen: sigstore-go based, independently released, and also the reference for cross-tests. |

## Decision
* `Contents/Helpers/cosign` and `Resources/sigstore/trusted_root.json` ship inside the app (CLI: next to the executable).
* Both are located only if their SHA-256 matches the pins in `Core/SigstoreVerifier.swift`. A cosign or root that is not pinned is never run, wherever it is found.
* cosign runs `verify-blob --bundle … --trusted-root … --certificate-identity <publish.yml@refs/heads/main> --certificate-oidc-issuer … --certificate-github-workflow-repository MacGuard/macguard-yara-channel`. With `--trusted-root` no network or TUF access is needed (verified offline with the network denied).
* Without a pinned verifier the installer refuses every release (fail closed) and `rules-status` says why.
* Rekor (Sigstore's log) and the MacGuard Merkle log are verified independently: Rekor by cosign, the MacGuard log by `ChannelVerifier` (inclusion proof, checkpoint, consistency with the persisted trusted head).

## Trusted root refresh policy
The root contains the Fulcio/Rekor keys and validity windows. It changes rarely. A new root ships with an app update
(`Scripts/refresh-trusted-root.sh` fetches it through TUF with cosign and prints the new SHA-256 to pin). A root that
is stale makes verification fail closed, never open.

## Consequences / residual risk
* The helper must be code-signed and notarized with the app (release step, pending).
* Only the darwin/amd64 cosign build is pinned today; the arm64 pin is added when the release build is made (pending).
* A native Swift verifier stays a possible future replacement; cosign remains the cross-check.
