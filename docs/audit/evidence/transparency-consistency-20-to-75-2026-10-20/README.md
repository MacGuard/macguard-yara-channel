# Transparency log consistency, checkpoint 20 → 75 (2026-10-20)

Read-only verification that the log published with release `rules-20261018-39150886414` (checkpoint of 75 entries) **extends** the log of
the previous release `rules-20261018-39103534527` (checkpoint of 20 entries) without rewriting any entry.

Nothing signed was changed: the two checkpoints here are byte-identical copies of `logs/checkpoints/00000020.txt` and
`logs/checkpoints/00000075.txt` (checked with `cmp`), and their Sigstore bundles stay in `logs/checkpoints/`.

## Method

1. The trusted previous checkpoint is the signed one for size 20. Its signature was verified independently of the verifier:

   ```
   cosign verify-blob --bundle logs/checkpoints/00000020.sigstore.json \
     --certificate-identity https://github.com/MacGuard/macguard-yara-channel/.github/workflows/publish.yml@refs/heads/main \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com logs/checkpoints/00000020.txt
   → Verified OK
   ```

2. The release was verified with the independent verifier, giving it that checkpoint:

   ```
   python3 -I scripts/verify_public_release.py --tag rules-20261018-39150886414 \
     --previous-checkpoint checkpoint-00000020.txt --json
   ```

## Result

| Check | Result |
|---|---|
| Checkpoint 20 signature (cosign, workflow identity) | pass |
| Release manifest and checkpoint 75 signatures | pass |
| 1174 files match the signed manifest byte for byte; `rules_root` `16d082395ef1ec53d0ad25d5840d83e7f5f3a75a283ce66f8fa75da106790ec5` | pass |
| Inclusion: entry 72 of 75 names that `rules_root` | pass |
| **Consistency: the trusted checkpoint (20) is a prefix of this one (75): consistency proof verifies** | **pass** |

Overall result `PASS`, exit code 0 (`verify-consistency-pass.json`).

Checkpoint 20 root `CkzIEBS7W/PHHLurB3p0ihpSJMowpNiS21SIoego8ho=`; checkpoint 75 root `G6ubuTZLOkL3aDWuE4v/rTPqo2lNACGv0gj1/VTmPZY=`.

## Negative control

The same command with a previous checkpoint whose root was altered in its last character fails (`result: FAIL`, exit code 3,
`verify-forged-previous-checkpoint-fail.json`). The check therefore rejects a log that does not extend the one trusted.

## Limits

- It proves the log is append-only between these two points, not that nothing was published outside the log.
- The previous release carries no `checkpoint.txt` asset (older format); the checkpoint comes from this repository's `logs/checkpoints/` and is
  authenticated by its own Sigstore bundle, not by the release.
- Run on 2026-10-20 from a verifier at the repository head `abb1bfa`.
