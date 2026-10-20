# Quarantine integration acceptance run (2026-10-20)

First real run of the circuit **GitHub Actions OIDC → Cloudflare Worker (`panel.mac-guard.com`) → D1**, made with the acceptance input
(`daily.yml`, `acceptance=true`) so that it could not start a release. The per-rule details of the quarantined files are deliberately **not**
in this folder: only counts, identities, checks and results.

## What was run

| | |
|---|---|
| Preconditions | `QUARANTINE_URL` absent, no `daily.yml`/`publish.yml` run active, latest release and `rules_root` recorded, D1 audit chain valid, upstream rule sources unchanged since the last review (`baseline-before-activation.json`). |
| Activation | repository variable `QUARANTINE_URL=https://panel.mac-guard.com` (exact value, no trailing slash: the client uses it as the OIDC audience). `AUTO_PUBLISH=true` untouched. |
| Run | `daily.yml` on `main` at `2d4b6d0`, `workflow_dispatch`, `acceptance=true`, run `39491935000`, attempt 1 started 2026-10-20T20:26:08Z. |
| Verification | `qcheck post`, a read-only checker that reads GitHub, D1 and the public release independently of the workflow's green status. |

## Result of attempt 1 (`qcheck-post-attempt1.txt`): every check passed

- **OIDC token accepted for the right workflow.** The Worker only sets the actor after verifying signature, issuer, audience, repository, `refs/heads/main` and workflow. D1 audit entry 8: actor `pipeline:daily.yml`, role `PIPELINE`, action `pipeline.submit`, target = the run id, `run_url` = that run, `count: 6, created: 6`.
- **Candidates persisted.** Six candidates in D1, all `PENDING` at version 1; the count equals the audit entry and the job log (`quarantine: 6 new, 0 already known`). No `UNAVAILABLE` line.
- **Hashes and paths are the real ones.** Every candidate path is one of the files that left the previous signed release, and every candidate hash equals the hash in that release's signed manifest.
- **Nothing technically rejected entered the panel**, and no decision existed that could change the published set (the only decision row is the archived synthetic one).
- **No publication.** `request-publish`, `macos` and `app-compat` were skipped; no `publish.yml` run exists after the dispatch; the latest release is still `rules-20261018-39150886414`, `rules_root` `16d082395ef1ec53d0ad25d5840d83e7f5f3a75a283ce66f8fa75da106790ec5`.
- **Audit chain valid** (checked with the Worker's own `chainHash`).

## Limits of this evidence

- `request-publish` was skipped because the run found **no effective change** (`candidate.not_publishable`, `candidate.unchanged`), not because of the acceptance guard. The guard is proven by `tests/test_daily_acceptance.py` (the real condition evaluated for every combination, including the 36 with `acceptance=true`); this run could not exercise it because nothing changed.
- The OIDC token itself cannot be observed outside the job; its acceptance is proven indirectly by the actor the Worker recorded.

## Re-runs (not started by the author of the test)

The run has three attempts. Attempts 2 and 3 were started from the same GitHub account at 20:33:49Z and 20:40:38Z, after the verification above.

- Attempt 2 repeated the review: D1 audit entry 9 is `pipeline.submit` with `count: 6, created: 0`, so the service is idempotent (no duplicates, versions unchanged). The signed transparency log received a second copy of the five events of the run (seq 166–170). Append-only: they stay.
- Attempt 3 ran for one second and changed nothing.
- `qcheck-post-after-reruns.txt` shows one failing check, and only because the checker compares the job log of the **latest** attempt (`0 new, 6 known`) with the total created (6). It is a consequence of the re-runs, not of the integration; no candidate, decision, release or audit-chain check failed. Final audit chain: 9 entries, head `78e095c3ca872e2cafdf5d06d2e74e27589dd2e60d54194b43d0ca8aab421935`.

## Not included on purpose

Names, paths, hashes and reason codes of the quarantined files. The public record already carries the counts (examined, accepted, quarantined, rejected, withheld).
