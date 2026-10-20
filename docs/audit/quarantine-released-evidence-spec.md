# Quarantine: when a candidate is RELEASED (contract and specification)

Status: proposed with the PR that implements it. **No D1 migration and no SQL are needed**: it reuses the existing columns (`state`, `version`,
`release_tag`, `updated_at`) and the append-only `audit` table. Nothing here changes a human decision or the technical gates of the pipeline.

## The defect

`APPROVED_PENDING_VALIDATION → RELEASED` was the only way a candidate became `RELEASED`, and it trusted the list of hashes in the request of the release
callback. A candidate that nobody approved but that passed every technical check (the pipeline publishes it by itself) stayed `PENDING` in the panel
although the signed release already contained it: the panel contradicted the public record. First observed with four rules recovered by the benchmark fix.

## Contract

States are unchanged: `PENDING`, `UNDER_REVIEW`, `APPROVED_PENDING_VALIDATION`, `REJECTED`, `RELEASED`.

| From | To | Who | On what |
|---|---|---|---|
| `PENDING`, `UNDER_REVIEW` | `APPROVED_PENDING_VALIDATION` | a REVIEWER or ADMIN (human `approve`) | only if the candidate has no technical finding and the approval can take effect (unchanged) |
| `APPROVED_PENDING_VALIDATION` | `RELEASED` | the publish workflow, authenticated with GitHub OIDC | **verified evidence of publication** |
| `PENDING`, `UNDER_REVIEW` | `RELEASED` | the publish workflow, authenticated with GitHub OIDC | **verified evidence of publication** (the pipeline published it on its own checks; no human decision exists) |
| `REJECTED` | — | nobody | a rejected candidate that a release lists is **not moved**; it is reported as `published_despite_rejection` |
| `RELEASED` | — | nobody | repeated callbacks leave it alone (idempotent) |
| `APPROVED_PENDING_VALIDATION`, `RELEASED` | `PENDING` | the pipeline (`revalidation-failed`, unchanged) | revalidation failed |

There is no human action that produces `RELEASED`: `/api/decisions` accepts `approve`, `reject`, `hold`, `review` and `release_review` only (anything else is a 400), and
`/api/pipeline/released` accepts only an OIDC token of `publish.yml` on `main`. A session of any role is refused (401).

**The `PENDING`/`UNDER_REVIEW → RELEASED` row is the change of contract**: before, a `PENDING` candidate could never become `RELEASED`. It is allowed now only
because the evidence below is exact; it is recorded with `basis: pipeline_checks_only` so the panel never presents it as human-reviewed.

## Verified evidence of publication

The Worker does not use the hashes of the request. For the tag in the request (shape `rules-YYYYMMDD-N`) it:

1. reads the public release from the GitHub API: it must exist, must not be a draft, must carry that tag and have a `manifest.json` asset hosted under
   `https://github.com/<repo>/releases/download/<tag>/`. If the API is unavailable for an explicit tag, the public download of the manifest is the evidence
   (assets of a draft are not served), recorded as `evidence: download`;
2. downloads `manifest.json` and checks its SHA-256 against the `digest` GitHub reports for the asset when it reports one;
3. verifies that the manifest is well formed (unique printable paths, SHA-256 per file) and that its `rules_root` is the RFC 6962 root of its own file list,
   with the same tree as `scripts/tlog.py` (`tests/fixtures/rules_root_vectors.json` keeps both implementations identical);
4. releases a candidate only if the manifest lists its **exact path and exact SHA-256** (and, when both sides state it, the same size). The same content at
   another path, other content at the same path, or a missing entry release nothing.

Any failure answers 400/409/422/502 with `nothing was changed` and writes no audit entry. The workflow client treats the service as optional, so the
publication is never blocked; the callback can be repeated.

What this does **not** verify: the Sigstore signatures. `publish.yml` verifies them before the release becomes public and `site.yml` verifies the public
release again; the Worker cannot run `cosign`. The evidence is the public release record and the manifest it serves, not a signature check.

## Atomicity, idempotency, concurrency

One D1 batch per callback: for every candidate a guarded update (`WHERE id AND version AND state`) followed by a check that **that statement** changed exactly
one row, then one audit entry. If a person or another callback moved a candidate first, the batch aborts as a whole and the callback reads again. The audit
chain stays linear (`audit_prev` unique index). A repeated or concurrent callback therefore releases each candidate once and records itself as
`receipt: idempotent_retry`.

## Audit (append-only)

`pipeline.released`, target = the release tag, detail: `tag`, `trigger`, `receipt` (`first` | `idempotent_retry`), `release` (`id`, `published_at`, `evidence`,
`asset_digest_checked`), `manifest_sha256`, `rules_root`, `manifest_files`, `changed`, `already_released`, `conflicts`, `claimed` and `claimed_not_in_manifest`
(what the request said, recorded as unverified), `run_url`, `token_run_id` and `run_attempt` (from the verified token), and `transitions[]` with, for each
candidate: `id`, `path`, `sha256`, **previous state**, **new state**, `basis` and `reason`. The sheet of a released candidate shows this evidence.

## Public counter

`released_after_review` in `/public/stats` counts only released candidates that a person approved (an `approve` decision exists). A rule the pipeline released
without any human decision is not "released after review".

## Effect on production

Nothing in D1 changes by itself. At the next release the callback marks the candidates the release lists: for the four rules recovered by the benchmark fix
(currently `PENDING`) that is `PENDING → RELEASED` with `basis: pipeline_checks_only`. Releases made before this change carry no evidence entry; their
candidates keep the state they have.

## Rollback

`wrangler rollback` to the previous Worker version. No schema or data migration is involved; candidates already moved to `RELEASED` stay valid (the audit
holds the evidence). The previous Worker would, again, only release approved candidates and on the word of the request.

## Not in this change

`docs-src/diagrams/quarantine-states.json` (public documentation of the states) is not touched here: changing `docs-src/` redeploys the public site. It should
add the second release row in a separate, deliberate change.
