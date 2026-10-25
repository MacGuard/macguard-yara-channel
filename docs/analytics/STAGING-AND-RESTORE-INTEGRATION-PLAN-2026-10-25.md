# Integration plan: staging (S1 to S3) and the first three cloud restores (2026-10-25)

Status: **PLAN. Nothing in this document has been executed.** It builds on `STAGING-PLAN.md` §8-9 (names, resources, permissions, costs, which are unchanged; S4 is not approved, the stagings stay) and `BACKUP-OBJECT-STORES.md`. Each phase ends with evidence and a stop: the next phase starts only after a person says so. A phase marked **OWNER** needs something only a person can supply.

## Phase 0: preconditions (OWNER, no remote change)
| Item | Who | Why | Verification |
|---|---|---|---|
| Cloudflare API token with **Workers Scripts: Edit** and **D1: Edit** only, account scope, stored in the Keychain (the existing item holds a wrong value) | owner | creates Workers and D1 | the token-verify endpoint reports it active; the token lists exactly those two permissions; it does not appear in any log |
| GitHub OAuth App for staging, callback `https://macguard-quarantine-staging.<account subdomain>.workers.dev/auth/callback` | owner (a person, not me) | panel login | client id and secret delivered to the Keychain, never to chat |
| Name conflicts checked in the right account (`9e96e19f…`) | me, read-only, with the token | the connector I have sees another account | `workers_list` and D1 list show none of `macguard-*-staging` |
| Spending ceiling: Cloudflare billing notification and the `[limits]` already in the staging config | owner | S4 is denied, so staging lives on | alert threshold configured; screenshot or API read recorded |
| Write scope of the three backup keys | owner | needed only for phase 3 | `HEAD` and a test write to a throw-away prefix **by the owner** |

## Phase 1: S1 gateway staging (reversible; production untouched)
| # | Operation | Permission | Cost | Security control | Evidence | Rollback |
|---|---|---|---|---|---|---|
| 1.1 | `wrangler d1 create macguard-gateway-staging` | D1:Edit | free allowance | account id pinned in the command; name must contain `-staging`; script refuses otherwise | D1 id recorded (not secret) | `wrangler d1 delete` of that name only |
| 1.2 | apply `schema.sql` and migrations to it | D1:Edit | none | `staging_sequence.mjs --check` (10 invariants) runs first | table list and row counts | drop and recreate the staging D1 |
| 1.3 | `wrangler secret put` for `KEY_PEPPER`, `ADMIN_PEPPER`, `TOTP_SEAL_KEY` with new random values piped from the shell, never echoed | Workers Scripts:Edit | none | values never touch disk, chat or logs | `secret list` shows names only | `secret delete` and re-put |
| 1.4 | deploy `macguard-gateway-staging` (workers.dev only, no route, no cron) with `--keep-vars` | Workers Scripts:Edit | free allowance | config contains no production id (checked) | `/readyz` OK and a first data arrival (a mock does not count) | previous version id noted before every deploy; `wrangler rollback` |
**Exit:** `STAGING_VERIFIED` only for what ran: `/readyz`, FREE_LAUNCH mode, no billing, no x402, data arrives. Stop.

## Phase 2: S2 panel staging
| # | Operation | Control | Evidence | Rollback |
|---|---|---|---|---|
| 2.1 | create D1 `macguard-quarantine-staging`, apply `schema.sql` (includes migration 0006 and the per-rule quality table) | name guard; no production binding | schema mirror test green first; table list | drop and recreate |
| 2.2 | secrets: `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` (from the Keychain, by the owner's hand or a pipe), `TOKEN_ENC_KEY`, `TELEMETRY_INGEST_SHA256`; `ALERT_SIGNING_KEY` only if a channel is tested | values never printed | `secret list` | delete and re-put |
| 2.3 | deploy `macguard-quarantine-staging` with `workers_dev = true`, cron `*/15 * * * *` on its own D1 | the staging config's allow-list is **not** the production one; production `PIPELINE_WORKFLOWS` is untouched | `/readyz`; one cron heartbeat visible in the Sources tab; login with the staging OAuth App | rollback to the previous version; cron removed by redeploy without it |
| 2.4 | run the panel E2E `STAGING-E2E.md` A1-A10 (ingest, outbox replay, quality report with rules, role checks: a viewer must not see quarantine decisions, outage and recovery) | a staging-only ingest token | each item recorded with its result | as 2.3 |
**Exit:** panel E2E result per item. The rollback exercise B1-B5 of that document is run here and recorded. Stop.

## Phase 3: the first three cloud restores (OWNER authorises the first write; nothing is overwritten or deleted)
Candidate: `20261024T050235Z` (3 objects, about 43.7 KB; ciphertext SHA-256 already verified locally). Order, one destination at a time, each independent of the others:
| # | Destination | Operation | Permission | Cost | Control | Evidence |
|---|---|---|---|---|---|---|
| 3.0 | **before any upload:** the owner creates the signing key, `backup_anchor.mjs sign` is run on `20261024T050235Z`, and the kit is generated (`backup_kit.mjs`) and stored outside the Mac | – | none | the signed statement travels with the three objects (5 objects, about 45 KB per destination) | `backup_anchor.mjs verify` OK; kit stored in two places | – |
| 3.1 | Backblaze B2 `macguard-archive-b2` | `sync --apply` (write-once PUT of 3 keys), then `verify` (re-read, compare) | write scope on that bucket | well under 1 MB stored and read; provider price lists were not re-read today | a key that already exists with different bytes is a conflict, not an overwrite; nothing is deleted | per-object checksum equality |
| 3.2 | Scaleway `macguard-archive-scw` | same | same | same | same | same |
| 3.3 | Cloudflare R2 `macguard-archive-r2` | same | same | same | same | same |
| 3.4 | restore drill, **each destination alone**, then `heads` across the three | `drill --identity <file> --trust-key <public key> --min-sequence 1` | read; the identity file is created by the owner from the Keychain and deleted afterwards | none | the drill is authenticated by the **signed anchor** (`anchor: signature`) and, while the Mac exists, also by the local SHA256SUMS; plaintext only in memory | per destination `ok`, `anchor: signature`, sequence, check list; `heads` shows three current heads |
| 3.5 | restore into **staging** | `restore_to_staging.mjs` from a downloaded copy into `macguard-gateway-staging` (refuses non-staging names) | D1:Edit (phase 1) | none | production D1 never named | row counts equal the manifest's |
"Three copies" is claimed only after 3.1 to 3.3 verify and 3.4 passes for all three.

**Rollback / stop conditions:** a conflict, a checksum mismatch or a failed drill stops the phase; the write-once design means there is nothing to undo, only objects to leave in place and report. Removing a test object is a deletion and needs its own authorisation.

## Residual gaps (stated, not hidden)
* `age` gives no sender authentication; the signed anchor (`BACKUP-AUTHENTICATION-AND-RECOVERY-2026-10-25.md`) closes it, provided the owner creates the signing key and keeps the public key and the newest sequence outside the buckets and the Mac.
* The age identity is an interim key in the Keychain; Bitwarden custody is not set up.
* Costs here are orders of magnitude; the current provider price lists were not re-read in this session.
