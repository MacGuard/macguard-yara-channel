# Staging plan for approval (nothing below has been created)

Presented before any remote resource is created, as the owner asked. It covers the gateway (commercial/analytics Worker) and, as an optional second part, the panel's new Sources-and-downloads migration. The step-by-step commands are in `STAGING-SEQUENCE.md` (generated from `gateway/tools/staging_sequence.mjs`, checked by `--check`); this page is the decision sheet.

## 1. Resources that would be created (all new, all staging-only)

| # | Resource | Name | Notes |
|---|---|---|---|
| 1 | Worker | `macguard-gateway-staging` | `workers_dev = true` only (`macguard-gateway-staging.<account subdomain>.workers.dev`); **no route, no Custom Domain, no DNS change** |
| 2 | D1 database | `macguard-gateway-staging` | empty at creation; production data arrives only through the restore step |
| 3 | Worker secrets | `KEY_PEPPER`, `ADMIN_PEPPER`, `TOTP_SEAL_KEY` | **new random values**, generated in the shell and never written to disk or chat; `set_worker_secret.mjs` refuses these names on any Worker not ending in `-staging`; `GITHUB_TOKEN` is **not** set in staging |
| 4 | A staging administrator | one `admins` row | created with the new peppers by `bootstrap_remote.mjs --admin-only`; credentials stay in a mode-600 file under `~/macguard-evidence` |

Not created: no R2 binding (the private Premium bucket is never read), no cron trigger (the hourly collector would spend GitHub's per-IP allowance that production needs), no second domain, no DNS record, no Access policy, nothing in Backblaze, Scaleway or the production D1. Account: `9e96e19f6dc0ccdd53e02f7c3b5cacab`.

## 2. Bindings (from `gateway/environments/staging.wrangler.toml`, checked by 10 invariants)

`DB` (D1 `macguard-gateway-staging`, migrations from `gateway/migrations`). Variables: `PUBLIC_BASE`, `COMMUNITY_ORIGIN`, `COMMUNITY_DOWNLOAD_BASE`, `COMMUNITY_DEFAULT_ASSET`, `MCP_ALLOWED_ORIGINS` (empty), `DOWNLOAD_TTL_SECONDS`, `GRACE_DAYS`, `X402_ENABLED = "false"`. `FREE_LAUNCH` stays the installed policy; Stripe live and x402 stay off (staging has no Stripe key at all).

## 3. Permissions the owner must grant

The Cloudflare token (or the interactive login that wrangler already has) needs, **for this account only**: Workers Scripts: Edit, D1: Edit (create and write). It does **not** need R2, DNS, Zone, Access or Account Settings. The read-only connector already used for the audit cannot create anything (the D1 and Workers listings work; the subscription call answers 403). Creation therefore needs the owner's own token or login; no key is requested in this chat.

## 4. Migrations and data

* `gateway/migrations` 0001 to 0003 are applied to the staging D1 **after** the restore of a verified, encrypted production copy (`restore_to_staging.mjs` refuses any database name that is not `*-staging`, `*-restore-test` or `*-scratch`). The copy used is an age-encrypted backup decrypted on this Mac into memory; production is only read by the export.
* Rows to restore (from the newest real backup manifest): 122 rows in 11 tables (audit 5, policy 2, admins 1, GitHub release counters 3 + 24 + 72, sync 11, daily analytics 4).
* Optional second part, the panel (`admin/worker`): migration `0006_source_telemetry.sql` on a **panel staging D1** and Worker (`macguard-quarantine-staging`, procedure in `admin/worker/STAGING.md`) before it goes to the production panel. Production panel, `panel.mac-guard.com`, is not touched by this plan.

## 5. Cost estimate (limits read on 2026-10-24 from Cloudflare's pricing pages; the account's plan could not be read, the subscription call answered 403)

| Item | Stated limit / price | Expected staging use | Cost |
|---|---|---|---|
| Workers requests | Free: 100,000 per day, 10 ms CPU per invocation. Paid: US$5 minimum per month, 10 million requests and 30 million CPU ms included, +US$0.30 per extra million | a smoke run and the checks: a few hundred requests | within the included amounts on either plan |
| D1 rows written | Free: 100,000 per day. Paid: 50 million per month included, US$1.00 per extra million | restore of 122 rows, three migrations, a handful of test calls: well under 1,000 | none |
| D1 rows read | Free: 5 million per day. Paid: 25 billion per month included | a few thousand | none |
| D1 storage | 5 GB included on both; an empty database is about 12 KB | well under 1 MB | none |
| Number of databases / Workers | no per-database charge listed | +1 D1, +1 Worker | none listed |

Cost limits to enforce: the staging Worker has no cron and no route, so it spends nothing when idle; the smoke tool makes a bounded number of requests; the resources are deleted after the rehearsal (their names are checked by the delete step; production names are refused). If the account is on the free plan, the daily limits above are the ceiling and nothing can bill.

## 6. Pre-flight checks already done locally (no remote call)

`staging_sequence.mjs --check` (10 invariants: separate names, no production id, no route, no R2, no cron, no secret-shaped value, every pre-production write scoped to staging); `test/staging_rehearsal.test.js` (the whole sequence against a local copy, including the rollback with the previously deployed code); `set_secret.test.js` (peppers refused outside staging); `restore_to_staging` refuses names that are not staging, restore-test or scratch.

## 7. What the owner approves, as a single yes or no per line

1. Create the Worker `macguard-gateway-staging` and the D1 `macguard-gateway-staging` (steps S3).
2. Set three NEW secrets and create a staging administrator (S6).
3. Restore the encrypted production copy into staging and apply migrations 0001 to 0003 (S4, S5).
4. Deploy the candidate commit to staging and run the smoke, security and rollback checks (S6 to S8).
5. (Optional) Do the same for the panel with migration 0006 (`macguard-quarantine-staging`).
6. Delete the staging resources after the report.

Production (`P1`) is a separate decision, line by line, and is not part of this approval.

## 8. Revision 2026-10-25 (after the owner approved the architecture: own Worker and own D1 per staging; still NOTHING created)

**Checked today, read-only.** The Cloudflare connector available to this session authenticates as `mac_guard@proton.me`, but its listings show one Worker (`lifeclock-gateway`, last modified 2026-10-17) and **no D1 database at all**; the MacGuard Workers and the production D1 named in this plan are not visible through it. So the name-collision check below is NOT proven from here: `wrangler` (not installed on this Mac) or the owner's token must list the account `9e96e19f6dc0ccdd53e02f7c3b5cacab` before step S3. Nothing has been written.

**Two stagings, independent of each other** (each with its own Worker, its own D1, its own secrets; neither shares a binding with production or with the other):

| Staging | Worker | D1 | Reached at | Cron | Secrets (all new) |
|---|---|---|---|---|---|
| Gateway | `macguard-gateway-staging` | `macguard-gateway-staging` | `workers.dev` only | none | `KEY_PEPPER`, `ADMIN_PEPPER`, `TOTP_SEAL_KEY` |
| Panel | `macguard-quarantine-staging` | `macguard-quarantine-staging` (schema incl. migration 0006) | `workers.dev` only (`workers_dev = true` in the staging copy; no route, no custom domain, **no DNS**) | `*/15 * * * *` on the staging D1 only, so the evaluator heartbeat can be proven; it touches nothing else | `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` (a **separate staging OAuth App**), `TOKEN_ENC_KEY` (new), `TELEMETRY_INGEST_SHA256` (hash of a new throw-away token) |

Panel staging needs from the owner: a GitHub OAuth App for staging (callback `https://macguard-quarantine-staging.<account subdomain>.workers.dev/auth/callback`), created by a person; its secret is shown once and never enters chat. The repository variable `QUARANTINE_URL` is pointed at the staging URL only for one manual `daily.yml` run and unset afterwards (as `admin/worker/STAGING.md` already says); `TELEMETRY_ENABLED` stays unset in the repository until the production decision.

**Permissions (unchanged):** Workers Scripts:Edit and D1:Edit on this account. No R2, DNS, Zone, Access or Account Settings. **Cost:** same table as section 5; the panel staging adds one Worker and one D1 with a cron every 15 minutes (96 invocations per day, far below the 100,000 per day free limit); the staging resources are deleted after the report.

**Gate for production (owner's rule, 2026-10-25):** migration 0006, the panel Worker and its cron do not go to production until (a) the E2E below passes in panel staging and (b) the rollback procedure has been exercised there. Both are the items of `docs/observability/STAGING-E2E.md`.

Lines to approve, one yes/no each: S1 gateway staging as in sections 1 to 4; S2 panel staging as in the table above (Worker + D1 + 4 secrets + OAuth App by a person); S3 run the staging E2E and the rollback exercise; S4 delete both stagings afterwards.

## 9. Revision 2026-10-25 (later): final names, permissions, costs, dependencies; S1-S3 approved, S4 NOT approved (stagings are kept)

**Owner decision:** S1 (gateway staging), S2 (panel staging) and S3 (E2E + rollback exercise) are approved in design; S4 (delete afterwards) is **not**: both stagings stay for future tests, with cost controls and nothing unnecessary. Nothing has been created yet; the creation commands wait for the owner's go on this final sheet.

### Final resources (account `9e96e19f6dc0ccdd53e02f7c3b5cacab`, the account whose R2 endpoint the backup tooling already answers on)
| # | Kind | Name | Reached at | Cron | Notes |
|---|---|---|---|---|---|
| 1 | Worker | `macguard-gateway-staging` | `workers.dev` only | none | config `gateway/environments/staging.wrangler.toml`, 10 invariants checked by `staging_sequence.mjs --check` |
| 2 | D1 | `macguard-gateway-staging` | – | – | restore of the encrypted production copy only through `restore_to_staging.mjs` (refuses non-staging names) |
| 3 | Worker | `macguard-quarantine-staging` | `workers.dev` only | `*/15 * * * *` on its own D1 | copy of `admin/worker/wrangler.toml` with `workers_dev = true`, no route, no custom domain |
| 4 | D1 | `macguard-quarantine-staging` | – | – | `schema.sql` (includes migration 0006 and the notification tables) |
| 5 | Worker secrets (gateway) | `KEY_PEPPER`, `ADMIN_PEPPER`, `TOTP_SEAL_KEY` | – | – | new random values, never written to disk or chat |
| 6 | Worker secrets (panel) | `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `TOKEN_ENC_KEY`, `TELEMETRY_INGEST_SHA256`, `ALERT_SIGNING_KEY` (only if a notification channel is tested) | – | – | the OAuth secret is created by a person; the rest are new random values |
Not created, on purpose: R2 buckets or bindings, KV, Queues, Durable Objects, Hyperdrive, custom domains, routes, DNS records, Access policies, Stripe objects, a second account.

### Permissions needed (one API token, account scope, created by the owner and kept in the Keychain)
Workers Scripts: Edit; D1: Edit. Nothing else (no R2, DNS, Zone, Access, Account Settings, Billing). The current Keychain item named for the Cloudflare token is known to hold a wrong value (open blocker); a token with exactly these two permissions is needed. The GitHub side needs an **OAuth App for staging** (callback `https://macguard-quarantine-staging.<account subdomain>.workers.dev/auth/callback`), created by a person, and, for the real-token E2E steps A3/A9, the repository variable `QUARANTINE_URL` pointed at the staging URL for one manual `daily.yml` dispatch only.

### Costs and the controls that keep staging cheap while it stays alive
Same limits as section 5. The only recurring activity is the panel cron: 96 invocations a day, each a few D1 reads/writes, far inside the free allowances (100,000 requests/day, 5 million rows read/day, 100,000 rows written/day); on the paid plan the same usage is inside the included amounts. Controls: (1) `[limits] cpu_ms` set to the minimum in both staging Worker configs; (2) the panel staging cron may be set to hourly when no test is running (`*/15` only during E2E); (3) the 365-day retention purge runs in staging too and `obs_notifications`/`obs_runs` are tiny; (4) no synthetic load generator is part of staging; (5) a monthly check by the owner of the Workers/D1 usage page (no API is polled by this repository); (6) if the account is on the free plan nothing can bill; if on paid, the minimum plan charge exists regardless of staging; (7) deletion remains available (`staging_sequence.mjs` delete step, which refuses production names) but is run only when the owner orders it.

### Dependencies and order
1. Owner: API token (Workers Scripts:Edit + D1:Edit), OAuth App for staging.
2. S1 gateway staging, then S2 panel staging (independent of each other).
3. S3: `docs/observability/STAGING-E2E.md` A1-A10 and the rollback exercise B1-B5 in the panel staging; the gateway sequence S3-S8 in the gateway staging.
4. Evidence is recorded as STAGING_VERIFIED only for what ran in staging. Production (`P1`) stays a separate decision, line by line.
