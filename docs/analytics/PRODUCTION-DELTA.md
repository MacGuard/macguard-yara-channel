# Production versus local: differences, migration proposal and rollback (2026-10-24)

Read-only check of Cloudflare on 2026-10-24 04:45Z: Worker `macguard-gateway` still at version **`2920e0d5-d7df-4c0d-a078-48764b461dd6`** (deployed 2026-10-23 19:27Z from `4d9b1ff`), Custom Domains unchanged (`panel` → Quarantine, `quarantine-api` → the gateway), no DNS record added or removed, D1 `macguard-gateway` and R2 `macguard-premium-private` as created. **Nothing remote was modified in this round** except: the cron kept running by itself, and two read-only exports of the D1 were written to the local backup directory.

## What production has and does not have
| Area | Production now (`4d9b1ff`) | Local branch (`feat/analytics-guardops`) |
|---|---|---|
| Hostname | `quarantine-api.mac-guard.com` (Quarantine's name) | gateway targets `api.mac-guard.com`; host gate `ALLOWED_HOSTS` |
| Body limits | JSON/MCP/webhook read before checking size | streamed, bounded reads on every route |
| Admin attempts | one audit write per anonymous attempt | none for unknown ids |
| Collector | maps every GitHub 403 to "rate limited", keeps no rate headers on failure, no token, 2 syncs in one second can lose a variation | classifies 403s, stores GitHub's message and headers, optional redacted token, no lost variation, reliability alert |
| Tenants / keys | no HTTP route (library functions only) | admin routes: create, issue once, revoke, rotate, suspend |
| Dashboards | Overview, Downloads, API, Premium, Cost, CRM | + Community observed windows with coverage, comparison, data classes, and (`550f0c0`) retention, pipeline, signatures, cas_backups |
| Test traffic | 4 probe rows counted | identified and excluded (`telemetry_exclusions`) |
| GuardOps | none | outbox + adapter, inert until configured |
| Schema | `4d9b1ff` schema | + migrations `0001` (exclusions), `0002` (`gh_sync.authenticated`), `0003` (`guardops_outbox`) — tested against the exact deployed schema |
| Secrets | `KEY_PEPPER`, `ADMIN_PEPPER`, `TOTP_SEAL_KEY` | + optional `GITHUB_TOKEN`, `GUARDOPS_INGEST_TOKEN` (neither set) |
| Vars | as deployed | + `ALLOWED_HOSTS` (and optional `ADMIN_HOSTS`, `GUARDOPS_*`) |

## Proposal (every step needs the owner's specific authorisation; nothing is applied)
0. **Backup**: `node gateway/tools/d1_backup.mjs` (automated, encrypted, verified). Note the live version id.
1. **Rehearse on staging**: `tools/restore_to_staging.mjs` with the latest backup into `macguard-gateway-staging`, then `wrangler d1 migrations apply macguard-gateway-staging --remote`, run the smoke tests against a staging Worker if one is created. (Needs creating a staging D1: a remote write.)
2. **Migrate production D1**: `wrangler d1 migrations apply macguard-gateway --remote --config gateway/environments/production.wrangler.toml` — additive only (`CREATE ... IF NOT EXISTS`, one `ADD COLUMN`), tested from the deployed schema; run **before** the code that needs it.
3. **Deploy the code on the current hostname first** (`production.wrangler.toml`, with `ALLOWED_HOSTS=quarantine-api…`): proves the new code without touching DNS. Smoke tests per area (`ROUTE-INVENTORY.md`).
4. **Secrets**: `GITHUB_TOKEN` (owner-created, never in chat). After 2–3 cron runs verify `authenticated = 1`.
5. **Mark the four probe rows**: `POST /admin/v1/analytics/exclusions` (see `DEPLOYMENT.md`).
6. **Domain move** (`DOMAIN-ARCHITECTURE.md`): transition config (both names) → smoke on `api` → target config (releases `quarantine-api`) → Quarantine attaches its own name.
7. **Edge**: apply the WAF/rate rules and, if wanted, the Access application, staging order, log-only first if the plan allows (`HARDENING.md`).
8. **GuardOps** later: ingest-only token + `GUARDOPS_INGEST_URL` (`GUARDOPS-ADAPTER.md`).

## Rollback
Code: `wrangler rollback 2920e0d5-d7df-4c0d-a078-48764b461dd6` (or redeploy `4d9b1ff`) — the previous code ignores the new tables and column, so the additive migrations do not need to be undone. Domain: redeploy `production.wrangler.toml`. D1: the migrations change no existing data; if the data itself ever had to be restored, use a verified backup into a *new* database and re-point the binding (`BACKUP-RECOVERY.md`); D1 Time Travel restore overwrites the live database and is a last resort. Secrets: delete or rotate with `wrangler secret`.

## Risks and dependencies
The cron keeps failing intermittently until a token is set (no data is lost; coarser timing). Migration `0002` cannot run twice (use the tracker). The Worker version `2920e0d5` has the weaker body handling until redeployed. Custom Domain re-assignment has no dry run (hence the transition step). The staging rehearsal and the token are the two items that unblock the rest.

## Addendum 2026-10-24 (second closing round, `550f0c0`)
- **Rollback of the code is now evidenced locally:** `test/staging_rehearsal.test.js` runs the code deployed in production (`4d9b1ff`, extracted from git) on the database after migrations 0001-0003 (health, administrator refusal, collector write) and restores the pre-migration backup into a fresh file. This removes the "unknown" that the migrations might break a rollback; it is still not proven on real D1 (that is step S8 of `STAGING-SEQUENCE.md`).
- **Four more dashboards exist only locally** (retention, pipeline, signatures, cas_backups); signatures and the transparency log are reported `NOT_INSTRUMENTED` because none exists yet.
- **Not changed in production:** Worker `2920e0d5`, Custom Domains, D1 schema, secrets, policy (FREE_LAUNCH v1), Stripe and x402 (off).
