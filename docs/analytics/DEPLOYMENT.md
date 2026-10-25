# Gateway deployment record

Authorised by the owner in chat on 2026-10-23 ("tienes autorización para desplegar"), hostname chosen by the owner: `quarantine-api.mac-guard.com`. `api.mac-guard.com` and `ingest.mac-guard.com` are **reserved by the owner and were not created**. Commercial mode stays **FREE_LAUNCH** (policy version 1, billing off, checkout closed, x402 off).

| Item | Value |
|---|---|
| Cloudflare account | `9e96e19f6dc0ccdd53e02f7c3b5cacab` (the MacGuard account; every command pinned to it) |
| Worker | `macguard-gateway`, Custom Domain `quarantine-api.mac-guard.com` (managed TLS, no `workers.dev`), cron `17 * * * *` |
| D1 | `macguard-gateway` (`92207c74-13f0-4613-bef3-85e30ca5b09a`), schema = `gateway/schema.sql`, plus the seed policy and the first administrator from `tools/bootstrap_remote.mjs` |
| R2 | new private bucket `macguard-premium-private` (empty; the archive bucket `macguard-archive-r2` was not touched) |
| Secrets | `KEY_PEPPER`, `ADMIN_PEPPER`, `TOTP_SEAL_KEY` generated locally, stored in the macOS Keychain (service `macguard-gateway-prod`) and uploaded with `wrangler secret put`. Administrator key, TOTP seed and id are in the same Keychain service (`ADMIN_KEY`, `ADMIN_TOTP_SEED`, `ADMIN_ID`). Never printed or committed. No Stripe, GitHub or other secret is configured |
| Code deployed | branch `feat/analytics-guardops` @ `4d9b1ff` (not merged to `main`) |
| Versions | `622afeaf-2c16-455d-b9f1-97f974a09d69` (first upload, before the secrets) → `2920e0d5-d7df-4c0d-a078-48764b461dd6` (current). Roll back with `wrangler rollback` to a previous version id (the first one has no secrets and is not usable) or by undeploying the Custom Domain |
| Per-environment config | outside the repository (`…/scratchpad/deploy/wrangler.toml`); keep a copy with the same content; the tracked `gateway/wrangler.toml` stays a template |

## Checked before deploying (read-only)
`quarantine-api.mac-guard.com` had no DNS record, Worker route or Custom Domain; the Worker and D1 names were free. Existing services (`panel.mac-guard.com` → `macguard-quarantine`, `rules.mac-guard.com` → Pages, `lifeclock-gateway`, `macguard-archive-r2`) were not modified; `panel` and `rules` still answered 200 afterwards.

## Verified on the deployed service (REMOTE, real Cloudflare)
Health 200 over TLS 1.3 with HSTS and `nosniff`; admin, tenant, Premium and intelligence routes answer 401 without credentials, including with a malformed key; unknown route 404; `/mcp` rejects a foreign `Origin` and non-POST; the Stripe webhook answers 503 (not configured); x402 404; the Community redirect answers 302 to the public release and rejects a bad tag or a traversal in `asset` with 400; errors carry no internals; the administrator (key + TOTP) can read KPIs, the policy and the dashboards; a forced GitHub sync recorded 3 releases / 24 assets from the real API (473 cumulative bundle downloads at that moment).

## Later findings and fixes (not deployed)
Commits after `4d9b1ff` fix defects found afterwards (bounded body reads, no audit write for unknown administrator ids, same-second sync, 403 classification) and add admin tenant/key routes and the test-traffic exclusion. They run only locally until a redeploy is authorised; see `MATRIX.md` and `MERGE-PROPOSAL.md`.

## Not verified, not done
- Authenticated **tenant** requests on the remote service (no tenant or API key exists; creating one would write to the append-only audit chain). Covered only by the local Node and workerd suites.
- WAF and per-IP rate limits at the edge, a rehearsed rollback, a D1 restore rehearsal (items 5–6 of `docs/monetization/ACTIVATION-CONDITIONS.md`). The Premium catalogue is empty and no Stripe account is connected.
- **Cron (checked 2026-10-23 20:18Z, read-only):** the hourly trigger did fire by itself and persisted its outcome, but the run **collected nothing**: GitHub answered 403 to the anonymous request (`github_rate_limited`, `consecutive_failures 1`). Over the next nine hours 6 of 10 runs failed and 4 succeeded, with correct variations stored (`GITHUB-403.md`; my first reading of `rate_remaining` there was wrong and is corrected). A read-only `GITHUB_TOKEN` Worker secret is needed from the owner; see `MATRIX.md`. The forced sync at deploy time had worked with the same code.
- **Test traffic, identified (the four rows of 2026-10-23):** `analytics_daily`, tenant `-`, status `4xx`, operations `account.analytics`, `premium.releases.list`, `intel.hash` (one request each, unauthenticated 401 probes) and `community_requests_daily` key `2026-10-23|rules-20261021-39541028283|rules-release.tar.gz|anonymous_request` with `redirected = 1` (content digest `e0d49c89fe4b85e0bf104988504a40b42e61c46570dd8e0e53f2274a1f90c7f7`). The code in the branch excludes tenant `-` from every commercial KPI by rule and lets an administrator mark the redirect row through `POST /admin/v1/analytics/exclusions` (it verifies the row exists and stores that digest); both need the redeploy + `migrations/0001_telemetry_exclusions.sql`. No row was deleted.
- **Test traffic (original note):** the verification above left 3 rows in `analytics_daily` (tenant `-`, unauthenticated 401 probes) and 1 in `community_requests_daily` (one redirect). They are mine, from 2026-10-23, and are the only telemetry rows that exist; a clean-up delete was blocked by the permission classifier and was not forced. They also sit inside the one-year retention window.
- Retention (one year) is in code (`src/retention.js`, daily at 03:00 UTC from the cron) and tested locally; it has not run remotely yet.
