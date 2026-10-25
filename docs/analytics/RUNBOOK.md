# Analytics runbook (local commands; nothing here deploys)

## Reproduce the checks
```
cd gateway
node --test test/*.test.js                 # 99 tests (analytics, KPI, cost/CRM, insights, API, plus the earlier suites)
node test/runtime/runtime.test.mjs         # workerd via Miniflare (needs admin/worker/node_modules from the primary checkout; else it says SKIPPED)
node tools/gen_openapi.mjs --check         # OpenAPI matches the code
node tools/gen_kpi_catalog.mjs --check     # KPI contract matches the code
node tools/d1_cost.mjs                     # D1 statements per request
python3 -m unittest discover -s tests      # Community/Python regression (repo root)
```

## Real, read-only GitHub observation
```
node tools/gh_sync_local.mjs --db FILE.sqlite        # one collector run against the public API (GITHUB_TOKEN optional, raises the rate limit)
node tools/render_dashboards.mjs --db FILE.sqlite --out DIR   # static HTML/JSON/CSV for the six dashboards and three reports
```
Deltas appear only from the second observation onward; coverage is shown on the dashboard. In the Worker the same collector runs hourly from `scheduled()` and records its own failures (`gh_sync`, `gh_sync_log`).

## Deployed service
`https://quarantine-api.mac-guard.com` (see `DEPLOYMENT.md`). Admin calls need the administrator key and a fresh TOTP, both in the Keychain service `macguard-gateway-prod`; a small helper that reads them without printing is in the (untracked) deploy folder. Force a GitHub sync with `POST /admin/v1/analytics/github/sync`; the same collector runs hourly from the cron.

## Costs
Admin API (`/admin/v1/analytics/costs/*`): `POST costs/import?provider=cloudflare` (CSV body: `period,service,amount,currency[,tenant_id,product,usage_unit,usage_quantity,invoice_ref]`, amounts as plain decimals with ≤ 6 decimals, YYYY-MM periods; re-importing the same file adds nothing; one bad row rejects the file), `PUT costs/rates` (owner-supplied price with its https source URL; measured units today: `cloudflare/workers/request`, `cloudflare/r2/transfer_byte`), `POST costs/estimate?period=`, `GET costs?period=`. Estimates exist only where a rate exists; everything else is *unknown*, never zero.

## Switches
- `ANALYTICS_ENABLED=0` — stop all telemetry writes (requests unaffected). Use it first if D1 writes ever look wrong.
- `ANALYTICS_PEPPER` — secret for actor hashes (falls back to `KEY_PEPPER`). Rotating it starts new actor identities (retention across the rotation is lost).
- `GITHUB_TOKEN` — optional secret for the collector; never in the repo.

## When something looks wrong
- Alert `telemetry.undercount` firing: analytics lost writes today; the ledger (`usage_events`) is the truth for billing. Check D1 errors, then the kill switch.
- Alert `github.collector_stale/failing`: look at `gh_sync.last_error` and `gh_sync_log`; the public channel is unaffected.
- A KPI shows `PARTIAL_COVERAGE`: the window starts before telemetry did; do not read the value as complete.
