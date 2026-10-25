# MacGuard analytics — what is measured, how, and what is not

Branch `feat/analytics-guardops` (local; nothing pushed, merged or deployed). Statuses: VERIFIED / IMPLEMENTED / PLANNED / BLOCKED / UNKNOWN. See `MATRIX.md` for the evidence per component.

## Design rules

1. **Counts, never contents.** Telemetry records counts, durations and status classes. No payload, no URL query, no IP, no header, no raw identifier.
2. **An actor is an API key, not a person.** An actor is `HMAC(pepper, "actor|"+key_id)` truncated; kinds are `authenticated_service | api_key_client | device_identity`. Human users are **NOT_INSTRUMENTED** (`active_humans`). Nothing is inferred from IPs, downloads or fingerprints.
3. **Telemetry never gates a request.** `track()` never throws and runs after the response is decided (`waitUntil`). Community redirect routes use no database in the request path. `ANALYTICS_ENABLED=0` turns every write off.
4. **The billing ledger stays the source for money.** `usage_events` is authoritative; `analytics_daily` is best-effort traffic data. Alert `telemetry.undercount` fires when analytics sees fewer metered units than the ledger. Replays add a request, never units or money.
5. **No fabricated history, no zeros for absence.** A KPI without data is `NO_DATA`; an immature cohort is `NOT_YET_OBSERVABLE`; a window that starts before telemetry did is `PARTIAL_COVERAGE`; payment states in `FREE_LAUNCH` are `NOT_APPLICABLE`.
6. **Theoretical value is not revenue.** `theoretical_value_micros` is labelled so; `billed_micros` is exact and is zero in FREE_LAUNCH.

## Components (all in `gateway/`)

| Piece | File | What it does |
|---|---|---|
| GitHub collector | `src/gh_collector.js` | Incremental cumulative `download_count` per `asset_id`; deltas only between observations of the same asset; falling counter = discontinuity (counts nothing); replaced asset = new series; classification bundle/manifest/signature/checkpoint/proof/changelog/metadata/other; records every sync and failure. Hourly via the existing cron. |
| Download states | `src/downloads.js` | `AUTHORIZED → STARTED → PARTIAL → COMPLETED` or `FAILED/UNKNOWN`, derived from the **union of delivered byte ranges**; a signed URL or redirect is never "completed". |
| Request telemetry | `src/analytics.js` | One aggregate upsert per request (latency histogram, status class, units, bytes) + idempotent first-seen rows; REST, MCP and download channels. |
| Community routes | `src/index.js` | `GET /v1/community/releases/{id}/download` and `/manifest`: validated 302 to GitHub, counted as *redirects issued*. Public GitHub URLs are untouched and need no auth. |
| KPI engine | `src/kpi.js`, `src/kpi_catalog.js` | DAU/WAU/MAU by kind, active orgs, recurring, D7/D30/D90 + monthly retention, churn, reactivation, time-to-first-use, Premium adoption (usage ≠ payment), consumption, latency (ESTIMATED), funnel. Catalog is generated to `contracts/v1/kpi-catalog.json`. |
| Cost intelligence | `src/cost.js` | Exact-decimal CSV invoice import (idempotent, all-or-nothing), owner-supplied rates (no seed) × measured quantities = *estimated*, invoices = *confirmed*, allocated vs unallocated, reconciliation, unit costs only when numerator and denominator exist, currencies never summed. |
| CRM | `src/crm.js` | Leads recorded by an admin or an authorised form only; state machine NEW_LEAD…WON/LOST; history; bulk listing hides contacts. |
| Alerts | `src/alerts.js` | Rules over the data returning normalised `macguard.alert/1` objects. **Evaluated, never sent.** |
| Dashboards/reports | `src/dashboards.js`, `tools/render_dashboards.mjs` | Panels are data (`macguard.dashboard/1`): state, source, accuracy, limitations. JSON, CSV (formula-injection neutralised) and escaped HTML; six dashboards, three report kinds. |
| Admin API | `src/analytics_api.js` | `/admin/v1/analytics/*` behind admin key + TOTP: KPIs, catalog, dashboards, reports, alerts, usage (keyset pagination, filters, CSV), costs, CRM. |
| Tenant API | `GET /v1/account/analytics` | A tenant reads **only its own** numbers; the tenant id comes from the key, never the request. |

## Documents in this folder
`MATRIX.md` status and evidence · `DEPLOYMENT.md` what runs where · `PRODUCTION-DELTA.md` production versus local, migration order, rollback · `DOMAIN-ARCHITECTURE.md` and `ROUTE-INVENTORY.md` hostnames and routes · `DOMAIN-MIGRATION.md` the move off Quarantine's hostname · `HARDENING.md` edge and Worker controls · `BACKUP-RECOVERY.md` and `KEY-CUSTODY.md` backups, keys, other-machine restore · `GITHUB-403.md` the collector's refusals · `GUARDOPS-ADAPTER.md` operational events · `SECURITY-REVIEW.md` · `MERGE-PROPOSAL.md` · `D1-COST.md` · `RUNBOOK.md` · `evidence/python-regression-runs.md`.

## Known limits (stated, not hidden)

- GitHub `download_count` counts requests GitHub served — not people, devices, countries or completed transfers — and includes our own and CI downloads. History before the first observation is unknown. Observed deltas need a continuous collector; coverage is reported.
- No production traffic exists yet, so cohorts, retention and adoption are verified on **synthetic test data only**. Dashboards show real data for the GitHub counters (3 releases, 467 cumulative bundle downloads on 2026-10-23, observed growth 0 — one baseline) and explicit empty states for everything else.
- Percentiles are histogram upper bounds (ESTIMATED), shown with ≥100 requests.
- One administrator role exists. Finer RBAC (analyst/read-only) would need a role column: **PLANNED**, not needed for the deployment.
- Provider cost APIs (Cloudflare, Backblaze, Scaleway, Fly, GitHub/GitLab, intelligence providers) are **BLOCKED** on credentials; CSV import is the working path. No rates are seeded.
- Stripe STR-01…STR-10 are **BLOCKED** (sandbox credentials). Dashboards show Stripe as `NOT_INSTRUMENTED`; nothing is simulated.
- Per-isolate first-seen cache and best-effort writes mean a lost write undercounts; that is why the ledger is the billing source.
- Not built: synthetic probes (OBS) and the pipeline/intelligence monitor (INT). GuardOps is a separate project (`docs/analytics/GUARDOPS-INTEGRATION.md`); MacGuard does not depend on it.
- Deployed on 2026-10-23 at `quarantine-api.mac-guard.com`: see `DEPLOYMENT.md` for what was and was not verified remotely.

## Privacy

No persistent visitor identifiers; no cookies or storage; no IP. Actor hashes are keyed (pepper from secrets) and cannot be reversed without it. Leads store only what an admin enters; contacts are never listed in bulk. Tenant dashboards omit GitHub, CRM and platform alerts. Exports neutralise CSV formulas. Retention of analytics aggregates is **one year** (owner decision, 2026-10-23): `src/retention.js` prunes `analytics_daily`, `activity_daily`, `community_requests_daily`, GitHub observations and sync logs older than 365 days, and an actor's first-seen row only once the actor has no activity left in the window. The billing ledger, audit chain, cost entries and leads are never pruned. Reports and the usage API are limited to 366-day ranges.
