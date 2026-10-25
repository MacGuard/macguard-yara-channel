# MacGuard → GuardOps: operational event adapter

MacGuard does **not** contain an incident, on-call or escalation engine and will not grow one: it reports operational facts to GuardOps' ingestion endpoint, `https://ingest.mac-guard.com`, and GuardOps decides what to do. GuardOps is not deployed (planning documents only), so everything here is verified against a **local fake receiver**: it proves what MacGuard sends, not that GuardOps accepts it.

## Contract
Envelope `macguard.event/1` (`contracts/v1/event.schema.json`, additive change only: seven operational types were added — `gateway.error`, `cron.run.failed`, `integrity.error`, `backup.failed`, `security.incident`, `saturation.detected`, `metrics.snapshot` — alongside the existing `download.failed`). Batches are `macguard.event-batch/1` (`{schema, events[]}`). Every event has a deterministic `event_id` (same fact → same id), an `occurred_at`, a platform `tenant_id` (`GUARDOPS_TENANT`, default `macguard`), `source`, `status` and a small `data` object with `severity` (`low|medium|high|critical`) and counters/ids. **No customer tenant id, key id, address, payload, token or file content leaves** (tested).

## What is forwarded
| Internal event | Sent as | Severity |
|---|---|---|
| `gateway.incident` (collector / cron / retention / stripe-report) | `cron.run.failed` | high — only on the **third** consecutive collector failure and every sixth after, not on every blip |
| `gateway.incident` (origin = the private R2) | `download.failed` | high |
| `gateway.incident` (anything else), `stripe.failure`, `billing.error` | `gateway.error` | high |
| `api.saturated` | `saturation.detected` | medium |
| `abuse.detected` | `security.incident` | high |
| `signature.invalid` | `integrity.error` | critical |
| `replication.failed` | `backup.failed` | high |
| daily metrics (06:xx UTC): requests, server errors, error rate, collector runs and successes | `metrics.snapshot` | — |
| backup alarms from `tools/backup_check.mjs` (via `tools/guardops_emit.mjs`) | `backup.failed` / `integrity.error` | per alarm |
Not forwarded: business events (`download.authorized`, `usage.near_limit`, `tenant.suspended`, `release.premium_published`) — they are not operational.

## Delivery guarantees
Durable **outbox** in D1 (`guardops_outbox`, migration `0003`): an event is queued in the same request that observed it (idempotent insert) and delivered **after** the response (`waitUntil`) or by the hourly cron. Retry with exponential backoff (60 s × 2^attempts, capped at 6 h, `Retry-After` honoured), dead-letter after 20 attempts or on a non-retryable 4xx, one batch of at most 50 per attempt, `Idempotency-Key` per batch. A down or slow receiver never changes a response (tested with R2 failing and the receiver down). Local tools spool to `~/macguard-backups/gateway/guardops-spool.jsonl` when the receiver is unreachable and resend once.

## Credentials and safety
Off by default: nothing is sent unless `GUARDOPS_INGEST_URL` **and** the secret `GUARDOPS_INGEST_TOKEN` are set. The URL must be `https` and its host in `GUARDOPS_ALLOWED_HOSTS` (default `ingest.mac-guard.com`): the token is never sent anywhere else, redirects are not followed, and it is never stored, logged or echoed. The token must be a **limited** credential issued by GuardOps for ingestion only (no read, no admin). Rotating it is `wrangler secret put GUARDOPS_INGEST_TOKEN`.

## To go live (owner, after GuardOps exists)
GuardOps issues an ingest-only token → apply migration `0003` → set the secret and `GUARDOPS_INGEST_URL` in the environment config → redeploy → watch `guardops_outbox` (`pending` stays near zero, `dead` empty) → confirm receipt on the GuardOps side with a `metrics.snapshot`. Until then the adapter is inert.
