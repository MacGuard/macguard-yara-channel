# D1 cost per request — measured

Tool: `node gateway/tools/d1_cost.mjs [--runs=20] [--json]` (statement trace: `tools/d1_trace.mjs`). It runs the **real SQL** of `schema.sql` on `node:sqlite` behind the D1 shim and counts round trips, read statements, write statements and rows actually written, per request in steady state (after a warm-up call). Counts are exact for this code. They say **nothing about latency or the Cloudflare bill** (D1 bills rows read/written; a conflicting `INSERT OR IGNORE` writes no row). Machine was under heavy load (load average ≈ 38), so no timing is claimed.

Run on 2026-10-23, 20 requests per scenario.

| Scenario | `78b1132` (monetization base) | `6aed24a` (analytics, before optimisation) | now, telemetry **off** | now, telemetry **on** |
|---|---|---|---|---|
| REST included op | 11 trips · 4 reads · **7 writes** · 7 rows | 12 trips · 4 reads · **13 writes** · 8 rows | 10 trips · 4 reads · **6 writes** · 6 rows | 11 trips · 4 reads · **7 writes** · 7 rows |
| REST metered op | 12 · 5 · 7 · 7 | 13 · 5 · 13 · 8 | 11 · 5 · 6 · 6 | 12 · 5 · 7 · 7 |
| MCP tool call | 11 · 4 · 7 · 7 | 12 · 4 · 13 · 8 | 10 · 4 · 6 · 6 | 11 · 4 · 7 · 7 |
| Community redirect | n/a (route did not exist) | 0 reads · 1 write | 0 · 0 | 1 write (aggregate) |

The audited "≈ 7 writes per request" is confirmed for the base. Where they came from (`d1_trace.mjs`): `api_keys.last_used_at` update, three atomic quota counters (`INSERT … ON CONFLICT … RETURNING`), and the usage-ledger insert plus its two state updates.

## What changed, and what deliberately did not

- **Changed:** `last_used_at` is refreshed at most every 5 minutes (nothing reads it for a decision) — one write less on almost every request. Telemetry first-seen statements (3 inserts + 2 updates) run once per actor-day per isolate, **only after the batch committed**; steady state is a single aggregate upsert. Net: analytics adds one statement per request, and the total is back to the base's 7 writes / 7 rows.
- **Not changed:** the three quota counters, the ledger insert and its `authorized → processed → completed` updates, and the audit chain. They carry atomic quotas, idempotency and crash-recovery semantics (a request stuck in `authorized` vs `processed` tells reconciliation whether work was done). Merging them would save writes but is a billing-path redesign needing its own reconciliation proof — **not done, not claimed**.
- **Evaluated, rejected for now:** buffering aggregates in memory and flushing periodically (would cut telemetry writes further but loses counts on isolate eviction and breaks counter consistency). Durable Objects / the Rate Limiting binding for per-minute counters remain options listed in `docs/monetization/COSTS.md`; no percentage saving is claimed.

Caveat on the "now / on" figures: the harness wraps the database object, which resets the per-database first-seen cache once; the 20-request average therefore shows 7.25 writes for the metered/included scenarios, and the steady state is 7.

Reproduce: `cd gateway && node tools/d1_cost.mjs`.
