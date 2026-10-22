# Test report: Subscriptions and Alerts (2026-10-23)

Baseline before this work (`feat/intelligence-eu`, clean tree): 774 tests, OK, 1 skipped. After it, full run of `python3.13 -m unittest discover -s tests -v` on `feat/alerts` @ 506e493 (MGCTL_AUDIT_BIN and ARCHIVE_REAL_AGE set, Chrome and Playwright present): **945 tests, 2 failures, 1 skipped** (573 s). Both failures were defects of the tests, not of the product, and are fixed in the next commit (see PR #38 for the commit): a race in the browser test (it waited for an old table) and an assertion "no source is cleared" that became false when MacGuard's own release log was cleared (it now asserts that it is the only one). Each fixed test was re-run (browser test 3 times, mgctl intelligence group once) and passes. The full suite was not repeated for test-only edits.

| Gate | Result | Evidence |
|---|---|---|
| Filters: validation, limits, closed vocabulary | PASS | `test_alerts_filters.py` (10) |
| Python = JavaScript on 92 vectors, answers and reasons | PASS (mutation-checked) | `test_the_javascript_evaluator_agrees_on_answers_AND_reasons` |
| Deduplication CVE/EUVD/GHSA, similar titles, conflicts | PASS | `test_alerts_engine.py` (28) |
| Severity change, new exploitation evidence, fixes, new sources | PASS | `IngestTests`, `MatchingTests` |
| Stale feeds | PASS | `FreshnessTests`, `test_stale_sources_do_not_count_as_current_exploitation` |
| Tenant isolation, unauthorised access | PASS | `test_alerts_tenancy.py` (37), `OrgApiTests` |
| Revoked/expired/rotated feed tokens, guessing throttled | PASS | `FeedTokenTests` |
| Leak between tenants and through caches/logs | PASS | `test_a_private_feed_shows_only_its_owner_matches_and_is_never_cacheable`, log redaction test |
| SSRF in webhooks (30 URL forms, 17 address classes, pinned TLS connection) | PASS | `WebhookSecurityTests`, real TLS handshake test |
| Retries, backoff, dead letters, idempotency | PASS | `WebhookDeliveryTests`, `IdempotencyTests` |
| Pagination | PASS | `QueryTests` |
| Accessibility WCAG 2.2 AA (axe) in ES/EN, light/dark, desktop/mobile, 8 pages | PASS | `test_alerts_e2e.py::test_2` (after fixing target sizes and one overflow) |
| ES/EN parity and no key leaking | PASS | `test_alerts_web.Bilingual`, browser test |
| Compatibility of the existing site | PASS | `test_web_intelligence.py` (30), `test_csp`, whole suite |
| Real browser journey across real boundaries | PASS | `test_1_the_user_journey_in_a_real_browser` |
| Linux host `dpkg` | SKIP (PENDING) | needs a real Debian/Ubuntu host |

## Measurements (synthetic data; `scripts/bench_alerts.py`, 3,000 alerts, 300 subscriptions, 150 new alerts, one laptop)

| Metric | Value |
|---|---|
| Matching latency per subscription evaluation p50 / p95 / p99 | 0.006 / 0.028 / 0.055 ms |
| Evaluations per second including storing matches | ≈ 9,400 |
| Ingest | ≈ 220 alerts/s; 4,711 real alerts in 37 s |
| Views built (cache warm-up) | 3,000 in 1.3 s; a warm query scans in 0.08 s |
| Delay from ingestion to match in the bench | bounded by the run interval (30 s simulated) |
| Failed deliveries, duplicates avoided, active subscriptions, source freshness and coverage | recorded in the `metrics` table and shown by `python3 -m alerts status` |

A time is a measurement here, never a criterion.

## First milestone, demonstrated on real data (local, nothing published)

1. Real downloads on 2026-10-22: KEV 1,754, EUVD exploited 1,770, EUVD 2,928 (2-day window), CERT-EU 10.
2. Validated and normalised: 4,708 vulnerability entries, 0 partial validations, 0 identifier conflicts; plus 3 YARA release alerts.
3. Added to the catalog (`python3 -m alerts ingest`, 37 s) with a **local-only override registry that treats those four sources as cleared** (not committed).
4. A filter selects them with reasons; 24 feed files were generated and each validated as RSS 2.0.
5. With the **real** registry the same run yields only the 3 first-party alerts: that is what the committed site data contains.
6. The web shows the alert, its sources and the reasons (browser tests); the YARA channel and the rest of the site are unchanged (whole suite).
