# Analytics, gateway and Premium: status matrix (updated 2026-10-24)

Repository `MacGuard/macguard-yara-channel`; local branch `feat/analytics-guardops` (worktree `…/scratchpad/wt-ana`), based on `feat/monetization` `78b1132`. **Nothing was pushed or merged.** Environments are named exactly: `NODE_LOCAL` = `node --test` over `node:sqlite` behind a D1 shim · `WORKERD_LOCAL` = Miniflare/workerd with D1 and R2 bindings, local · `PY313_LOCAL` = `python3.13 -m unittest discover -s tests` · `REMOTE_CLOUDFLARE` = the deployed Worker/D1 · `SYNTHETIC` = made-up content. **No `STRIPE_SANDBOX` test exists** (credentials not provided).

## Deployed service (REMOTE_CLOUDFLARE)
| Item | Value |
|---|---|
| URL | `https://quarantine-api.mac-guard.com` — **this hostname belongs to Quarantine by the owner's design; the planned home is `https://api.mac-guard.com`** (`DOMAIN-MIGRATION.md`, not executed) |
| Account / Worker / D1 / R2 | `9e96e19f…` / `macguard-gateway` / `macguard-gateway` (`92207c74…`) / `macguard-premium-private` |
| Deployed code | `4d9b1ff` · Worker versions `622afeaf-…` (first upload) → **`2920e0d5-d7df-4c0d-a078-48764b461dd6`** (current) |
| Mode | FREE_LAUNCH, policy v1, billing off, x402 off, no Stripe secret, 0 tenants, 0 keys |
| **Not deployed yet (everything after `4d9b1ff`; full list in `PRODUCTION-DELTA.md`)** | `0d36670` bounded body reads and no audit write for unknown administrator ids · `2c29c9b` same-second sync fix · `da111ab` test-traffic exclusion (needs `migrations/0001_telemetry_exclusions.sql`) · `b295a77` tenant/key admin routes · `378a3ed` Community/comparison dashboards. **Until a redeploy is authorised the running Worker lacks these fixes.** |
| Cron `17 * * * *` | see "Cron" below |

## Status by feature
| ID | Feature | Status | Commit | Tests (environment) | Evidence / blockers |
|---|---|---|---|---|---|
| ANA-01/02 | GitHub collector, same-asset deltas, kinds (bundle/manifest/signature/checkpoint/proof/changelog/metadata) | VERIFIED (local); manual real sync REMOTE | `d0721a6`, `2c29c9b` | 11 + 3 cron tests with the 10 real asset names (NODE_LOCAL) | a defect found and fixed: two syncs in one second lost a variation |
| ANA-03 | Download states from delivered byte ranges | VERIFIED (local) | `d0721a6` | brute-force model of ranges; E2E with out-of-order fragments (NODE_LOCAL) | not exercised on workerd for partial transfers |
| ANA-04/05 | REST/MCP/download telemetry, replay-safe; Community redirect (config-driven) | VERIFIED (local); redirect + 401s REMOTE | `d0721a6`, `b14660f`, `fc98933` | 12 in `analytics.test.js` | public GitHub URLs untouched |
| ANA-06 | KPI engine + catalog | VERIFIED on synthetic data | `b8185d2` | 7 | no real traffic: real cohorts UNKNOWN |
| ANA-07/08 | Cost intelligence, CRM | VERIFIED (synthetic invoices) | `b1580ae` | 6 | provider cost APIs BLOCKED (credentials); no rates seeded |
| ANA-09/10 | Alerts (evaluated, not sent), dashboards (11: overview, downloads, api, premium, cost, crm, comparison, retention, pipeline, signatures, cas_backups), reports | VERIFIED (local) | `69503ee`, `378a3ed` | 10 | Community windows show coverage; comparison keeps units apart |
| ANA-11/12 | Admin analytics API, tenant API, tenant isolation | VERIFIED (local); admin KPIs REMOTE | `6aed24a`, `da111ab` | 7 (analytics API; isolation assertions included) | remote tenant path not verified (no tenant exists) |
| ANA-13 | D1 statements per request | MEASURED (counts only) | `7e548db` | `tools/d1_cost.mjs` | 7 writes, same as base with telemetry |
| ANA-14 | Contracts `contracts/v1` | EXPERIMENTAL | several | alert + KPI contract exercised | no external consumer |
| ANA-17 | Retention: one year | VERIFIED (local, isolated fixtures); not run remotely | `407705a` | 3 + 1 cron-gated | never deletes ledger, audit, costs, policy, evidence; first remote run due 03:xx UTC after the next deploy |
| ANA-19 | Test-traffic identification (not deletion) | VERIFIED (local); migration pending | `da111ab` | 1 | the 4 probe rows on the remote D1 are still counted until the migration + redeploy |
| ANA-20 | Admin tenant and API-key lifecycle | VERIFIED (local) | `b295a77` | 3 | not deployed |
| SEC-01 | Bounded body reads, method limits, admin oracle/replay/enumeration, no write amplification | VERIFIED (local) | `0d36670` | 6 in `security.test.js` | **not deployed** |
| SEC-02 | Edge hardening rules (WAF/rate limits) | PREPARED, NOT APPLIED | `68fc299` | 4 (rules evaluated against Community requests: none matched) | needs owner authorisation and a check of the plan's rule limits |
| REC-01 | D1 backup + isolated restore verification | VERIFIED (REMOTE read-only export, local restore) | `1fe90f4` | 7 + a real run: 8/8 checks, audit chain intact on production rows | no schedule; secrets backup via `age` tested locally (`fac7fdd`); DR into a remote scratch database not done |
| DOM-01 | Domain separation `api.mac-guard.com` | **PLANNED; read-only audit done** | `17f2808` | three configs validated with `wrangler --dry-run` | needs the owner's specific authorisation |
| PRE-01 | Source inventory | DONE | `c7c0224` | — | 5 real connectors on the intelligence stack, none approved for Premium |
| PRE-02 | Licence evidence | DOSSIER (proposals) | `3143443` | — | owner decision; KEV and SigmaHQ are candidates |
| PRE-07 | Bundle families (executable vs data), gates per family | VERIFIED (SYNTHETIC) | `5c17ef5` | 26 Python (PY313_LOCAL) | unsigned, nothing published |
| PRE-11/13 | Builder → gateway E2E (range, integrity, ledger billed 0, dashboard) | VERIFIED (SYNTHETIC, NODE_LOCAL) | `5e5f1a7` | 2 | **Premium is NOT operational: no real publication, no real complete download** |
| PRE-12 | Community vs Premium comparison | VERIFIED (local) | `378a3ed` | 2 | real data only for GitHub counters |
| PRE-03/04/05/06/08/09/10/14/15/16 | connectors into the builder, validators, rule QA, quarantine hook, signing + transparency, CAS, R2 publication, review | NOT STARTED / PLANNED | — | — | dependencies in `SOURCE-INVENTORY.md`; need the intelligence stack, owner decisions and authorisation |
| GH-403 | GitHub 403 in the cron: investigation | **INVESTIGATED, cause not proven**; production run data analysed (6 of 10 runs failed, 4 ok, 48 correct variations stored) | `7956d74`, `b635edd`, `2d3131e` | classification, token and reliability tests | most likely the per-IP anonymous limit on shared egress; proof needs the instrumented build or a token (owner). My first reading of `rate_remaining` was wrong and is corrected |
| GH-TOK | Optional read-only `GITHUB_TOKEN`, never leaked | VERIFIED (local) | `b635edd` | 3 | the secret is not set; needs the owner |
| TEST-01 | `test_dynamic_gate` load sensitivity | FIXED (local) | `e075dcc` | 14 in the module (3 new, timing-independent) | root cause: a failed run returned a different shape; now stable, labelled `performance` vs `functional`; the two historic runs are kept in `ana-evidence/` |
| REC-02 | Automated encrypted backup, status, alarms, retention (dry run), staging-restore plan, launchd template | VERIFIED (real remote export, local isolated restore) | `1751bef` | 8 in `backup_flow.test.js` + real run 8/8 on the ciphertext | interim age key lives in the same Keychain; schedule not installed; staging restore not run |
| MIG-01 | D1 migrations 0001–0003 from the exact deployed schema | VERIFIED (local) | `e8fc66a`, `ce85bac` | 4 | not applied remotely |
| DOM-02 | Seven-hostname architecture, generated route inventory (drift-tested), hostname gate | VERIFIED (local) | `e8fc66a` | 3 + 1 | no DNS or Worker change; `api` still free |
| GOP-ADP | Operational events to `ingest.mac-guard.com` (outbox, allow-listed https, limited credential) | VERIFIED against a LOCAL fake receiver; inert in production | `ce85bac` | 7 | GuardOps does not exist yet: delivery to the real receiver UNKNOWN |
| SEC-03 | Access payload (prepared), per-route WAF regression | PREPARED / VERIFIED (local) | `ce85bac` | 2 | nothing applied to Cloudflare |
| PRE-03/04 | Adapter from a built data channel (KEV, EUVD, Feodo…) to a Premium candidate | VERIFIED (SYNTHETIC channel) | `646c08e` | 4 Python | the connectors live on the intelligence stack (not in this tree); human review never assumed; licence gate still decides |
| KEY-01 | Audit of the provisional `age` backup key: permissions, format, persistence, recoverability | **AUDITED: gap found** | `5f53b6d` | 2 (rotation, other-machine restore) | key, ciphertext and secrets all sit on one machine and one Keychain (not iCloud-synced). Rotation tool and offline-escrow procedure exist; the owner must do the escrow and copy backups off the machine (`KEY-CUSTODY.md`) |
| GH-DENY | Collector tells primary, secondary, 401, 404 and other denials apart; token tools (`set_worker_secret`, `check_collector`) | VERIFIED (local); evidence from GitHub's docs and read-only probes | `fd52553` and later | 6 + 3 | production still runs the old classification; the token needs the owner |
| TEN-01 | Tenant isolation matrix (idempotency across tenants, usage/entitlements/analytics, MCP, admin views, no cookies/CORS) | VERIFIED (local) | `712920a` | 5 | no remote tenant exists |
| CTR-01 | Contract examples for the GuardOps receiver, generated by the adapter, drift-checked; self-hosted endpoint rules | VERIFIED (local, fake receiver) | `712920a` | 2 | GuardOps does not exist; no real data sent |
| STR-01…10 | Stripe sandbox | **BLOCKED** (credentials) | — | none | existing adapter tested against `LOCAL_HTTP_FAKE` only |

## Cron
**What was verified REMOTE (read-only queries of the live D1):** the hourly trigger fired by itself at `2026-10-23T20:18:00Z` (the `17 * * * *` schedule), the Worker ran the collector, and the outcome was persisted: `gh_sync` shows `last_attempt_at 20:18:00Z`, `last_success_at 19:27:39Z` (the manual sync), `last_status github_rate_limited`, `consecutive_failures 1`, `rate_remaining 21`, and `gh_sync_log` gained a row `(20:18:00Z, 0, 0, github_rate_limited)`. So scheduling, timestamps, error handling and persistence work in production.
**What failed:** the automatic run **did not collect data**: GitHub answered 403 to the anonymous request from the Worker. (Correction, 2026-10-24: I earlier read `rate_remaining 21` with a past reset time as a sign that this was not a plain rate limit; that was wrong, those values came from the previous successful sync because the deployed code stores rate headers only on success. See `GITHUB-403.md`.) No variation could be computed remotely. **Blocker for the owner:** a read-only `GITHUB_TOKEN` (a fine-grained token with no permissions is enough for public repositories) set as a Worker secret; anonymous calls from shared Cloudflare egress addresses are not reliable. The fix `7956d74` (not deployed) classifies 403s and stores GitHub's own message, so the next failure explains itself.
**Verified locally with the real `scheduled()` handler** (`test/cron.test.js`, NODE_LOCAL): baseline then variation with the ten real asset names (bundle +25 while manifest and signature growth stay separate), failures recorded and reset, retention only in the 03:xx run, and a same-second double sync no longer loses a variation (defect found and fixed). Alert `github.collector_failing` fires after three consecutive failures.

## Regression (round of 2026-10-24; the earlier round is kept below)
| Suite | Result | Tree / environment |
|---|---|---|
| Gateway Node | **177/177** | `712920a`, NODE_LOCAL |
| workerd | **9/9** | `712920a`, WORKERD_LOCAL |
| Drift checks (OpenAPI, KPI catalog, route inventory, contract examples, hardening payload) | all current | `712920a` |
| Python 3.13, third full pass | 601 run, **1 failure** (`GateTests.test_a_good_set_passes…`), 10 skipped | `5f53b6d`+ with my Node suites running at the same time; the approved set came out empty ("did not converge"): the same load mechanism as the two earlier errors |
| Python 3.13, fourth full pass | **601 run, OK, 10 skipped** | `c077902` (gate tests fixed, machine otherwise idle); later commits changed only gateway JavaScript, docs and tools, none of which Python tests read |
Four Python passes are kept as evidence (`evidence/python-regression-runs.md`, raw logs in `~/macguard-evidence/2026-10-24/`). The third failure was investigated before repeating: tests that expect the gate to *accept* a good set now use generous timing limits (they test correctness, not speed) and only the three blocking-rule tests keep a finite per-file timeout (3 s). Not claimed: that these tests can never flake on a machine under extreme load.

### Previous round (2026-10-23)
| Suite | Result | Commit / environment |
|---|---|---|
| Gateway Node | **136/136** | `7956d74` (code), NODE_LOCAL |
| workerd | **9/9** | `a243a8f` (code identical to `7956d74` except the collector diagnostics), WORKERD_LOCAL |
| OpenAPI and KPI contract drift checks | current | `a243a8f` |
| Python 3.13, first full pass | 594 run, **2 errors**, 10 skipped | `a243a8f`, PY313_LOCAL, machine under heavy load (load average above 60 from other agents plus my own Node runs) |
| Python 3.13, second full pass | **594 run, OK, 10 skipped** | `6333623` (docs-only commits after the code), PY313_LOCAL, machine quiet |
The two errors of the first pass were `test_dynamic_gate.BenignHitRateTests` (`KeyError: benign_hits_by_file`). Investigated, not just retried: this branch does not touch `scripts/dynamic_gate.py` or its test (empty diff against the base); the module passes alone (11/11, 143 s); reading the code shows the dynamic gate returns a result **without** that key whenever its timing-based verdict is not `ok`/`no-baseline`, which happens when the machine is overloaded. So it is a **pre-existing load sensitivity** (a test whose outcome depends on timing), not a defect of this work; making those two tests independent of wall-clock performance is a separate fix. The 10 skipped tests are not passes. The historical 588 became 594 because six new family tests were added.
Web and docs checks: wiki 23/23, `wiki_check` OK with 0 lines needing review, kanban `--check` matches, web-intelligence 30/30, alerts-web 14/14, docs 48/48 (run on the stacked branches).

## Risks
(1) The deployed Worker lacks the post-deploy security fixes (unbounded body reads; one audit write per anonymous admin attempt) until a redeploy is authorised. (2) The gateway sits on Quarantine's hostname. (3) Premium has no approved content: do not announce it. (4) No edge rules, no scheduled backup, no rehearsed rollback or restore of the live database. (5) One administrator and one TOTP device: losing it needs a re-bootstrap. (6) The audit chain head is not anchored outside D1. (7) Test rows of 2026-10-23 remain in the remote telemetry until the migration.

## Actions to close production (each needs the owner)
1. Authorise a redeploy of the current branch plus `migrations/0001_telemetry_exclusions.sql`, then mark the 4 probe rows. 2. Authorise the domain migration (`DOMAIN-MIGRATION.md`). 3. Authorise the edge rules (`HARDENING.md`) and choose whether `/admin` goes behind Cloudflare Access. 4. Provide an `age` recipient for the secrets backup and decide the backup schedule. 5. Decide the licence questions (KEV, SigmaHQ, GPL/DRL material) so a first real Premium candidate can be built. 6. Provide Stripe sandbox credentials. 7. Approve the merge order in `MERGE-PROPOSAL.md`.


## Final matrix, second closing round (2026-10-24, SHA `550f0c0` on `feat/analytics-guardops`)
Environment words: **LOCAL** = this Mac, Node/node:sqlite/workerd/Python; **SIMULATED** = synthetic data or a fake receiver/provider; **REMOTE-RO** = read-only calls to real Cloudflare/GitHub; **STAGING** = a staging Worker/D1 (none exists: creating it is a remote write that needs the owner); **PRODUCTION** = what is deployed (code `4d9b1ff`, Worker `2920e0d5`). Nothing below is verified in STAGING; only the first column group of GitHub and Cloudflare reads touched real providers, read-only.
| FEATURE | IMPLEMENTED | VERIFIED | BLOCKED | FAILED | UNKNOWN | BRANCH | COMMIT | TESTS | EVIDENCE | NEXT_ACTION |
|---|---|---|---|---|---|---|---|---|---|---|
| GitHub collector, same-asset deltas | yes (LOCAL) | LOCAL + SIMULATED; **REMOTE-RO**: two real runs 70 s apart (24 baselines, then 0 new baselines and 0 deltas, status ok); PRODUCTION cron: 5 ok runs with 48 correct deltas | — | — | whether a real delta is captured across a real download (counters did not move in 70 s) | `feat/analytics-guardops` | `7956d74`, `b635edd` | `gh_collector`, `cron` | `~/macguard-evidence/2026-10-24/collector-real-run{1,2}.json`; `GITHUB-403.md` | owner: create the token; redeploy |
| HTTP 403 classification (primary / secondary / credentials / not found / other) | yes | LOCAL + SIMULATED (statuses, headers, redaction) | cause of the production 403s unproven | production code lacks the diagnostics | exact cause (likely shared-egress per-IP limit) | same | `7956d74` | `gh_collector` | `GITHUB-403.md` | token + redeploy, then `check_collector.mjs` |
| Authenticated read-only token integration | yes (secret tool, shape check, never printed) | LOCAL (tool and redaction tested) | **no `GITHUB_TOKEN` in the secret manager** | — | token behaviour against real GitHub | same | `b635edd`, `c077902` | `set_secret`, `gh_collector` | `GITHUB-403.md` | owner creates a no-permission fine-grained token |
| Freshness and consecutive-failure alerts | yes (`github.collector_stale`, `_failing`, `_reliability`, `_token_rejected`) | LOCAL | delivery needs GuardOps | — | — | same | `69503ee` | `insights` | `alerts.js` | wire to a receiver when it exists |
| Community channel free, FREE_LAUNCH policy, Stripe live off, x402 off | yes | PRODUCTION read-only (policy v1, no Stripe secret, x402 false) + LOCAL | — | — | — | same | `4d9b1ff` | `security`, `e2e_premium` | `DEPLOYMENT.md` | none |
| Source matrix (YARA, IOC, CVE, KEV, EUVD, EPSS, Sigma, Suricata, threat context) | yes (`docs/monetization/SOURCE-INVENTORY.md`, licence dossier) | five real connectors ran LOCAL (KEV, EUVD, EUVD exploited, CERT-EU, Feodo) | **no source approved for Premium** (owner licence decisions) | — | EPSS, Sigma, Suricata, Malpedia terms not downloaded/validated | `feat/monetization` + this | `c7c0224`, `3143443` | `test_premium` | `SOURCE-INVENTORY.md` | owner decides licences |
| Premium bundle published | builder + gateway E2E (SIMULATED) | SIMULATED only | **no approved content, no real publication, no real download** | — | — | `feat/analytics-guardops` | `5c17ef5` | `e2e_premium`, `test_premium` | `MATRIX.md` PRE rows | not operational: do not claim |
| Dashboards: downloads (Community and Premium), API/MCP, usage/orgs, retention, cost, pipeline, signatures, CAS/backups | yes (11 dashboards) | LOCAL + SIMULATED; states NO_DATA / NOT_INSTRUMENTED / PARTIAL_COVERAGE tested; test traffic excluded; GitHub requests never presented as unique users | signatures and transparency log, CAS: not instrumented by design (do not exist yet) | — | rendering with real production data (none yet) | same | `550f0c0` | `dashboards_extra`, `insights` | `dashboards.js` | build PRE-07 signing before showing signatures |
| Staging sequence (backup, verify, migrate, deploy, smoke, security, restore/rollback) | yes: plan + `smoke.mjs` + `staging.wrangler.toml` + local rehearsal | LOCAL rehearsal passes, **including rollback: the previously deployed code `4d9b1ff` runs on the migrated schema** | STAGING not run: needs a staging D1/Worker (remote writes) | — | behaviour on real D1/workerd of staging | same | `b6a1b73`, `550f0c0` | `staging`, `staging_rehearsal` | `STAGING-SEQUENCE.md` | owner approves S3-S8 on staging |
| D1 migrations 0001-0003 | yes | LOCAL (from the exact deployed schema, additive, data intact) | not applied remotely (owner) | — | real D1 apply | same | `da111ab` (0001), `4d9b1ff`..`b635edd` (0002), `ce85bac` (0003) | `migrations` | `PRODUCTION-DELTA.md` | staging first |
| Domain architecture and route ownership | yes | LOCAL (inventory drift test; gateway and Quarantine path sets disjoint) ; REMOTE-RO audit of Custom Domains | DNS / Custom Domain changes: owner | — | whether anything outside Cloudflare answers `api.` | same | `b6a1b73` | `routes`, `route_ownership` | `DOMAIN-ARCHITECTURE.md` | none until authorised |
| Backup, age encryption, SHA-256, isolated restore, recovery without Keychain, key rotation | yes | LOCAL + a REMOTE-RO export restored in isolation | owner: offline key escrow, off-machine destination, second computer | — | restore into a real remote D1 | same | `1751bef`, `b6a1b73` | `backup`, `backup_flow`, `key_custody`, `offsite` | `KEY-CUSTODY.md`, `BACKUP-RECOVERY.md` | owner actions listed in KEY-CUSTODY |
| Backup failure alarms | yes (`backup.*`, `--custody`) | LOCAL; on this Mac `backup.offsite_stale` and `backup.drill_stale` FIRE (true) | — | — | — | same | `b6a1b73` | `offsite` | `backup_check.mjs --custody` | configure destination |
| Security: tenant isolation, API keys, admin MFA, WAF rules, body limits, rate limits, host allowlist, CORS/cookies, webhooks, R2 protection, secrets, audit | yes | LOCAL / SIMULATED (edge rules are data, regression-tested, not applied) | edge rules and Access: owner authorisation | — | WAF behaviour on the real edge | same | several | `security`, `tenant_isolation`, `hardening`, `e2e_premium`, `set_secret` | `SECURITY-REVIEW.md`, `HARDENING.md` | staging, log-only first |
| GuardOps adapter, outbox, contracts | yes | LOCAL + SIMULATED (fake receiver) | no authorised receiver exists | — | real receiver behaviour | same | `ce85bac` | `guardops` | `GUARDOPS-ADAPTER.md` | none until GuardOps exists |
| Regression on this SHA | — | Node **202/202**, workerd **9/9**, OpenAPI / KPI / route / dashboard-source / first-bundle drift current; Python 3.13 **608 OK, 10 skipped** (`evidence/python-regression-runs.md`, seventh pass) | — | — | — | same | `e4bd426` | all | `~/macguard-evidence/2026-10-24/` | repeat on the merge result |

## Third round (2026-10-24 evening, code `e4bd426`)
Real Cloudflare state re-read (read-only, account `9e96e19f…`): Workers `macguard-gateway` (version `2920e0d5…`, 100 %) and `macguard-quarantine`; D1 `macguard-gateway` and `macguard-quarantine`; R2 `macguard-archive-r2` and `macguard-premium-private`; Custom Domains `panel` → quarantine, `quarantine-api` → gateway; workers.dev subdomain set. **No staging resource exists** (no `macguard-gateway-staging` Worker or D1): staging is PREPARED, not real.
| FEATURE | IMPLEMENTED | VERIFIED | BLOCKED | FAILED | UNKNOWN | BRANCH | COMMIT | TESTS | EVIDENCE | NEXT_ACTION |
|---|---|---|---|---|---|---|---|---|---|---|
| Staging provisioning plan, incl. staging-only peppers and a staging administrator | yes | LOCAL: the secret tool refuses `KEY_PEPPER`/`ADMIN_PEPPER`/`TOTP_SEAL_KEY` on any Worker not named `*-staging`; `--admin-only` bootstrap leaves the restored policy and audit chain untouched | **real staging needs the owner's specific approval** (D1 + Worker creation, secrets, deploy) | — | behaviour on real D1 / workerd of staging | `feat/analytics-guardops` | `e4bd426` | `set_secret`, `staging_rehearsal`, `staging` | `STAGING-SEQUENCE.md` | owner approves S3-S8 |
| Eleven dashboards and their sources | yes | LOCAL: `DASHBOARDS.md` generated from the code and drift-tested; on an empty gateway only 3 static panels claim data | panels with real traffic: none exists | — | rendering with production data | same | `e4bd426` | `dashboards_extra` | `DASHBOARDS.md` | none until traffic exists |
| Retention 365 d does not touch ledger, audit, policy, releases or hashes | yes | LOCAL: the job names only analytics tables; byte-identical protected tables in an isolated run | not run remotely | — | — | same | `407705a` | `retention` | `src/retention.js` | first remote run after redeploy |
| Backup recipient and a real backup | yes | **LOCAL on the real files**: `recipient.txt` equals the recipient of the Keychain identity; newest real backup decrypts and its SHA-256 equals the manifest | Bitwarden-held identity: **no `bw` CLI / vault** · second destination: only the internal boot volume is mounted · another computer | — | — | same | `e4bd426` | `offsite`, `key_custody` | `KEY-CUSTODY.md` (audit section) | owner: external disk, Bitwarden, second Mac |
| Off-machine copy refuses the same volume | yes | LOCAL | — | — | — | same | `e4bd426` | `offsite` | found while dry-running to `/Volumes/Muky HD` (a symlink to `/`) | — |
| Licence classification for a first bundle | yes (proposals; matrix unchanged) | LOCAL: no real source passes the gate; unknown sources denied; document generated and drift-tested | **every source awaits the owner**: candidates are CISA KEV (data) and SigmaHQ (rules, per-rule audit) | — | EUVD, NVD, EPSS, OSV, ClamAV, ESET, Volexity terms | same | `e4bd426` | `test_premium` (RealMatrixTests) | `docs/monetization/FIRST-BUNDLE.md` | owner decisions; build PRE-07 signing |
| Signatures / transparency log | not built | — | PRE-07 | — | — | — | — | — | dashboards say NOT_INSTRUMENTED | build |
| Plaintext backup on disk | — | AUDIT: `~/macguard-backups/gateway/20261023T200122Z` holds `d1-export.sql` (unencrypted, checksums OK) from before encryption was enabled; the newest (`20261024T050235Z`) is `.age` and checksums OK | decision to securely remove the plaintext copy belongs to the owner (nothing deleted) | — | — | — | `e4bd426` | `backup_flow` | this section | owner: encrypt-and-remove or keep offline |
| `/Volumes/Muky HD` | — | AUDIT: symlink to `/` (same boot volume), so it is not a second copy; `offsite.json` and `drills.json` do not exist | external disk | — | — | — | `e4bd426` | `offsite` | `KEY-CUSTODY.md` | owner: mount a real external disk |

## Unified pipeline round (2026-10-24 night): one pipeline, two bundles
Branch `feat/unified-pipeline` = `feat/analytics-guardops` + `feat/intelligence-eu` (merged locally, no conflicts) + this round. Code SHA `0f56770` (see the last commit of the branch for later docs-only changes). Design: `docs/intelligence/PIPELINE-TWO-BUNDLES.md`. Per-source matrix: `docs/intelligence/SOURCE-MATRIX.md` (generated).

| FEATURE | STATUS | BRANCH | SHA | TESTS | EVIDENCE | BLOCKERS | NEXT_ACTION |
|---|---|---|---|---|---|---|---|
| Community channel unchanged (existing pipeline, URLs, manifests, signatures, log) | VERIFIED for the pipeline: no pipeline script and no workflow differs from `main` (`git diff 89162af..HEAD` on `scripts/prepare.py decide.py seal.py tlog.py make_public_candidate.py verify_release.py validate.py admission.py` and `.github/workflows` is empty). One public page differs: `web/index.html` gained an additive link to the Intelligence section from the earlier `feat/intelligence-web` commit `8d37c53` (not this round) | `feat/unified-pipeline` | `0f56770` | `tests/` (Python full) | the diff above | none | none |
| Intelligence manifest names the Community release and proves exact/subset | VERIFIED (local) | same | `2c639e6` | `test_premium` (CommunityLinkTests, 5) | `PIPELINE-TWO-BUNDLES.md` | owner licence decisions decide exact vs subset | decide `macguard-yara-releases` for the commercial product |
| `from-community`: verified signed Community release copied byte for byte | VERIFIED with a stub verifier + the real verifier refusing an unsigned release; IMPLEMENTED against a real signed release (not run: needs a published release dir) | same | `21e7b26` | `test_premium` (CommunityCandidateTests, 4) | tests | a real Community release directory and its Sigstore bundle | run it on the latest published release |
| Source/artifact matrix (generated, drift-tested) | VERIFIED | same | `3dc8111`, `39842ba` | `test_premium` | `SOURCE-MATRIX.md` | — | regenerate when a licence decision lands |
| EPSS validator + live wiring | IMPLEMENTED; VERIFIED on synthetic input and a local HTTP server | same | `356533d` | `test_families` | no real download stored | licence NOT REVIEWED; none run | owner reads the FIRST usage terms; then one real run |
| MITRE ATT&CK validator + live wiring | IMPLEMENTED; VERIFIED on synthetic input and a local HTTP server | same | `356533d` | `test_families` | no real download stored | derivative-works terms | owner/counsel; then one real run |
| Suricata syntax validator | IMPLEMENTED (syntax only); engine validation NOT_RUN | same | `356533d` | `test_families` | — | `suricata -T` not installed; no fetcher; GPL scope | install engine in CI; decide licence |
| Sigma validator | BLOCKED (needs a YAML parser or pySigma; the repository is standard-library only) | — | — | — | — | dependency policy | owner decides the dependency |
| NVD / OSV / GHSA / ClamAV / Feodo-next adapters | UNKNOWN/not built (NVD, OSV adapters absent **when this row was written; corrected: they exist in `intel/vulns/live_more.py` and ran on 2026-10-25**; Feodo, KEV, EUVD, CERT-EU built earlier) | — | — | — | `SOURCES-STATUS.md` | licences LICENSE_REVIEW | after owner decisions |
| Transactional publication (`publish_premium`) | VERIFIED locally with failure injection at every step; real `--apply` NOT run | same | `af85f9a` | `gateway/test/publish.test.js` (3) | tests | a signed release (PRE-07), owner go-ahead | build signing, then dry-run on staging |
| Signing + transparency log for Intelligence | NOT DONE | — | — | — | proof says `NOT_SIGNED` / `NOT_LOGGED` | design + owner | PRE-07 |
| Backups to B2 + Scaleway + R2 (independent, write-once, read-back, per-provider drill + alarms) | VERIFIED locally (in-memory stores + local HTTP server + SigV4 test vector); real providers NOT exercised | same | `09ffa4e` | `gateway/test/objstore.test.js` (7) | `BACKUP-OBJECT-STORES.md` | no `MG_*` credentials here; Scaleway bucket unknown | owner supplies credentials at run time; first real `sync --apply` |
| Provider panels in `cas_backups` | VERIFIED locally | same | `09ffa4e` | `dashboards_extra` | `DASHBOARDS.md` | no real copies recorded | after the first real sync |
| Bitwarden recovery copy of the age identity | BLOCKED (no `bw` CLI) | — | — | — | `KEY-CUSTODY.md` | owner installs Bitwarden CLI | owner |
| Dashboards: Community vs Intelligence separated | IMPLEMENTED (earlier rounds) and unchanged; no real data | `feat/analytics-guardops` | `e4bd426` | `dashboards*` | `DASHBOARDS.md` | no traffic | none |
| Quarantine panel reused (no second panel) | VERIFIED by absence (no new panel code) | — | — | — | grep | — | — |
| REST/MCP quotas, idempotency, tenant isolation | VERIFIED (earlier rounds, still green in this branch's regression) | `feat/analytics-guardops` | `e4bd426` | `tenant_isolation`, `api`, `security` | Node log | — | — |
| Flaky assertion in `core.test.js` (secret fragment) | FIXED: ~4.6% false failure because the secret is base64url and can contain `_` | `feat/unified-pipeline` | `0f56770` | `core.test.js` | `~/macguard-evidence/2026-10-24/node-full-unified.log` (the failing run) | — | record in lessons |


### Regression of the unified branch (code `0f56770`, docs `2422c2c`)
Node **212/212**, workerd **9/9**, Python 3.13 **955 OK / 14 skipped**; OpenAPI, KPI catalog, route inventory, DASHBOARDS.md, FIRST-BUNDLE.md and SOURCE-MATRIX.md drift checks current. Logs: `~/macguard-evidence/2026-10-24/*unified*`. Lesson: a test that checks "the secret is never stored" must search for the WHOLE secret; the previous fragment (`split('_')[2]`) is a short string whenever the base64url secret contains `_` (about 4.6 % of runs), which produced a false failure that had been latent since the first gateway commit.

## Sources and downloads round (2026-10-24 night): observability of every provider in the existing panel
Branch `feat/sources-monitoring` (from `feat/licence-audit` from `feat/unified-pipeline`; local, nothing pushed). Code SHA `0865e72`. Design and honest state: `docs/observability/SOURCES-AND-DOWNLOADS.md`. Real read-only evidence and screenshots: `~/macguard-evidence/2026-10-24/telemetry-real/`.

| FEATURE | STATUS | BRANCH | SHA | TESTS | EVIDENCE | BLOCKERS | NEXT_ACTION |
|---|---|---|---|---|---|---|---|
| Source inventory derived from registry, YARA config, connector code, workflow cron, backup destinations, licence matrix (no second list) | VERIFIED | `feat/sources-monitoring` | `3bbf55e` | `tests/test_sources_inventory.py` (4) | `scripts/sources_inventory.py`; 19 sources today | — | new connectors appear by themselves |
| Run telemetry `macguard.source-run/1` from the intel connectors (counts by file, answer and record; error classes; 304; pagination; partial) | VERIFIED locally; KEV, Feodo, CERT-EU, EUVD and EUVD-exploited also run for real, read-only | same | `1e1791d`, `7a7f01c` | `tests/test_telemetry.py` (17) | `telemetry-real/outbox` (6 records) | no scheduler runs the connectors | a scheduler (owner) |
| Persistent, idempotent outbox + flush (Python and Node); recovery after outage, restart, D1 error | VERIFIED (E2E with injected failures, a real flush process, a real HTTP request) | same | `114ca2b` | `e2e_telemetry.test.js` (8), `gateway/test/telemetry.test.js` (4) | tests | — | — |
| Telemetry never breaks a connector, a backup or Community distribution | VERIFIED; the E2E found and fixed a real defect (an unusable outbox directory stopped a connector) | same | `114ca2b` | `e2e_telemetry` (6th), `test_telemetry` | tests; grep shows no reference in Community pipeline, workflows, public page or download path | — | — |
| Migration 0006 (+ rollback, schema mirror) and ingest/read API `macguard.feeds-api/1` | VERIFIED on node:sqlite AND real workerd + real D1 (concurrency: 1 of 8 simultaneous deliveries counted) | same | `afd3954`, `0865e72` | `feeds.test.js` (16), `test-runtime` (+1) | tests | not applied to the production D1 | owner: apply 0006 |
| Charts: files/records/outcome/bytes/latency p50-p95-p99/success %/errors by class/family comparison/Community vs Intelligence, 24h-365d, overlay of up to 8 sources, explicit FAILED / NO_TELEMETRY / NOT_SCHEDULED | IMPLEMENTED + VERIFIED in Chromium, Firefox, WebKit; real records previewed | same | `0f1f501`, `7a7f01c` | `feeds.ui.test.mjs` (6 x 3 engines) | screenshots in `telemetry-real/` | **real data in the production panel: none** | deploy, then first runs |
| Alerts (20 rules) with dedupe, auto-recovery, acknowledge / silence / resolve, per-source thresholds, append-only history, audit chain | VERIFIED | same | `afd3954` | `feeds.test.js` | tests | cron for time-based rules not deployed | owner: deploy `wrangler.toml` |
| RBAC: viewer reads, reviewer acknowledges/resolves, administrator silences/configures/tests; no API-key access; read access to GitHub is not panel access | VERIFIED | same | `afd3954` | `feeds.test.js`, UI tests | tests | — | — |
| Administrator connection test (SSRF containment, rate limits, no credential, changes nothing) | VERIFIED locally | same | `afd3954` | `feeds.test.js` | tests | not run against a real provider from the panel | after deploy |
| Backups B2 / Scaleway / R2 reported per destination and operation; critical alert when none holds a recent verified copy | VERIFIED with fake stores + the real panel handler; **no real upload has happened** | same | `fd6d10b`, `114ca2b` | `gateway/test/telemetry.test.js`, `e2e_telemetry` (7th) | tests | credentials, Scaleway bucket | first real `sync --apply` (owner) |
| YARA (Community) records from the pipeline artifacts, read-only | IMPLEMENTED; run on the last local `dist/` (2026-10-18: nextron 752 files examined, 729 approved; community 435, 432) | same | `e540382` | `test_telemetry_yara.py` (4), `e2e_telemetry` (8th) | tool output | **the step in `daily.yml` and a record after `publish.yml` are NOT applied** (they change Community workflows) | owner approval |
| Intelligence publication events | NOT DONE | — | — | — | — | no publication, no signing (PRE-07) | after PRE-07 |
| ES/EN, accessibility (WCAG 2.2 AA), phone layout | VERIFIED | same | `0f1f501` | `feeds.ui.test.mjs`, `i18n.test.js` | tests | — | — |
| Deployment of any of this | NOT DONE | — | — | — | — | Worker deploy, D1 migration, cron, ingest token, workflow steps | owner |

Findings of this round worth keeping: (1) an unusable telemetry directory used to stop a connector (fixed); (2) rows with equal timestamps were ordered randomly by run id (now by arrival); (3) a decision-stage YARA record raised a false "not published" alert (rule now fires only on a failed publication); (4) on-demand connectors were reported as missing telemetry (now `scheduled`); (5) a fixed-clock test of the backup tool produced records timed by the real clock (now the injected clock).


### Later in the same round
| FEATURE | STATUS | BRANCH | SHA | TESTS | EVIDENCE | BLOCKERS | NEXT_ACTION |
|---|---|---|---|---|---|---|---|
| Signing and transparency log for the Intelligence release (`scripts/premium_seal.py`, own Merkle log, cosign over manifest + checkpoint, inclusion proof) | VERIFIED with a real cosign and a local key (rehearsal); publisher refuses a rehearsal | `feat/sources-monitoring` | `a5211a3` | `tests/test_premium_seal.py` (4), `gateway/test/publish.test.js` (4) | `PIPELINE-TWO-BUNDLES.md` | **no production (keyless) identity: needs a publishing workflow and the owner** | create the workflow, first real seal |
| NVD (CVE API 2.0) and OSV (changed records, per-record licence) connectors | IMPLEMENTED + VERIFIED locally; run for real read-only on 2026-10-24 (NVD 3 pages, 6,000 records of a 6,418-record day, deliberately capped; OSV PyPI, 29 records + 1 withdrawn) | same | `8a315bb` | `tests/test_nvd_osv.py` (12) | `~/macguard-evidence/2026-10-24/telemetry-real/nvd.json`, `osv.json` | NVD terms of use unread (script-rendered page); OSV needs per-record licence tags in the candidate path; both `not-evaluated` | owner/counsel |
| Sigma strict YAML-subset reader + schema validator + release-archive connector | IMPLEMENTED + VERIFIED; the real SigmaHQ release r2026-07-01 was validated read-only: 3,297 of 3,302 rule files accepted, 4 refused by the reader (reasons recorded), 1 invalid ATT&CK tag | same | `12cb12d` | `tests/test_sigma.py` (9) | tests; real run output in the delivery report | conversion with pySigma and a target backend NOT_RUN; the reader refuses rather than guesses | decide whether to adopt pySigma |
| Suricata ET Open connector (syntax gate only) | IMPLEMENTED + VERIFIED against a local server; the real `emerging-all.rules` exists (46.9 MB, HEAD only) and was NOT downloaded | same | `114ca2b` | `tests/test_families.py` | tests | `suricata -T` engine validation needs the engine installed (a download: not done) | owner approves installing Suricata |
| Additional encrypted copy of the plaintext backup `20261023T200122Z`, verified by isolated restore with the Keychain identity | VERIFIED (13 checks, byte-identical to the original; original untouched) | same | `70728ed` | `gateway/test/legacy_encrypt.test.js` | `BACKUP-OBJECT-STORES.md` | deletion of the original waits for the three-provider restore and the owner | after first sync |
| Scaleway bucket `macguard-archive-scw` exists (fr-par, versioning off) | VERIFIED read-only | same | `70728ed` | — | MCP `object_bucket_get` | versioning and retention settings are owner actions | owner |
| Per-file licence audit and what-if simulation for the Community rules in Intelligence | VERIFIED (739 of 1,174 files would enter under the proposal; 9 CC BY-NC excluded by law; 426 GPL files need counsel) | same | `be4c260` | `tests/test_premium.py` | `docs/monetization/LICENSE-AUDIT-2026-10-24.md` | owner and counsel decisions | owner |
| Staging plan for approval | PREPARED (nothing created) | same | `70728ed` | `staging_sequence --check` | `docs/analytics/STAGING-PLAN.md` | owner approval of six lines | owner |

## Round of 2026-10-25: owner decisions on telemetry in Community, staging, signing, backups, licences, Suricata, panel
Branch `feat/community-telemetry` (from `feat/sources-monitoring` at `a3dc11a`; local, nothing pushed). Status words as before; LOCAL means proved on this Mac only. **Nothing is proved in staging or production**: none exists.

| FEATURE | STATUS | BRANCH | SHA | TESTS | EVIDENCE | BLOCKERS | NEXT_ACTION |
|---|---|---|---|---|---|---|---|
| Additive telemetry step in `daily.yml` and `publish.yml` (last step, `continue-on-error`, off unless `TELEMETRY_ENABLED=1`) | IMPLEMENTED, VERIFIED LOCAL (artifacts byte-identical with telemetry off, on, dead / failing / hanging panel; workflows equal the committed ones apart from the marked blocks; `actionlint` clean for the new blocks) | `feat/community-telemetry` | `95040df` | `tests/test_telemetry_step.py` (9), Node `feeds.test.js`, `e2e_telemetry.test.js` | `docs/observability/SOURCES-AND-DOWNLOADS.md` | not pushed; never run on GitHub Actions | owner pushes via MR, sets the variable only after panel staging |
| `publish` operation (records_published only) in the panel | VERIFIED LOCAL | same | `95040df` | `feeds.test.js` | same | migration 0006 amended in place (never deployed) | – |
| Evaluator heartbeat, reconciliation on every cron tick, per-provider last verified upload and restore drill | VERIFIED LOCAL (Node shim) | same | `d4420cc` | `feeds.test.js` (+2) | `SOURCES-AND-DOWNLOADS.md` | cron not deployed | staging E2E A7 |
| Intelligence keyless signing workflow `intelligence-release.yml` | IMPLEMENTED, structure tested; **never executed** (keyless needs GitHub) | same | `c5d07ae` | `tests/test_intelligence_workflow.py` (6), `actionlint` | `docs/intelligence/PIPELINE-TWO-BUNDLES.md` | needs push, protected environment `intelligence-signing`, variable `INTELLIGENCE_SIGNING`, licence approvals (else it fails closed) | owner decisions |
| Manifest covers every artefact (`credits_sha256`; extra, missing or altered members, loose CREDITS.md) and a restored older log is detected | VERIFIED LOCAL with a real cosign and a local key | same | `c5d07ae` | `tests/test_premium_seal.py` (6) | same | – | – |
| Suricata 8.0.7 installed (own prefix, pinned tarball SHA-256) and engine validation | VERIFIED LOCAL: 7 engine tests; real ET Open feed: 51,537 rules load, 0 fail; gate fixed for 4 protocols (1,066 rules wrongly refused) | same | `0735862` | `tests/test_suricata_engine.py` | `docs/intelligence/SURICATA-ENGINE.md` | traffic behaviour NOT_RUN; ET Open licence `pending-legal` | traffic corpus (owner) |
| Staging plan revised: two independent stagings, `workers.dev` only, no DNS | PREPARED, nothing created; connector cannot see the MacGuard Workers/D1 (name-collision check unproven) | same | `14506e2` | – | `STAGING-PLAN.md` §8, `docs/observability/STAGING-E2E.md` | owner approval of S1-S4; OAuth App for staging by a person | owner |
| Panel staging E2E and rollback | NOT DONE (procedure written; local rollback proof exists) | same | `14506e2` | `feeds.test.js` migration test | `STAGING-E2E.md` | needs staging | after approval |
| Backup destinations verified read-only | B2 exists (private, file lock on, SSE-B2); Scaleway `macguard-archive-scw` exists (fr-par, versioning off); **R2 not enabled** for the reachable account (403 10042) | same | `14506e2` | – | `BACKUP-OBJECT-STORES.md` | R2 enablement, scoped keys, owner go-ahead for first sync | owner |
| NVD and EPSS terms read from official sources | DOCUMENTED, **not approved** (no explicit redistribution grant) | same | `4b9607f` | – | `LICENSE-AUDIT-2026-10-24.md` addendum | owner/counsel reading of primary text | owner |

## Round of 2026-10-25 (second part): telemetry durability, notifications, quality gates
Status words: **LOCAL_VERIFIED** (executed on this Mac, log read), **STAGING_VERIFIED**, **PRODUCTION_VERIFIED**, **BLOCKED**, **FAILED**. Nothing is STAGING_ or PRODUCTION_VERIFIED: no staging exists and nothing was deployed. Branch `feat/community-telemetry` (local, not pushed).

| FEATURE | STATUS | SHA | TESTS | EVIDENCE | BLOCKERS | NEXT_ACTION |
|---|---|---|---|---|---|---|
| Durable private telemetry outbox: sealed (S/MIME) envelopes as artifacts, hourly replay, idempotent delivery, bounded storage, producer check against a forged envelope | LOCAL_VERIFIED | `693166b`, `4409827` | `tests/test_telemetry_replay.py` (11), Node `feeds.test.js` scope test | `docs/observability/SOURCES-AND-DOWNLOADS.md` | real `gh`, OIDC and the protected environment `telemetry-replay` need the repository; secret `TELEMETRY_REPLAY_KEY` must be stored by the owner | owner steps listed in the document |
| `policy-snapshot` intermittent test: root cause found and fixed (substring `ada` inside random SHA-256 hex, about 1 run in 25); 60 stressed runs clean | LOCAL_VERIFIED | `4409827` | `policies.test.js` | commit message | – | – |
| External alert notification (contract `macguard.alert-event/1`): channels created, tested and approved by an administrator, signed, durable outbox, bounded, never silent | LOCAL_VERIFIED | `003d44f` | `admin/worker/test/notify.test.js` (6) | `docs/observability/ALERT-CONTRACT.md` | no channel configured; no real alert sent; `ALERT_SIGNING_KEY` not set | owner configures and approves a channel after panel staging |
| One state vocabulary: NEVER_RAN, ERROR, STALE, NO_DATA (+ OK, NO_NEWS, DISABLED, NO_CONNECTOR) | LOCAL_VERIFIED | `6ae5da4` | `feeds.test.js`, three-browser UI test | `SOURCES-AND-DOWNLOADS.md` | not deployed | staging E2E |
| Keyless verification demands ref and trigger; Intelligence workflow (never executed) | LOCAL_VERIFIED (command) / BLOCKED (execution) | `3c5a1ac` | `tests/test_premium_seal.py` (KeylessConstraints), `tests/test_intelligence_workflow.py` | `docs/intelligence/PIPELINE-TWO-BUNDLES.md` | needs GitHub, environment `intelligence-signing`, licence approvals | owner |
| Backups: the three buckets answer to the stored read keys (B2, Scaleway, R2 all **EXIST** by `HEAD bucket`); a missing or forbidden bucket stops the destination | LOCAL_VERIFIED (read-only) | `e1d541a` | `gateway/test/objstore_bucket.test.js` | `docs/analytics/BACKUP-OBJECT-STORES.md` | no copy written anywhere; write permission unverified | owner authorises the first encrypted sync |
| Quality gates: verdict model, hash-chained evidence, engine binding, approved-budget rules, policy matrix | LOCAL_VERIFIED | `17e8f25`, `63847a7` | `tests/test_quality_budgets.py`, `test_quality_suricata.py` (real Suricata 8.0.7), `test_quality_yara.py` (real YARA), `test_quality_sigma.py`, `test_quality_data.py` | `docs/quality/QUALITY-GATES.md` | **every budget is PROPOSED**: timing and minimum-corpus gates are INCONCLUSIVE until approved | owner approves `config/quality/budgets.json` |
| Publication gate in the builder and the publisher; quarantine submissions; isolation of culprits; rebuild without them | LOCAL_VERIFIED | `6f0f301`, `6862c5f`, `c940775` | `tests/test_quality_acceptance.py` (22), `gateway/test/publish_quality.test.js` (3) | `docs/quality/QUALITY-GATES.md` acceptance table | – | – |
| First real runs: 51,537 ET Open rules; real KEV (1,756) and EPSS (395,249); real SigmaHQ (3,302) | LOCAL_VERIFIED | `a05e80d` | evidence chains in `~/macguard-evidence/2026-10-25/` | `docs/quality/FIRST-RUN-2026-10-25.md` | nothing publishable: unapproved budgets, no real-traffic corpus, ET Open licence pending-legal | owner |
| Panel: quality reports (idempotent ingest, bounded, no rule text), Quality tab ES/EN | LOCAL_VERIFIED | `8177755`, `9823812` | `admin/worker/test/quality.test.js` (5), `feeds.ui.test.mjs` (Quality tab, 3 engines, WCAG 2.2 AA) | – | migration 0006 not deployed | panel staging E2E |
| Pre-push audit and the stacked PR plan | LOCAL_VERIFIED | `030f546` | gitleaks over 427 commits: 5 false positives, all reviewed | `docs/audit/PRE-PUSH-AUDIT-2026-10-25.md` | personal e-mail in `2ef2c6d`; local path in `0f1f501` | owner decides on a history rewrite |
| Staging final sheet (names, permissions, costs, dependencies; S4 not approved) | BLOCKED (nothing created, approval requested) | `123678c` | – | `docs/analytics/STAGING-PLAN.md` §8-9, `docs/observability/STAGING-E2E.md` | API token (Workers Scripts:Edit + D1:Edit) and staging OAuth App | owner |

## Round of 2026-10-25 (third part): sanitised history, real engines on real data, per-rule panel
Environment of everything below: **LOCAL**. STAGING: nothing exists. PRODUCTION: nothing deployed. Allowed words: VERIFIED (executed, log read), IMPLEMENTED (code, not exercised end to end), FAILED, BLOCKED, INCONCLUSIVE, NOT_RUN.

### Regressions (`TEST_SUITE | SHA | TOTAL | PASSED | FAILED | SKIPPED | EXIT | LOG`)
| TEST_SUITE | SHA | TOTAL | PASSED | FAILED | SKIPPED | EXIT_CODE | LOG (private, `~/macguard-evidence/2026-10-25/`) |
|---|---|---|---|---|---|---|---|
| Python 3.13 complete, real Suricata 8.0.7 + YARA + pySigma | `fa9e782` | 1147 | 1144 | **3** | 14 | 1 | `py313-full-fa9e782.log`: 1 policy regression of mine (tool freshness), 2 from a dev-server seed that did not load; fixed in `4d59a75` |
| Python 3.13 complete | `bfa4a8b` | 1147 | 1133 | 0 | 14 | 0 | `py313-full-bfa4a8b.log` |
| Python, suites touched by `01d8691` (quality, oracle, preflight, premium, seal, telemetry) | `01d8691` | 92 | 92 | 0 | 0 | 0 | run in the session |
| Node Admin | `01d8691` | 268 | 268 | 0 | 0 | 0 | `node-admin-01d8691.log` |
| workerd Admin | `01d8691` | 16 | 16 | 0 | 0 | 0 | `workerd-01d8691.log` |
| Panel UI (Chromium) | `01d8691` | 57 | 57 | 0 | 0 | 0 | `ui-panel-01d8691.log` |
| Feeds UI, Chromium + Firefox + WebKit, axe WCAG 2.2 AA | `01d8691` | 24 | 24 | 0 | 0 | 0 | `ui-feeds-3engines-01d8691.log` |
| Node Gateway | `01d8691` | 223 | 223 | 0 | 0 | 0 | `node-gateway-01d8691.log` |
| gitleaks, all refs after the rewrite | `0cebdbc` tree | 23 MB history | – | 0 findings | – | 0 | `gitleaks-all-after-sanitize.json` |
| actionlint | `01d8691` | – | – | 2 `info/style` findings in `publish.yml:97` and `app-tests.yml:41` (Community code, outside my diff) | – | – | not blocking |

The 14 skips are conditional ones declared in the tests (real `age` binary, zstd/real historic releases, cosign-dependent and platform-specific cases); the exact list of this run was not enumerated. `workerd Gateway` is not a separate suite in this repository and was not run. Community gate, signing, transparency-log, verification and policy files are byte-identical to `c806662` (the former `682c089`).

### Features (`FEATURE | STATUS | ENV | BRANCH | SHA | TESTS | EVIDENCE | BLOCKERS | NEXT_ACTION`)
| FEATURE | STATUS | ENV | BRANCH | SHA | TESTS | EVIDENCE | BLOCKERS | NEXT_ACTION |
|---|---|---|---|---|---|---|---|---|
| History sanitisation (symlink, e-mail mention) of 93 unpublished commits; recovery bundle | VERIFIED | LOCAL | 6 branches | `0cebdbc` | 93/93 commits differ from the original only in the allowed files; gitleaks 0 | `docs/audit/HISTORY-SANITIZATION-2026-10-25.md` | the 5 published commits with the address cannot be changed locally | owner decides on a remote rewrite |
| Sigma on pySigma (3,302 rules, 3 backends, pinned) | VERIFIED (conversion) / NOT_RUN (efficacy) | LOCAL | `feat/community-telemetry` | `56f0619` | `test_quality_pysigma.py` | `SIGMA-PYSIGMA-2026-10-25.md` | adoption of pySigma; no event corpus | owner decision |
| Suricata upstream oracle 132/132 and harness negative controls | VERIFIED (harness) | LOCAL | same | `244c052` | `test_suricata_oracle.py` | `QUALITY-GATES.md` | efficacy of ET rules NOT_RUN (no per-rule vectors) | per-rule vectors |
| Suricata three-level profile on real mixed captures | INCONCLUSIVE (every timing saturated) | LOCAL | same | `244c052` (profiler), `fa9e782` (evidence) | – | `suricata-profile-2026-10-25.json`, `BUDGET-PROPOSAL-2026-10-25.md` | quiet host; unapproved budgets | run `BENCHMARK-RUNNER-PROCEDURE.md` |
| Data gates on real EUVD, CERT-EU, ATT&CK, KEV, EPSS | VERIFIED (integrity) / INCONCLUSIVE (performance) | LOCAL | same | `71a93b0` | `test_quality_data_families.py` | `RULE-STATUS-BY-FAMILY-2026-10-25.md` | budgets; Feodo 0 records (NO_DATA); no hash connector | connector decisions |
| Per-rule panel (state, gates, efficacy, FP, compat, cost, reviewer-only decisions) | VERIFIED | LOCAL | same | `4f6cc04` | `quality.test.js` (8), feeds UI x3 engines | `QUALITY-GATES.md` | migration 0006 not deployed | staging |
| Held-back rules are not counted as approved | VERIFIED | LOCAL | same | `ce2331d` | `test_quality_report.py` | – | – | – |
| Benchmark preflight refuses a saturated host | VERIFIED | LOCAL | same | `01d8691` | `test_benchmark_preflight.py` | live run: 3.99/5.59/4.66 per core, not quiet | no dedicated runner | provide a runner |
| New workflows off; activation checklist | IMPLEMENTED (never executed on GitHub) | LOCAL | same | `ce2331d` | workflow tests | `docs/security/NEW-WORKFLOWS-ACTIVATION-CHECKLIST.md` | environments, secret, allow-list | owner |
| Backups B2 / Scaleway / R2 | buckets EXIST (read); **NO write, NO restore tested** | LOCAL read-only | – | `e1d541a` | `objstore_bucket.test.js` | `BACKUP-OBJECT-STORES.md` | write permission unconfirmed | owner authorises first encrypted sync |
| Staging S1–S3 | BLOCKED (nothing created) | – | – | – | – | `STAGING-PLAN.md` §8-9 | token, OAuth App, names | owner |

### Engine report (`ENGINE | VERSION | PLATFORM | CORPUS | SAMPLE | P50 | P95 | P99 | CPU | PEAK_MEM | THROUGHPUT | VERDICT`)
| ENGINE | VERSION | PLATFORM | CORPUS | SAMPLE | P50 | P95 | P99 | CPU | PEAK_MEM | THROUGHPUT | VERDICT |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Suricata, one rule | 8.0.7 | macOS 15 Intel i5-8279U, 8 CPU | `real-mixed-40mb.pcap` c57e2fc5… (196,500 pkts) | 100 rules | 3.87 µs/pkt | 6.46 | 8.15 | 0.084 s (p50 delta, noise-dominated) | 107 MB | n/a | INCONCLUSIVE (load 6–37 per core) |
| Suricata, ET Open whole set | 8.0.7 | same | same | 5 runs | 48.0 µs/pkt (3 usable) | – | – | 22.0 s median | 1,378 MB | 20,849 pps median | INCONCLUSIVE |
| Sigma conversion, SQLite / Splunk / Lucene | pySigma 2.0.1 / 1.5.1 | same | SigmaHQ 3,302 rules | 3,302 | 0.30 / 0.62 / 0.71 ms | 1.5 / 2.6 / 2.8 | 5.3 / 6.2 / 7.1 | 11.7 / 24.5 / 28.2 s | 45–47 MB | – | INCONCLUSIVE |
| Data ingest EPSS | – | same | 395,249 records | 2 runs | lookup p99 1.3 µs | – | – | – | 407 MB | 155–226 k rec/s | INCONCLUSIVE |
| YARA | Community pipeline | – | – | – | inherited, not re-measured | | | | | | NOT_RUN here |
| Linux, Apple silicon, YARA-X | – | – | – | – | – | – | – | – | – | – | NOT_RUN |

## Round of 2026-10-25 (fourth part): owner decisions of the afternoon
Environment: **LOCAL** only. Per-rule, per-source, per-engine detail: `docs/quality/MATRIX-BY-SOURCE-ENGINE-2026-10-25.md`.

| TEST_SUITE | SHA | TOTAL | PASSED | FAILED | SKIPPED | EXIT_CODE | LOG |
|---|---|---|---|---|---|---|---|
| Python 3.13 complete (Suricata 8.0.7, YARA 4.5.8, YARA-X 1.22.0, pySigma) | `7bac25e` | 1170 | 1156 | 0 | 14 | 0 | `py313-full-7bac25e.log` |
| Node Admin / workerd / Gateway / panel UI / feeds UI x3 engines | `01d8691` | 268 / 16 / 223 / 57 / 24 | all | 0 | 0 | 0 | `*-01d8691.log`; `admin/` and `gateway/` are byte-identical at `7bac25e` (no diff since `01d8691`) |

| FEATURE | STATUS | ENV | BRANCH | SHA | TESTS | EVIDENCE | BLOCKERS | NEXT_ACTION |
|---|---|---|---|---|---|---|---|---|
| `sigma.functional` mandatory; self-derived events only a label | VERIFIED | LOCAL | `feat/community-telemetry` | `aaee7a6` | `test_quality_sigma_functional.py` (9) | `QUALITY-GATES.md` | no independent events: all 3,302 held back | provide events |
| YARA-X 1.22.0 compatibility label | VERIFIED | LOCAL | same | `ebe97b8` | `test_quality_yarax.py` (7) | `yarax-compat-community-2026-10-25.json` | not an engine of record | owner |
| Community local files against the published release | VERIFIED (hashes) | LOCAL + public read | same | `aaee7a6` | – | `COMMUNITY-RELEASE-COMPARISON-2026-10-25.md` | release signature not re-verified here | run `verify_release.py` |
| NVD and OSV adapters on live APIs, through the data gates | VERIFIED (integrity) / INCONCLUSIVE (performance) | LOCAL | same | `32b6dd4` | – | `MATRIX-BY-SOURCE-ENGINE-2026-10-25.md` | terms of use not evaluated; NVD snapshot incomplete | licence review |
| File-hash feeds | BLOCKED | – | – | – | – | abuse.ch bulk exports answer HTTP 410 | API key from an account a person must create | owner |
| Corpus catalogue; per-rule matrix generator | VERIFIED | LOCAL | same | `65fe195`, `a0a7cb8` | `test_quality_corpora.py` (4) | `config/quality/corpora.json` | no representative corpus | owner |
| Runner inventory, preflight, procedure | IMPLEMENTED | LOCAL | same | `01d8691`, `32b6dd4` | `test_benchmark_preflight.py` (3) | live preflight: not quiet | ThinkCentre unknown | owner provides host |
| First encrypted backup sync | prepared, NOT_RUN | LOCAL | same | `32b6dd4` | – | `BACKUP-OBJECT-STORES.md` | write permission; restore drill (identity not retrievable by name) | owner |

## Round of 2026-10-25 (fifth part): verification of the published release, backups audit, sources
Environment: **LOCAL** (public artifacts read). Incremental tests only, as asked; no new complete regression (the last one is `7bac25e`, 1170 Python tests OK).

| FEATURE | STATUS | ENV | BRANCH | SHA | TESTS | EVIDENCE | BLOCKERS | NEXT_ACTION |
|---|---|---|---|---|---|---|---|---|
| Cryptographic verification of Community `rules-20261021-39541028283`: Sigstore signatures (manifest and checkpoint) with pinned identity, issuer and repository; certificate decoded (publish.yml@refs/heads/main, workflow_dispatch, commit `b267b2b` on main); 1,178 hashes and sizes; rules_root; log head; inclusion proof; consistency proof 75 to 180; 4 negative controls | VERIFIED | LOCAL on PUBLIC release | `feat/community-telemetry` | `546c119` | `scripts/verify_release.py` (existing), `scripts/tlog.py` | `COMMUNITY-RELEASE-VERIFICATION-2026-10-25.md` | the first root of the consistency proof was not compared with an earlier signed checkpoint | decide whether to add the consistency check to `verify_release.py` |
| Restore drill anchored to the local SHA256SUMS | VERIFIED (code + test + mutation) | LOCAL | same | `546c119` | `gateway/test/objstore.test.js` (8), gateway suite 224/224 at `eb57757` | `BACKUP-RESTORE-AUDIT-2026-10-25.md` | restore with the real identity NOT_RUN; no write permission confirmed | owner |
| abuse.ch interfaces and hash alternatives | VERIFIED (research + probes) | LOCAL | same | `546c119` | – | `ABUSECH-AND-HASH-SOURCES-2026-10-25.md` | file hashes need an Auth-Key and commercial wording is a licence question | owner |
| Independent corpus candidates (T0/T1/T2) | IMPLEMENTED (research only; nothing downloaded) | LOCAL | same | `546c119` | – | `INDEPENDENT-CORPORA-CANDIDATES-2026-10-25.md` | no licensed benign Windows baseline or full-payload benign capture identified | owner provides or approves sources |
| YARA-X: the four incompatible files explained and the behaviours checked on YARA 4.5.8 | VERIFIED | LOCAL | same | `546c119` | – | `YARAX-INCOMPATIBLE-FILES-2026-10-25.md` | adoption as an engine is not requested | – |
| Source matrix shows NVD and OSV as run, with incomplete snapshots flagged | VERIFIED | LOCAL | same | `eb57757` | `test_premium.py` drift test | `docs/intelligence/SOURCE-MATRIX.md`, `live-evidence/2026-10-25/` | licences pending | licence review |
| Staging S1-S3 and first three cloud restores: concrete plan | IMPLEMENTED (plan) | – | same | `eb57757` | – | `STAGING-AND-RESTORE-INTEGRATION-PLAN-2026-10-25.md` | token, OAuth App, write scope | owner |
| ThinkCentre qualification steps | IMPLEMENTED (procedure) | – | same | `d11f7ac` | – | `BENCHMARK-RUNNER-PROCEDURE.md` §7 | host unknown | owner provides inventory |

Reminder of the vocabulary used in the per-rule matrix: **COMPATIBLE** (a backend or engine accepts the rule) is never **FUNCTIONALLY_VERIFIED** (independent positive and negative vectors agreed).

## Round of 2026-10-25 (sixth part): independent backup authentication, YARA-X review, corpora
Environment: **LOCAL**. Throw-away keys only; no real signing key or age identity was created or read; nothing remote. Incremental tests only.

| TEST_SUITE | SHA | TOTAL | PASSED | FAILED | SKIPPED | EXIT_CODE | LOG |
|---|---|---|---|---|---|---|---|
| Node Gateway complete (includes the new anchor, recovery and heads tests) | `8f16459` | 240 | 240 | 0 | 0 | 0 | run in the session |
| `objstore` 11, `backup_anchor` 10, `backup_recovery` 3 | `8f16459` | 24 | 24 | 0 | 0 | 0 | same |
| mutation checks of the anchor verifier (hash comparison removed; rollback removed; wrong namespace) and of the shell verifier (signature check removed) | `8f16459` | 4 | each makes tests FAIL | – | – | – | same |

| FEATURE | STATUS | ENV | BRANCH | SHA | TESTS | EVIDENCE | BLOCKERS | NEXT_ACTION |
|---|---|---|---|---|---|---|---|---|
| Independent signed anchor for backups (ed25519 SSH signature over a statement with the file hashes, a sequence number and the previous head), verified with only a public key; works with no local copy | VERIFIED (tests, throw-away keys) | LOCAL | `feat/community-telemetry` | `8f16459` | `backup_anchor.test.js`, `objstore.test.js` | `BACKUP-AUTHENTICATION-AND-RECOVERY-2026-10-25.md` | no signing key exists; no real backup is signed | owner creates the key |
| Adversarial cases: forged self-consistent backup, altered manifest, rollback, equivocation, missing link, lost provider, lost machine, smuggled key options | VERIFIED | LOCAL | same | `8f16459` | same | same | – | – |
| Clean-machine recovery (`recover_verify.sh`: ssh-keygen, age, SHA-256, python3) and recovery kit generator that refuses private material | VERIFIED | LOCAL | same | `8f16459` | `backup_recovery.test.js` | same | the age identity could not be located by name; real decrypt NOT_RUN | owner supplies an identity file |
| `heads`: compare the signed head across B2, Scaleway and R2 | VERIFIED (fake providers) | LOCAL | same | `8f16459` | `objstore.test.js` | same | no write to the real buckets | owner authorises phase 3 |
| Review of the four YARA-X-incompatible Community rules | VERIFIED (measurements); Community untouched | LOCAL | same | `034fe20` | – | `YARAX-INCOMPATIBLE-FILES-2026-10-25.md`, `yarax-review-2026-10-25.json` | PE behaviour NOT_RUN (no corpus) | Community owner decides |
| `RAT_PoetRATPython`: 14 false positives in 6,109 benign Python files (6 distinct files), 0 for the variant without the empty branch | VERIFIED on a non-representative corpus | LOCAL | same | `034fe20` | – | same | real PoetRAT samples NOT_RUN | Community owner |
| `RAT_PlugX`: the published rule does not match the text with a backslash before `VMware` that its description implies | VERIFIED on synthetic text | LOCAL | same | `034fe20` | – | same | real event logs NOT_RUN | Community owner |
| Independent corpora classified by licence, provenance, labelling, size, representativeness | IMPLEMENTED (research; nothing downloaded) | LOCAL | same | `ff63233` | – | `INDEPENDENT-CORPORA-CANDIDATES-2026-10-25.md` | no licensed benign Windows or full-payload benign traffic corpus | owner supplies or approves a benign source |

## Round of 2026-10-25 (seventh part): disaster-recovery checkpoint, custody, preflight, rule issues
Environment: **LOCAL**. Throw-away keys only; no real key or identity was created, read or printed; nothing was written to a provider; Community untouched.

| TEST_SUITE | SHA | TOTAL | PASSED | FAILED | SKIPPED | EXIT_CODE | LOG |
|---|---|---|---|---|---|---|---|
| Node Gateway complete (anchor, checkpoint, recovery, custody, preflight, objstore) | `9c865a1` | 257 | 257 | 0 | 0 | 0 | run in the session |
| Python incremental: secret hygiene, community rule-defect tests (YARA and YARA-X), premium drift, workflow prerequisites, telemetry replay | `9c865a1` | 70 | 69 | 0 | 1 | 0 | the skip is the optional pin check (`MG_COMMUNITY_RULES`), run separately and passing against the verified release |
| Mutation checks: checkpoint (5), custody verifier (1), preflight (3) | `aded084` | 9 | each makes tests FAIL | – | – | – | one mutation was left in place by my own mistake and removed before the commit; the final tests pass |

| FEATURE | STATUS | ENV | BRANCH | SHA | TESTS | EVIDENCE | BLOCKERS | NEXT_ACTION |
|---|---|---|---|---|---|---|---|---|
| External signed checkpoint of the last confirmed sequence, in its own namespace; several copies; staleness; used by heads, drill, shell verifier and preflight | VERIFIED (throw-away keys) | LOCAL | `feat/community-telemetry` | `5332a5d` | `backup_checkpoint.test.js` (8), `objstore.test.js` | `BACKUP-AUTHENTICATION-AND-RECOVERY-2026-10-25.md` addendum | no signing key exists | owner creates the key |
| All three providers serving an old, coherent, genuinely signed copy | VERIFIED: caught with the checkpoint, invisible without it | LOCAL | same | `5332a5d` | same | same | – | – |
| Custody instructions for the age identity and the signing key (Bitwarden commands not run; independent second copy; schedule); custody verifier; secret-hygiene test | VERIFIED (scripts and tests) / IMPLEMENTED (instructions) | LOCAL | same | `5332a5d`..`aded084` | `backup_custody.test.js` (3), `test_secret_hygiene.py` (3) | `BACKUP-KEY-CUSTODY-2026-10-25.md` | `bw` is installed and locked; not unlocked | owner |
| Read-only go/no-go preflight for the first copy; real run on the local backups | VERIFIED; real result **NO_GO** | LOCAL | same | `aded084` | `backup_preflight.test.js` (5) | `FIRST-SYNC-AND-RESTORE-RUNBOOK-2026-10-25.md`, `preflight-real-2026-10-25.json` (private) | anchor, trusted key and kit absent | owner |
| B2 key scopes read; costs read from the provider pages | VERIFIED (read-only metadata) | REMOTE READ (B2 API, pricing pages) | same | `9c865a1` | – | same, `gateway/environments/provider-limits.json` | Scaleway and R2 scopes unknown; write key can delete and bypass retention | owner |
| Four Community rule issues drafted with patches, tests and preserved PoetRAT evidence (6,109 files, 14 matches, 6 distinct files, 0 for the variant) | VERIFIED (measurements); nothing opened or changed remotely | LOCAL | same | `aded084` | `test_community_rule_defects.py` (11) | `docs/quality/community-rule-issues/` | real positive samples NOT_RUN; Community owner decides | owner |
| Staging kept prepared: gateway staging sequence passes its 10 invariants; panel template passes the placeholder guard | VERIFIED locally; nothing deployed | LOCAL | same | `9c865a1` | `staging_sequence.mjs --check`, `test_check_worker_config.py` | `STAGING-AND-RESTORE-INTEGRATION-PLAN-2026-10-25.md` | token, OAuth App, names | owner |
