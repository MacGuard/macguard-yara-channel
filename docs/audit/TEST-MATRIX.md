# Test matrix

Every line says what was run, where, and the result. **NOT RUN** is a result, not an omission to be read as a pass. Commands are meant to be re-run by someone else.

## 1. Layers

| Layer | What | Command / location | Result |
|---|---|---|---|
| SAST | semgrep (python, javascript, github-actions), bandit, ruff `E9,F,B,S`, shellcheck, actionlint, zizmor | see `SECURITY-FINDINGS.md` (triage) | run; findings fixed or triaged. Final actionlint: only two shellcheck style notes. zizmor: 3 accepted `artipacked` |
| SAST | CodeQL (actions, python, javascript-typescript) | `codeql.yml`, run 39272512418 (2026-10-19) | run: 6 alerts, triaged in `SECURITY-FINDINGS.md` (FA-37): 1 hardened (`docs-redirect.js`), 5 are test-code false positives left **open** (dismissing them was not permitted in this session; see RR-17) |
| SAST | ESLint | no JS lint config exists; `node --check` on every browser script | syntax only |
| SCA | OSV API for Mermaid, wrangler, cosign, actions; `osv-scanner` | `evidence/osv-queries-before-fixes.json` | Mermaid 10.9.3: 8 advisories → fixed; others clean. `osv-scanner` found no lockfile (the repo has none) |
| SCA | Syft SBOM | `evidence/sbom.cdx.json` | done; Grype and OpenSSF Scorecard **NOT RUN** (not installed) |
| Secrets | gitleaks over 104 commits | `gitleaks detect` | no leaks |
| Unit / property | Python suite, 21 modules | `python3 -m unittest discover -s tests` | local, last full run on the tree before the final two commits: 273 tests, 272 OK, 1 failure (`test_csp` found the inline script of `docs/index.html`; fixed, module re-run OK). Modules touched afterwards re-run: `test_csp`, `test_docs`, `test_docs_og` (51 OK), `test_verify_public_release` (36 OK). The full suite on the fixed tree ran in CI (`daily.yml`, run 39254094180: success) |
| Unit | quarantine service (Node shim over `node:sqlite`) | `cd admin/worker && npm test` | 37 OK (7 new in the audit, +1 for `public/_headers`) |
| Runtime | quarantine service on **workerd with a real D1** (Miniflare); GitHub (OAuth, API, OIDC keys) is faked | `cd admin/worker && npm run test:runtime`; CI job `quarantine-service` of `ci.yml` | 12 OK locally (macOS) and in CI (Linux, Node 24). Covers: anonymous 401s, forged/expired/wrong-audience/wrong-repo/wrong-workflow OIDC tokens, 300-candidate submission and 120-rule batch over D1, rejection-wins, race, audit chain + append-only triggers + tamper detection, persistence across a restart, login state binding. Found FA-35 (UI assets bypassed the headers). **Does not prove** real OAuth or real Actions tokens |
| Black-box | deployed quarantine service | `admin/worker/staging-smoke.sh <url>` | script validated against the local runtime (18 PASS); **NOT RUN against a deployment** (none exists) |
| Adversarial | Merkle: every one-element mutation of inclusion and consistency proofs for all tree sizes ≤ 33/30, forked histories, second preimage | `tests/test_tlog_adversarial.py` (17) | OK |
| Adversarial | checkpoint parser: 23 malformed or non-canonical forms, 3,000 random byte strings and single-byte mutations | same | OK (red before FA-12) |
| Adversarial | inventory: duplicates, `..`, absolute, NUL, newline, RTL override, percent, upper-case/short hashes, 257-file root sensitivity | same | OK |
| Adversarial | log tampering: edit, drop, reorder, truncate, no final newline, stale checkpoint copy, forged root, longer-than-log checkpoint, unsigned | same | OK |
| Adversarial | hostile archives: `..`, absolute, backslash, deep, long, links, hardlink, fifo, device, duplicates, case collision, size/total/member bombs, truncated/corrupt gzip | `tests/test_tar_adversarial.py` (7) | OK |
| Adversarial | YARA text: every truncation point, 1,500 byte-damaged variants, unicode/control, 1 MB pathological inputs (nested regex, open braces/comments, 3,000 nested loops) bounded to 8 s | `tests/test_rulecheck_adversarial.py` (5) | OK |
| Adversarial | sealing and verifying a release with a stub `cosign`: evidence for another set / failing / missing; unsafe inventory; 10 tamper cases | `tests/test_seal_evidence.py` (6) | OK |
| Adversarial | quarantine service (agent): route × role matrix, CSRF, OIDC scoping, replay, races, SQLi probes, headers | `evidence/audit-quarantine-service.md` | 18 adversarial tests, all findings fixed or recorded |
| Fuzzing | Atheris / libFuzzer / Hypothesis | not installed in the repository's environment; property tests above use the standard library with fixed seeds | **NOT RUN** (RR-10) |
| Contract | docs vs code (24 events, policy numbers, commands, manifests, ES/EN parity), mirror parity, CSP vs real pages | `tests/test_docs.py` (43), `test_csp`, `test_compare_mirrors` | OK |
| Crypto, real data | independent verifier on the real latest release and on two real releases (consistency), rollback and fork detection | `tests/test_verify_public_release.py` | 36 OK |
| Integration | acceptance chain with synthetic candidates (static, dynamic with an engine-blocking rule, quarantine API, approvals, revalidation, privacy) | `python3 scripts/chain_test.py` | 22/22 locally; with `--publish` in Actions (run 39255895996): 27/27 — Sigstore keyless signing, sealing with `evidence`, real release, site build, public verification, tamper |
| E2E web | real pages in headless Chrome incl. tamper and missing-proof modes | `scripts/web_check.sh site`, `… site tamper`, `… site missing` | OK (the new cases are red on the old code) |
| E2E docs | 20 pages × 2 languages × 2 widths, 80 Mermaid renders, toolbar, legibility, under the CSP | `scripts/docs_check.py --site site --mode full` | 80/80; negative control (`script-src 'none'`) fails as it must |
| DAST | OWASP ZAP baseline, passive, both hosts | `evidence/zap-baseline-before-fixes.md` | run before the fixes, after them and on the final tree; see the three tables in the file |
| DAST | quarantine API against a staging deployment | `admin/worker/STAGING.md` | **NOT RUN** (service not deployed; needs the human actions in that file) |
| UX / a11y | Playwright + axe-core (WCAG 2.2 AA tags) 7 page types × light/dark × 1280/390; keyboard walk; zoom 200 %/400 % by viewport; Lighthouse mobile | `evidence/web-audit-scripts/` | axe 0 violations after the fixes; Lighthouse before fixes in `evidence/audit-public-portal.md` |
| Cross-browser | Chromium, **Firefox, WebKit** (Playwright 1.64.1): e2e (normal, tampered log, missing proof), console/page errors/failed requests/CSP violations, 4 docs diagrams render, no horizontal scroll, axe WCAG 2.x A/AA + 2.2 AA at 1280 and 390 px, light and dark, 7 pages | `PW_DIR=… node tests/web/cross_browser.mjs site` | **51/51** (17 per engine) on the build of `aa09f2a`. Before the fix it found a real defect (release-delta pill contrast 4.02:1, FA-36) |
| UX | real screen readers | — | **NOT RUN** |
| Performance | Lighthouse mobile, transfer sizes, filter latency (30–280 ms on 1,174 files), site build 11 s, docs fast check 11–26 s | audit report + below | baselines recorded |
| Regression | the failed scheduled daily run: any job that runs the suite must install cosign first | `tests/test_workflow_prereqs.py` (2) | OK; red when the installer step is removed |
| CI/CD | actionlint, zizmor, workflow runs | GitHub Actions | site 39258422035 success; daily 39254094180 success; chain 39255895996 success; scheduled daily 39196469644 FAILED before the fix (FA-31) |
| Publication | `verify_live.py` on both hosts + `compare_mirrors.py` | after deployment | PASS on both, mirrors identical |

## 2. The 20 integration scenarios of the brief

| # | Scenario | Covered by | Result |
|---|---|---|---|
| 1 | no changes | `test_decide::no_effective_change…`, `test_release_meta`, `precheck` | tested |
| 2 | one valid new rule | `chain_test` (added) | tested |
| 3 | one valid modified rule | `chain_test` (modified is a new candidate) | tested |
| 4 | one rule removed | `chain_test`, `test_decide::rules_gone_upstream_are_retired` | tested |
| 5 | one defective rule | `test_decide`, `chain_test` | tested |
| 6 | several defective rules | `chain_test` (5 candidates, 4 approved, 1 rejected) | tested |
| 7 | compile failure | `test_rulecheck`, `test_decide` | tested |
| 8 | CPU regression | `test_bench`, `test_dynamic_gate` (engine-blocking rule isolated) | tested |
| 9 | memory regression | `test_bench::large_memory_regression_is_detected` | tested |
| 10 | quarantine service unreachable | `test_decide::without_the_quarantine_store…`, `test_quarantine_client` | tested |
| 11 | signing error | `test_publish_failures::PublishWorkflowShape` (signing and verification steps precede the release step; marking rules released only `if: success()`; record step `if: always()`) | tested (workflow shape; no real failing cosign) |
| 12 | error creating the release | `test_publish_failures` runs the real `run:` script of `publish.yml` with a fake `gh` that fails `release create` | tested with a mock: exit ≠ 0, nothing made public |
| 13 | error uploading an asset | same: fake `gh` fails the upload, and returns 0/5/8 assets | tested with a mock: never published (red when the count check is weakened) |
| 14 | deployment error | independent jobs, `record` always runs (`PublishWorkflowShape`); Cloudflare job verified after deploy | tested (shape); no provoked deployment failure |
| 15 | interruption during publication | fake `gh` killed with SIGKILL during `release create`; draft-first order | tested with a mock: nothing public |
| 16 | duplicate workflows | `precheck` skip; `publish.yml` group `macguard-log`, `cancel-in-progress: false` (asserted) | tested (configuration); GitHub's queue behaviour **NOT RUN** (RR-15) |
| 17 | simultaneous executions | site uses its own group; only the `record` job takes `macguard-log` (asserted) | tested (configuration); real overlapping runs **NOT RUN** (RR-15) |
| 18 | error recording the checkpoint | `tlog` refuses non-consistent / no-new-entries checkpoints; verified by `test_tlog` | tested (script level) |
| 19 | mirrors out of sync | `test_compare_mirrors` | tested (script level) |
| 20 | recovery afterwards | next daily run recomputes (design); not provoked | **NOT RUN** |

Scenarios 11–17 are now exercised against the real publish script with a mocked `gh` and by assertions on the workflow files. What remains **NOT RUN** is GitHub itself failing or queueing (a real 5xx on upload, a real pending-run replacement) and scenario 20 (recovery by the next scheduled run, which needs the cron): they would need real runner failures or overlapping real releases and no historical release was touched. See RR-15.

## 3. Requirement → code → test → result → evidence

| Requirement | Code | Test | Result | Evidence |
|---|---|---|---|---|
| Sources with provenance, commits, licences | `config/sources.json`, `prepare.py`, `licensing.py` | `test_licensing`, `test_rulecheck::license_…` | OK | manifest `sources[]` |
| Static + dynamic validation on a reference engine | `rulecheck.py`, `dynamic_gate.py`, `bench.py` | `test_rulecheck` (24), `test_dynamic_gate` (7), `test_bench` (21), adversarial | OK | `chain_test` |
| Quarantine, private service, batches | `decide.py`, `admin/worker`, `quarantine_client.py` | 36 + 11 + 26 tests | OK locally; not deployed | `evidence/audit-quarantine-service.md` |
| SHA-256, manifest, Merkle, proofs | `seal.py`, `tlog.py` | `test_tlog` (16), adversarial (17), `test_seal_evidence` | OK | `verify_live.py` |
| Sigstore keyless signatures | `publish.yml`, `tlog.cosign_verifier` | real-release tests, `verify_live.py` | OK on real releases | live |
| Attestations of provenance/results | `manifest.evidence` | `test_seal_evidence` | partial (RR-02) | — |
| Append-only signed log, private/public separation | `tlog.py`, `make_public_candidate.py` | `test_tlog`, `test_public_candidate` | OK | live log |
| Complete releases | `publish.yml`, `release_meta.py` | `test_release_meta` (7) | OK | 2 releases |
| Portal | `web/`, `build_site.py` | e2e, axe | OK after fixes | — |
| 40 pages + 20 diagrams + checks | `docs-src/`, `build_docs.py` | `test_docs`, `docs_check` | OK | — |
| Open Graph 1200×630 | `og_inject.py` | `test_docs_og`, `verify_live` | OK | live |
| Automatic deployment to both Pages | `site.yml` | `verify_live`, `compare_mirrors` | OK | runs |
