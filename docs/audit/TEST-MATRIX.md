# Test matrix

Every line says what was run, where, and the result. **NOT RUN** is a result, not an omission to be read as a pass. Commands are meant to be re-run by someone else.

## 1. Layers

| Layer | What | Command / location | Result |
|---|---|---|---|
| SAST | semgrep (python, javascript, github-actions), bandit, ruff `E9,F,B,S`, shellcheck, actionlint, zizmor | see `SECURITY-FINDINGS.md` (triage) | run; findings fixed or triaged. Final actionlint: only two shellcheck style notes. zizmor: 3 accepted `artipacked` |
| SAST | CodeQL | `.github/workflows/codeql.yml` (weekly / on demand) | **NOT RUN** (workflow added, first run pending) |
| SAST | ESLint | no JS lint config exists; `node --check` on every browser script | syntax only |
| SCA | OSV API for Mermaid, wrangler, cosign, actions; `osv-scanner` | `evidence/osv-queries-before-fixes.json` | Mermaid 10.9.3: 8 advisories → fixed; others clean. `osv-scanner` found no lockfile (the repo has none) |
| SCA | Syft SBOM | `evidence/sbom.cdx.json` | done; Grype and OpenSSF Scorecard **NOT RUN** (not installed) |
| Secrets | gitleaks over 104 commits | `gitleaks detect` | no leaks |
| Unit / property | Python suite, 21 modules | `python3 -m unittest discover -s tests` | local, last full run on the tree before the final two commits: 273 tests, 272 OK, 1 failure (`test_csp` found the inline script of `docs/index.html`; fixed, module re-run OK). Modules touched afterwards re-run: `test_csp`, `test_docs`, `test_docs_og` (51 OK), `test_verify_public_release` (36 OK). The full suite on the final tree runs in CI (`daily.yml`, run 39254094180, result in `FINAL-AUDIT-REPORT.md`) |
| Unit | quarantine service | `cd admin/worker && npm test` | 36 OK (7 new, red on the old source) |
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
| Integration | acceptance chain with synthetic candidates (static, dynamic with an engine-blocking rule, quarantine API, approvals, revalidation, privacy) | `python3 scripts/chain_test.py` | 22/22 locally; with `--publish` (Sigstore, real release, tamper) it runs only in Actions: see report |
| E2E web | real pages in headless Chrome incl. tamper and missing-proof modes | `scripts/web_check.sh site`, `… site tamper`, `… site missing` | OK (the new cases are red on the old code) |
| E2E docs | 20 pages × 2 languages × 2 widths, 80 Mermaid renders, toolbar, legibility, under the CSP | `scripts/docs_check.py --site site --mode full` | 80/80; negative control (`script-src 'none'`) fails as it must |
| DAST | OWASP ZAP baseline, passive, both hosts | `evidence/zap-baseline-before-fixes.md` | run **before** the fixes; re-run after deployment: see report |
| DAST | quarantine API against a staging deployment | — | **NOT RUN** (service not deployed) |
| UX / a11y | Playwright + axe-core (WCAG 2.2 AA tags) 7 page types × light/dark × 1280/390; keyboard walk; zoom 200 %/400 % by viewport; Lighthouse mobile | `evidence/web-audit-scripts/` | axe 0 violations after the fixes; Lighthouse before fixes in `evidence/audit-public-portal.md` |
| UX | real screen readers, Firefox, WebKit | — | **NOT RUN** |
| Performance | Lighthouse mobile, transfer sizes, filter latency (30–280 ms on 1,174 files), site build 11 s, docs fast check 11–26 s | audit report + below | baselines recorded |
| CI/CD | actionlint, zizmor, workflow runs | GitHub Actions | see report |
| Publication | `verify_live.py` on both hosts + `compare_mirrors.py` | after deployment | see report |

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
| 11 | signing error | workflow order (sign before release); no failing-cosign run | **NOT RUN** |
| 12 | error creating the release | draft-then-public order | **NOT RUN** (reasoned) |
| 13 | error uploading an asset | asset count check before `--draft=false` | **NOT RUN** (reasoned) |
| 14 | deployment error | independent jobs, `record` always runs | **NOT RUN** (reasoned) |
| 15 | interruption during publication | unique tags, drafts invisible | **NOT RUN** (reasoned) |
| 16 | duplicate workflows | `precheck` skip, group serialisation | **NOT RUN** |
| 17 | simultaneous executions | concurrency groups (FA-16) | **NOT RUN** |
| 18 | error recording the checkpoint | `tlog` refuses non-consistent / no-new-entries checkpoints; verified by `test_tlog` | tested (script level) |
| 19 | mirrors out of sync | `test_compare_mirrors` | tested (script level) |
| 20 | recovery afterwards | next daily run recomputes (design); not provoked | **NOT RUN** |

Scenarios 11–17 and 20 would need real runner failures or overlapping real releases; they were not provoked because that would create or alter public releases. They are listed as residual risk RR-15.

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
