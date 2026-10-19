# Production readiness — GO / NO-GO

## Verdict: **NO-GO** (for declaring V1 closed)

The channel itself works and is verifiable: two real signed releases, both hosts serve the same verified bytes, the rule pipeline fails closed, the cryptographic chain rejects every tampering tried. What stops a GO is not a known flaw in that chain but **four conditions of the brief that cannot be demonstrated yet** and **one that needs a human decision**. Nothing below was relaxed to reach a verdict.

| # | GO criterion of the brief | State | Evidence |
|---|---|---|---|
| 1 | no critical defect open | **met** | `SECURITY-FINDINGS.md`: 0 critical |
| 2 | no exploitable HIGH without accepted mitigation | **met** | FA-19/FA-23 (portal) fixed, deployed and verified live on both hosts (see "Live verification") |
| 3 | automatic publication proven end to end | **partly** — two real releases through `daily → publish → site` (dispatched); the only scheduled run so far FAILED (FA-31, fixed; proved by dispatched run 39254094180); `evidence` sealing proved by the acceptance chain with real Sigstore (run 39255895996, 27/27), not yet by a production release | `gh run list`, `RR-04` |
| 4 | signatures and cryptographic proofs valid | **met** | `verify_live.py` PASS on both hosts; 23 checkpoint-parser forms, every one-element proof mutation, 9 manifest tamper cases rejected |
| 5 | quarantine prevents publishing problematic rules | **met at the pipeline** (a quarantined or rejected file cannot enter the set; without the service the safe default applies); **service not deployed** | `test_decide`, `chain_test.py` 22/22 |
| 6 | the private API enforces real authorization | **NOT demonstrated**: tested on a local harness only (route × role matrix, CSRF, OIDC scoping, batch atomicity all pass there); real OAuth/OIDC/D1 not run (RR-03) | `evidence/audit-quarantine-service.md` |
| 7 | no private-information leak | **met by test** (`make_public_candidate`, public candidate carries counts only); the service's public endpoint returns four counts | `test_public_candidate`, `chain_test` privacy check |
| 8 | releases verifiable | **met** | `verify_public_release.py` / `verify_live.py` |
| 9 | web works | **met** (deployed; e2e, axe 0 violations, `verify_live` on both hosts) | |
| 10 | documentation in sync, diagrams legible | **met** | `test_docs` 43, `docs_check` full 80/80 |
| 11 | mandatory tests pass | **met** for everything that could run; see `TEST-MATRIX.md` for the NOT RUN list (DAST of the API, real GitHub failure/queue behaviour, Grype/Scorecard, screen readers) | |
| 12 | required deployments verified | **met**: site run 39258422035, both hosts `LIVE VERIFICATION PASSED`, mirrors identical | below |
| 13 | recovery from failures proven | **partly**: draft-then-public release, unique tags, republish by the next daily run, `compare_mirrors`; interruption/duplicate-run scenarios were reasoned, not provoked (RR-15) | `ARCHITECTURE-REVIEW.md` |
| — | repository protections (secret scanning, required checks, immutable releases) | **human decision pending** (RR-01) | `gh api` outputs in the baseline |

### What turns this into a GO (no new development needed)

1. Owner enables secret scanning + push protection + Dependabot security updates, a ruleset on `main` (required status checks, bypass only for the log bot) and immutable releases (RR-01).
2. Deploy the quarantine service to a staging Worker/D1 with a GitHub OAuth app, run the adversarial suite of `evidence/audit-quarantine-service.md` against it, add Cloudflare rate-limiting for `/auth/*` and `/api/decisions`, then production and set `QUARANTINE_URL` (RR-03).
3. Read the first scheduled `daily.yml` (2026-10-19 03:17 UTC), the `site.yml` of 04:17 UTC and, when upstream changes, the first release carrying `manifest.evidence` (RR-04).
4. Run `codeql.yml` once and triage.

When 1–4 are done and the checks below still pass, tag `v1.0.0` (see "Closing" below) and freeze.

## Closure round (2026-10-19, after the NO-GO): blocker by blocker

Verdict after the round: **still NO-GO.** Four blockers need a person or the clock; everything that could be closed without them was, with evidence. Nothing was relaxed and no repository setting was changed.

| # | Blocker | State | Evidence | What is missing, exactly |
|---|---|---|---|---|
| 1 | private quarantine API | **partly closed.** Service now also proved on workerd + real D1 (12 tests, local and CI run 39274617820/39274524287); found and fixed FA-35 (UI headers); runbook + black-box smoke ready (`admin/worker/STAGING.md`, `staging-smoke.sh`, 18 PASS against the local runtime) | `admin/worker/test-runtime/`, `TEST-MATRIX.md` | **Human:** a Cloudflare token (Workers Scripts:Edit + D1:Edit), a staging GitHub OAuth app, the hostname; then the role table of STAGING.md with real accounts. Nothing was created in the Cloudflare account |
| 2 | repository protections | **audited and prepared, not applied** | `docs/audit/repo-hardening/apply.sh verify` (read-back below); `ruleset-main.json`, `ruleset-release-tags.json`; `ci.yml` supplies the required checks (green, run 39274617820) | **Human:** explicit authorization, then `apply.sh apply` (secret scanning, push protection, Dependabot alerts + security updates, immutable releases, two rulesets). Decision RR-16 (`AUTO_PUBLISH`) |
| 3 | scheduled daily run | **cause proved and pinned; cron not yet observed** | the 03:49 UTC schedule run 39196469644 failed (`dependency.cosign … was not found`); `tests/test_workflow_prereqs.py` fails without the installer step; `scripts/schedule_evidence.py` currently prints `NOT YET` | **Time:** the next cron (2026-10-20 ≈ 03:17–03:50 UTC). Dispatched runs (e.g. 39254094180) are not counted |
| 4 | CodeQL | **run and triaged** | run 39272512418, FA-37: 1 hardened + regression test, 5 test-code false positives | **Human:** dismiss the 5 (RR-17); alert 5 closes at the next CodeQL run |
| 5 | publication with `manifest.evidence` | **isolated environment: done; real release: waits for a real change** | chain test on the current tree, run 39275246567: 27/27 (Sigstore keyless, sealing with `evidence`, real release created then deleted, site built from it, public verification, tamper detected) | **Upstream change:** the next legitimate rule change. No artificial change was made |
| 6 | GitHub release failures and concurrency | **closed with mocks; GitHub's own behaviour not provoked** | `tests/test_publish_failures.py` (8): the real `publish.yml` script with a fake `gh` — create/upload failure, SIGKILL, 0/5/8 assets, publish failure: nothing public; red when the count check or draft flag is removed. Group configuration asserted | real 5xx/queueing on GitHub: RR-15 (no historical release was touched) |
| 7 | Firefox, WebKit, accessibility | **closed for automated checks** | `tests/web/cross_browser.mjs`: 51/51 on Chromium, Firefox, WebKit (17 each: e2e normal/tamper/missing, no console/CSP errors, diagrams, no horizontal scroll, axe light+dark at 1280/390); found FA-36 (fixed, deployed) | real screen readers (VoiceOver/NVDA) not run (RR-11) |
| 8 | both mirrors serve the same approved set | **closed** | after the last deploy (site run 39274421640, tree `aa09f2a`): `verify_live.py --external` PASSED on both hosts; `compare_mirrors.py` identical (manifest `f75c2146…`, rules_root `16d08239…`, log 75); the served CSS has the FA-36 fix on both | — |

Repository protections as read back on 2026-10-19 (`apply.sh verify`): secret scanning, push protection, Dependabot security updates, validity checks **disabled**; Dependabot alerts **disabled** (HTTP 403 "disabled for this repository"); rulesets **none**; classic protection of `main`: no required checks, no required reviews, force pushes off; immutable releases **disabled**.

### Criteria still not met → what turns it into GO
1. Criterion 6 (private API authorization): rows 1 above.
2. Criterion 3 (autonomous publication proven): the scheduled run of 2026-10-20 (`schedule_evidence.py` → PASS) and, ideally, the first real release with `evidence`.
2b. The repository-owner decisions: rows 2 and RR-16.
3. Close the five CodeQL alerts (RR-17); not blocking by itself.
Then re-run, in this order: `schedule_evidence.py`, `apply.sh verify`, `staging-smoke.sh` on production, `verify_live.py` on both hosts and `compare_mirrors.py`, `ci.yml`; update this file and only then tag `v1.0.0`.

## Maintenance and recovery (so another person can operate this)

* **Daily cycle:** `daily.yml` 03:17 UTC → (change?) → `publish.yml` → `site.yml`; `site.yml` also runs 04:17 UTC and on web/docs changes. Nothing needs a person unless `AUTO_PUBLISH` is turned off (then `stable-signing` asks a reviewer).
* **Is it healthy?** `gh run list -R MacGuard/macguard-yara-channel -L 10`; `python3 scripts/verify_live.py <host> --identity https://github.com/MacGuard/macguard-yara-channel/.github/workflows/publish.yml@refs/heads/main --repo MacGuard/macguard-yara-channel --external`; `python3 scripts/compare_mirrors.py https://macguard.github.io/macguard-yara-channel/ https://macguard-rules.pages.dev/`.
* **A release failed half way:** nothing is public until the last asset is attached; delete the draft (`gh release delete <tag>`), the next daily run recomputes and publishes. Never edit or reuse a tag.
* **Cloudflare mirror failing:** read the `cf-preflight:` line and the job summary of `site.yml`; replace `CLOUDFLARE_API_TOKEN` (Account → Cloudflare Pages → Edit) and `CLOUDFLARE_ACCOUNT_ID`; the next run deploys by itself. GitHub Pages is unaffected.
* **A published rule must be withdrawn:** reject it in the panel (or remove it upstream), the next daily run withholds it and publishes a new full release; clients move forward, tags are never rewritten.
* **Log or checkpoint trouble:** `python3 scripts/tlog.py verify --identity … --repo …`; the log is append-only and every checkpoint is signed; never rewrite `logs/`.
* **Rotate/inspect secrets:** names only are in the repository; values live in Actions secrets.

## Live verification

2026-10-19, tree `1cd2a02` plus log commits: `verify_live.py --external` PASSED on `https://macguard.github.io/macguard-yara-channel/` and `https://macguard-rules.pages.dev/`; `compare_mirrors.py` identical (manifest `f75c2146…`, rules_root `16d08239…`, log 75 entries); Mermaid 12.2.0 with DOMPurify 3.4.12 served by both; CSP meta on GitHub Pages, CSP/COOP/permissions/nosniff headers on Cloudflare; unknown paths answer 404 on both. Passive ZAP re-run results are in `evidence/zap-baseline-before-fixes.md`.

## Closing (only after GO)

Final commit, tag `v1.0.0` on the commit that passed, CI green, both hosts verified, functional freeze, residual risks recorded, daily operation observed without intervention. **None of these steps was performed**, because the verdict is NO-GO.
