# Production readiness — GO / NO-GO

## Verdict: **NO-GO** (for declaring V1 closed)

The channel itself works and is verifiable: two real signed releases, both hosts serve the same verified bytes, the rule pipeline fails closed, the cryptographic chain rejects every tampering tried. What stops a GO is not a known flaw in that chain but **four conditions of the brief that cannot be demonstrated yet** and **one that needs a human decision**. Nothing below was relaxed to reach a verdict.

| # | GO criterion of the brief | State | Evidence |
|---|---|---|---|
| 1 | no critical defect open | **met** | `SECURITY-FINDINGS.md`: 0 critical |
| 2 | no exploitable HIGH without accepted mitigation | **met in the repository; live after the next deployment** | FA-19/FA-23 (portal) fixed in code, still served old until `site.yml` runs on this tree — see "Live verification" below |
| 3 | automatic publication proven end to end | **partly** — two real releases through `daily → publish → site`, all triggered by `workflow_dispatch`; no scheduled run yet (FA-30); `evidence` in the manifest has been exercised by tests and by the remote chain test (below), not by a production release | `gh run list`, `RR-04` |
| 4 | signatures and cryptographic proofs valid | **met** | `verify_live.py` PASS on both hosts; 23 checkpoint-parser forms, every one-element proof mutation, 9 manifest tamper cases rejected |
| 5 | quarantine prevents publishing problematic rules | **met at the pipeline** (a quarantined or rejected file cannot enter the set; without the service the safe default applies); **service not deployed** | `test_decide`, `chain_test.py` 22/22 |
| 6 | the private API enforces real authorization | **NOT demonstrated**: tested on a local harness only (route × role matrix, CSRF, OIDC scoping, batch atomicity all pass there); real OAuth/OIDC/D1 not run (RR-03) | `evidence/audit-quarantine-service.md` |
| 7 | no private-information leak | **met by test** (`make_public_candidate`, public candidate carries counts only); the service's public endpoint returns four counts | `test_public_candidate`, `chain_test` privacy check |
| 8 | releases verifiable | **met** | `verify_public_release.py` / `verify_live.py` |
| 9 | web works | **met after deployment of 6c4f830** (HIGH W-01 fixed) | e2e + axe |
| 10 | documentation in sync, diagrams legible | **met** | `test_docs` 43, `docs_check` full 80/80 |
| 11 | mandatory tests pass | **met** for everything that could run; see `TEST-MATRIX.md` for the NOT RUN list (CodeQL first run, DAST of the API, real Cloudflare/GitHub concurrency scenarios) | |
| 12 | required deployments verified | **to be confirmed** after pushing this tree; both hosts were verified on the previous tree | below |
| 13 | recovery from failures proven | **partly**: draft-then-public release, unique tags, republish by the next daily run, `compare_mirrors`; interruption/duplicate-run scenarios were reasoned, not provoked (RR-15) | `ARCHITECTURE-REVIEW.md` |
| — | repository protections (secret scanning, required checks, immutable releases) | **human decision pending** (RR-01) | `gh api` outputs in the baseline |

### What turns this into a GO (no new development needed)

1. Owner enables secret scanning + push protection + Dependabot security updates, a ruleset on `main` (required status checks, bypass only for the log bot) and immutable releases (RR-01).
2. Deploy the quarantine service to a staging Worker/D1 with a GitHub OAuth app, run the adversarial suite of `evidence/audit-quarantine-service.md` against it, add Cloudflare rate-limiting for `/auth/*` and `/api/decisions`, then production and set `QUARANTINE_URL` (RR-03).
3. Read the first scheduled `daily.yml` (2026-10-19 03:17 UTC), the `site.yml` of 04:17 UTC and, when upstream changes, the first release carrying `manifest.evidence` (RR-04).
4. Run `codeql.yml` once and triage.

When 1–4 are done and the checks below still pass, tag `v1.0.0` (see "Closing" below) and freeze.

## Maintenance and recovery (so another person can operate this)

* **Daily cycle:** `daily.yml` 03:17 UTC → (change?) → `publish.yml` → `site.yml`; `site.yml` also runs 04:17 UTC and on web/docs changes. Nothing needs a person unless `AUTO_PUBLISH` is turned off (then `stable-signing` asks a reviewer).
* **Is it healthy?** `gh run list -R MacGuard/macguard-yara-channel -L 10`; `python3 scripts/verify_live.py <host> --identity https://github.com/MacGuard/macguard-yara-channel/.github/workflows/publish.yml@refs/heads/main --repo MacGuard/macguard-yara-channel --external`; `python3 scripts/compare_mirrors.py https://macguard.github.io/macguard-yara-channel/ https://macguard-rules.pages.dev/`.
* **A release failed half way:** nothing is public until the last asset is attached; delete the draft (`gh release delete <tag>`), the next daily run recomputes and publishes. Never edit or reuse a tag.
* **Cloudflare mirror failing:** read the `cf-preflight:` line and the job summary of `site.yml`; replace `CLOUDFLARE_API_TOKEN` (Account → Cloudflare Pages → Edit) and `CLOUDFLARE_ACCOUNT_ID`; the next run deploys by itself. GitHub Pages is unaffected.
* **A published rule must be withdrawn:** reject it in the panel (or remove it upstream), the next daily run withholds it and publishes a new full release; clients move forward, tags are never rewritten.
* **Log or checkpoint trouble:** `python3 scripts/tlog.py verify --identity … --repo …`; the log is append-only and every checkpoint is signed; never rewrite `logs/`.
* **Rotate/inspect secrets:** names only are in the repository; values live in Actions secrets.

## Live verification

Appended by the final section of `FINAL-AUDIT-REPORT.md` after the tree was pushed and deployed.

## Closing (only after GO)

Final commit, tag `v1.0.0` on the commit that passed, CI green, both hosts verified, functional freeze, residual risks recorded, daily operation observed without intervention. **None of these steps was performed**, because the verdict is NO-GO.
