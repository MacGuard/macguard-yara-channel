# MacGuard YARA Channel — final audit report (MACGUARD-FINAL-AUDIT-01)

> **Note (2026-10-22): superseded in part.** This is a snapshot of 2026-10-19. The private quarantine service and panel were deployed afterwards (production check recorded by the owner on 2026-10-21), so "the service is not deployed" below no longer holds; persistent policies, audit anchors and source proposals (migrations 0003 to 0005) are in `main` and not deployed. See `docs-src/en/limits.md` and `docs-src/en/admin-panel.md`. The body is kept as written.

Date: 2026-10-19. Scope: the channel repository, its pipeline, quarantine service, signing/transparency chain, releases, web, documentation, Open Graph, deployment to GitHub Pages and Cloudflare Pages. The macOS application was not touched.

## Verdict: **NO-GO** for closing V1

The published channel is sound and every defect found in it was fixed and deployed. The verdict is NO-GO because four conditions of the brief cannot be demonstrated today and one depends on a human decision. Details and the exact steps that turn it into GO are in `PRODUCTION-READINESS.md`.

* the private quarantine API's authorization is proven only on a local harness (the service is not deployed);
* the autonomous *scheduled* cycle has run once and failed (found and fixed in this audit); the fix is proved by a dispatched run, the next scheduled run (03:17 UTC) is the remaining evidence;
* repository protections (secret scanning, push protection, required checks on `main`, immutable releases) are off and are a repository-owner decision;
* the first release carrying the new signed `evidence` has not been published (it will be at the next real change of upstream rules); its sealing and verification were exercised by tests and by the real Sigstore run of the acceptance chain.

## What changed (about 15 commits on `main` besides the bot's log commits, none force-pushed)

| Area | Change | Commits |
|---|---|---|
| Quarantine service | human rejection can no longer be overridden by identical bytes at another path; content hashed before storing; audit entry only for decisions that took effect; view-audit dedupe; OAuth state bound to the browser; D1 parameter limits; fresh GitHub check on every state change; append-only triggers; bounded bodies; client over https only, no redirect with the token, containment, chunking | 2e812cc, 718a0d9 |
| Cryptography | canonical checkpoint encoding; inventory validation (duplicates, traversal, NUL, hash form); newest-checkpoint copies checked; unlisted files and stats mismatches fail; **signed `evidence` block** tying the published rules to the review run and dynamic measurement | c16bc18 |
| CI/CD | all actions pinned by SHA + Dependabot; least privilege; template-injection sinks removed; site runs no longer hold the log concurrency group (a pending `publish.yml` could be silently replaced); the Cloudflare mirror is downloaded and verified and compared with GitHub Pages; the application is no longer a precondition for a release; **cosign installed in the daily review** (the scheduled run had failed); the acceptance chain repaired | 7cbbf96, 7d46c41, bbce190 and followers |
| Web | Mermaid 12.2.0 (10.9.3 had 8 advisories, 10.9.8 bundled DOMPurify 3.4.2 with 11); CSP on every page and real headers on Cloudflare; real 404 and robots.txt; home tile bug; honest transparency verdicts; WCAG AA contrast, reflow, focus; wording | 631591e, 5d941f1, 9b73e36, 517b02d, 1cd2a02 |
| Verifier | token not forwarded across hosts; http(s) only | 6b14364 |
| Tests | 6 new Python test modules (adversarial Merkle/checkpoint/inventory/log, hostile archives, hostile YARA text, sealing and verifying, CSP, mirror comparison), 7 new service tests, 2 new e2e cases | |
| Reports | `docs/audit/*` and reproducible evidence | |

## Evidence of the final state

| Check | Result | How to repeat |
|---|---|---|
| Both hosts verify live, release `rules-20261018-39150886414` (1,174 files, 9,958 YARA rules) | PASS on `macguard.github.io` and `macguard-rules.pages.dev` | `scripts/verify_live.py <url> --identity https://github.com/MacGuard/macguard-yara-channel/.github/workflows/publish.yml@refs/heads/main --repo MacGuard/macguard-yara-channel --external` |
| Same release on both | identical (manifest `f75c2146…`, rules_root `16d08239…`, log 75) | `scripts/compare_mirrors.py <a> <b>` |
| Deployed fixes | Mermaid 12.2.0 / DOMPurify 3.4.12 served by both; CSP meta (GitHub) and header (Cloudflare); unknown path → 404; robots.txt 200 | `curl` |
| Site workflow on the final tree | run 39258422035 success: build, docs-check, GitHub Pages, Cloudflare Pages, live verification of both, record | `gh run view 39258422035` |
| Daily review on the fixed tree | run 39254094180 success (full test suite, no change → no release, as expected) | `gh run view 39254094180` |
| Acceptance chain with real signing | run 39255895996: 27/27 (Sigstore keyless signature of a manifest carrying `evidence`, real release created and deleted, site built from it, public verification, tamper detected) | `gh workflow run chain-test.yml` |
| Local | Python suite 273 tests (one failure found by the new CSP test, fixed; affected modules re-run green), service 36, `chain_test.py` 22/22, e2e incl. tamper and missing-proof, `docs_check` full 80/80 on macOS Chrome and Linux Chromium, axe 0 violations (7 page types × light/dark × 1280/390) | `TEST-MATRIX.md` |

## IMPLEMENTADO / PROBADO / PUBLICADO / PENDIENTE

* **Implemented:** everything in the table above plus the earlier work (sources, pipeline, quarantine service, Merkle log, Sigstore, releases, portal, 40 documentation pages and 20 diagrams, Open Graph, automatic double deployment).
* **Tested:** see `TEST-MATRIX.md`; the NOT RUN list is explicit (CodeQL first run, Grype/Scorecard, Atheris/Hypothesis, DAST of the API, real concurrency scenarios 11–17 and 20, Firefox/WebKit/screen readers, real D1/OAuth).
* **Published:** the double deployment and the fixes above are live and verified; two real releases exist; no new release was made by this audit (upstream did not change; sealing with `evidence` awaits the next change).
* **Pending:** `RESIDUAL-RISKS.md` (RR-01 repository protections, RR-03 deploy and test the private service, RR-04 observe the scheduled cycle, RR-02 independent attestation, plus the non-blocking items).

## Things the reader should not take for granted

* A green workflow is not evidence: the Cloudflare half used to be "deployed" when the job ended; the scheduled daily review failed on day one although every test suite was green; the acceptance chain had been failing since the documentation was added and nobody saw it because it only runs on demand.
* `manifest.evidence` is the publishing workflow's signed statement, not an independent attestation of the review (documented under "limits" in the site documentation).
* The audit's own sub-reports (`evidence/audit-*.md`) were produced by read-only agents; their findings were re-checked by reading the code or by tests before being acted on, and the discarded items are listed in them.
* Dependabot is now enabled: it opened two PRs (major bumps of `actions/cache` and `actions/upload-artifact`); they trigger the application's macOS test workflow, which is red for reasons outside this audit. They were not merged.
