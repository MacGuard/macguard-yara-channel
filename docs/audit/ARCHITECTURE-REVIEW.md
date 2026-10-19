# Architecture and business-logic review

Method: every critical script was read end to end (`prepare`, `rulecheck`, `decide`, `dynamic_gate` interfaces, `make_public_candidate`, `changes`, `seal`, `tlog`, `verify_release`, `quarantine_client`, `check_run`, the seven workflows, the quarantine worker). The questions of the brief were answered from the code and then tested; a green test was never accepted as proof that the behaviour was right.

## 1. The business flow, as it really behaves

| Question | Answer from the code | Verdict |
|---|---|---|
| What is a valid rule file? | one that passes `rulecheck` (not truncated/corrupt, balanced, modules within policy), compiles with `yarac` together with the files it needs, is below 1 MB with no NUL byte, has a path the signed inventory can represent (new), and whose source licence still matches the reviewed text | right; the path rule is new (FA-13) |
| What is an accepted rule? | `VALIDATED` after `decide.py`: valid, not a dynamic culprit, not generic against the clean corpus, not rejected by a person, dependencies also accepted | right |
| What does "tested" mean? | compiled and scanned with the **reference engine** against a safe corpus and detection canaries, compared with the previous release's measurements; on Linux with Ubuntu YARA 4.5.0, on macOS with the pinned 4.5.8 build. It is not detection quality and not an independent macOS VM | right, honestly documented |
| What does quarantine mean? | the file is left out of the release and its details go only to the private service; a person can approve judgement-only findings (`WAIVABLE`), never compile errors, truncation, corruption, crashes, a changed licence or a dynamic failure | right |
| When is a whole release blocked? | dynamic evidence missing / for another set / failing / canaries not detected; nothing approved; no effective change; a change above 15 % removed or 40 % touched without a person; accounting identity broken | right |
| When is one rule excluded? | any single failing file, individually; a dependent of an excluded file is excluded too; an unrepresentable file name is left out alone (new) rather than failing the seal | right |
| A previously published rule that now fails? | withheld, reported as `rules.withheld`, absent from the next full release | right |
| What justifies a release? | an effective change: a file added, modified (hash) or removed; a new upstream commit with identical bytes is not | right |
| When are statistics updated? | per run from the log, per release from signed manifests, on every site build; a day without a run is "no observation" | right; the invariant `examined = accepted + quarantined + rejected + deprecated` is enforced before logging |
| When is a publication complete? | release public with all assets, site deployed, **and** each public host downloaded and verified (the Cloudflare half is new) | was incomplete (FA-18) |
| GitHub Pages works, Cloudflare fails? | the primary stays; the mirror keeps its previous valid release; the run goes red and the log says `site.cloudflare_failed`; the hosts then legitimately differ and `compare_mirrors.py` is skipped | right |
| Log and publication out of step? | the log gets `release.approved` and a signed checkpoint before the release exists; if the release then fails the log says `release.failed`. The log is history of decisions, not proof of release; clients use the manifest's `log` head plus the inclusion proof, both signed | acceptable, now documented |
| Interrupted run? | tags are unique per run, a draft release is never visible, the next daily run recomputes everything against the latest public release; stale drafts are harmless | right |
| What controls `latest`? | `gh release edit --latest` after the last asset is attached; clients do not use it: the site's `latest.json` is built from the newest release **whose signature and identity verified** in that run | right |

## 2. Architectural findings

1. **The release depended on the application** (`request-publish` needed the macOS job that builds MacGuard). Wrong layer and against the product decision. Split into `macos` (reference engine, gates) and `app-compat` (report only). FA-17.
2. **A control that could silently lose a release.** Sharing one concurrency group between a long site run and `publish.yml` lets GitHub replace the single pending run. The log-writer group now covers only the short jobs that write the log. FA-16. This was reasoned from GitHub's documented semantics and could not be reproduced; the safety net is that the next daily run republishes.
3. **Validation results were not bound to the signature.** Added `evidence` to the signed manifest, checked at sealing and by the verifier. FA-11. Still a statement by the publishing workflow; a signed in-toto statement from the review job would be independent (residual risk RR-02).
4. **A check ran after publication that could not stop it.** `verify-live` verifies GitHub Pages after it is deployed; a failure leaves the bad site online until the next run (the previous site is only "kept" if the deploy never happened). The pre-deploy checks (`verify_release`, `docs-check`) are the real gate. Residual RR-05; making Pages deployment two-phase is a new feature and was not added.
5. **Duplicated verification logic by design.** `verify_release.py` (CI), `verify_live.py` (network) and `verify_public_release.py` (strangers) share or re-implement Merkle code deliberately; they now share the same strictness only where they use `tlog.py`. The independent verifier does not call `check_inventory`; it has its own limits (members, depth, sizes, no links).
6. **Dead code, left alone:** the `DEPRECATED` filter after counting in `decide.py`; unused imports reported by ruff.
7. **Configuration contradictions:** none found between `config/policy.json`, the workflows and the documentation (checked by `tests/test_docs.py`).
8. **TOCTOU:** `precheck` and `publish` compare the candidate with the latest release twice; both run inside the log group, so no other release can appear in between. The candidate artifact is downloaded by run id and name from the run that `check_run.py` just validated. `check_run.py` does not require the review run's commit to be the current tip of `main`; the publish job re-runs the static and dynamic checks with the current code, so a stale candidate cannot bypass newer rules.
9. **Impossible or unrecoverable states:** none found in the workflows. In the quarantine state machine REJECTED and RELEASED are terminal for people, only the pipeline moves RELEASED→PENDING on revalidation failure; there is no human path to withdraw a released rule (design gap, no bypass).

## 3. What was NOT concluded

* Real concurrency between `daily.yml`, `publish.yml` and `site.yml` on GitHub was not provoked (it would need overlapping real runs and would consume runners and create releases).
* The dynamic gate was reviewed through its interface and tests, not re-derived line by line, and what `dynamic_gate.py` writes to the job log of a public repository (as opposed to the public candidate, which is filtered by `make_public_candidate.py`) was not audited.
* Differences between YARA 4.5.0 (Linux gate) and 4.5.8 (shipped) in dynamic behaviour are not excluded (static classification is identical for the whole set).
