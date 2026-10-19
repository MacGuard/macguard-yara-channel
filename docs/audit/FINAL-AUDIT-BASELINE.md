# Final audit — baseline (state before any change)

Scope: `MacGuard/macguard-yara-channel` pipeline, quarantine service, release/signing chain, web, documentation and deployment.
Out of scope and untouched: the macOS application (GUI, CLI, TUI, engine, updater).
Everything below can be re-checked with the commands shown; none of it relies on the auditor's word.

## 1. Freeze

| Item | Value | How to check |
|---|---|---|
| HEAD | `aa8fa2ad4b4abaef428d197a8d385024f00b4648` (`main`) | `git rev-parse aa8fa2a` |
| Working tree | clean, one worktree | `git status -sb`, `git worktree list` |
| Latest release | `rules-20261018-39150886414`, 1,174 files, 9,958 YARA rules | `gh release list -R MacGuard/macguard-yara-channel` |
| Package SHA-256 | `97304ccc48e2ab69368618c49dbf40f18cd7d0c310dfd4ee736ed8823170a8d0` | `latest.json` on both hosts |
| Manifest SHA-256 | `f75c214683d6c169716be1a5ac6f90a7c9a74f408c5cd139553a87e5a25370ad` | `latest.json` |
| rules_root / log | `16d082395ef1ec53d0ad25d5840d83e7f5f3a75a283ce66f8fa75da106790ec5`, 75 entries | `latest.json` |
| Hosts | https://macguard.github.io/macguard-yara-channel/ and https://macguard-rules.pages.dev/ | `scripts/verify_live.py <url> --identity … --repo … --external` |

From this point only defect, security, usability and documentation-consistency fixes were allowed. No new dependency was introduced except test-only tooling run outside the repository (ruff, bandit, zizmor, hypothesis in a scratch virtualenv).

## 2. Inventory

* 30 scripts in `scripts/` (3,061 lines), 7 workflows, 15 Python test modules (226 tests, all passing at baseline: `python3 -m unittest discover -s tests`, 387 s), the quarantine worker `admin/worker` (4 source files, 29 Node tests), documentation sources `docs-src/` (20 pages × 2 languages, 20 diagrams, 24 events).
* Workflows at baseline: `daily.yml` (03:17 UTC), `publish.yml` (dispatched), `site.yml` (push + 04:17 UTC), `chain-test.yml`, `build-engine.yml`, `runner-probe.yml`, `app-tests.yml`.
* Repository configuration (names only, no values): secrets `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN`; variable `AUTO_PUBLISH=true`; environments `stable-signing` (required reviewer), `stable-signing-auto` (branch policy only), `github-pages`. `QUARANTINE_URL` is **not** set: the private service is not deployed.
* Repository security settings at baseline: `main` protected against force-push and deletion only (no required reviews or status checks, admins not enforced); secret scanning, push protection and Dependabot security updates **disabled**; immutable releases **disabled**; default workflow permissions `read`.
* Last CI: all `site.yml` runs since the Cloudflare fix green; `App tests (macOS runner)` red on `eb552a0` and `aa8fa2a` (only `LiveChannelTests.testLiveChannelInstallsWithRealSignatures`, application side, outside this audit); no scheduled `daily.yml` run had happened yet (the repository is a day old).

## 3. Architecture as built (reconstructed from code, then compared with the documentation)

```
upstream (Nextron signature-base, Yara-Rules)   ── pinned commit tarballs ──► prepare.py ► dist/candidate.json
        rulecheck.py (static) ► dynamic_gate.py (reference engine, canaries) ► decide.py ► make_public_candidate.py ► artifact candidate-<run>
        quarantine_client.py ⇄ admin/worker (private; not deployed)           macos job (reference engine measurements)
daily.yml ──dispatch──► publish.yml: check_run ► re-verify ► tlog event+checkpoint+cosign ► seal.py ► cosign ► archive ► release_meta ► verify ► draft release ► public
publish.yml ──dispatch──► site.yml: build_site (+ build_docs) ► docs-check ► GitHub Pages ► verify_live ║ Cloudflare Pages ► record (log)
```

Documentation vs code: the 24 documented events, the policy numbers, the commands and the manifest fields are checked by `tests/test_docs.py` (43 tests). No contradiction was found at baseline, but see the findings for behaviour the documentation described correctly and the code did not guarantee.

## 4. Requirement → implementation → test → evidence → state (at baseline)

| # | Requirement | Implementation | Test | Evidence | State |
|---|---|---|---|---|---|
| R1 | Verified sources, provenance, commits, licences | `config/sources.json`, `prepare.py`, `licensing.py` | `test_licensing`, `test_rulecheck` | manifest `sources[].commit`, `license_check` | Nextron + Yara-Rules real; VirusTotal/yara-x listed as **engine only**, not a rule feed |
| R2 | Daily download, normalise, de-duplicate, compile, static + dynamic validation | `daily.yml`, `rulecheck.py`, `dynamic_gate.py`, `bench.py` | `test_rulecheck`, `test_dynamic_gate`, `test_bench`, `chain_test.py` | green dispatched runs; scheduled run not yet observed | implemented; engine = Ubuntu YARA 4.5.0 (Linux) and 4.5.8 (macOS job) |
| R3 | Quarantine + private service (query, approve, reject, revalidate, batches) | `decide.py`, `admin/worker`, `quarantine_client.py` | 29 Node tests, `test_quarantine_client`, `chain_test.py` | local harness only | implemented, **not deployed** |
| R4 | SHA-256, manifest, Merkle, proofs, Sigstore, attestations | `seal.py`, `tlog.py`, `release_meta.py`, `publish.yml` | `test_tlog`, `test_verify_public_release` | `verify_live.py` PASS on both hosts | signatures and proofs real; **no attestation of validation results** at baseline |
| R5 | Append-only signed log, checkpoints, public events, private separation | `tlog.py`, `make_public_candidate.py` | `test_tlog`, `test_public_candidate` | 75 entries, checkpoints signed | implemented |
| R6 | Complete releases with all assets | `publish.yml`, `release_meta.py` | `test_release_meta`; real runs | 2 published releases | implemented; GitHub immutable releases **off** |
| R7 | Public portal | `web/`, `build_site.py`, `catalog.py`, `stats.py` | `scripts/web_check.sh`, `docs_check.py` | live pages | implemented |
| R8 | 40 docs pages + 20 diagrams + coherence checks | `docs-src/`, `build_docs.py`, `docs_check.py` | `test_docs` (43) | docs-check job | implemented |
| R9 | Open Graph 1200×630 on both hosts | `og_inject.py`, `web/img/yara-rules.png` | `test_docs_og`, `verify_live.py` | PASS on both | implemented |
| R10 | Automatic deploy to both Pages | `site.yml` | `verify_live.py` | runs 39155181443 … 39164717438 | GitHub Pages verified live in CI; **Cloudflare only "job finished"**, not verified live in CI |
| R11 | Optimised, limited, validated workflows; keep stable version on failure | all workflows | — | timeouts present on every job | partial (see findings) |
| R12 | Security of secrets, permissions, OIDC, sources, private data, admin changes, crypto | see findings | — | — | partial |

## 5. Duplicates, dead code, partial features found while reading

* `decide.py`: `res['approved'] = [c for c in res['approved'] if c['state'] != DEPRECATED]` can never remove anything (only VALIDATED files reach `approved`). Harmless, left in place.
* The same "verify a release" logic exists three times on purpose (`verify_release.py` for CI, `verify_live.py` over the network, `verify_public_release.py` for strangers). They share `tlog.py` or re-implement the Merkle maths independently; the independent copy is deliberate.
* `quarantine_client.py released/failed` exit 0 on failure by design (publication must not depend on the service): the service state can drift from the release; documented.
* Partial: observability is the public log and statistics page only; there is no external alert on a failed daily run beyond GitHub's own workflow-failure e-mails.
