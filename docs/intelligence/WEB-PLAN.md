# Web plan: from "YARA Channel" to "MacGuard Security Intelligence" (DESIGN)

**Resumen (ES).** Plan para transformar la web estática actual (`web/*.html`, `docs-src/`, `scripts/build_site.py`, `scripts/build_docs.py`, `.github/workflows/site.yml`) en «MacGuard Security Intelligence» con diez páginas: Inicio, Explorador de detecciones, Canales de inteligencia, Pipeline de pruebas, Procedencia del software, Transparencia y attestation, Descargas y API, Registro de licencias, Seguridad y confianza, Wiki y hoja de ruta. Para cada página: propósito, fuente de datos REAL (fichero que produce un script concreto), filtros, ficha de artefacto, reglas de insignias operational/experimental/planned (una página solo puede mostrar «operational» para lo que el pipeline produce hoy), accesibilidad e i18n ES/EN, restricciones de sitio estático (sin servidor, CSP de `scripts/csp.py`), preservación de todas las URL públicas existentes con redirecciones versionadas, y despliegue por etapas. **Nada se despliega sin autorización del propietario.** No se ha editado ningún fichero de la web.

Status: everything here is **planned**. Badges: `operational` (produced by the pipeline today, file and script cited), `experimental` (code exists, unproven or partial), `planned` (design only).

## 1. What the site is today (verified)

Build: `scripts/build_site.py` copies `web/` to `site/`, adds the latest verified release, then generates `catalog.json`, `releases.json`, `stats.json`, `consistency.json`, `rules-list.html`, copies `verify_public_release.py` + `.sha256`, calls `scripts/build_docs.py` (docs ES/EN), and finally `scripts/csp.py inject` (CSP meta tag in every page). `site.yml` then runs `og_inject.py`, verifies the release like a client (`verify_release.py`), runs the `docs-check` job, deploys to GitHub Pages (primary) and Cloudflare Pages (mirror, `_headers` from `csp.py headers`), and `verify-live` downloads and checks the public bytes.

### 1.1 Existing public URLs that must keep working
Relative to the site root (`https://macguard.github.io/macguard-yara-channel/`, mirror `https://macguard-rules.pages.dev/`):

| Path | Produced by |
|---|---|
| `index.html`, `/` | `web/index.html` (+ `script.js`, `channel.js`) |
| `rules.html`, `rules-list.html` | `web/rules.html` (+ `rules.js`); `build_site.py` `plain_list()` |
| `releases.html` | `web/releases.html` (+ `releases.js`) |
| `transparency.html` | `web/transparency.html` (+ `transparency.js`) |
| `docs.html` | `web/docs.html` (+ `docs.js`, `docs.css`) |
| `docs/index.html` (redirect by language) | `build_docs.py` + `web/docs-redirect.js` |
| `docs/es/<slug>.html`, `docs/en/<slug>.html`, 20 slugs each: overview, architecture, sources, static-validation, dynamic-validation, quarantine, admin-panel, decision-gate, merkle, transparency-log, sigstore, release, web-distribution, operations, client-update, client-failures, verification, threat-model, limits, glossary | `docs-src/pages.json` + `docs-src/{es,en}/*.md` via `build_docs.py` |
| `404.html`, `robots.txt`, `style.css`, `common.js`, `img/yara-rules.png`, `vendor/mermaid-12.2.0.min.js` | `web/` |
| `latest.json`, `manifest.json`, `manifest.sigstore.json`, `inclusion-proof.json`, `rules-release.tar.gz`, `catalog.json`, `releases.json`, `stats.json`, `consistency.json` (when a previous release exists) | `build_site.py` |
| `logs/log.jsonl`, `logs/checkpoint.txt`, `logs/checkpoint.sigstore.json` | `build_site.py` (copies `logs/`) |
| `verify_public_release.py`, `verify_public_release.py.sha256` | `build_site.py` |
| `rules/<source>/…` (every rule file at the path in the manifest) | extracted from `rules-release.tar.gz` |
| `_headers` (Cloudflare mirror only) | `csp.py headers` in `site.yml` |

These are consumed by external clients: the apps (`ChannelVerifier`, `mgctl intelligence`), `verify_public_release.py`, `verify_live.py` and `tests/test_csp.py`. They are **frozen contracts**: the redesign may add, never move or change the schema of an existing file (see section 6).

### 1.2 Existing data capabilities (so the plan does not invent any)
- Catalog row (`catalog.json`, `scripts/catalog.py`): path, name, category (derived from directory or file-name prefix), source, repository, commit, sha256, bytes, `validation` (`compiled` | `unchecked`), first_release, changed_in, platforms (heuristic from rule text).
- Filters that exist: text search, source, category, platform, validation (`web/rules.html`, `web/rules.js`).
- **Not available today**: licence per file (licence evidence exists in `config/policy.json` and is checked by `scripts/licensing.py`, but is not in `catalog.json`), MITRE ATT&CK tags (no pipeline stage extracts them), family, compatibility between engines, per-file test results, per-file provenance. Any filter on those is `planned` and the UI must say so.
- Only YARA rules are published. Sigma, ClamAV, IOC, heuristics, behaviour, ML and sandbox have no published artefact. (The repository's `config/sources.json` lists two rule sources and one engine entry.)

## 2. Cross-cutting rules

### 2.1 Badge rules (enforced by the build, not by editors)
- A badge is computed at build time from a **status registry** (planned `docs-src/intelligence/status.json`) in which every capability names the file and script that evidences it, e.g. `{"capability":"yara-catalog","evidence":["catalog.json","scripts/catalog.py"]}`.
- `operational` is allowed **only if** the evidence file exists in the built `site/` and its producing script ran in this build. If the file is missing the build downgrades the badge to `planned` and prints a warning; a hand-set `operational` without evidence is a build error (same philosophy as `build_docs.py`: "an unresolved placeholder is a build error").
- `experimental` requires the code path to exist in the repository and a documented limit shown beside the badge.
- `planned` pages and sections render a visible banner "Planned: not available yet", no fake data, no placeholder charts, no sample numbers presented as real.
- No claim of "tested", "attested", "SLSA" or "GitHub attestation" unless a signed tests attestation exists (see `VALIDATION-PLAN.md` section 5; not produced today).
- Existing honesty statements stay: "validated = the YARA compiler accepted the file", activity counts are what the pipeline observed (not downloads), no download telemetry, "a day without a run is no observation, not zero".

### 2.2 Static-site constraints
- No server, no database, no API server. "API" means static JSON files under the site root, cacheable, versioned by path (section 6). GitHub Pages cannot send headers; the CSP travels in a `<meta>` tag (`scripts/csp.py`); the Cloudflare mirror also gets real headers.
- CSP (`scripts/csp.py`): `default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; object-src 'none'`. Consequences: all scripts are separate same-origin files (no inline script, no eval); all fetches are same-origin; **no third-party CDN, analytics, fonts, embeds or external API calls from the browser**; no forms posting anywhere. `tests/test_csp.py` checks real pages; every new page must pass it unchanged. Loosening the policy needs a human decision.
- No `localStorage`/cookies for anything except the existing language and theme preferences (`web/common.js`), wrapped in try/catch.
- Everything verifiable client-side stays what it is: the browser re-checks Merkle maths and file SHA-256 but does **not** verify Sigstore signatures (README); independent verification means `cosign` or `verify_public_release.py`.

### 2.3 Accessibility and i18n
- ES/EN parity, as today: `docs-src/{es,en}` with parity checked by `tests/test_docs.py`; app pages use `data-t` keys and `common.js` (`MG.lang()`, default `es`), missing keys fall back to the Spanish text. New pages follow the same mechanism; a key missing in one language fails the build (stricter than today; planned).
- WCAG 2.2 AA target: semantic landmarks, `<caption class="sr">` on tables, `scope` on headers, visible focus, `aria-live="polite"` for result counts (already used in `rules.html`), colour never the only carrier of status (badge text + icon), contrast checked in light and dark themes, keyboard-operable filters, 390 px and 1280 px layouts (the same two widths `scripts/docs_check.py` already uses), content readable without JavaScript where the data allows it (the `rules-list.html` precedent), `lang` attribute updated on language switch.
- Dates always UTC and ISO 8601; numbers formatted by locale; every chart has a text table alternative.

### 2.4 Artifact card (shared component)
Fields, each with a source or the literal text "not available":

| Field | Content | Source today |
|---|---|---|
| identity | name, technology family, path, version/tag | `catalog.json` / `manifest.json` |
| source and licence | source id, upstream repo, commit, SPDX, redistribution class | repo, commit: `catalog.json`. SPDX: not published per file today (planned export from `config/policy.json`) |
| hashes | SHA-256 and size; Merkle `rules_root` of the release | `manifest.json`, `catalog.json` |
| signature | Sigstore bundle link, identity (`publish.yml@refs/heads/main`), issuer, how verified | `manifest.sigstore.json`, `releases.json` `verification` |
| log inclusion | checkpoint, inclusion proof, consistency proof | `logs/checkpoint.txt`, `inclusion-proof.json`, `consistency.json` |
| tests | per-gate PASS/FAIL/SKIP/ERROR counters, tool versions | today: only `validation: compiled`; per-gate results planned (tests attestation) |
| provenance | where the file came from, how it was transformed | repo+commit today; richer provenance planned (`file-provenance` schema, other work item) |
| compatibility | engine versions (YARA, YARA-X, ClamAV, backends) | `platforms` heuristic today; engine compatibility planned |
| independent verification how-to | exact commands | `verify_release.py`, `verify_public_release.py`, `cosign verify-blob` (README) |
| status | operational / experimental / planned badge | status registry |

## 3. Pages

All pages below are **planned**; "Today" says what the page can honestly show now. Planned URL scheme: new pages are added as new files; none replaces an existing path.

### 3.1 Home (`index.html`, existing path kept)
- Purpose: one-screen statement of what MacGuard Security Intelligence is, the trust model, the latest release, and what is operational versus planned.
- Real data: `latest.json` (`build_site.py`), `stats.json` (`scripts/stats.py`), `releases.json`.
- Filters: none. Cards link to each page.
- Badge: YARA channel `operational`; every other family `planned`.
- Keep the existing "30-day activity" chart with its "no observation" semantics.

### 3.2 Detection Explorer (`explorer.html`; `rules.html` stays)
- Purpose: browse every published detection artefact across families.
- Real data today: `catalog.json` (YARA only). Planned: `intelligence/catalog.json` (union across families, additive new file, produced by a planned `scripts/build_intel_catalog.py`).
- Filters: **format** (YARA today; Sigma, ClamAV, IOC … planned), **source** (exists), **licence** (planned: needs SPDX per file in the catalog), **platform** (exists, heuristic), **compatibility** (planned), **family** (planned), **MITRE ATT&CK** (planned: needs technique ids extracted from rule metadata by a pipeline stage that does not exist; show the filter disabled with "planned" until then), **status** (validation: `compiled` / `unchecked` exists; test status planned).
- Card: section 2.4. `rules.html` keeps its present behaviour and links here.

### 3.3 Intelligence Channels
- Purpose: list channels (signed feeds) with their cadence, sources, last release, how a client subscribes and verifies.
- Real data: `latest.json`, `releases.json`, `config/sources.json` (planned export as `sources.json`; today the allow-list is only in the repo and in `docs-src/*/sources.md`), `stats.json`.
- Filters: family, source, status.
- Badge: "YARA rules channel" `operational`; others `planned` with the reason (no validator, no feed).

### 3.4 Testing Pipeline
- Purpose: show what is tested before a release and the real results, with the PASS/FAIL/SKIP model.
- Real data today: `stats.json` (examined/accepted/rejected per day from the log), `logs/log.jsonl` events, `docs-src/*/static-validation.md`, `dynamic-validation.md`, `decision-gate.md`. Planned: `tests/summary.json` per release from the tests attestation (`VALIDATION-PLAN.md`).
- Filters: technology, gate, result (PASS/FAIL/SKIP/ERROR), release.
- Rule: a SKIP is displayed as SKIP, never merged into PASS; technologies without a validator show `planned`/`NOT_IMPLEMENTED`. The page must state that "compiled" does not mean "detects well".
- Badge: static admission and dynamic benchmark `operational`; other technologies `planned`.

### 3.5 Software Provenance
- Purpose: where each artefact comes from and how it was built (source repo, commit, pipeline run, transformation).
- Real data today: `catalog.json` (repository, commit), `manifest.json` (`sources`, `rules_root`), `release.json`/`changes.json`/`CHANGELOG.md` release assets (`scripts/release_meta.py`), `releases.json`.
- Planned: per-file provenance documents (schema in `docs/intelligence/schemas/file-provenance.schema.json`, written by another work item); build provenance (SLSA/in-toto) is **not produced today** and the page says so.
- Filters: source, release, family.
- Badge: upstream commit pinning `operational`; per-file provenance and build provenance `planned`.

### 3.6 Transparency & Attestation
- Purpose: the transparency log, checkpoints, inclusion/consistency proofs, and (when it exists) the tests attestation.
- Real data: `logs/log.jsonl`, `logs/checkpoint.txt`, `logs/checkpoint.sigstore.json`, `inclusion-proof.json`, `consistency.json` (`scripts/tlog.py`, `catalog.py`). This is the current `transparency.html`, kept at its path and extended.
- Filters: event type, date (UTC), release.
- Badge: log and Sigstore signing `operational`; tests attestation `planned`; GitHub/SLSA attestations `planned` and explicitly "not produced today".
- Keep the browser-side Merkle check and the disclaimer that signatures are verified with cosign or the CLI.

### 3.7 Downloads & API
- Purpose: download artefacts and use the static "API" (JSON files), with verification instructions.
- Real data: release assets (`rules-release.tar.gz`, `manifest.json`, signatures, proofs, `release.json`, `changes.json`, `CHANGELOG.md`, `consistency.json`), `latest.json`, `catalog.json`, `releases.json`, `stats.json`, `verify_public_release.py` + `.sha256`, and the apps' install paths (`docs/cli/mgctl-install.md`).
- Planned: `api/v1/…` index (section 6.2); an OpenAPI-like description of the static files (documentation only).
- Filters: file type, family, release.
- Badge: current files `operational`; `api/v1` `planned`.
- No download counters (no telemetry exists).

### 3.8 License Registry
- Purpose: licence and redistribution status per source and per artefact.
- Real data today: `config/policy.json` `licenses` (Neo23x0/signature-base: DRL-1.1 allowed-with-attribution; Yara-Rules/rules: GPL-2.0 allowed-with-license-notice) and the `license_check` record computed by `scripts/prepare.py` using `scripts/licensing.py`. Neither is currently published on the site: a planned build step would export a `licenses.json` from the policy and the latest check (additive file).
- Filters: SPDX, redistribution class, source, family.
- Rule: the page says the README's boundary verbatim in substance: licence review of upstream rules is not automated, evidence checks only that the reported licence still matches the reviewed one. It is not legal advice. Families without a licence decision (for example ClamAV databases) show `unknown / not reviewed`.
- Badge: `experimental` (data exists in the pipeline but is not exported yet).

### 3.9 Security & Trust
- Purpose: threat model, trust roots, what is and is not guaranteed, vulnerability reporting, responsible disclosure.
- Real data: `docs-src/*/threat-model.md`, `limits.md`, `sigstore.md`, `verification.md`, `docs/audit/RESIDUAL-RISKS.md` and `SECURITY-FINDINGS.md` (only what the owner approves for publication), CSP summary, signing identity.
- Filters: none (search).
- Badge: `operational` for facts about the existing chain; residual risks listed as published in the audit documents.
- Must include the privacy statement: no telemetry, no tracking, no third-party requests (enforced by CSP).

### 3.10 Wiki & Roadmap
- Purpose: documentation hub (the current 20-page docs) plus a roadmap that separates `operational`, `experimental`, `planned`.
- Real data: `docs-src/pages.json` + Markdown (existing); roadmap from the status registry; planned items link to `docs/intelligence/*.md` design documents once the owner publishes them.
- Filters: topic, language.
- Badge: docs `operational`; roadmap items carry their own badge; MacGuard Cloud shown as `planned` only (no service exists).

## 4. Navigation and page inventory

Primary navigation (ES/EN): Home · Detection Explorer · Intelligence Channels · Testing Pipeline · Software Provenance · Transparency & Attestation · Downloads & API · License Registry · Security & Trust · Wiki & Roadmap. The current pages map as: `rules.html` into Explorer, `releases.html` into Channels/Downloads, `transparency.html` into Transparency, `docs/*` into Wiki. The old pages keep serving; the nav links to them or to their successors per section 6.

## 5. Build and test plan (all planned)

- New generators are separate scripts called by `build_site.py` after the existing steps and before `csp.py inject`, each deterministic and covered by unit tests: status registry resolver, intelligence catalog, licences export, tests summary.
- Required checks before any deploy: the existing `docs-check` job (headless Chrome at 1280 and 390 px), `tests/test_csp.py`, `tests/test_docs.py` parity, a new URL-preservation test (every path in section 1.1 returns 200 or a documented redirect), a badge-evidence test (no `operational` without evidence), an ES/EN key-parity test, an accessibility check (axe or equivalent in headless Chrome; tool choice open), and `scripts/web_check.sh`.
- `verify-live` (`site.yml`) must keep passing on both hosts, because the apps and the verifier depend on those bytes.
- Run heavy browser checks with a scheduler plan (`engctl sched plan`), own worktree and ports; downloads in tests go to a temporary directory.

## 6. Preserving URLs and versioned redirects

### 6.1 Rules
1. **No existing public path is removed or changes meaning.** Every path in section 1.1 keeps its content type and, for JSON, its current fields (additive fields only, same rule as in `CLOUD-CONTRACTS.md`).
2. New pages use new names. Where a new page supersedes an old one (for example Explorer over `rules.html`), the old page stays and gets a banner and a link; it is not replaced by a redirect until a published deprecation period has elapsed.
3. If a redirect is eventually needed: static HTML stub with `<meta http-equiv="refresh">` plus a canonical `<link>` and a visible link (the pattern already used by `docs/index.html`); on the Cloudflare mirror, additionally a `_redirects` entry generated at build time. No JavaScript-only redirects (CSP and no-JS readers).
4. Redirects are **versioned**: `docs-src/intelligence/redirects.json` (planned) lists `{from, to, since_site_version, until_site_version, status}`; the build generates the stubs and a test asserts that every `from` resolves and that no entry is removed before its `until`.
5. Documentation slugs (`docs/<lang>/<slug>.html`) are permanent; new documentation pages are added to `docs-src/pages.json` at the end of the list.
6. Machine-readable files consumed by clients (`latest.json`, `manifest.json`, `catalog.json` …) never move. They carry `"schema": 1` today; a breaking change would publish `/…/v2/…` alongside, never in place.

### 6.2 Static API (planned)
`api/v1/index.json` lists the available files with their schema, hash and status badge; it initially points at the existing files (`../latest.json`, `../catalog.json`, `../releases.json`, `../stats.json`). Future family-specific files appear as `api/v1/<family>/…`. `api/v2` is only created for a breaking change and v1 keeps being published for the announced period. Each file lists `generated_utc` and the release tag it derives from.

## 7. Staged rollout (nothing deploys without owner authorisation)

Every stage ends at a gate where the owner decides. Agents prepare changes in a branch and pull request; nobody merges to `main`, triggers `site.yml` deployment, or changes Pages/Cloudflare settings without the owner's explicit approval (`main` is protected and `site.yml` deploys on push to `main`).

| Stage | Scope | Deployed? | Exit criteria |
|---|---|---|---|
| 0 | This design reviewed by the owner; open questions answered | no | written decisions |
| 1 | Status registry + badge component + URL-preservation test, no visible change | only after approval | tests green locally and in CI; `verify-live` unchanged |
| 2 | Local preview build of the new nav and Home using only existing data, served locally (`site/` in headless Chrome) | no | screenshots at 1280 and 390 px reviewed by the owner |
| 3 | Pages whose data already exists: Transparency & Attestation, Downloads & API, Security & Trust, Wiki & Roadmap | after approval | all checks of section 5; the old URLs verified |
| 4 | Explorer, Channels, Provenance, License Registry (with the `licenses.json` export) | after approval | export reviewed against `config/policy.json`; no unsupported filter enabled |
| 5 | Testing Pipeline with per-gate results and the tests attestation | after approval and after the attestation exists | an attestation verified by cosign on a real release |
| 6 | New families appear only when their validator, bench and artefact exist (`VALIDATION-PLAN.md`) | per family, after approval | evidence listed in the status registry |

Rollback: the site is rebuilt from the latest signed release on every run, so rollback is reverting the pull request and rerunning `site.yml`; the redirect table and frozen paths make that safe. Pages stays private/public exactly as the owner configured it; this plan changes no repository setting.

## 8. Risks and honest limits
- Several requested filters (licence, MITRE ATT&CK, compatibility, family) have no data source in the pipeline today; showing them enabled would be fake. They ship disabled with a "planned" tag until a stage produces the data.
- Cross-family pages invite overclaiming; the badge registry and the "no operational without evidence file" build rule are the guard.
- A larger site increases the verification surface of `verify-live`; keep new files out of the set the apps depend on.
- The Cloudflare mirror currently depends on a credential that may not work (README, "Configure"); the plan must work on GitHub Pages alone.
