# Third-party notices and attributions: DRAFT

> **Resumen en español.** Borrador de avisos y atribuciones basado en evidencia leída el 2026-10-22. **No es asesoramiento jurídico, no está aplicado en ningún sitio** y no crea ningún `LICENSE`, `NOTICE` ni cambio de release. Mantiene separados cuatro regímenes: (1) licencia del código propio, (2) licencia de la documentación y los diagramas originales, (3) licencias de las reglas YARA de terceros, (4) licencias de las bibliotecas y componentes que se redistribuyen. Hallazgo principal: el paquete `rules-release.tar.gz` de la última release (`rules-20261021-39541028283`) contiene 1178 ficheros de reglas y `manifest.json`, **sin ningún fichero de licencia ni de avisos**; los ficheros de reglas conservan sus metadatos propios (autor, licencia) tal como vienen de origen. Varias reglas llevan una licencia distinta de la de su repositorio (por ejemplo CC BY-NC 4.0). La compatibilidad jurídica entre DRL-1.1 y GPL-2.0 queda **PENDIENTE** de revisión especializada. La firma Sigstore prueba identidad del publicador e integridad, no titularidad. Decisiones del propietario en la sección 7.

## 1. Purpose and status

- Purpose: collect, from evidence in this repository and in the public upstream repositories, what each third-party item asks for and whether the project ships it today, so the owner can decide and a lawyer can review.
- Status: **DRAFT**. Not legal advice. Not applied. No `LICENSE`, `NOTICE`, workflow, release or configuration file is created or changed by this document. The repository has no licence file for its own code (`git ls-files` shows no `LICENSE`/`COPYING`; only `web/vendor/mermaid-LICENSE.txt`; `gh api repos/MacGuard/macguard-yara-channel` reports `license: null` per `docs/wiki/provenance.json` EV-YC-81).
- Date the evidence was read: **2026-10-22**. Paths are relative to the repository root unless a URL is given.
- Method: repository files; the latest release assets (`gh release view` and `gh release download` of `rules-20261021-39541028283`, published 2026-10-21T03:57:41Z), extracted into a scratch directory and counted; upstream licence texts read through `gh api repos/<repo>/license`.
- "Not verified" means the item was not checked in this review. The "licence as evidenced" column is what a file or API says, not a legal conclusion.

### Four regimes, kept separate

| # | Regime | Who holds the rights | What this document does |
|---|---|---|---|
| 1 | Own code (scripts, `admin/worker`, `DMGTrustAuditor`) | The owner | Nothing: no licence is chosen here (decision D1) |
| 2 | Original documentation and diagrams (wiki, `docs-src`, `.mmd` sources) | The owner | Nothing: no licence is chosen here (decision D2) |
| 3 | Third-party YARA rules redistributed in releases | Their authors; licence per source and, in places, per rule | Records requirements and proposes notice texts (sections 2.3, 3) |
| 4 | Libraries and components redistributed or bundled | Their authors | Records licences and what is shipped (section 2.4) |

A signature on a release is not part of any regime (section 5).

## 2. Tables per regime

Columns: component, role, licence as evidenced, evidence and date read, what the licence asks for, notice shipped today (yes/no/unknown), action proposed, status. PASS here means "evidence shows the requirement is met"; PENDING means not met, not verified or awaiting a human decision.

### 2.1 Regime 1: own code

| Component | Role | Licence as evidenced | Evidence (read 2026-10-22) | What it asks for | Notice shipped | Action proposed | Status |
|---|---|---|---|---|---|---|---|
| Scripts, `admin/worker`, `DMGTrustAuditor`, `web/*.html/js/css` (own) | Project code | None. No licence file; GitHub reports `license: null` | `git ls-files` (no LICENSE/COPYING at root); `docs/wiki/provenance.json` EV-YC-81 | Not applicable until a licence exists. Without one, rights are reserved | No (nothing to ship) | Owner chooses (D1). Not proposed here | PENDING |

### 2.2 Regime 2: original documentation and diagrams

| Component | Role | Licence as evidenced | Evidence | What it asks for | Notice shipped | Action proposed | Status |
|---|---|---|---|---|---|---|---|
| Wiki text `docs/wiki/{en,es}`, `docs-src`, Mermaid sources `*.mmd` | Documentation | None assigned | `docs/wiki/LICENSING-PROPOSAL.md`; `docs/wiki/en/Contribute.md` ("Wiki text and diagrams: license pending") | Not applicable | No | Owner chooses (D2). Documentation licence is independent of code and of rules | PENDING |
| Preview image `web/img/yara-rules.png` (1200x630 PNG, Open Graph) | Site asset | Not verified: no authorship or licence record found for the image | `file web/img/yara-rules.png`; git history shows only the commits that added/resized it; `grep` in README/docs finds no credit | Unknown | Unknown | Owner confirms who made it and under what terms; record it | PENDING |
| Fonts | Site CSS | None loaded: CSS uses system font stacks only | `web/style.css`, `web/docs.css` (`-apple-system`, `ui-monospace`); no `@font-face` | Nothing | n/a | None | PASS |

### 2.3 Regime 3: third-party YARA rules

Both sources are redistributed in the release package. Release package contents (read 2026-10-22, asset `rules-release.tar.gz`, 2,062,199 bytes, sha256 `1ed6c83a8f536857fb21004064c2ba466c16cc21e539e09e03ec388691f9b0bb` per `release.json`): 1179 entries; 1178 rule files (745 under `rules/nextron/yara`, 433 under `rules/community`) and `manifest.json`. **No file named or containing a licence or notice**: the only non-rule file is `manifest.json`.

| Component | Role | Licence as evidenced | Evidence and date read | What the licence asks for (paraphrased) | Notice shipped today | Action proposed | Status |
|---|---|---|---|---|---|---|---|
| `Neo23x0/signature-base` (id `nextron`), commit `3ce6640c26046da8e6d8094af3eaaee3ee84e648` in the release | Rule source, 745 files | Detection Rule License (DRL) 1.1. GitHub reports `NOASSERTION` for it | https://github.com/Neo23x0/signature-base/blob/master/LICENSE read via `gh api repos/Neo23x0/signature-base/license` on 2026-10-22; sha256 of the text `8a959b2413d0c83ca1b3ce9153076c649abf2e4bbfebbb493fb24c2074a1eb8a` equals `license_check.sha256` in the release `manifest.json`; `config/policy.json` `licenses` | See 2.3.1 | **Partly.** Per-rule metadata (author, licence line, reference) travels inside each file, which `scripts/prepare.py` copies byte for byte (lines 71-80: `raw=path.read_bytes()` then `write_bytes(raw)`). The licence text itself and a statement of the source are **not** in the package; `manifest.json` records repository, commit and the licence-check verdict only, not the licence text or URL | Ship a notice file with the licence URI and source URI (sections 3, 4); legal review of wording | PENDING |
| `Yara-Rules/rules` (id `community`), commit `0f93570194a80d2f2032869055808b0ddcdfb360` | Rule source, 433 files | GPL-2.0 (GitHub SPDX `GPL-2.0`) | https://github.com/Yara-Rules/rules/blob/master/LICENSE via `gh api repos/Yara-Rules/rules/license` on 2026-10-22; sha256 `c03cea027b4b40e4402fabd08557736727ec3d5bc54ad64ab6472de432198cad` equals `license_check.sha256` in the manifest. README line 6 (read same day): "Our Yara ruleset is under the GNU-GPLv2 license ... open to any user or organization, as long as you use it under this license" | See 2.3.2 | **Partly.** 294 of the 433 files carry the GPLv2 sentence in their own header (counted by text search). The licence text (GPL-2.0, 18,047 bytes) is **not** in the package | Ship the GPL-2.0 text or URI and the notice; legal review (R-LIC-1) | PENDING |
| `VirusTotal/yara-x` (id `yara-x`, `kind: engine`), commit `e27597f2c05e13fe1c2bb459781aef8899afc485` | Engine entry only | BSD-3-Clause per GitHub (`gh api repos/VirusTotal/yara-x/license`, 2026-10-22; default branch, the licence at the recorded commit was not compared) | `config/sources.json`; release `manifest.json` lists it with commit and no `license_check` | Nothing is redistributed (see 2.5) | n/a: no YARA-X code or binary is in the package | None unless YARA-X is ever redistributed; then BSD-3-Clause notice is required | PASS (nothing redistributed, per evidence) |

#### 2.3.1 DRL 1.1: what it asks for (paraphrase of the text read)

- It grants permission to use, copy, modify, merge, publish, distribute, sublicense and sell the Rules without restriction, subject to conditions.
- If you **share** the Rules (also modified), you must retain, **if supplied within the Rules**: (1) identification of the author(s) in the `author` field and anyone else designated for attribution, in a reasonable manner requested by the author; (2) a URI or hyperlink to the rule set or the explicit rule, as far as reasonably practicable; (3) an indication that the Rules are licensed under the DRL, with the text of, or a URI to, the licence, as far as reasonably practicable.
- If you **use** the Rules on data, messages based on matches must retain the author identification, if supplied within the Rules.
- Provided "as is", with a no-warranty and no-liability clause.
- Observation relevant to the second duty: the Installer Auditor app code under `DMGTrustAuditor/DMGTrustAuditor/{Core,App,CLI}` contains no reference to a rule `author` field (text search, 2026-10-22), so it is **not verified** that match messages shown to users keep the author. This needs a human check in the running app.

#### 2.3.2 GPL-2.0 (Yara-Rules/rules): what it asks for (paraphrase; the full text is the licence file read)

- Verbatim copies may be distributed if you keep the copyright notice and the disclaimer of warranty on each copy, keep intact the notices referring to the licence, and give recipients a copy of the licence (section 1).
- Modified copies may be distributed if modified files carry prominent notice of the change and date, and the whole work is licensed to all third parties under the GPL (section 2). Section 2 also says that mere aggregation of another work on a volume of a storage or distribution medium does not bring that work under the licence. Whether a release package of rule files from two sources counts as aggregation is exactly the open legal question (R-LIC-1); this document does not answer it.
- Source-form distribution (section 3): rule files are already source text; no separate source offer was analysed.
- Provided without warranty; no sublicensing beyond the licence (sections 4, 11, 12).

#### 2.3.3 Licences found inside individual rule files (evidence that file-level terms differ from the repository-level licence)

Method: text search over the extracted release package (`license = "..."` meta lines and licence names in comments), 2026-10-22. Counts are of files, not rules; this is an inventory, not an interpretation.

| Where | Observed per-file licence text | Files (approx.) |
|---|---|---|
| `rules/nextron/yara` | `Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE` | 314 |
| `rules/nextron/yara` | `Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License` (a different URL) | 4 |
| `rules/nextron/yara` | `https://creativecommons.org/licenses/by-nc/4.0/` (CC BY-NC 4.0 URL in a `license` field) | 9 |
| `rules/nextron/yara` | `CC BY 4.0` or its URL | 5 |
| `rules/nextron/yara` | `https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/` | 1 |
| `rules/nextron/yara` | `See license at https://github.com/volexity/threat-intel/...LICENSE.txt` | 3 |
| `rules/nextron/yara` | `BSD 2-Clause`, `MIT`, and a link to `kevoreilly/CAPEv2` LICENSE | 4, 1, 1 |
| `rules/community` | GPLv2 sentence in the file header | 294 |
| `rules/community` | `BSD 2-Clause`, an MIT mention, two mentions of CC BY-NC-SA 4.0 | 4, 1, 2 |
| `rules/nextron/yara` | No licence word at all in the file | 392 |

Consequences, stated as open points and not as conclusions: (a) a repository-level licence label does not describe every file; (b) at least some files point to non-commercial (CC BY-NC) terms, whose compatibility with redistribution in this channel was **not assessed**; (c) 392 of 745 `nextron` files carry no licence line, so for those only the repository licence is evidenced. The count of `author = ` meta lines is about 4,891 in `nextron` and 4,785 in `community` (text search), so the DRL "author" field is generally present in the files.

### 2.4 Regime 4: libraries and components redistributed or bundled

| Component | Role and where it goes | Licence as evidenced | Evidence and date read | What the licence asks for | Notice shipped today | Action proposed | Status |
|---|---|---|---|---|---|---|---|
| Mermaid 12.2.0 (`web/vendor/mermaid-12.2.0.min.js`) | Renders diagrams in the documentation site; served from the site, not a CDN | MIT, copyright 2014-2022 Knut Sveidqvist | `web/vendor/mermaid-LICENSE.txt` (first lines read); `web/vendor/README.md`; sha256 of the file `a8a6a6f8...c3b9f` recomputed 2026-10-22 and equal to the README; upstream `mermaid-js/mermaid` LICENSE at tag `mermaid@12.2.0` read via `gh api` | Keep the copyright and permission notice in copies or substantial portions | **Yes** for Mermaid itself: `mermaid-LICENSE.txt` sits beside the file. It is a vendored file in the repository and in the site build; whether `build_site.py` copies the licence file into the published site was **not verified** | Verify the licence file is published with the site | PENDING (partial) |
| DOMPurify 3.4.12, bundled inside the Mermaid minified file | Sanitiser inside the bundle | The bundle's own banner: "Released under the Apache license 2.0 and Mozilla Public License"; GitHub SPDX for `cure53/DOMPurify` is Apache-2.0 | `grep` of `@license` banners in the minified file, 2026-10-22 (only two `@license` banners found: Mermaid-level and DOMPurify) | Apache-2.0: keep the licence text and notices. MPL-2.0 alternative has its own terms; which one is chosen is not decided here | **No** separate DOMPurify licence text is shipped; only the banner inside the file | Add its licence to the notices (section 4) | PENDING |
| Other packages inside the Mermaid bundle (for example D3, Dagre, Khroma, and similar) | Bundled by Mermaid's build | **Not verified**: the minified file shows no per-package banners; the list of bundled packages was not extracted | `web/vendor/mermaid-12.2.0.min.js` only two banners | Depends on each | Unknown | Extract the dependency list from the `npm pack mermaid@12.2.0` metadata and record their licences | PENDING |
| Python scripts | Pipeline and site tools | Standard library only: imports in `scripts/*.py` are stdlib or local modules (`tlog`, `archive`, `catalog`, ...); no `requirements*.txt`, `pyproject.toml` found | `grep` over imports, `find` for requirement files, 2026-10-22 | Nothing redistributed | n/a | None | PASS |
| `admin/worker` Node dev dependencies (`axe-core 4.10.2`, `miniflare`, `playwright 1.64.1`) | Test tooling of the quarantine panel; `private: true` | Not read in this review | `admin/worker/package.json` (devDependencies), 2026-10-22 | Not redistributed in the release package or the site (per file layout); not verified for the deployed Worker bundle | n/a | Confirm that the Worker bundle includes no dev dependency | PENDING (not verified) |
| GitHub Actions used in workflows (`actions/*`, `sigstore/cosign-installer`, `cloudflare/wrangler-action`, `github/codeql-action`) | Run in CI; pinned by commit | Not read | `.github/workflows/*.yml` | Not redistributed | n/a | None | PASS (not redistributed) |
| YARA 4.5.8 (`yara`, `yarac`), built from source | Engine shipped with the Installer Auditor (`Contents/Helpers/`) | BSD-3-Clause ("Copyright (c) 2007-2016. The YARA Authors") | `DMGTrustAuditor/DMGTrustAuditor/Scripts/build-yara-engine.sh` (URL `VirusTotal/yara` tag `v4.5.8`, SHA-256 pinned); `docs/ENGINE.md`; `COPYING` at tag `v4.5.8` read via `gh api`, 2026-10-22 | Binary redistribution must reproduce the copyright notice, the conditions and the disclaimer in the documentation or other materials | **No** licence file found for it: no `LICENSE`/`NOTICE`/`COPYING` under `DMGTrustAuditor/` (`find`, 2026-10-22); `engine-manifest.json` lists versions and hashes only. Whether a built app has one is **not verified** (no built app inspected) | Add the YARA licence to the app bundle notices | PENDING |
| OpenSSL 3.5.9, static in the engine | Provides `hash` and `pe` modules | Apache-2.0 per GitHub (`openssl/openssl`, default branch) | `build-yara-engine.sh` (version, SHA-256 pinned); `gh api repos/openssl/openssl/license`, 2026-10-22; the licence at tag 3.5.9 was not compared | Apache-2.0: include licence text, keep notices; state changes | **No** (same as above) | Add to the app bundle notices | PENDING |
| cosign v3.1.1 darwin binaries (arm64, amd64), pinned by SHA-256 | Installed as `Helpers/cosign` for packaging (`Scripts/fetch-cosign.sh`); also installed in CI by `sigstore/cosign-installer` | Apache-2.0 (`gh api repos/sigstore/cosign/license`; file `LICENSE` exists at tag `v3.1.1`) | `fetch-cosign.sh`; `Core/SigstoreVerifier.swift` lines 18-19 (pins) | Apache-2.0: include a copy of the licence with redistribution; keep notices | **No** licence file found beside the helper in the repository | Add to the app bundle notices | PENDING |
| Sigstore trusted root `DMGTrustAuditor/DMGTrustAuditor/Resources/sigstore/trusted_root.json` | Public key material bundled in the app | **Not verified** (published by the Sigstore project; licence of the data file not read) | `find Resources` | Unknown | Unknown | Check the origin file's terms | PENDING |
| Packaging output for the Installer Auditor (signed app) | | Not built in this review | `docs/ENGINE.md` ("Not done: Developer ID signing and notarization") | | Unknown | Inspect a real build when one exists | PENDING |

### 2.5 YARA-X: what is and is not redistributed

- Recorded: `config/sources.json` has `{"id":"yara-x","repo":"VirusTotal/yara-x","kind":"engine","paths":[]}`; the release `manifest.json` lists it under `sources` with commit `e27597f2...` and no licence check.
- Not redistributed: the release package contains only `.yar`/`.yara` files from the two rule sources and `manifest.json` (tar listing, 2026-10-22). `paths` is empty, so no file of YARA-X is downloaded into the package. The engine shipped with the app is YARA 4.5.8, built from the `VirusTotal/yara` source, not YARA-X (`docs/ENGINE.md`).
- Licence of YARA-X per GitHub: BSD-3-Clause. It would matter only if its code or binary were ever distributed.

## 3. Proposed attribution texts for third-party rule sources

For legal review. Based only on what each licence says (sections 2.3.1 and 2.3.2). Not applied anywhere. Wording in square brackets needs a human choice.

### 3.1 Neo23x0/signature-base (Detection Rule License 1.1)

```
Rules under rules/nextron/ come from the signature-base repository
(https://github.com/Neo23x0/signature-base), at commit 3ce6640c26046da8e6d8094af3eaaee3ee84e648 for this release.
They are licensed under the Detection Rule License (DRL) 1.1:
https://github.com/Neo23x0/signature-base/blob/master/LICENSE
The author of each rule is named in the "author" field of that rule, which is kept unmodified in the file.
Some files declare a different licence or reference in their own metadata; that declaration applies to that file.
These rules are provided as is, without warranty. The MacGuard project does not claim copyright over them.
```

### 3.2 Yara-Rules/rules (GPL-2.0)

```
Rules under rules/community/ come from the Yara-Rules repository
(https://github.com/Yara-Rules/rules), at commit 0f93570194a80d2f2032869055808b0ddcdfb360 for this release.
That repository states that its ruleset is under the GNU General Public License version 2:
https://github.com/Yara-Rules/rules/blob/master/LICENSE
[A copy of the GNU GPL version 2 text is included with this release as <file>.]
The copyright notices and the licence statements in each file are kept unmodified.
These rules are provided without warranty. The MacGuard project does not claim copyright over them.
```

### 3.3 Per-file declarations

```
A rule file may carry its own licence declaration (for example a licence name or URL in its "license" metadata or
in a header comment). Where it does, that declaration is preserved in the file and is the one that describes that file.
A list of files whose declaration differs from the repository licence is [generated per release | not provided].
```

## 4. Proposed text for releases (a NOTICE/attribution file shipped with each release; NOT created)

What a file such as `NOTICE` or `THIRD-PARTY-NOTICES` inside `rules-release.tar.gz` (or as a separate release asset) should list, to be decided by the owner and reviewed by a lawyer:

1. A statement that the package redistributes third-party rule files unmodified, that the project holds no copyright over them, and that the signature of the release says nothing about rights over content (section 5).
2. For each source: repository URL, commit, licence name, licence URL, and the licence text or a copy of it (DRL 1.1 text is 1,939 bytes; GPL-2.0 is 18,047 bytes). The manifest already has repository, commit and the SHA-256 of the licence text read; the NOTICE would add what the manifest lacks.
3. The attribution texts of section 3.
4. The path prefix of each source inside the package (`rules/nextron/`, `rules/community/`).
5. The list or a pointer to the files that declare a licence other than the repository one (section 2.3.3), so that a reader can see them. Whether to list, exclude or ask upstream is decision D5.
6. A separate section for the Installer Auditor application: YARA 4.5.8 (BSD-3-Clause), OpenSSL 3.5.9 (Apache-2.0), cosign v3.1.1 (Apache-2.0), with their licence texts. For the documentation site: Mermaid 12.2.0 (MIT), DOMPurify 3.4.12 (Apache-2.0 / MPL), and the packages bundled in the Mermaid build once identified.
7. A line saying that the regimes are separate: own code, own documentation, third-party rules and bundled components each keep their own terms.

Whether the notice is one file for all sources or one per source/package (so that GPL-2.0 files and DRL files are not presented as one work) is part of the legal question R-LIC-1 and is not decided here.

## 5. What a signature proves and does not prove

A Sigstore or GitHub signature or attestation proves, within its trust model, **who published an artifact (the identity of the publishing workflow) and that the signed bytes were not altered**. It does **not** prove that the publisher owns the content, that it has the right to distribute it, or that any licence applies. A signed package that contains rules written by other people stays a package of third-party rules. Equally, a public source repository does not by itself authorise redistribution: the licence of each source decides. Nothing in this document, in `manifest.json` or in any `*.sigstore.json` file should be read as an assertion of ownership of the rules.

Evidence for what the project's signatures cover: the latest release lists `manifest.sigstore.json` and `checkpoint.sigstore.json` among its assets (`gh release view`, 2026-10-22); `.github/workflows/publish.yml` signs `manifest.json` and the checkpoint with `cosign sign-blob`.

## 6. Risks, kept separate

| ID | Risk | Evidence | Status |
|---|---|---|---|
| R-LIC-1 | Combined redistribution of DRL-1.1 and GPL-2.0 material in one package: whether it needs separate notices, a NOTICE file or separate packages, and whether GPL-2.0 effects reach anything beyond its own rules. Includes files that declare other licences (for example CC BY-NC) | One tarball holds both sources (2.3); per-file declarations differ (2.3.3); the GPL section 2 aggregation wording (2.3.2) | **PENDING legal review** by a specialised lawyer. Not a documentation matter |
| R-LIC-2 | Missing licence/notice files in release artifacts | Confirmed for the latest release: the package has no licence or notice file; release assets are `CHANGELOG.md`, `changes.json`, `checkpoint.*`, `consistency.json`, `inclusion-proof.json`, `manifest.json`, `manifest.sigstore.json`, `release.json`, `rules-release.tar.gz`. Earlier releases were not inspected | **Confirmed for `rules-20261021-39541028283`; PENDING action** |
| R-LIC-3 | Components whose licence text is not distributed with the application (YARA, OpenSSL, cosign; DOMPurify and other bundled packages in Mermaid) | No licence file for them under `DMGTrustAuditor/` or in the Mermaid bundle (2.4). Built app not inspected | **PENDING** (not verified for a built app) |
| R-LIC-4 | Documentation licence undecided | No licence for wiki text and diagrams (2.2) | **PENDING** (owner decision) |
| Related, not numbered | Author kept in match messages (DRL "use on data") | No `author` reference in the app code (2.3.1) | Not verified in the running app |
| Related, not numbered | The channel's own licence check is not a legal check | `scripts/licensing.py` compares SPDX id, a marker string and a text hash; `README.md` line 69: "Licence review of upstream rules is not automated"; the check does not read per-file declarations | Documented limit |

## 7. Decisions the owner must take

- **D1.** Licence of the own code (or none yet). Affects regime 1 only.
- **D2.** Licence of the documentation text and diagrams. Independent of D1; also covers who made `web/img/yara-rules.png`.
- **D3.** Whether to commission a specialised legal review of DRL-1.1 + GPL-2.0 redistribution (R-LIC-1), before or after adding notices.
- **D4.** Whether releases ship a NOTICE/attribution file and in which form (single file, per-source, separate packages), using section 4 as a starting point.
- **D5.** What to do with rule files that declare other licences (for example CC BY-NC): keep and list, exclude, or ask upstream. No exclusion rule exists today in `config/policy.json`.
- **D6.** Whether the Installer Auditor bundle must include a notices file (YARA, OpenSSL, cosign), and whether the documentation site must publish the Mermaid and DOMPurify notices.
- **D7.** Whether the app must show the rule author in match messages (DRL duty on use), after checking the running app.
- **D8.** Whether to extend `scripts/licensing.py` to read per-file declarations. This is a change to code and policy; it needs a human approval and is not proposed as done.

None of these decisions has been taken or applied.
