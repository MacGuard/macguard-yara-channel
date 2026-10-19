# Audit of the public MacGuard YARA channel portal

Date of audit: 2026-10-19 (live data: release `rules-20261018-39150886414`). Hosts: `https://macguard.github.io/macguard-yara-channel/` (gh) and `https://macguard-rules.pages.dev/` (cf).
Method: GET/HEAD only, passive. One headless Chromium (Playwright 1.64.1) at a time; crawl at <=4 req/s. Nothing in the repo was edited.
All scripts and evidence are in `/private/tmp/claude-501/-Users-dmuino-Downloads-macguard-yara-channel/82cd2f90-db22-4237-8d88-d9b30daab0c1/scratchpad/web-audit/` (call it `$W`): scripts `*.mjs`, results in `$W/out/`, screenshots in `$W/shots/`, mirrors in `$W/mirror/`.

Note: during the audit the repo HEAD moved from `aa8fa2a` to `8c3cf22` ("Mermaid 10.9.8 and a Content Security Policy on every page"). The live sites still serve the old build (see W-02). Source line references are against the HEAD present at the end of the audit.

## Summary

CRITICAL 0 / HIGH 2 / MEDIUM 16 / LOW 10 (28 findings).
What works: all numbers agree between hosts and with the signed data. The package contains 1174 files whose hashes equal the manifest, and the catalog equals the manifest. The 45 HTML pages differ between hosts only in OG absolute URLs (+48 bytes each). All non-HTML files are byte-identical (manifest sha256 `f75c2146...`, package sha256 `97304ccc...`). All 40 docs pages (20 ES, 20 EN) render with 40 Mermaid diagrams and no errors. There are 0 console errors, 0 failed requests, 0 non-self origins loaded, 0 broken links or anchors in the crawl, and the Merkle checks reject every tampered input I tried.

## Findings

### HIGH

**W-01 | HIGH | functional | index `#tiles-dist` ("Lo que se distribuye ahora")**
- Evidence: the tile "Reglas YARA individuales" shows `—` and the "descomprimido 7.5 MB" subtitle is missing, while the "Última release" box right above says 9958. On gh it reproduces 4 of 4 loads. On cf it reproduced 3 of 4 (fixed run order differs).
- Reproduction: `node $W/race.mjs gh` and `node $W/race.mjs cf`. Output: `Reglas YARA individuales —` (the 1.5 s delayed `latest.json` case fails on both hosts).
- Root cause: `web/channel.js:37` builds the tile from `S.latest.stats`. `draw()` is only called from the `stats.json` and `releases.json` handlers (lines 86-87). The `latest.json` handler (line 88) only calls `latest()`, so the tile is never redrawn when `latest.json` arrives last.
- Fix: in the `latest.json` handler call `draw()` as well (`S.latest=x;latest();draw()`), or wait for all with `Promise.all` before the first draw.

**W-02 | HIGH | security | both hosts, all pages with diagrams and response headers**
- Evidence:
  - The live Mermaid is `vendor/mermaid-10.9.3.min.js` (1,005,294 B transfer). The repo's own commit `8c3cf22` says that version has 8 advisories. `vendor/mermaid-10.9.8.min.js` returns 404 live.
  - No `Content-Security-Policy` meta on any page (`grep` on `$W/mirror/gh/index` returns 0).
  - No CSP header on either host. cf has no frame-ancestors or Permissions-Policy and no COOP. gh sends only HSTS, with no `X-Content-Type-Options`. See `$W/out/headers.txt`.
  - The workflow step `site.yml:224` (`csp.py headers site/_headers`) is not reflected in the live cf headers.
- Mitigation: Mermaid runs with `securityLevel:'strict'` and the diagram sources are static and built from the repo, which lowers exploitability. SRI is present.
- Fix: deploy `8c3cf22`. After the deploy, re-check that Mermaid is 10.9.8, that `<meta http-equiv=Content-Security-Policy>` is in the pages, that cf sends the `_headers` content, and that the docs still render (the CSP uses `style-src 'unsafe-inline'`). Re-run `$W/sweep.mjs` to confirm there are no console CSP violations.

### MEDIUM

**W-03 | MEDIUM | functional/seo | cf: every unknown path returns 200 + index HTML (soft 404)**
- Evidence: `/nonexistent-xyz`, `/rules/nope.yar`, `/catalog.jsonx`, `/favicon.ico`, `/robots.txt` and `/sitemap.xml` all return `200 text/html` (the index, 7,422 B). gh returns a real 404 with a CSP. Lighthouse cf SEO is 0.91 on the main pages and 0.82 on the docs page (invalid robots.txt). The Lighthouse "agentic-browsing" category scores 0.45-0.5 on cf.
- Impact: a broken download link on cf looks like success. The in-page hash check would report "NO coincide" instead of "not found". Crawlers parse HTML as robots.txt.
- Root cause: no `404.html` in the deployed site, so Cloudflare Pages applies SPA fallback (`scripts/build_site.py` ships none).
- Fix: ship a minimal `404.html` (real 404 status). Optionally ship `robots.txt`, `favicon` and `sitemap.xml`.

**W-04 | MEDIUM | ux/claims | `rules.html` per-file and package checks**
- Evidence:
  - The per-file check (button "Comprobar") prints "✔ coincide con el manifiesto". The code compares against `catalog.json` (`web/rules.js` `verifyFile`, `f.sha256` from `S.cat.files`). The signed `manifest.json` is not read there. I verified offline that catalog equals manifest (`$W/mirror`), but the page does not.
  - The package check prints "✔ SHA-256 coincide con latest.json". That reference is unsigned and served from the same origin as the file.
  - The "Descargar paquete completo" link points to the GitHub Releases copy (`#dl-pkg` href `https://github.com/MacGuard/.../rules-release.tar.gz`, set at `rules.js:38`). The button verifies the site copy `rules-release.tar.gz`, not the file the user just downloaded.
  - The green ✔ is easy to read as "authentic". Only the footnote `hashnote` explains the limit.
- Reproduction: `$W/rules.mjs` (keys `verify0`, `pkgcheck`, `pkgHref`) and `$W/out/rules_gh.json`.
- Fix: say "coincide con catalog.json" (or compare against `manifest.json`). Label the package check "integridad contra latest.json (no firmado)". Point the link and the button at the same copy.

**W-05 | MEDIUM | security-ux | `transparency.html` "Ejecutar comprobaciones" fails open when files are missing**
- Evidence: with `inclusion-proof.json` returning 404 (local interception) the page shows 3 ✔ lines and the verdict "Result: mathematical coherence checked in your browser...". The inclusion check is silently skipped. The same happens when `manifest.json` fails (the check of manifest log head vs checkpoint is skipped).
- Reproduction: `node $W/pages.mjs gh` (key `tr.proofMissing` in `$W/out/pages_gh.json`).
- Root cause: `web/transparency.js` line 23, `if(p){...}` has no `else` branch (consistency has one, `c3n`). The `if(man&&man.log)` check has none either.
- Fix: add a visible "✘/not checked: inclusion proof not available" line and do not print the "checked" verdict unless every check ran.
- Tamper tests (tampered log line, truncated log, checkpoint root, proof path, proof entry, consistency path) all give ✘ correctly.

**W-06 | MEDIUM | ux | `transparency.html` entries table does not mark unsigned entries**
- Evidence: "Entradas en log.jsonl 113 (+38 entradas posteriores al último checkpoint)", tree size 75. The table (`#log-table`) lists entries 0..112 in one list with no signed/unsigned marker. Unsigned entries (index >= 75) look the same as covered ones.
- Fix: add a column or badge ("firmada por el checkpoint" / "posterior"), or a separator row at index 75.

**W-07 | MEDIUM | a11y (WCAG 1.4.3) | all pages, light theme**
- Evidence: axe `color-contrast` serious: `#6b7a90` on `#fff` is 4.36:1 (needs 4.5) on `aside > small`, nav links and muted text. 76 nodes on index (1280), 22 on rules, 13 on releases, 23 on transparency, 13-34 on docs. The same colour on `--bg #f1f5fa` is lower.
- Root cause: `web/style.css` line 1, `--muted:#6b7a90`.
- Fix: darken to about `#5b6b80` (>= 5.3:1) and re-run axe.

**W-08 | MEDIUM | a11y | dark theme**
- Evidence: `.delta.neg` (`#b3261e` on `#312c37`) is 2.07:1 (index tiles 1 and 3). `.lv-INFO` (`#1b6e3c` on `#1d2934`) is 2.35:1 on the whole transparency log table. rules, releases and docs are clean.
- Reproduction: `node $W/dark.mjs`.
- Root cause: fixed colours in `style.css` (`.lv-INFO`, `.lv-ERROR`, `.delta.neg`) are not redefined under `body.dark`.
- Fix: add dark-theme variants (for example `#7bd88f`, `#ff8f8a`).

**W-09 | MEDIUM | a11y (WCAG 1.4.10 reflow) | index at 320 CSS px (400% zoom)**
- Evidence: `scrollWidth 369 > clientWidth 320`. Cause: `.act-ctl` (the two selects `#act-view`, `#act-range`) overflows. The sidebar nav (`A#nav-docs` right=663) scrolls inside its own container, which is acceptable. Other pages reflow at 320 and 640. See `$W/out/sweep_*.json`, key `index|z400`, and `$W/shots/gh_index_z400.png`.
- Fix: `.act-ctl{flex-wrap:wrap}` and `select{max-width:100%}`.

**W-10 | MEDIUM | consistency/claims | `index.html` static fallback text contradicts the live state**
- Evidence: with JS off (and before JS runs) the page shows "Canal pendiente de activar" (two `.status` boxes), and the static `<small data-i="needskey">` says "Requiere clave propia". The channel is active and signs keyless. The "Cargando…" state stays forever and `#act-chart` is empty. `$W/out/rules_gh.json` key `noJS index`; screenshot `$W/shots/gh_index_nojs.png`.
- Root cause: `web/index.html` hard-codes the pre-activation copy; `script.js`/`channel.js` replace it.
- Fix: put the current wording in the HTML (or remove the status when JS is absent) and put the noscript links first.

**W-11 | MEDIUM | ux | index "Cambios entre releases" delta chips**
- Evidence: "Nuevas 0 −100% vs. análisis anterior" is rendered red (`.delta.neg`) and "Eliminadas 10 +10 vs. análisis anterior" is not. The comparison is release vs previous release, but the label says "análisis anterior". "−100%" is an artefact of comparing with the initial import (1184 new). Fewer new files is not "bad".
- Root cause: `web/channel.js:17` (`bad? diff>0 : diff<0` plus the `t.vs` text) and `:36` (the same `tile()` is reused for releases).
- Fix: use a release-specific label ("vs. release anterior") and do not colour-code or percent-scale these counters (show absolute `+0/+10`).

**W-12 | MEDIUM | ux | index "Descargas" heading and the activity chart**
- Evidence: `<h3 id="h-dl">Descargas</h3>` contains only the sentence "Descargas reales: no se miden". The legend and bar chart follow in the same visual block (screenshot `$W/shots/gh_index_full.png`), so the chart reads as downloads. The nav item is "Actividad" and the chart shows files examined per day. The y axis has numbers (0/1000/2000) with no unit or axis title. 29 of 30 days are hatched ("sin observación"), so the chart has one real bar (2026-10-18). The 14/7-day ranges and the "changes" view show 1-2 bars.
- Fix: rename the block ("Descargas: no medidas") and move the chart under "Actividad del canal" with its own heading. Add a y-axis title ("ficheros examinados por análisis"). Hide the chart, or show a plain statement, until there are >= N observed days.

**W-13 | MEDIUM | ux/terminology | "reglas" used for files**
- Evidence: `rules.html` count says "1174 de 1174 reglas" (these are 1174 files; 9958 individual YARA rules). `releases.html` column "Rules" shows `1174 (9958 YARA)`. Index "Reglas examinadas 1184" means files (the stats definition says "rule files"). The index "Última release" box uses the correct "Ficheros de reglas 1174 / Reglas YARA individuales 9958".
- Fix: use "ficheros" in the `rules.html` count, the `releases.html` column and the index tile label. Keep "reglas YARA" for the 9958.

**W-14 | MEDIUM | ux/claims | platform facet vs the macOS audience**
- Evidence: platforms in the catalog: Windows 829, unspecified 266, Linux ~90, Android/Java ~50, macOS 25 of 1174 (2.1%). The platform is "inferred from markers in the rule text" and that explanation lives only in a `title` tooltip (not keyboard or touch accessible), `rules.js` td `title`. A "safer macOS" channel where 98% of the files are not tagged macOS, with the caveat hidden, is confusing.
- Fix: show a visible note under the filter ("inferred from rule text, not a guarantee"). Say plainly how many rules apply to macOS.

**W-15 | MEDIUM | ux/functional | `releases.html` no drill-down or compare**
- Evidence: the table shows "+0 / 0 / −10" but there is no list of which 10 files were removed. The release assets `changes.json` and `CHANGELOG.md` exist (listed on the index) but are not linked from the releases table (links are only package/manifest/bundle/proof). `rules_root` is cut to 16 chars with the full value only in a `title`. On a 390 px viewport the table is 905 px wide inside a 298 px wrapper without `tabindex`.
- Reproduction: `$W/pages.mjs` (keys `rel.rows`, `rel.links`, `rel.m.tablescroll`).
- Fix: link `changes.json` and `CHANGELOG.md` per release, add a "ver cambios" view, make `.tablewrap` focusable (`tabindex=0`, `role=region`, label).

**W-16 | MEDIUM | ux | how to verify is easy to miss, and the verifier is not independently rooted**
- Evidence: the index has no "how to verify" call to action. On `rules.html` it is the 4th bullet of "Descargas y comprobaciones" as "Descargar verificador · Download verifier" (one mixed-language link) next to "Cómo verificar / How to verify". The verifier `.sha256` file is served from the same origin (`shaComputed == shaFile`). The docs page states that this is not an independent root of trust. The portal pages do not.
- Fix: put a prominent "Verificar esta release" block (3 commands) on index and rules. Say next to the verifier link that its hash is not an independent root, and link the signed copy once it exists (docs list it as PROPUESTA).

**W-17 | MEDIUM | a11y/ux | diagram text too small even on desktop**
- Evidence (`$W/docs2.mjs`, `$W/out/docs2_gh.json`, `$W/shots/gh_doc_toolbar2.png`): at 1280 px the effective minimum font is 9 px for `fig-trust-boundaries` (1872 px wide, scale 0.56, scrolls), `fig-sigstore-sequence` (0.75), `fig-release-sequence` (0.75) and 9.5 px for `fig-sources-sequence`. At 390 px the minimum is 9 px (the floor) on 24+ pages, with horizontal scroll inside the stage. All 40 diagrams render with no errors.
- Root cause: `web/docs.js:28`, `fit()` clamps the scale at `9 / minFont`.
- Fix: raise the floor to about 12 px (stage scrolls), or redraw the widest diagrams (`trust-boundaries`) as TB layouts.

**W-18 | MEDIUM | perf | docs pages with Mermaid**
- Evidence (Lighthouse mobile preset, `$W/lh.mjs`, `$W/out/lh_*.json`): `docs/es/architecture.html` performance 0.69 (gh) / 0.70 (cf), TBT 4167 / 2860 ms, main thread 7118 ms, bootup 5170 ms, 1,022,582 B transferred of which Mermaid is 1,005,294 B gz (gh) or 952,808 B (cf). 24 of 40 docs pages load it. Diagram render takes about 0.4-0.7 s per page on a fast desktop (4.5 s first load including the download). Index/rules score 0.96-0.99 and TBT <= 70 ms.
- Fix: load Mermaid lazily (dynamic import when the figure nears the viewport), or pre-render the SVGs at build time and keep Mermaid only for the theme switch.

### LOW

**W-19 | LOW | ux | `transparency.html` failed verdict is a bare "✘"**
- Evidence: after any failed check the last `<li>` is "✘" with no wording (`checks` list in `tr.logLineTampered` and the others). Root cause: `web/transparency.js` end of `run()`, `all?x().trust:x().bad` and `bad:'✘'`.
- Fix: a sentence ("No uses esta release / Do not trust this release") with the failing steps named.

**W-20 | LOW | a11y | scroll regions and toolbar names**
- Evidence: axe `scrollable-region-focusable` (serious) on `.tablewrap` at `transparency.html` (390 px) and `.codeblock > pre` at `docs/en/merkle.html` (390 px). axe `label-content-name-mismatch` (serious) on diagram toolbar buttons: visible "1:1" / "⬇ SVG" vs `aria-label` "Tamaño real" / "Descargar SVG" (WCAG 2.5.3).
- Fix: `tabindex=0` plus a label on those scrollers, and include the visible text in the `aria-label`.

**W-21 | LOW | ux | i18n gaps**
- Evidence:
  - `rules.html` in EN keeps the search placeholder "nombre, ruta o SHA-256" and the sort options "nombre/categoría/fuente/tamaño ↓/cambio reciente" in Spanish (`web/rules.html`, generated by `scripts/gen_pages.py:27`).
  - The verification box check list comes from `verification.json` in English only, even when the page is in Spanish.
  - Index offers fr/de: nav and several headings stay English ("Activity YARA rules Releases..."), and other pages only support es/en (a `fr` choice is treated as `en`).
  - Both a Spanish `<html lang>` and an English OG description are served on Spanish pages.
- Reproduction: `$W/pages.mjs` (keys `idx.lang.fr`, `idx.lang.de`) and `$W/rules.mjs` (`en`).
- Fix: translate the options and placeholder via `data-t`. Remove fr/de or finish them. Provide `checks` in both languages.

**W-22 | LOW | ux | filters and sorts that add nothing**
- Evidence:
  - The "Validación" filter has one value (`compiled`, 1174 of 1174).
  - The "cambio reciente" sort gives the same order as name (all `first_release/changed_in` are the same day), and the column "Incorporada / cambiada" is `2026-10-18` for every row.
  - The category facet has near-duplicates (`mal`/`malware`, `webshell`/`webshells`, `expl`/`exploit_kits`, `gen`/`general`) and singletons (`configured`, `thor`, `crypto`).
  - The count text "N de 1174 reglas (1174 en el manifiesto)" repeats the same number twice (`rules.js` `shown(all.length, S.cat.count, S.cat.count)`).
- Fix: hide the validation filter and the "changed" sort until they vary. Normalise categories in `scripts/catalog.py`. Drop the repeated count.

**W-23 | LOW | ux | empty and error states**
- Evidence: 0 results shows only "0 de 1174 reglas" and an empty `<tbody>` (no message, no "clear filters"). `catalog.json` failure shows "No se pudo cargar el catálogo" in the count line only, with no retry and no link to `rules-list.html` (the link is inside `<noscript>`). `$W/rules.mjs` keys `emptyStateText`, `state:catalog500`. Slow catalog shows "Cargando…" with no skeleton. Search is plain substring (`.*` and `%` return 0), which is fine but not documented.
- Fix: add an empty-state row and a "limpiar filtros" button. On error show the retry and static-list links.

**W-24 | LOW | perf | misc**
- Evidence: CLS 0.13 on `transparency.html` (Lighthouse, gh and cf; above the 0.1 limit) and 0.065 on `rules.html` (table populated after load). All `MG.get` calls use `cache:'no-store'`, so `catalog.json` (74 KB gz) and `manifest.json` are re-downloaded every visit. The index and transparency pages fetch `manifest.json` (66 KB gz, 194 KB raw) for small uses. No favicon: gh 404 on every page, cf returns 200 HTML (5.4 / 2.9 KB). Transfer sizes: HTML 2.2-3 KB gz, CSS 2.2 KB, JS 2-7 KB, OG image 250,728 B.
- Fix: reserve space for tables and facts, use `cache:'no-cache'` (ETag revalidation), add a favicon.

**W-25 | LOW | seo/meta | head tags**
- Evidence:
  - All non-docs pages share the same English `og:description`/`description`; `og:title` for rules/releases is Spanish.
  - No `rel=canonical` on any page.
  - On cf, `og:url` points at `.html` paths that 308-redirect (for example `/rules.html` -> `/rules`).
  - Docs `hreflang` is a relative href with no self-reference and no `x-default` (Lighthouse `hreflang` audit fails, gh docs SEO 0.9).
  - `docs/index.html` is a `meta refresh` to the Spanish overview for everyone and has no OG `twitter:*` or hreflang.
  - The docs `og:description` for `merkle` contains literal Markdown backticks ("How `rules_root` and the log root...").
- OK: `og:image` and `twitter:image` are absolute URLs of the serving host, the PNG is 1200x630 and byte-identical on both hosts (sha256 prefix `a45e583f`), `og:image:width/height` are right, and `twitter:card` is `summary_large_image`.
- Reproduction: `$W/sweep.mjs` (`meta` per page), `$W/compare.mjs`.
- Fix: per-page descriptions, canonical per host, absolute self/alternate hreflang plus `x-default`, strip backticks in `scripts/og_inject.py`, use extensionless `og:url` on cf.

**W-26 | LOW | consistency | cache and header differences between hosts**
- Evidence: gh `cache-control: max-age=600` and no ETag-only revalidation. cf `max-age=0, must-revalidate`. gh has no `X-Content-Type-Options` and no Referrer-Policy; cf sends `nosniff` and `strict-origin-when-cross-origin`. cf has no explicit HSTS (`.pages.dev` is on the preload list). `Content-Type` of JSON on gh is `application/json; charset=utf-8`, on cf `application/json` (no charset). After a release the two hosts show new data at different times (up to 10 min on gh).
- Fix: unify via `_headers` on cf (already generated by `csp.py`, see W-02); note that gh cannot match.

**W-27 | LOW | ux | index hard-coded facts and dense link list**
- Evidence: "Repositorios revisados 3 / 2 rules · 1 engine", "Frecuencia 24h", "Sigstore" are static HTML, not read from data (they would not change if sources or schedule changed). "Última release" bullet list repeats each file twice ("copia canónica (GitHub Releases)" and "copia en este sitio") for 5 artifacts, plus a 7-row facts list.
- Fix: derive from `latest.json`/`manifest.sources`; keep one primary link per artifact and the mirror as secondary.

**W-28 | LOW | ux | rules table density**
- Evidence: 11 columns, table 1357 px inside a 924 px wrapper at 1280 (horizontal scroll). A 64-char SHA-256 column is always shown. Each row has a "Comprobar" button (50 per page).
- Fix: collapse repository/commit/SHA into a details row, or hide columns below 1400 px.

## What was run

| Run | Script | Result |
|---|---|---|
| Crawl, GET only, depth 3, <=4 req/s, both hosts | `$W/crawl.mjs` -> `$W/crawl.json` | gh 71 URLs, cf 116 (46 are 308 redirects). 0 broken, 0 bad anchors, 8 external links (github.com), 0 external subresources |
| Cross-host byte comparison | `$W/compare.mjs` | 24 files identical; 45 HTML differ only in OG URLs (+48 bytes each); non-HTML identical |
| Headers / redirects / cache (HEAD) | `$W/out/headers.txt` | W-02, W-03, W-26 |
| Data consistency (manifest/catalog/stats/releases/latest, package extraction hash of 1174 files) | inline python, see session; mirrors in `$W/mirror` | Consistent. Package has 1175 files (adds `manifest.json`), so expanded 8,055,352 vs manifest 7,861,571 is explained |
| Page sweep: console, network, meta, axe (1280/390), zoom 200%/400% (640/320 px), keyboard walk, headings, landmarks, screenshots; 9 page types x 2 hosts | `$W/sweep.mjs` + `$W/analyze_sweep.py` | W-07, W-09, W-20, W-25. 0 console errors, 0 failed requests; skip link first; focus visible everywhere; no traps (tab wraps) |
| Dark theme axe contrast + reduced motion | `$W/dark.mjs` | W-08. Reduced motion: CSS has only `scroll-behavior`, no animations, so pass |
| Rules page functional: search (9 terms incl. `<img src=x>`), 4 filters, 5 sorts, 3 page sizes, paging, 3 per-file hash checks, package check, download hash, ES/EN, 6 forced states, JS off | `$W/rules.mjs gh` and `cf` | Works; filter/search time 30-280 ms on 1174 files. W-04, W-10, W-21, W-22, W-23 |
| Index, releases, transparency functional; Merkle check with 7 tampered/missing inputs | `$W/pages.mjs gh` and `cf` | W-05, W-06, W-11, W-12, W-15, W-19. Tampered inputs all rejected |
| Race repro | `$W/race.mjs` | W-01 |
| Docs: 80 page loads (40 pages x desktop/mobile) on gh, 3 on cf; diagrams, TOC anchors, hreflang, language switch, toolbar (zoom, fit, 1:1, SVG download) | `$W/docs.mjs`, `$W/docs2.mjs` | All 40 diagrams render; W-17, W-25 |
| Lighthouse mobile (index, rules, docs with Mermaid, transparency) x 2 hosts | `$W/lh.mjs` | Index 0.99/0.96, rules 0.99/0.98, docs 0.69/0.70, transparency 0.95/0.93 (gh/cf). Accessibility 0.96 everywhere |
| OG image | curl + `sips` | 1200x630, identical on both hosts |

## Not run

- GET of external links (github.com release tag, actions run, upstream repos): outside the two authorised hosts.
- Execution of `verify_public_release.py`: needs `cosign` and calls the GitHub API (external). I only checked that the download works and that its `.sha256` matches.
- Firefox and WebKit, Lighthouse desktop preset, real screen readers, real browser zoom (emulated with 640 and 320 CSS px viewports), a real INP measurement (proxy: filter and search latency above), throttled network tests.
- Reading any private admin panel or app (out of scope).

## False positives and discarded items

- Fullscreen toolbar button: after `⛶` the synthetic Escape key did not leave native fullscreen and the theme button stayed covered. That is a headless-Chromium limitation, not a page bug (`docs.js` handles Escape only for its `.dg-full` fallback). Discarded.
- Sidebar nav "clipped" links on mobile (`right=663` etc.): the nav is `overflow:auto`, so it scrolls inside its container and does not cause page overflow. Discarded.
- Tab walk: `unique < tab count` on short pages is only focus wrapping around, not a trap.
- Expanded size mismatch (8,055,352 vs 7,861,571 B): the package also holds `manifest.json`; the docs "Límites" page already explains the definition.
- The cf HTML byte differences (+48 B per page): expected, they come from `og_inject.py` with host-specific URLs.
- axe `incomplete` items (18 per category for contrast and name mismatch): "needs review" results for text on gradients and the chart, not violations.
- `rules.html` opening in English with an English browser locale: by design (`MG.lang()` uses `navigator.language`).
- Lighthouse favicon request: counted once as W-24, not separately.
