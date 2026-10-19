# UX, accessibility and performance review of the public portal

Method: a read-only agent drove the two live hosts with Playwright 1.64.1 (GET/HEAD only, one browser at a time, ≤ 4 requests/s), plus axe-core, Lighthouse (mobile) and a byte comparison of both hosts; the full report with scripts and screenshots paths is `evidence/audit-public-portal.md` (ids `W-01` …). After the fixes the same axe configuration was re-run against the rebuilt site (`evidence/web-audit-scripts/axe_local_after_fixes.mjs`).

## What worked

Both hosts serve identical bytes apart from the Open Graph URLs (same manifest SHA-256 `f75c2146…`, package `97304ccc…`, catalog of 1,174 files, stats, documentation); the package's 1,174 file hashes equal the manifest; 40 documentation pages and 40 Mermaid renders without error; no console errors, failed requests, external origins or broken links in the crawl; every tampered Merkle input tried in the browser was rejected; the Open Graph image is 1200×630 and identical on both hosts; Lighthouse accessibility 0.96 on all page types.

## Findings and state

| ID | Sev. | Page / element | Problem | State |
|---|---|---|---|---|
| W-01 | HIGH | home, tile "individual YARA rules" | showed "—" when `latest.json` arrived last | fixed (6c4f830), e2e |
| W-02 | HIGH | all | Mermaid 10.9.3, no CSP | fixed and live (Mermaid 12.2.0, CSP meta on GitHub Pages, real headers on Cloudflare) |
| W-03 | MED | Cloudflare | every unknown path answered 200 + index | fixed and live (404 and robots.txt verified on both hosts) |
| W-04 | MED | rules | "matches the manifest" compared with `catalog.json`; the package check used unsigned `latest.json` on the site copy, the link goes to the GitHub copy | wording fixed; the two copies are still two (RR-07) |
| W-05 | MED | transparency | skipped checks still gave a clean verdict | fixed, e2e red/green |
| W-06 | MED | transparency | entries after the last checkpoint looked signed | marked "after the latest checkpoint, not signed yet" |
| W-07, W-08, W-09 | MED | all, dark theme, home at 320 px | contrast 4.36:1, 2.07:1, 2.35:1; horizontal scroll | fixed; axe 0 violations (7 page types × light/dark × 1280/390) |
| W-10 | MED | home, no script | "channel not activated" / "needs own key" | fixed |
| W-11 | MED | home, release deltas | red "−100 %" for fewer new files; label said "previous run" | fixed: plain numbers |
| W-12 | MED | home | the chart sat under the "Descargas" heading and had no unit | chart moved under its controls, unit added, heading says "not measured" |
| W-13 | MED | rules, home | files called "rules" | fixed on home, rules count and releases; some copy still says "reglas" for files (RR-09) |
| W-14 | MED | rules, platform facet | 2 % of the files are macOS-specific; caveat only in a tooltip | OPEN |
| W-15 | MED | releases | no list of what changed; `changes.json` / `CHANGELOG.md` not linked | links added; in-page diff list OPEN |
| W-16 | MED | home, rules | "how to verify" hard to find; verifier hash is same-origin | OPEN (docs explain; signing the verifier is a proposal) |
| W-17 | MED | docs | diagram text 9 px | floor raised to 11 px; `docs_check` full run green |
| W-18 | MED | docs with Mermaid | Lighthouse performance 0.69–0.70, TBT 2.9–4.2 s (1 MB library on every diagram page) | OPEN (lazy loading / pre-rendering is a redesign) |
| W-19, W-20 | LOW | transparency, scroll regions, toolbar | bare "✘", unfocusable scrollers, names not containing the visible text | fixed |
| W-21 | LOW | rules, home | partial translation (placeholders, sort options, French/German offered) | OPEN |
| W-22, W-23, W-24, W-26, W-27, W-28 | LOW | filters, empty/error states, CLS 0.13 on transparency, cache headers, hard-coded facts, dense table | OPEN |
| W-25 | LOW | head tags | backticks in descriptions fixed; no canonical/hreflang self-reference | partly |

## Judgement

The portal tells the truth about numbers and about what it does not know (no download telemetry, no signature check in the browser). Its main remaining weakness is not visual: the **verification path is not the first thing a visitor sees** (W-16), the two copies a user can verify differ (W-04), and the platform facet in a macOS-oriented channel lists 98 % non-macOS files without saying so prominently (W-14). Those are product decisions rather than defects and are left to the owner.

WCAG 2.2 AA conformance is **not** claimed: axe automated rules pass on seven page types; keyboard order, 200 %/400 % zoom reflow and screen-reader behaviour were checked by script or not at all (Firefox, WebKit and a real screen reader were not run).
