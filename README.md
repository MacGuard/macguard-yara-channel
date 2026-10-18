# MacGuard YARA Channel

An autonomous pipeline that collects public YARA rules, validates them, signs a **complete** rule set with Sigstore (no stored key), publishes it as an immutable-by-convention GitHub Release, records every step in a Merkle transparency log, and serves the catalog on GitHub Pages (Cloudflare Pages as a mirror when its credential works). The MacGuard apps (GUI, TUI, CLI) install only releases they can verify.

Nothing in the pipeline needs Claude, a Mac or an interactive session. It runs on GitHub Actions.

## How a release happens
| Step | Workflow | Notes |
|---|---|---|
| 1. Fetch sources, pin commits | `daily.yml` (03:17 UTC and manual) | `config/sources.json` is the allow-list |
| 2. Validate every rule file with `yarac` | `daily.yml` | files that fail block the candidate |
| 3. Compare with the latest release | `daily.yml` (`scripts/changes.py`) | effective change = a rule file added, modified or removed |
| 4. No change → log `candidate.unchanged`, stop | `daily.yml` | no release, no approval request |
| 5. Change → request `publish.yml` | `daily.yml` | `precheck` job re-compares and skips duplicates before asking anyone |
| 6. **Human approval** (`stable-signing` environment) | `publish.yml` | required reviewer, `main` only |
| 7. Seal manifest, sign manifest and checkpoint (Sigstore keyless), inclusion proof | `publish.yml` | identity `publish.yml@refs/heads/main` |
| 8. Metadata: `release.json`, `changes.json`, `CHANGELOG.md`, `consistency.json`, checkpoint | `publish.yml` (`scripts/release_meta.py`) | |
| 9. Verify the artifacts, then create a **draft** release, attach everything, publish | `publish.yml` | the release is never visible half-uploaded |
| 10. Build site, verify the release again, deploy | `site.yml` | `latest.json` only ever points at a release that was verified in this run |
| 11. Verify the **public** URL | `site.yml` `verify-live` | downloads the package and every rule file, checks catalog, links, signatures, proofs |
| 12. Log the result | `site.yml` `record` | `site.live_verified` / `site.live_failed`, `site.cloudflare_blocked` |

Every release is the full current rule set: it installs on its own, without earlier releases. A correction is a new release; tags are never reused.

## Release contents
`rules-release.tar.gz`, `manifest.json` (signed; includes `rules_root` and `stats`: files, yara_rules, expanded_bytes), `manifest.sigstore.json`, `inclusion-proof.json`, `checkpoint.txt`, `checkpoint.sigstore.json`, `release.json`, `changes.json`, `CHANGELOG.md`, and `consistency.json` when a previous release exists.

## Configure (one-time, human)
1. Settings → Pages → GitHub Actions.
2. Protected environment `stable-signing` with a required reviewer and `main`-only deployments.
3. **Recommended:** enable GitHub *immutable releases* (`gh api -X PUT repos/<owner>/<repo>/immutable-releases`). The workflow already creates the release as a draft and publishes it after all assets are attached, which is the flow that setting requires. It is a repository security setting, so it is not changed automatically.
4. Cloudflare (optional mirror): secrets `CLOUDFLARE_API_TOKEN` (Account → Cloudflare Pages → Edit) and `CLOUDFLARE_ACCOUNT_ID`; the expected account id is public in `config/cloudflare_account_id.txt`. `scripts/cf_preflight.sh` classifies a bad credential (format, account id, validity, permission) without printing it and the deploy is skipped, never retried blindly.

## Verify a release yourself
```
scripts/verify_release.py DIR --identity https://github.com/MacGuard/macguard-yara-channel/.github/workflows/publish.yml@refs/heads/main --repo MacGuard/macguard-yara-channel
scripts/verify_live.py https://macguard.github.io/macguard-yara-channel/ --identity ... --repo ... --external
```
The first checks signatures (cosign), every file hash, the rules root, the checkpoint and the Merkle inclusion proof. The second does that on the bytes a public URL serves, plus every rule file and link.

The browser pages (`rules.html`, `releases.html`, `transparency.html`) show the catalog and re-check the Merkle maths in your browser. They do **not** verify Sigstore signatures; use cosign or the app for that.

## Site
`index.html` (latest release, 30-day activity), `rules.html` (searchable catalog with per-file hash check), `releases.html` (history, changes by manifest diff), `transparency.html` (log, checkpoint, proofs), `docs.html`.
Activity counts are what the pipeline observed (examined / accepted / rejected, and new / modified / removed per release). They are not user downloads; no download telemetry exists. A day without a run is "no observation", not zero.

## Apps
`DMGTrustAuditor/` holds the macOS app and the `macguard-audit` CLI/TUI, which share one engine (`Core/`). See `DMGTrustAuditor/DMGTrustAuditor/CLI/README.md` and `docs/ADR-0001-sigstore-verification.md`.

## Tests
`python3 -m unittest discover -s tests` (log, stats, catalog, release metadata); `scripts/web_check.sh` (real pages in headless Chrome, including tamper cases); `tests/tui_pty_check.py` (TUI in a pseudo-terminal); Xcode scheme `DMGTrustAuditor` (engine, installer failure matrix, Merkle consistency, `.app` bundles, responsiveness).

## Boundaries
- Nextron and YARA-Rules provide rules; VirusTotal/yara-x is tracked as an engine, not a rule feed.
- Normalization records paths and hashes; it does not rewrite rule semantics. "Validated" means the YARA compiler accepted the file, not that it detects anything well.
- Licence review of upstream rules is not automated.
- Upstream repositories do not endorse or sign these releases.
