# MacGuard Installer Auditor

[Home](EN-Home) · [Ecosystem](EN-Ecosystem) · [Roadmap](EN-Roadmap) · [Code signing and notarization](EN-Tech-CodeSigning)

## In 30 seconds

Installer Auditor (in the repository, the `DMGTrustAuditor/` folder) checks a downloaded installer or app (`.dmg`, `.pkg`, `.app`) **before you open it**: it looks at its signature, its hash, its origin and runs YARA rules over it (lists of clues for suspicious patterns). It has three ways of use over one core: a window (GUI), a command line (`macguard-audit`) and a terminal explorer (TUI) {{ev:EV-EC-69}}.

Its rules come from the YARA Channel and are installed only if they pass every verification {{ev:EV-YC-09}}. When it cannot decide it says **unknown**, never "safe". It is **not an antivirus** nor a certification of malware absence. State: **development**, neither signed nor notarized {{ev:EV-EC-68}}.

## An everyday example

It is like a customs inspector who checks the parcel's seal, where it comes from, and compares it with a list of traits of problem parcels. If the parcel matches nothing on the list, the inspector cannot promise it is harmless: only that nothing was recognized.

## Diagram

{{diagram:installer-auditor-core}}

## Step by step

1. You pick a file (GUI) or run `macguard-audit scan <path>`.
2. The core checks signature, hash and package or bundle structure, and runs static heuristics (not exhaustive).
3. If an engine and rules are present, `YARAEngine` compiles and scans with the `yara` and `yarac` executables.
4. Each finding gets a state: `passed`, `warning`, `failed` or `unknown`. Exit codes: 0 (no confirmed failure, not a guarantee), 2 (a check failed), 3 (arguments), 4 (evidence or capability unavailable).
5. Separately, `update-rules` downloads and installs channel rules (see below).

{{diagram:client-update-1-fetch}}

{{diagram:client-update-2-verify-install}}

## Under the hood

**Installing channel rules** (`RuleInstaller.install`) {{ev:EV-EC-70}}:

- Problem: nobody should be able to slip in altered rules. Input: a channel origin. Output: active rules or nothing.
- Origin order: GitHub Pages first, then a Cloudflare Pages mirror; only a network failure moves on to the next, a verification failure never does {{ev:EV-EC-77}}.
- Downloads with byte caps, safe extraction (rejects links, out-of-place paths and hidden entries; caps of 10,000 entries, 160 MB expanded, depth 16, 60 s), requires the package manifest to be identical to the signed one, verifies, re-hashes right before activation and activates with two journalled renames; keeps the previous version.
- `ChannelVerifier.verify` checks hashes and sizes, the rules Merkle root, inclusion in the transparency log, the checkpoint and that there is no rollback. Without a Sigstore verifier it **installs nothing**.

**Sigstore signature** (`SigstoreVerifier`, ADR-0001) {{ev:EV-EC-71}}: uses the official `cosign` as a helper (v3.1.1), only if its SHA-256 matches the one pinned in the code, with a bundled trust root and no network. It requires the identity of the channel repository's `publish.yml` workflow. An expired root makes verification fail (fail closed). The ADR is "accepted", with human review pending.

**YARA engine** (`YARAEngine`) {{ev:EV-EC-72}}: **YARA 4.5.8 as external `yara` and `yarac` executables** (universal arm64 + x86_64, minimum macOS 13), built from pinned source. **YARA-X is not used**: it does not appear in the project code. Before using them it checks hash against the manifest, `codesign --verify --strict`, minimum version 4.5.0, architecture and a canary rule. There is no PATH or Homebrew fallback. One rule per namespace; files that do not compile are named and left out. Current scan limits: 25,000,000 bytes per file and 2,000 files per pass (`maxFileBytes`, `maxFiles`). Files over the per-file limit are not scanned, and files beyond the per-pass count are left out, so a clean result does not cover them: the scan is not a complete defence.

**Signing of its own executables** {{ev:EV-EC-73}}: the `yara`/`yarac` helpers are signed **ad hoc** with the hardened runtime; Developer ID signing and notarization await credentials. See [Code signing and notarization](EN-Tech-CodeSigning).

## Check it yourself

With the public repo and Xcode: `cd DMGTrustAuditor/DMGTrustAuditor && xcodegen generate`, then `xcodebuild -scheme macguard-audit build`; `macguard-audit rules-status` and `macguard-audit verify-rules`. Tests: `xcodebuild ... test` as in `.github/workflows/app-tests.yml`. None of this was run for this page.

## Tests

Static count of `func test`: 105 functions in 9 files (32 TrustAndInstaller, 21 YARAEngine, 11 ContentDetector, 9 AppBundle, 8 ChannelVerifier, 7 ChannelUpdate, 7 DesignSystem, 6 BoundedProcess, 4 Responsiveness) {{ev:EV-EC-74}}. CI runs them on a macOS runner; no stored result was read. `LiveChannelTests` installs from the live channel with real signatures, but only with `MACGUARD_LIVE=1` (otherwise it is skipped); it is a **functional** test.

### End-to-end performance test with the live channel: PLANNED

**It does not exist.** The closest things {{ev:EV-EC-75}} {{ev:EV-YC-10}}:

| What exists | Why it is not that test |
|---|---|
| `scripts/macguard_smoke.py` (job `app-compat`, report only) | Copies the rules in directly and writes a fake manifest: it **skips channel verification**; measures times, not the real install |
| `scripts/bench.py` | Measures the reference YARA engine, not the app |
| `ResponsivenessTests` | Measures UI-thread stalls with synthetic rules, no channel |

How it should be tested: on a clean macOS runner, with the app and the pinned cosign, install from the published channel (`update-rules`) measuring download, verification and activation times; then scan a fixed corpus measuring time, memory and failures, and check that every verification step really runs. Thresholds would be set by a human after measuring; a time would never be a PASS criterion.

## Limits

- It is not an antivirus; "unknown" does not mean safe; PKG is only partially inspected.
- No Developer ID signature or notarization: Gatekeeper will treat a download as not notarized {{ev:EV-EC-68}}.
- **Stale documentation in the folder** {{ev:EV-EC-76}}: several older documents still describe a source prototype not compiled on macOS, an unsigned ZIP, an experimental updater that reads from a GitHub branch, no bundled engine and a "40 rules and 30 files" limit. The current code installs only from the signed channel, includes an engine and has macOS CI; its limits come from `YARAEngine`. The signing note is still valid (neither signed nor notarized).
- Sigstore trust root: renewing it requires an app update.

## State

| Capability | State |
|---|---|
| GUI, CLI and TUI over one core; verified rule install; YARA 4.5.8 engine | Implemented, not distributed (no signed build or app tag) |
| Developer ID signing and notarization of the app and helpers | Planned (credentials missing) |
| End-to-end performance test with the live channel | Planned |
| Native Swift Sigstore verifier | Mentioned as possible; not planned |

CLI version: `macguard-audit` 0.2.0, JSON schema 1 {{ev:EV-EC-69}}. No dates.
