# DMG Trust Auditor — MacGuard v4 (source prototype)

Native SwiftUI macOS 13+ project, using the MacGuard design tokens and components vendored in `App/DesignSystem` (rules in `DESIGN_RULES.md`). Supports Intel and Apple Silicon when built on macOS.

## Build

```sh
cd DMGTrustAuditor
xcodegen generate
open DMGTrustAuditor.xcodeproj
```

Choose **My Mac** as the run destination, not a build-only destination. Build with Cmd+B, run with Cmd+R. No precompiled binary is included. The code has **not been compiled on macOS in this environment**.

## Added in v4

- Two-pane layout that follows the system light/dark appearance, with a Spanish/English picker that starts from the system language, and the shared MacGuard tokens/components.
- Optional automatic AASA lookup from the explicitly supplied HTTPS publisher host. An AASA claim is not a macOS DMG authenticity guarantee.
- Automatic SHA-256 lookup **only when** the user provides a direct HTTPS checksum-manifest URL ending in `.sha256`, `.sha256sum`, or with `checksums` in the filename. Matching is against the exact DMG filename; no guessed hashes, arbitrary search results or crawling.
- If no checksum manifest is available, the report explains how to obtain a publisher hash. SHA-256 comparisons from unverified sites do not prove provenance.
- Basic static malware triage for suspicious shell commands, persistence, credential access, quarantine bypass and privilege escalation; basic PKG signature, script/payload archive inventory. **Not exhaustive**: compressed PKG scripts and payloads are not fully scanned; no AV engine or behavioral sandbox is included.
- JSON/TXT report and heuristic confidence score, with explicit unknown findings.

## Security limits

**Not an antivirus and not a malware-free certification.** Unknown findings are not passes. PKG expansion and DMG mounting still parse untrusted data; use a disposable VM for hostile samples. The network source is supplied by the user, not authenticated as a publisher. The current URL validation is not a complete DNS-rebinding/SSRF defense and should not be deployed as a privileged network service. Do not execute files from untrusted installers. The static inspection engine currently supports DMG as input; PKGs inside the DMG are partially inspected.

## Scope still open

Full PKG archive extraction with resource budgets and sandbox isolation, malware signature scanning, independent manufacturer-domain verification, complete nested Mach-O inventory, tests on macOS Intel and Apple Silicon, fully localized audit-engine output, and real signing/notarization of the auditor itself.

## Signing and contextual help (v5)

See `SIGNING.md` and `Scripts/release-sign-notarize.sh`. The result rows now include contextual info buttons (Spanish/English) with official Apple documentation where applicable. This source ZIP is unsigned.

## v7 — YARA without Homebrew

See `YARA_INTEGRATION.md`. The app scans only with a signed `Contents/Helpers/yara` included by the release pipeline. The source project deliberately does not ship an unverified precompiled executable. Developer builds without the helper report YARA unavailable. Community rule updates inherited from v6 remain experimental and must be hardened before distribution.
