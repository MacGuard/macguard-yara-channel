# DMG Trust Auditor v8 — YARA updates

## User behavior

- The SwiftUI window opens immediately; every launch starts an asynchronous GitHub revision check (3-second request timeout, 4-second resource timeout).
- Conditional ETag requests avoid transferring unchanged commit metadata.
- When a newer upstream revision is confirmed, the app asks for consent in Spanish or English. Rejecting does not download anything.
- On consent, the app downloads the archive at the discovered immutable Git commit, displays download (0–80%) and rule validation (80–99%) progress, and activates only rules that pass the bundled engine's syntax test.
- Previously installed rules are preserved on download/validation failures. Starter rules remain local.
- Users can click the button to check again; no Homebrew install is performed.

## Critical limits and release gates

**No executable YARA engine is included in this source ZIP.** The existing release script requires a reviewed universal `YARA_BINARY` (x86_64+arm64), embeds it, signs the nested helper and app, and submits to Apple notarization. Until that is done, rule updates cannot be activated; the app reports the missing engine rather than claiming a successful scan.

The community update channel is **NOT cryptographically signed**. TLS and GitHub commit pinning provide transport protection and reproducibility, but not independent publisher authentication. This is NOT a production-grade trusted update channel. For production, replace with a MacGuard-controlled signed manifest and pinned SHA-256 archive digest verified against an embedded public key.

Rules are capped at 160 candidates per update, 1 MB each, 60 MB compressed, 160 MB expanded; unsupported rules are rejected. The scanner still inspects at most 40 rules and 30 files per audit, with no exhaustive PKG payload inspection. Do not claim full coverage or a malware-free verdict.

## Developer build

```sh
cd DMGTrustAuditor
xcodegen generate
open DMGTrustAuditor.xcodeproj
```

To publish a self-contained app, follow `YARA_INTEGRATION.md` and `Scripts/release-sign-notarize.sh`. This project has not been compiled or tested on macOS in this environment.
