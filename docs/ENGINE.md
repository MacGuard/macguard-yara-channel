# The YARA engine that ships with MacGuard

`Scripts/build-yara-engine.sh` builds YARA 4.5.8 from the pinned source tarball (SHA-256 checked) as a universal binary (arm64 + x86_64, minimum macOS 13.0) with a static OpenSSL 3.5.9 (also pinned) so the `hash` and `pe` modules work. The `magic`, `cuckoo` and `dex` modules are off: they need external libraries. The result is ad-hoc signed with the hardened runtime and described by `engine-manifest.json` (versions, source hashes, architectures, SHA-256 of both binaries).

## What the app checks before it uses the engine (`Core/YARAEngine.swift`)
`yara`, `yarac` and `engine-manifest.json` present → both binaries equal the manifest hashes → `codesign --verify --strict` → version ≥ 4.5.0 and equal to the manifest → the binary has the CPU architecture we run on → self-test (compile a canary rule, scan a canary file and a clean file). There is no PATH or Homebrew fallback. A missing engine is reported `UNAVAILABLE`; a damaged one fails the audit (`failed`), it never degrades to "clean".

## Where it lives
App: `Contents/Helpers/`. CLI/TUI: beside `macguard-audit` (or `engine/`, `../libexec/macguard`). Developer override: `MACGUARD_YARA_DIR` (same checks). The Xcode targets copy `build/engine` (or `$ENGINE_DIR`) into place after the build.

## How rules are loaded
One namespace per rule file with copies of the files it depends on (`depends_on` is part of the signed manifest). Upstream sources define the same rule name in hundreds of files, so a single namespace cannot work. If some files do not compile with this engine (about 8 of 1,184 today) they are named in the audit and left out; scanning continues. The compiled set is cached by rules root and engine version.

## Not done: Developer ID signing and notarization
The engine is **ad-hoc signed**. Developer ID signing and notarization need an Apple Developer account, a Developer ID Application certificate and notarytool credentials; none is configured. Until then Gatekeeper treats a downloaded build as unnotarized. Steps once credentials exist: sign `yara`, `yarac` and the app with the Developer ID identity and `--options runtime --timestamp`, notarize the app, staple. The app's own verification keeps working unchanged (it checks hashes and a valid signature).

## Tested where
Local (Intel Mac): 19 tests in `YARAEngineTests` with the real universal engine (x86_64 slice executed, arm64 slice present and signed). CI (macOS arm64 runner): see `build-engine.yml` and `app-tests.yml`.
