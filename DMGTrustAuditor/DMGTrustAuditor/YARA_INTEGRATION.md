# Bundled YARA engine — v7

The app no longer looks for Homebrew or system YARA. Runtime scanning requires `Contents/Helpers/yara` and validates its code signature before invoking it. A missing engine yields **not scanned**, never a clean result.

## Release prerequisites

The repository does not include a third-party executable. Before shipping, a release engineer must obtain YARA from its upstream source, review its dependencies/license, build both macOS architectures, test and combine with `lipo`, and provide `YARA_BINARY` to `Scripts/release-sign-notarize.sh`. The script refuses a missing architecture, bundles and signs the helper, signs the parent, and submits for Apple notarization. No user Homebrew installation is needed in the finished release.

Example after producing and reviewing a universal YARA executable:

```bash
export TEAM_ID='YOUR_REAL_TEAM_ID'
export BUNDLE_ID='YOUR_REGISTERED_BUNDLE_ID'
export SIGNING_IDENTITY='Developer ID Application: YOUR COMPANY (YOUR_TEAM_ID)'
export NOTARY_PROFILE='YOUR_KEYCHAIN_PROFILE'
export YARA_BINARY='/absolute/path/to/reviewed/universal/yara'
bash Scripts/release-sign-notarize.sh
```

## Update safety — IMPORTANT

The inherited v6 community rule updater downloads a mutable branch archive without a pinned digest or verified publisher signature. It MUST NOT be treated as a trusted security update channel. Before production distribution, replace it with a signed, versioned manifest, pinned rule archive digest, compilation validation, atomic activation and rollback. The existing rules update UI is experimental. The existing scanner limits its coverage to 40 rules and 30 files and does not fully extract PKG payloads. Do not claim comprehensive malware detection.

The built-in starter rules are heuristic only. No compiled or universal YARA engine binary is included in this source ZIP. macOS compilation and notarization have not been run in this environment.
