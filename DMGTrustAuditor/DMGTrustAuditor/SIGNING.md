# Release signing and notarization (Intel / Apple Silicon)

The source package is **not signed or notarized**. Only you can perform release signing using your Apple Developer team and private signing identity.

1. Register a unique Bundle ID in your Apple Developer team (e.g. `com.yourcompany.dmgtrustauditor`). Do not use the provisional `com.macguard.dmgtrustauditor` unless your team owns it.
2. Install your **Developer ID Application** certificate and its private key in your macOS Keychain. `security find-identity -v -p codesigning` lists available identities. Never upload the private key or a `.p12` to this chat.
3. Configure a notarytool Keychain profile following Apple's official docs: `xcrun notarytool store-credentials PROFILE_NAME --apple-id ... --team-id ... --password ...` (app-specific password), or supported App Store Connect API key authentication. Keep secrets out of the repository and command history.
4. From `DMGTrustAuditor`, run:

```sh
TEAM_ID='YOUR_REAL_TEAM_ID' \
BUNDLE_ID='com.yourcompany.dmgtrustauditor' \
SIGNING_IDENTITY='Developer ID Application: Your Legal Name (YOUR_REAL_TEAM_ID)' \
NOTARY_PROFILE='your-keychain-profile' \
./Scripts/release-sign-notarize.sh
```

The script builds a Release `.app`, verifies its signature, notarizes a ZIP, staples the ticket to the `.app`, and checks Gatekeeper. It does **not** create a distributable DMG; if packaging one, sign/notarize and verify the **final DMG separately**. The script has not been tested on macOS here.

**Architecture:** This build targets the local host by default. Build and verify x86_64 and arm64 slices separately or configure `ARCHS`/`ONLY_ACTIVE_ARCH=NO` with appropriate toolchains, and test both on real machines.

**Hardened Runtime:** Enabled through `ENABLE_HARDENED_RUNTIME=YES`; review entitlements and sandboxing before distribution. Do not enable unnecessary entitlements or disable library validation casually. Debug signing and production Developer ID signing are different workflows.

**Important:** Notarization is not a malware-free certification. Never sign unreviewed code or include untrusted files in the release bundle.
