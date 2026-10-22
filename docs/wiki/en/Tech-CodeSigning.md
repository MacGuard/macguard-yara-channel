# Code signing, notarization and Gatekeeper

[Home](EN-Home) · [Ecosystem](EN-Ecosystem) · [Roadmap](EN-Roadmap) · [Installer Auditor](EN-App-InstallerAuditor) · [MacFirewallGuard](EN-App-Firewall) · [Network Extension](EN-Tech-NetworkExtension)

## In 30 seconds

Three pieces that are often confused:

- **Code signing**: the developer puts a digital seal on their app. It says who signed it and lets you tell whether it was altered afterwards.
- **Notarization**: the developer sends the signed app to Apple, which checks it automatically and returns a "ticket". It is an automatic check, **not** a guarantee that there is no malware.
- **Gatekeeper**: the part of macOS that, when you open something downloaded, checks the seal and the notarization and asks for your approval {{ev:EV-EC-78}}.

## An everyday example

The signature is the wax seal on a letter: it says who it came from and whether it was opened. Notarization is the post office running the envelope through a machine before delivery. Gatekeeper is the doorman who looks at both when it reaches your door.

{{diagram:codesigning-chain}}

## How they relate (technical)

The notarization flow this project follows (`SIGNING.md` in Installer Auditor, based on Apple's documentation; Apple's page could not be read in full from here): sign with a **Developer ID Application** certificate, **hardened runtime**, send with `xcrun notarytool`, staple the ticket to the `.app`, and check with Gatekeeper {{ev:EV-EC-68}}. Gatekeeper verifies developer identity, notarization and integrity at first launch, and tracks file provenance {{ev:EV-EC-78}}.

An **ad-hoc** signature (`codesign --sign -`) carries no developer identity: it serves to check local integrity, but not for Gatekeeper to accept a download as notarized.

## Where this project uses it

### Installer Auditor

- **Signing:** its `yara`/`yarac` helpers are signed **ad hoc** with the hardened runtime.
- **Notarization:** the app and helpers are **not notarized**; Developer ID is missing for lack of credentials {{ev:EV-EC-73}}.
- **Reading signatures:** it runs `codesign --verify --strict` on its own helpers before using them {{ev:EV-EC-72}}.

### MacFirewallGuard

- **Reading signatures:** it reads the real signature of processes through Security.framework so as not to trust the name {{ev:EV-EC-63}} {{ev:EV-EC-65}}.
- **Own signing:** there is no signed or notarized build.

### YARA Channel

- Does not sign apps; it signs the rules channel with Sigstore, a different mechanism {{ev:EV-YC-03}}.

### MacProcessGuard

- Nothing: it is a concept {{ev:EV-EC-05}}.

The signing state of MacUSBGuard, MacCoreGuard and MacGuardDesignKit was not reviewed for this page: **not verified**.

## Limits

- A signed and notarized app can be malicious; notarization is not a certification of malware absence (Installer Auditor's own `SIGNING.md` says so).
- A valid signature shows who signed and that it did not change, not that the code is good.
- Notarizing the app does not cover an already packaged `.dmg`: the final DMG must be signed and checked separately (`SIGNING.md`).

## Who else uses it

- **Apple** defines and enforces the mechanism: Gatekeeper on macOS checks identity, notarization and integrity. Same technology. Source: Apple Platform Security guide, "Gatekeeper and runtime protection" {{ev:EV-EC-78}}.
- No other users of this technology are cited: no reliable source naming them was opened.

None of this implies that Apple or anyone else uses MacGuard. What could not be backed by an open source is omitted.
