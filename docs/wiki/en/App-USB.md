# MacUSBGuard

[Home](EN-Home) · [Ecosystem](EN-Ecosystem) · [Global roadmap](EN-Roadmap) · [Endpoint Security](EN-Tech-EndpointSecurity) · [DriverKit](EN-Tech-DriverKit)

## In 30 seconds

MacUSBGuard is a Mac program that decides which USB devices may work **while the screen is locked**. It treats four families separately: keyboards and mice (HID), storage sticks, USB network adapters and login keys such as YubiKeys. By design a new device starts as "untrusted" and would be fully blocked while the Mac is locked. Today the program only observes: it blocks nothing {{ev:EV-EC-20}}.

**State: validation.** Today the program reports itself as **observe only** (OBSERVE ONLY), never "active", because the Apple permission needed to block keyboards and mice is missing {{ev:EV-EC-01}} {{ev:EV-EC-02}}. It is not a production-ready security control.

It cannot guarantee: blocking a malicious keyboard today on the test machine, blocking USB network adapters (it only detects them), or protecting against an attacker who reaches an unlocked Mac.

## An everyday example

It is like a building doorman with a tenant list: at night (Mac locked) he lets in only people on the list and only to the rooms meant for them. The analogy does not say the doorman already has the keys to every door: here he still lacks the building administrator's permission (Apple's).

## Diagram

{{diagram:usb-decision-flow}}

## Step by step

1. You plug in a device. The program inventories it (IOKit) and computes a SHA-256 fingerprint of its canonical data {{ev:EV-EC-23}}.
2. If the Mac is unlocked, it does not intervene.
3. If locked, a **two-stage** resolver decides first on the device (untrusted means deny everything) and then on each granted interface; if the identity changes, re-admission is blocked.
4. The decision becomes an Endpoint Security reply (HID) or a mount dissent (storage).
5. A global resolver combines each domain's state: it cannot reach "strong" while a required domain only observes.

## Architecture

SwiftPM package (Swift 6, macOS 13 or later), no external dependencies {{ev:EV-EC-26}}:

- `MacUSBGuardCore`: pure policy and model, no IOKit or Endpoint Security.
- `MacUSBGuardStoragePlatform`: DiskArbitration and IOKit inventory.
- `MacUSBGuardPlatform`: session, PIV smart cards and Endpoint Security.
- `MacUSBGuardPolicyDaemon`: privileged daemon; depends only on Core and StoragePlatform, so it **cannot reach** Endpoint Security or the UI (enforced by the dependency graph).
- `macusbguardctl` (command line), `MacUSBGuardApp` (SwiftUI) and `macusbguard-tests` (test harness).

Trust boundary: the app and CLI talk to the daemon over XPC and the daemon verifies the caller's code signature.

## Under the hood

| Piece | Problem it solves | What it does NOT prevent | Evidence |
|---|---|---|---|
| `TwoStageAdmissionResolver` | Decides device, then interface, while locked | A trusted device that misbehaves | `Core/TwoStageAdmissionResolver.swift` |
| `DeviceFingerprint` | SHA-256 fingerprint of a canonical device string | A device that clones every field | `Core/DeviceFingerprint.swift` |
| `EndpointSecurityDecisionEngine` | Turns an `AUTH_IOKIT_OPEN` event into allow/deny with a reason; refuses to act without reliable identity | Nothing live: there is no permission to run it {{ev:EV-EC-21}} | `Core/EndpointSecurityDecisionEngine.swift` |
| `OverallProtectionResolver` | Honest per-domain overall state | False "greens" from averaging | `Core/OverallProtectionResolver.swift` |
| `StorageAdmissionPolicy` | Approves or rejects mounts via DiskArbitration | Whether `diskarbitrationd` honours the dissent: unproven | `Core/StorageAdmission.swift` |
| PIV challenge | Cryptographic proof of a key (signed nonce) instead of a mere fingerprint | Physical theft of the key and its PIN | `Platform/SmartCardAuthenticationService.swift` |

Technologies proven in code: Endpoint Security, DiskArbitration, IOKit, XPC, Security.framework, CryptoTokenKit, LocalAuthentication, SMAppService {{ev:EV-EC-23}}. **Planned or rejected only:** DriverKit (branches only, see below), NetworkExtension (studied and rejected because it would disable other content filters), CGEventTap (documented as not chosen) {{ev:EV-EC-22}}.

## Tests

The figures are self-reported and **this review did not run them**. There is a single in-house harness (`macusbguard-tests`, 63 files) with about 2,929 literal `check(` occurrences (static count; loops multiply real runs) {{ev:EV-EC-25}}.

There are two **diverging** lines of development and their figures are neither added nor compared:

| Line | Declared figure | Source |
|---|---|---|
| Tag `v1.0.0-rc1` (c2f9492) | 10,862 verifications, 0 failures | the tag's readiness report |
| Current branch `ai/v1-release-integration` (78f7d37) | 816 checks, 0 failures, 8 unverified | the branch README (predates later work) |

The tag is **not an ancestor** of the current branch {{ev:EV-EC-20}}. Which one is "the" V1 candidate is unresolved in what was reviewed. Documented pending items: HID and storage hardware gates, VoiceOver validation, visual audit and install validation.

## Check it yourself

The code is private, so verification belongs to the owner. Commands cited in its README: `./build.sh hardware-preflight`, `./scripts/storage-hardware-gate` and `macusbguardctl es-status`. They were not run for this wiki.

## Limits

- On the test machine HID is partial: the restricted Endpoint Security entitlement is missing {{ev:EV-EC-02}}.
- USB network: detection only.
- A local `0.9.0-beta` DMG has notes saying "Notarization: PASS", but that is a self-declared note in an untracked folder: **notarization and publication are not verified** {{ev:EV-EC-24}}. The rc1 tag report says `NOT_NOTARIZED` the same day. The README states ad hoc signing.
- No other MacGuard application uses it and it uses none: there are no dependencies between them {{ev:EV-EC-01}}.

## State

| Capability | State |
|---|---|
| Policy engine and resolvers | Implemented, tested by its own harness |
| Storage admission | Implemented; real effect unverified |
| HID blocking via Endpoint Security | Compiles; live use unverified (permission missing) |
| USB network blocking | Not implemented |
| DriverKit | Planned/branch-only, outside the product |
| DMG notarization / publication | Not verified |

Documented next objective: create the V1 candidate; the next workstream is unselected {{ev:EV-EC-01}}.

## Further reading

[Endpoint Security](EN-Tech-EndpointSecurity) · [DriverKit](EN-Tech-DriverKit) · [Code signing](EN-Tech-CodeSigning) · [MacCoreGuard](EN-App-Core) · [Evidence matrix](EN-Evidence)
