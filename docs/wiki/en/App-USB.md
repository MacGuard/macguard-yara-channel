# MacUSBGuard

[Home](EN-Home) · [Ecosystem](EN-Ecosystem) · [Global roadmap](EN-Roadmap) · [Endpoint Security](EN-Tech-EndpointSecurity) · [DriverKit](EN-Tech-DriverKit)

## In 30 seconds

MacUSBGuard is a Mac program designed to decide which USB devices may work **while the screen is locked**. It treats four families separately: keyboards and mice (HID), storage sticks, USB network adapters and login keys such as YubiKeys. By design a new device starts as "untrusted" and is designed to be fully blocked while the Mac is locked. Today the program only observes: it blocks nothing {{ev:EV-EC-20}}.

**State: validation.** Today the program reports itself as **observe only**, never "active", because the Apple permission needed to block keyboards and mice is not confirmed as usable {{ev:EV-EC-01}} {{ev:EV-EC-02}}. It is not a production-ready security control.

It cannot guarantee: blocking a malicious keyboard today on the test machine, blocking USB network adapters (it only detects them), or protecting against an attacker who reaches an unlocked Mac.

## An everyday example

It is like a building doorman with a tenant list: at night (Mac locked) he is meant to let in only people on the list and only to the rooms meant for them. The analogy does not say the doorman already has the keys to every door: here he still lacks the building administrator's permission (Apple's).

## Diagram

{{diagram:usb-decision-flow-1-locked}}

{{diagram:usb-decision-flow-2-resolver}}

{{diagram:usb-decision-flow-3-deny}}

## Step by step

1. You plug in a device. The program inventories it and computes a SHA-256 fingerprint of its canonical data {{ev:EV-EC-23}}.
2. If the Mac is unlocked, it does not intervene.
3. If locked, a **two-stage** decision is designed: first on the device (untrusted means deny everything) and then on each granted interface; if the identity changes, re-admission is blocked.
4. The decision becomes an Endpoint Security reply (HID) or a mount decision (storage).
5. A global resolver combines each domain's state: it cannot reach "strong" while a required domain only observes.

## Architecture

A Swift package for macOS 13 or later with no external dependencies {{ev:EV-EC-26}}, organized in layers:

- decision logic that makes no system calls;
- platform adapters;
- an interface: an app, a command-line tool and a privileged component, plus an internal test harness.

Trust boundary: the privileged component is separate from the interface and checks who is calling it.

## Under the hood

| Piece | Problem it solves | What it does NOT prevent | Evidence |
|---|---|---|---|
| Two-stage admission decision | Decides device, then interface, while locked | A trusted device that misbehaves | See the [evidence matrix](EN-Evidence) |
| Device fingerprint | SHA-256 fingerprint of a canonical device description | A device that clones every field | See the [evidence matrix](EN-Evidence) |
| Endpoint Security decision engine | Turns a device-open event into allow/deny with a reason; refuses to act without reliable identity | Nothing live: there is no usable permission to run it {{ev:EV-EC-21}} | See the [evidence matrix](EN-Evidence) |
| Overall protection resolver | Honest per-domain overall state | False "greens" from averaging | See the [evidence matrix](EN-Evidence) |
| Storage admission policy | Approves or rejects storage mounts | Whether the system honors the decision: unproven | See the [evidence matrix](EN-Evidence) |
| Key challenge | Cryptographic proof of a key instead of a mere fingerprint | Physical theft of the key and its PIN | See the [evidence matrix](EN-Evidence) |

The code uses Apple system services for devices and disks, inter-process communication, code-signature checks, smart cards and local authentication {{ev:EV-EC-23}}. **Planned or rejected only:** DriverKit (an explored option, not part of the product, see below) and other approaches that were studied and not chosen {{ev:EV-EC-22}}.

## Tests

The figures are self-reported and **this review did not run them**. There is a single in-house test harness with thousands of checks (a static count; loops multiply real runs) {{ev:EV-EC-25}}.

Two sets of self-reported test figures exist and they are not comparable; nothing was re-run {{ev:EV-EC-20}}. Which build is "the" V1 candidate is unresolved in what was reviewed. Documented pending items: HID and storage hardware gates, VoiceOver validation, visual audit and install validation.

## Check it yourself

The code is private, so verification belongs to the owner. Nothing was run to write this page: the data comes from a static read of the project.

## Limits

- On the test machine HID is partial: the restricted Endpoint Security entitlement is not confirmed as usable {{ev:EV-EC-02}}.
- USB network: detection only.
- A local beta installer has notes saying the notarization check passed, but that is a self-declared note: **notarization and publication are not verified** {{ev:EV-EC-24}}. Another report says it was not notarized. The documentation states ad hoc signing.
- No other MacGuard application uses it and it uses none: there are no dependencies between them {{ev:EV-EC-01}}.

## State

| Capability | State |
|---|---|
| Policy engine and resolvers | Implemented, tested by its own harness |
| Storage admission | Implemented; real effect unverified |
| HID blocking via Endpoint Security | Client compiles; live use unverified (no entitlement confirmed as usable) |
| USB network blocking | Not implemented |
| DriverKit | Explored option, not verified, outside the product |
| Installer notarization / publication | Not verified |

Documented next objective: create the V1 candidate; the next workstream is unselected {{ev:EV-EC-01}}.

## Further reading

[Endpoint Security](EN-Tech-EndpointSecurity) · [DriverKit](EN-Tech-DriverKit) · [Code signing](EN-Tech-CodeSigning) · [MacCoreGuard](EN-App-Core) · [Evidence matrix](EN-Evidence)
