# DriverKit

[Home](EN-Home) · [Ecosystem](EN-Ecosystem) · [MacUSBGuard](EN-App-USB) · [Endpoint Security](EN-Tech-EndpointSecurity)

## In 30 seconds

DriverKit is Apple's technology for writing **hardware drivers that run outside the system's core**, as separate programs. If a driver fails, it does not take the whole Mac down. It is like a service desk with its own door: it works with the device but never enters the machine room. Apple documents it as a framework {{ev:EV-EC-36}}; drivers need specific permissions from Apple (the Karabiner project documents this in its README) {{ev:EV-EC-34}}.

## In this project: planned and branch-only

**MacUSBGuard does not use DriverKit in its current code.** Its README says DriverKit "is not part of this product" because, per the project documentation, Apple would not grant a USB permission of that scope for this purpose; the code records it as a "deliberately unrequested" entitlement and a test checks that {{ev:EV-EC-22}}.

Even so, **separate branches** exist (`ai/dk2-driverkit-v1` and derivatives: DK2.2-B, C1, C2) with driver files (`Driver/MacUSBGuardDriver.iig`, `.cpp`, a narrow user client) and contract tests. Its documentation describes them as frozen milestones whose verification with the real Apple entitlement "remains external". On the current branch (`ai/v1-release-integration`, 78f7d37) there is no DriverKit symbol in `Sources`; only comments, the recorded entitlement and tests.

| Question | Verified answer |
|---|---|
| In the current product? | No |
| Does code exist? | Yes, on branches only |
| Does it work on a real Mac with Apple's permission? | Not verified |
| Is it a deployed defence? | No: only an explored option |

## Limits

- A driver is not a firewall or an antivirus: it only looks at devices.
- Apple's approval does not depend on the code, and is unresolved for this use.
- More recent branches may exist that this review did not examine; only the listed local branches were reviewed.

## Who else uses it

- **Karabiner-DriverKit-VirtualHIDDevice** (open project by pqrs-org) implements a virtual keyboard and mouse with DriverKit, and its README says permissions must be requested from Apple, with approval that can take time. Classification: uses the same technology {{ev:EV-EC-34}}.

No further examples are included because no other official source could be opened. None of this implies those projects use MacGuard.

## State in this project

| Capability | State |
|---|---|
| DriverKit driver for USB | Planned / branch-only, outside the product |
| DriverKit dependency in the current product | None |

## Further reading

[MacUSBGuard](EN-App-USB) · [Endpoint Security](EN-Tech-EndpointSecurity) · [Evidence matrix](EN-Evidence)
