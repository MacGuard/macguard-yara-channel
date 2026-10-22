# DriverKit

[Home](EN-Home) · [Ecosystem](EN-Ecosystem) · [MacUSBGuard](EN-App-USB) · [Endpoint Security](EN-Tech-EndpointSecurity)

## In 30 seconds

DriverKit is Apple's technology for writing **hardware drivers that run outside the system's core**, as separate programs. If a driver fails, it does not take the whole Mac down. It is like a service desk with its own door: it works with the device but never enters the machine room. Apple documents it as a framework {{ev:EV-EC-36}}; drivers need specific permissions from Apple (the Karabiner project documents this in its README) {{ev:EV-EC-34}}.

## In this project: planned and outside the product

**MacUSBGuard does not use DriverKit in its current code.** Its documentation says DriverKit "is not part of this product"; per the project documentation, such an entitlement is not requested, and the code records it as deliberately unrequested, which a test checks {{ev:EV-EC-22}}.

Even so, driver code exists only on unreleased development lines outside the product, with contract tests. Their documentation describes them as frozen milestones; verification with Apple's entitlement is pending. On the current integration line there is no DriverKit code in the application sources; only comments, the recorded entitlement decision and tests.

| Question | Verified answer |
|---|---|
| In the current product? | No |
| Does code exist? | Yes, only on unreleased development lines |
| Does it work on a real Mac with Apple's permission? | Not verified |
| Is it a deployed defence? | No: only an explored option |

## Limits

- A driver is not a firewall or an antivirus: it only looks at devices.
- Apple's approval does not depend on the code, and is unresolved for this use.
- More recent development lines may exist that this review did not examine.

## Who else uses it

- **Karabiner-DriverKit-VirtualHIDDevice** (open project by pqrs-org) implements a virtual keyboard and mouse with DriverKit, and its README says permissions must be requested from Apple, with approval that can take time. Classification: uses the same technology {{ev:EV-EC-34}}.

No further examples are included because no other official source could be opened. None of this implies those projects use MacGuard.

## State in this project

| Capability | State |
|---|---|
| DriverKit driver for USB | Planned, unreleased development lines only, outside the product |
| DriverKit dependency in the current product | None |

## Further reading

[MacUSBGuard](EN-App-USB) · [Endpoint Security](EN-Tech-EndpointSecurity) · [Evidence matrix](EN-Evidence)
