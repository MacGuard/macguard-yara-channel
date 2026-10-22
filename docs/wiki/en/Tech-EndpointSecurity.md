# Endpoint Security

[Home](EN-Home) · [Ecosystem](EN-Ecosystem) · [MacUSBGuard](EN-App-USB) · [DriverKit](EN-Tech-DriverKit)

## In 30 seconds

Endpoint Security is an Apple feature that tells a security program what happens on the Mac, such as opening a program or using a device {{ev:EV-EC-35}}. In some cases, the program can answer "yes" or "no" before it happens. Using it requires a special permission (entitlement) that Apple grants case by case {{ev:EV-EC-21}}.

## An everyday example

It is like a doorman who, for certain visitors, phones the security office and waits for its answer before opening the door. For other visitors, the doorman only notes who came in (a notify event). If the office does not answer in time, the building acts against it. And only an office holding a credential from management may pick up that line.

## In more detail

Events come in two kinds: **notify** (they only inform) and **authorization or AUTH** (the program must answer allow or deny within a deadline; if it does not, the system can act against it). A client is created with `es_new_client`, subscribes to events with `es_subscribe` and answers with `es_respond_auth_result`. This general description uses Apple's public API names; the body of Apple's page could not be read, so it does not rest on it.

## Where this project uses it

Only **MacUSBGuard** {{ev:EV-EC-21}}:

- MacUSBGuard uses Endpoint Security authorization events for device access (a client that compiles; live use unverified).
- A decision without reliable device identity refuses to act on a guess.

**What is verified and what is not.** It compiles and links against a recent Xcode SDK. **Live enforcement is unverified**: no Apple restricted entitlement is confirmed as usable (nor the system extension and Full Disk Access approvals), so the overall state shows as observe only and the HID hardware checks remain unverified {{ev:EV-EC-02}}. There is also no proof the system delivers all keyboard events to this client (event coverage requires testing on a real system).

No other MacGuard application uses it today; MacFirewallGuard uses the sibling network technology, not covered here.

## Limits

- An AUTH client decides on a specific event: it does not replace a firewall or an antivirus.
- A wrong decision can block a legitimate keyboard (false positive) or let a malicious one through (false negative); that is why the design refuses to deny without reliable identity.

## Who else uses it

Official sources opened for this page; it does not imply any of these companies uses MacGuard.

- **Microsoft Defender for Endpoint on macOS** uses, per its documentation, an "endpoint security extension" (`com.microsoft.wdav.epsext`) plus a network extension, both as Apple system extensions that need approval and Full Disk Access. Classification: uses the same technology (the documentation calls it an endpoint security extension; it does not name the framework) {{ev:EV-EC-33}}.

No further examples are added because no official source for them could be opened.

## State in this project

| Capability | State |
|---|---|
| ES client with authorization events in MacUSBGuard | Compiles; live use unverified (no entitlement confirmed as usable) |
| Live enforcement of blocks | Not verified |

## Further reading

[MacUSBGuard](EN-App-USB) · [DriverKit](EN-Tech-DriverKit) · [Code signing](EN-Tech-CodeSigning) · [Evidence matrix](EN-Evidence)
