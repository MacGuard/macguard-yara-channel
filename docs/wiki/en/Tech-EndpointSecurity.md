# Endpoint Security

[Home](EN-Home) · [Ecosystem](EN-Ecosystem) · [MacUSBGuard](EN-App-USB) · [DriverKit](EN-Tech-DriverKit)

## In 30 seconds

Endpoint Security is an Apple technology that lets a security program **receive notices of what happens on the system** (opening a program, touching a file, using a device) and, in some cases, **answer "yes" or "no" before it happens**. It is like a guard the system asks "may I let this through?". Apple offers it as a documented framework {{ev:EV-EC-35}}; to use it a developer needs a restricted permission (entitlement) that Apple grants case by case, according to MacUSBGuard's README {{ev:EV-EC-21}}.

## In more detail

Events come in two kinds: **notify** (they only inform) and **authorization or AUTH** (the program must answer allow or deny within a deadline; if it does not, the system can act against it). A client is created with `es_new_client`, subscribes to events with `es_subscribe` and answers with `es_respond_auth_result`. This general description comes from the API as used in the project's code; the body of Apple's page could not be read, so it does not rest on it.

## Where this project uses it

Only **MacUSBGuard**, and only like this {{ev:EV-EC-21}}:

- Subscribed event: `ES_EVENT_TYPE_AUTH_IOKIT_OPEN` (someone opens an IOKit device; used to decide on USB keyboards and mice while the Mac is locked).
- Documented implementation: an Endpoint Security event adapter and a separate decision engine. It uses `es_new_client`, `es_subscribe` and `es_respond_auth_result`.
- The build separates the SDK-dependent adapter from the rest of the decision engine.
- A decision without reliable device identity (ES message older than version 10) refuses to act on a guess.

**What is verified and what is not.** It compiles and links against the Xcode 26.3 SDK per the README. **Live enforcement is unverified**: Apple's restricted entitlement is missing (and the system extension and Full Disk Access approvals), so the overall state shows as observe only and the HID hardware checks remain unverified {{ev:EV-EC-02}}. There is also no proof the system delivers all keyboard events to this client (event coverage requires testing on a real system).

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
| ES client with IOKit AUTH events in MacUSBGuard | Compiles; live use unverified (Apple permission missing) |
| Live enforcement of blocks | Not verified |

## Further reading

[MacUSBGuard](EN-App-USB) · [DriverKit](EN-Tech-DriverKit) · [Code signing](EN-Tech-CodeSigning) · [Evidence matrix](EN-Evidence)
