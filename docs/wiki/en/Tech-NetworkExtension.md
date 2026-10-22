# Network Extension

[Home](EN-Home) · [Ecosystem](EN-Ecosystem) · [Roadmap](EN-Roadmap) · [MacFirewallGuard](EN-App-Firewall) · [Code signing and notarization](EN-Tech-CodeSigning)

## In 30 seconds

Network Extension is Apple's framework that lets a program see and filter the network connections of other apps on the Mac. Apple requires a special permission (entitlement) tied to the developer account. Without that permission, a program cannot block other apps' connections.

## An everyday example

It is a guard post at a building's exit, where someone decides who may leave (the network filter). Only someone holding a credential issued by the management (Apple's permission) may stand there. A neighbor can note who leaves from their window, that is, half-observe, but cannot close the barrier or stop an exit.

{{diagram:networkext-gap}}

## How it works (technical)

In MacFirewallGuard's design, real blocking would go through a **socket content filter** (`NEFilterDataProvider`) inside a **system extension**. The project documents also mention a DNS proxy (`NEDNSProxyProvider`) and a transparent proxy (`NETransparentProxyProvider`) as alternatives, none implemented {{ev:EV-EC-60}}. The planned implementation depends on the appropriate Network Extension entitlement, whose operational availability has not been established. Required authorization and configuration must be verified before claiming live blocking {{ev:EV-EC-60}}.

Apple's official Network Extension documentation could not be read in its body from this tool; what is described here about permissions comes from the project documents, not from an Apple quotation {{ev:EV-EC-81}}.

## Where this project uses it

### MacFirewallGuard

- **Use verified in code:** only data types for translating flows.
- **No** system extension or running provider exists.
- Operational authorization (the entitlement) has not been demonstrated {{ev:EV-EC-63}}.

### The other applications

- **Use verified in code:** none. They do not use Network Extension; Installer Auditor does not import NetworkExtension in its code.

No entitlement is confirmed as usable for this project. **Not verified** whether one was requested or what the answer was {{ev:EV-EC-60}}.

## Limits

- Without a usable entitlement, no block decision is applied: it ends as "action unavailable: entitlement missing" {{ev:EV-EC-60}}.
- Enabling this product's filter may disable other active content filters; coexistence is a documented, unresolved blocker {{ev:EV-EC-60}}.
- A network filter does not replace process identity or installer review.

## Who else uses it

- **LuLu** (Objective-See), an open-source firewall that "blocks unknown outgoing connections"; its page says some traffic may not go through Network Extensions "such as LuLu" and explains approving its filter in System Settings. It uses the same technology MacFirewallGuard aims to use {{ev:EV-EC-79}}.

No other application is cited: a second page consulted (a commercial firewall) did not mention the mechanism. This does not imply that LuLu uses MacGuard.
