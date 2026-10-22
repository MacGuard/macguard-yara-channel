# Network Extension

[Home](EN-Home) · [Ecosystem](EN-Ecosystem) · [Roadmap](EN-Roadmap) · [MacFirewallGuard](EN-App-Firewall) · [Code signing and notarization](EN-Tech-CodeSigning)

## In 30 seconds

Network Extension is Apple's framework that lets a program **see and control the network traffic of other apps** on the Mac (filter connections, proxy DNS, create a VPN). Apple does not let just anyone use it: a **special permission (entitlement)** granted to the developer account is needed. Without it, a program cannot block other apps' connections.

## An everyday example

It is a guard post at a building's exit. Only someone holding a credential issued by the management may stand there and watch who leaves. A neighbour can note who leaves from their window (half-observing), but cannot close the barrier.

{{diagram:networkext-gap}}

## How it works (technical)

In MacFirewallGuard's design, real blocking would go through a **socket content filter** (`NEFilterDataProvider`) inside a **system extension**. The project documents also mention a DNS proxy (`NEDNSProxyProvider`) and a transparent proxy (`NETransparentProxyProvider`) as alternatives, none implemented {{ev:EV-EC-60}}. The permissions the project lists as needed are `com.apple.developer.networking.networkextension` (with the content-filter value as a system extension), which is the one that is **missing**, and `com.apple.developer.system-extension.install`, which its decision document records as granted {{ev:EV-EC-60}}.

Apple's official Network Extension documentation could not be read in its body from this tool; what is described here about permissions comes from the project documents, not from an Apple quotation {{ev:EV-EC-81}}.

## Where this project uses it

| App | Use verified in code |
|---|---|
| MacFirewallGuard | Only `NetworkExtension` types (`NEFilterSocketFlow`) as a **translation bridge** (`NEFilterSocketFlowBridge.swift`, `FilterFlowTranslation.swift`). **No** system extension or running provider exists; there are no entitlement files in the main tree {{ev:EV-EC-63}} |
| The others | They do not use Network Extension; Installer Auditor does not import NetworkExtension in its code |

The project classifies its situation as "the entitlement is absent and can be requested" (entitlement decision document). **Not verified** whether the request was already filed or answered {{ev:EV-EC-60}}.

## Limits

- Without the entitlement, no BLOCK decision is applied: it ends as `UNAVAILABLE(ENTITLEMENT_MISSING)` {{ev:EV-EC-60}}.
- Enabling this product's filter may disable other active content filters; coexistence is a documented, unresolved blocker {{ev:EV-EC-60}}.
- A network filter does not replace process identity or installer review.

## Who else uses it

- **LuLu** (Objective-See), an open-source firewall that "blocks unknown outgoing connections"; its page says some traffic may not go through Network Extensions "such as LuLu" and explains approving its filter in System Settings. It uses the same technology MacFirewallGuard aims to use {{ev:EV-EC-79}}.

No other application is cited: a second page consulted (a commercial firewall) did not mention the mechanism. This does not imply that LuLu uses MacGuard.
