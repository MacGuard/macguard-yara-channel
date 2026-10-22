# MacFirewallGuard

[Home](EN-Home) · [Ecosystem](EN-Ecosystem) · [Roadmap](EN-Roadmap) · [Network Extension](EN-Tech-NetworkExtension) · [Code signing and notarization](EN-Tech-CodeSigning) · [MacProcessGuard](EN-App-Process)

## In 30 seconds

MacFirewallGuard is a macOS program designed to **observe which apps connect to the network and, later, apply rules** to those connections. Its central idea: an app can call itself "Safari" without being Safari, so the program reads the **real code signature** of processes instead of trusting the name. If evidence is missing, the engine answers "indeterminate" and does not treat it as "allowed" (the final action under a real policy is not yet tested).

**There is no real blocking today**: no Network Extension entitlement is confirmed as usable for this project {{ev:EV-EC-60}}. It is an observation and policy engine, in **development** {{ev:EV-EC-03}}. It is not a working firewall and must not be relied on as protection.

## An everyday example

Think of a doorman with a guest list who checks your ID card, not the visitor's word. The doorman already knows how to read IDs and apply the list, but has no key to lock the door yet: if the list says "no entry", all he can do is write down "I have no key".

## Diagram

{{diagram:firewall-decision}}

## Step by step

1. An observed network flow comes in (today from synthetic or test input: no real packet was ever captured {{ev:EV-EC-64}}).
2. A signature resolver finds out the real code signature of the process.
3. The policy engine evaluates the rules: match, no match or **indeterminate** when evidence is missing.
4. An enforcement step turns the decision into an action. Without a usable entitlement, a block decision ends as "action unavailable: entitlement missing" {{ev:EV-EC-60}}.
5. An audit event is created and kept in a local queue; sending it to MacCoreGuard has only been tested against a test double {{ev:EV-EC-04}}.

## Under the hood

Layered architecture {{ev:EV-EC-63}}:

| Layer | Role |
|---|---|
| Domain logic | Pure logic: flows, policy, DNS, correlation, network, audit events and a local queue |
| Platform adapters | The only layer that talks to Apple frameworks |
| Interface | A SwiftUI app (uses the shared MacGuardDesignKit library) and a read-only command-line tool |

Algorithms with code behind them (problem, evidence):

- **Policy evaluation**: decides with three values (match / no match / indeterminate). Avoids treating "no data" as "allowed".
- **Signature resolution**: resolves the signing identity from an audit token, a pid or a path. It is not meant to detect code injection: that is assigned to MacProcessGuard, which is a concept only.
- **DNS, TLS and QUIC readers**: read DNS, the TLS server name and QUIC initial packets. Only tested with test bytes.
- **Network integrity rules**: detect VPN, route or DNS changes; observe and alert modes only.
- Optional **packet-capture sensor**: on the development machine access was denied for lack of permissions {{ev:EV-EC-64}}.

### Channel to MacCoreGuard

The architecture documentation describes an authenticated channel as the target design on the MacCore side. **The client uses a simpler local channel than the target design; the production sources do not contain the target implementation** {{ev:EV-EC-61}}. The client and its checks are exercised only against a test double.

## Check it yourself

The repository is private, so there are no public commands to run. Nothing was run to write this page: the data comes from a static read of the project.

## Tests: which numbers exist and where they come from

The README's test figure is **stale** {{ev:EV-EC-62}}. The project's own documents report figures from hundreds to a little over a thousand deterministic checks across successive phases, none re-measured for this review, and an independent suite for the network-integrity module that passes in full by its own report.

Pending per its own closeout: no real packet capture, no thread-sanitizer run, no coverage-guided fuzzing, no performance benchmarks {{ev:EV-EC-64}}. The README also claims no external dependencies, which is no longer true (it uses MacGuardDesignKit).

## Limits

- It neither blocks nor observes real traffic today {{ev:EV-EC-60}}.
- There is no signed or notarized build, and the project itself does not declare itself production-ready {{ev:EV-EC-65}}.
- Coexisting with other content filters already installed is a documented, unresolved blocker.
- It does not replace MacProcessGuard (process identity) or MacCoreGuard (verifiable record): neither exists as a service {{ev:EV-EC-05}}.

## State

| Capability | State |
|---|---|
| Policy engine, flow model, signature resolution, SwiftUI app, command line | Implemented, not deployed |
| MacCoreGuard client (simple local channel) | Implemented, tested only against a test double |
| Real observation and blocking (system extension) | Planned, no entitlement confirmed as usable |
| Endpoint Security, packet tap, Rust | Planned or outside this repository; no code |

Early foundation and interface phases are closed; a later phase is partial; the network-integrity module is merged {{ev:EV-EC-04}}. No dates. More: [Network Extension](EN-Tech-NetworkExtension), [Code signing](EN-Tech-CodeSigning).
