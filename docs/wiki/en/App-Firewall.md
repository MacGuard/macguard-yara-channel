# MacFirewallGuard

[Home](EN-Home) · [Ecosystem](EN-Ecosystem) · [Roadmap](EN-Roadmap) · [Network Extension](EN-Tech-NetworkExtension) · [Code signing and notarization](EN-Tech-CodeSigning) · [MacProcessGuard](EN-App-Process)

## In 30 seconds

MacFirewallGuard is a macOS program designed to **observe which apps connect to the network and, later, apply rules** to those connections. Its central idea: an app can call itself "Safari" without being Safari, so the program looks at the **real code signature** and does not trust the name. If evidence is missing, the answer is "I don't know", never "allowed".

**Today it cannot block anything**: Apple has not granted this project the Network Extension entitlement {{ev:EV-EC-60}}. It is an observation and policy engine, in **development** {{ev:EV-EC-03}}. It is not a working firewall and must not be relied on as protection.

## An everyday example

Think of a doorman with a guest list who checks your ID card, not the visitor's word. The doorman already knows how to read IDs and apply the list, but has no key to lock the door yet: if the list says "no entry", all he can do is write down "I have no key".

## Diagram

{{diagram:firewall-decision}}

## Step by step

1. An observed network flow comes in (today from synthetic or test input: no real packet was ever captured {{ev:EV-EC-64}}).
2. `CodeSignatureResolver` finds out the real signature of the process.
3. `PolicyEngine` evaluates the rules: match, no match or **indeterminate** when evidence is missing.
4. `EnforcementResolver` turns the decision into an action. Without the entitlement, a BLOCK ends as `ACTION=UNAVAILABLE(ENTITLEMENT_MISSING)` {{ev:EV-EC-60}}.
5. An audit event is created and kept in a local spool; sending it to MacCoreGuard has only been tested against a mock {{ev:EV-EC-04}}.

## Under the hood

Layered architecture (from `Package.swift`) {{ev:EV-EC-63}}:

| Layer | Role |
|---|---|
| `MacFirewallGuardCore` | Pure domain (flows, policy, DNS, correlation, network) |
| `MacFirewallGuardAudit` | Canonical events and durable spool (`DurableAuditSpool`) |
| `MacFirewallGuardPlatform` | The only layer touching Apple frameworks (Security, Network, SystemConfiguration, NetworkExtension as a translation bridge) |
| `CBPFShim` | Small C module with BPF constants |
| `MacFirewallGuardUI` and `MacFirewallGuardApp` | SwiftUI app (uses MacGuardDesignKit, the only external dependency) |
| `macfirewallguardctl` | Read-only CLI: `capabilities`, `privileges`, `events`, `adversarial`, `preflight`, `explain` |

Algorithms with code behind them (name, problem, evidence):

- **`PolicyEngine.evaluate`**: decides with three values (match / no match / indeterminate). Avoids treating "no data" as "allowed". File `Sources/MacFirewallGuardCore/Policy/PolicyEngine.swift`.
- **`CodeSignatureResolver`**: resolves the signing identity from an audit token, a pid or a path (`Platform/CodeSignatureResolver.swift`). It does not detect code injection: its threat model assigns that to MacProcessGuard, which does not exist.
- **`DNSWireParser` and `TLSClientHelloParser`** (Core) and **`QUICInitialPacketParser`** (Platform): read DNS, TLS SNI and QUIC. Only tested with test bytes.
- **`NetworkIntegrityRuleEngine`** (F2-NIM): detects VPN, route or DNS changes; observe and alert modes only.
- Optional **BPF sensor** (`BPFDevice`, `BPFCaptureSensor`): on the development machine access was denied for lack of permissions {{ev:EV-EC-64}}.

### Transport to MacCoreGuard: XPC or socket

The architecture documents and the capability matrix speak of "authenticated XPC" as the target design on the MacCore side. **The client code uses a Unix socket** (`AF_UNIX`, `SOCK_STREAM`, length-prefixed JSON messages) in `Platform/MacCoreGuardIPCClient.swift`; a comment in `MacCoreAuditClient.swift` says the transport "is NSXPC" as a future intention, but there is no XPC implementation in the production sources {{ev:EV-EC-61}}. The client checks, using the kernel credential (`LOCAL_PEERPID`), the signature of the process at the other end of the socket. That check and the server are exercised only with a test-only mock server.

## Check it yourself

The repository is private, so there are no public commands. In a copy with access: `swift run macfirewallguardctl explain` and `swift run macfirewallguardctl preflight` (both exist in the README). Nothing was run to write this page: the data is a static read of commit `052007e`.

## Tests: which numbers exist and where they come from

The README says "661 deterministic + 10 live checks", but it is **stale** (header "FOUNDATION_V1") {{ev:EV-EC-62}}. Figures per document, none re-measured:

| Figure | Comes from |
|---|---|
| 661 deterministic | `docs/testing/TESTING_V1.md` and README (phase F1-A) |
| 1038 deterministic | total pinned in the `verify` harness (`EXPECTED_DETERMINISTIC_TOTAL`) |
| 1160 passed (1043 + 70 + 47) | `docs/release/F2A_CLOSEOUT.md` |
| 78/78 | `docs/architecture/F2_NIM_ARCHITECTURE.md`, suite `macfirewallguard-nim-tests` |

Pending per its own closeout: no real packet capture, no TSan run, no coverage-guided fuzzing, no performance benchmarks {{ev:EV-EC-64}}. The README also says "zero external dependencies", which is no longer true (it uses MacGuardDesignKit).

## Limits

- It neither blocks nor observes real traffic today {{ev:EV-EC-60}}.
- There is no signed or notarized build, and `FIREWALL_PRODUCTION_READY = NO` {{ev:EV-EC-65}}.
- Coexisting with other content filters already installed is a documented, unresolved blocker.
- It does not replace MacProcessGuard (process identity) or MacCoreGuard (verifiable record): neither exists as a service {{ev:EV-EC-05}}.

## State

| Capability | State |
|---|---|
| Policy engine, flow model, signature resolution, SwiftUI app, CLI | Implemented, not deployed |
| MacCoreGuard client (Unix socket) | Implemented, tested only with a mock |
| Real observation and blocking (system extension) | Planned, blocked by Apple's entitlement |
| Endpoint Security, PKTAP, Rust | Planned or outside this repository; no code |

Phases: F1-A, F1-B and GUI-V1 closed; F2-A partial (`F2A_COMPLETE = NO`); F2-NIM merged {{ev:EV-EC-04}}. No dates. More: [Network Extension](EN-Tech-NetworkExtension), [Code signing](EN-Tech-CodeSigning).
