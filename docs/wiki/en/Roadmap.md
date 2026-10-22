# MacGuard global roadmap

[Home](EN-Home) · [Ecosystem](EN-Ecosystem)

## In 30 seconds

Here you see which phase each application is in, what is already done, what blocks it and what comes next. **There are no dates or percentages**: we do not invent them. A phase is "done" only if there is linked evidence; an application is not "50% done" because it has 500 tests.

## Global view

{{diagram:roadmap-global}}

## By application

| Application | Current phase | Done | Blockers | Next |
|---|---|---|---|---|
| YARA Channel | V1.1, phase 2 | Signed and verified channel (V1); V1.1 phase 1 merged {{ev:EV-YC-02}} {{ev:EV-YC-06}} {{ev:EV-YC-07}} | Three changes that alter publication guarantees await a specific acceptance; human validations are missing for the formal V1 sign-off | Deploy and migrate after authorization; test restorations from the three archive providers {{ev:EV-YC-08}} |
| Installer Auditor | Development | Installs rules only if they pass every channel check {{ev:EV-YC-09}} | Neither signed nor notarized; one architecture decision awaits human review | End-to-end performance test with the live channel, planned {{ev:EV-YC-10}} |
| MacUSBGuard | Validation | Tag v1.0.0-rc1 (on a line different from the current branch, see its page); audit reports {{ev:EV-EC-01}} | Apple's Endpoint Security permission is missing {{ev:EV-EC-02}} | V1 candidate; the next workstream is not chosen yet |
| MacFirewallGuard | F2-A (partial) | F1-A, F1-B, GUI-V1 and F2-NIM {{ev:EV-EC-04}} | Apple's Network Extension permission is missing; MacCoreGuard does not exist as a service {{ev:EV-EC-03}} | Complete F2-A |
| MacCoreGuard | Prototype | Protocol and cryptography layer with their own tests {{ev:EV-EC-06}} | Ledger, signing and ingest are placeholders | Work waves defined in its contract, no dates |
| MacGuardDesignKit | Development | Versions 0.1.0 to 0.3.1 {{ev:EV-EC-07}} | Five pending design decisions | 1.0 once two products use it |
| MacProcessGuard | Concept | Nothing beyond the boundary described in other projects {{ev:EV-EC-05}} | No repository or specification exists | Decide whether to start it |

## Dependencies between projects

- Installer Auditor depends on YARA Channel continuing to publish verifiable releases.
- MacFirewallGuard needs MacProcessGuard (process identity) and MacCoreGuard (verifiable evidence) to complete its design.
- MacGuardDesignKit 1.0 depends on two products adopting it.

## Live tracking

Progress is tracked on GitHub with real milestones, issues and releases: [V1.1 milestone](https://github.com/MacGuard/macguard-yara-channel/milestone/2), [triple archive milestone](https://github.com/MacGuard/macguard-yara-channel/milestone/4) and [releases](https://github.com/MacGuard/macguard-yara-channel/releases). This page is updated through changes reviewed by pull request, not automatically.

## What we do not know yet

- Delivery dates: they are not defined or backed.
- The state of the private projects beyond the commits reviewed: each row names its reference commit in the [evidence matrix](EN-Evidence).
