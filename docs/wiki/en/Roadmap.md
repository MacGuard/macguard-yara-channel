# MacGuard global roadmap

[Home](EN-Home) · [Ecosystem](EN-Ecosystem)

## In 30 seconds

Here you see which phase each application is in, what is already done, what blocks it and what comes next. **There are no dates or percentages**: we do not invent them. A phase is "done" only if there is linked evidence; an application is not "50% done" because it has 500 tests.

## An everyday example

It is like a building-site board: it shows which floor is finished, which is stalled and why. It does not promise an opening date.

## Global view

{{diagram:roadmap-global-1-yara-channel}}

{{diagram:roadmap-global-2-firewall}}

{{diagram:roadmap-global-3-usb}}

{{diagram:roadmap-global-4-others}}

{{diagram:intelligence-roadmap}}

## By application

Stages used: concept, prototype, development, validation, release candidate and published. Each application is placed in the one its evidence supports.

### YARA Channel

- **Phase:** V1 published; V1.1, phase 2, in development.
- **Done:** signed and verified channel (V1); V1.1 phase 1 merged {{ev:EV-YC-02}} {{ev:EV-YC-06}} {{ev:EV-YC-07}}.
- **Implemented in the repository, not yet deployed:** persistent withdrawals, policies, source proposals; archive not operational.
- **Blockers:** changes that alter publication guarantees await a specific acceptance; human validations are missing for the formal V1 sign-off.
- **Next:** deploy and migrate after authorization; test restorations from the three archive providers {{ev:EV-YC-08}}.

### Installer Auditor

- **Phase:** development.
- **Done:** installs rules only if they pass every channel check {{ev:EV-YC-09}}.
- **Blockers:** neither signed nor notarized; one architecture decision awaits human review.
- **Next:** end-to-end performance test with the live channel, planned {{ev:EV-YC-10}}.

### MacUSBGuard

- **Phase:** validation (a release candidate has been prepared).
- **Done:** a prepared release candidate and audit reports {{ev:EV-EC-01}}.
- **Blockers:** no Endpoint Security entitlement is confirmed as usable {{ev:EV-EC-02}}.
- **Next:** V1 candidate; the next workstream is not chosen yet.

### MacFirewallGuard

- **Phase:** development (a later phase is partial).
- **Done:** the early phases and the network-integrity module {{ev:EV-EC-04}}.
- **Blockers:** no Network Extension entitlement is confirmed as usable; MacCoreGuard does not exist as a service {{ev:EV-EC-03}}.
- **Next:** complete the partial phase.

### MacCoreGuard

- **Phase:** prototype.
- **Done:** protocol and cryptography layer with their own tests {{ev:EV-EC-06}}.
- **Blockers:** ledger, signing and ingest are placeholders.
- **Next:** planned work, no dates.

### MacGuardDesignKit

- **Phase:** development.
- **Done:** several pre-1.0 versions {{ev:EV-EC-07}}.
- **Blockers:** pending design decisions.
- **Next:** 1.0 once two products use it.

### MacProcessGuard

- **Phase:** concept (no repository, no specification).
- **Done:** nothing beyond the boundary described in other projects {{ev:EV-EC-05}}.
- **Blockers:** no repository or specification exists.
- **Next:** decide whether to start it.

### Security Intelligence

- **Phase:** development (implemented in the repository, not deployed).
- **Done:** real sources downloaded and validated, an alerts engine with filters, feeds, e-mail, webhooks, organisations and roles, and a bilingual web section, all with tests {{ev:EV-SI-02}} {{ev:EV-SI-03}} {{ev:EV-SI-07}}.
- **Blockers:** the owner has not confirmed the reuse of any third-party vulnerability source, ENISA's reuse terms were not found, and there is no signing workflow, hosted service, mail relay or identity provider {{ev:EV-SI-01}}.
- **Next:** owner decisions on licences and signing; then publish the cleared channels. Correlating alerts with customers' equipment waits for MacGuard Cloud {{ev:EV-SI-09}}. See [Security Intelligence](EN-Intelligence).

## Dependencies between projects

- Installer Auditor depends on YARA Channel continuing to publish verifiable releases.
- MacFirewallGuard needs MacProcessGuard (process identity) and MacCoreGuard (verifiable evidence) to complete its design.
- MacGuardDesignKit 1.0 depends on two products adopting it.

## Live tracking

Progress is tracked on GitHub with real milestones, issues and releases: [V1.1 milestone](https://github.com/MacGuard/macguard-yara-channel/milestone/2), [triple archive milestone](https://github.com/MacGuard/macguard-yara-channel/milestone/4) and [releases](https://github.com/MacGuard/macguard-yara-channel/releases). This page is updated through changes reviewed by pull request, not automatically.

## Measured GitHub data

{{roadmap:table}}

The numbers are what GitHub reports on the date shown (refreshed with `python3 scripts/wiki_roadmap.py` and merged through a pull request). They are not a progress percentage.

## What we do not know yet

- Delivery dates: they are not defined or backed.
- The state of the private projects beyond what was reviewed: each row names the state and the review date in the [evidence matrix](EN-Evidence).
