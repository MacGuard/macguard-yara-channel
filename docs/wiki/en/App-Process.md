# MacProcessGuard

[Home](EN-Home) · [Ecosystem](EN-Ecosystem) · [Roadmap](EN-Roadmap) · [MacFirewallGuard](EN-App-Firewall)

## In 30 seconds

MacProcessGuard is a **concept**: a piece that, if undertaken, would watch which programs run on the Mac. **It does not exist**: no repository, no code, no specification of its own {{ev:EV-EC-05}}. This page only says what other projects write about it. **No implemented function is attributed to it.**

## An everyday example

It is a reserved gap on a floor plan: someone drew a door labelled "process control would go here", but the room is not built. We know where it would fit, not what it would be like.

## Diagram

{{diagram:process-boundary}}

## Step by step: what exactly exists

1. The MacFirewallGuard README literally says MacProcessGuard "does not exist yet" {{ev:EV-EC-05}}.
2. Its architecture documents call it a "separate, not-yet-started" sibling product; a recorded decision keeps it as a separate product {{ev:EV-EC-66}}.
3. In the MacFirewallGuard code there are only **reserved slots**: a placeholder correlation category marked "not implemented yet; reserved" and a process-identity reference whose provider state is "absent" {{ev:EV-EC-67}}.
4. There are proposed interface placeholders (a "Process Activity" sidebar); they are design mock-ups, not functions {{ev:EV-EC-66}}.

## Under the hood

There are no algorithms to describe. The only thing with code is the **boundary** on the MacFirewallGuard side, made of reserved slots:

- a process-identity reference that identifies a process and carries a correlation state; in production that state always stays "absent" {{ev:EV-EC-67}}.
- a list of recognized external producers; an unrecognized producer is treated as not admissible.

What MacFirewallGuard **says** MacProcessGuard would do (execution provenance, executable hash, process lineage, persistence, injection detection) is a **boundary drawn by another project**, not a commitment or a specification {{ev:EV-EC-66}}. Endpoint Security is named as the suitable API, but there is no code and no usable Apple permission for it in this ecosystem. No use of XPC, YARA or any other technology is documented.

Unresolved name: the project material sometimes refers to a similar endpoint-oriented product. The documentation does not state they are the same product; **not verified**.

## Check it yourself

There is nothing to run. The check is negative: in the local copies reviewed, no directory, repository or package with that name was found, and the MacFirewallGuard README declares it nonexistent.

## Limits

- It protects nothing today. Nobody should depend on it.
- MacFirewallGuard reserving a slot does not oblige anyone to build MacProcessGuard; the owner has not yet decided whether to undertake it ({{ev:EV-EC-66}}).
- While it does not exist, MacFirewallGuard's process identity remains whatever its own signature resolution gives, and injection detection has no owner.

## State

| Capability | State |
|---|---|
| MacProcessGuard product | Concept |
| Reserved slots in MacFirewallGuard | Implemented (as placeholders only) |
| Any process-monitoring function | Planned in the weakest sense: only mentioned; no design |

No dates. See the [Roadmap](EN-Roadmap) and [MacFirewallGuard](EN-App-Firewall).
