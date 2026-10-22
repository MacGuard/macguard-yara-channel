# The MacGuard ecosystem

[Home](EN-Home) · [Global roadmap](EN-Roadmap)

## In 30 seconds

Think of the security of a house: a lock on the door, an alarm on the window, a doorman who looks at who comes in. No single thing is enough. MacGuard follows the same idea: **several small, independent layers**, each with one concrete job and clear limits. None of them promises to stop everything.

## The layers

{{diagram:protection-layers}}

Each layer covers a different point on the path something follows until it runs on your Mac. If a layer fails or does not exist yet, the others **do not replace it**.

## How the applications relate

- **YARA Channel** supplies signed rules. **Installer Auditor** is the consumer with evidence today: it installs rules only if they pass every signature, hash and transparency-log check {{ev:EV-YC-09}}.
- **MacFirewallGuard** is designed to receive each process's identity from **MacProcessGuard**, but MacProcessGuard is still only a concept, so that piece is missing {{ev:EV-EC-05}}.
- **MacFirewallGuard** has a client for **MacCoreGuard**, tested only against a test double, because MacCoreGuard is still a prototype {{ev:EV-EC-04}} {{ev:EV-EC-06}}.
- **MacGuardDesignKit** gathers interface pieces meant to be shared. The evidence reviewed does not yet show other projects depending on it {{ev:EV-EC-07}}.
- **MacUSBGuard** works on its own; the evidence reviewed shows no dependency on the other applications {{ev:EV-EC-01}}.

## What each layer can and cannot do

| Layer | Helps to... | Does not guarantee... |
|---|---|---|
| Supply (YARA Channel) | Know the rules are the published ones and were not altered | That the rules detect everything, or that they are harmless: third parties write them {{ev:EV-YC-01}} |
| Installers (Installer Auditor) | Check a file with verified rules | That a file with no match is safe. A rule only recognizes what it already knows |
| Devices (MacUSBGuard) | Observe what is connected | Blocking: its hardware tests depend on an Apple permission that is missing {{ev:EV-EC-02}} |
| Network (MacFirewallGuard) | Observe and model connections | Blocking connections: it cannot today {{ev:EV-EC-03}} |
| Processes (MacProcessGuard) | Nothing yet: it is a concept | Nothing: it does not exist {{ev:EV-EC-05}} |

## What we do not know yet

- When each application will be ready: there are no backed dates.
- How the whole set behaves on a real Mac with all the layers: there is no end-to-end test across applications {{ev:EV-YC-10}}.

For per-application detail and the current state, go to the [Global roadmap](EN-Roadmap).
