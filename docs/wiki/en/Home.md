# Welcome to MacGuard

## In 30 seconds

MacGuard is a family of tools to protect a Mac. Each one watches a different thing: the installers you download, USB devices, network connections. One of them, **YARA Channel**, distributes the "lists of clues" (YARA rules) used to recognise suspicious files, and does it in a way anyone can check that nothing was tampered with.

This wiki explains what each piece does, how it works and **where its development really stands**. When something is not proven, we say so.

## The map at a glance

{{diagram:ecosystem-map}}

| Application | What it does, in one sentence | State | Evidence |
|---|---|---|---|
| YARA Channel | Collects, validates and publishes signed, verifiable YARA rules | Published | {{ev:EV-YC-02}} |
| Installer Auditor | Checks installers with those rules before you open them | In development | {{ev:EV-YC-09}} |
| MacUSBGuard | Watches the USB devices that get connected | In validation | {{ev:EV-EC-01}} |
| MacFirewallGuard | Observes network connections and will apply a policy | In development | {{ev:EV-EC-03}} |
| MacProcessGuard | Would identify which program does what | Concept only | {{ev:EV-EC-05}} |
| MacCoreGuard | Common base to keep verifiable evidence | Prototype | {{ev:EV-EC-06}} |
| MacGuardDesignKit | Interface pieces shared between the apps | In development | {{ev:EV-EC-07}} |

## What exists today

- **Published:** the YARA rule channel, with a Sigstore signature and a verifiable transparency log {{ev:EV-YC-03}} {{ev:EV-YC-04}}.
- **Working, for internal use:** the private panel where quarantined rules are reviewed {{ev:EV-YC-05}}.
- **No other application is published as a final product** according to the evidence reviewed.

## What we are working on

- YARA Channel: persistent withdrawals and source proposals, written and tested but not deployed yet {{ev:EV-YC-06}} {{ev:EV-YC-07}}, and the three-provider historical archive, which is **not operational yet** {{ev:EV-YC-08}}.
- MacFirewallGuard and MacUSBGuard: moving the tests that depend on Apple permissions that are still missing {{ev:EV-EC-02}} {{ev:EV-EC-04}}.

## Next milestone

There are no committed dates. Each application's next step, blockers and dependencies are in the [Global roadmap](EN-Roadmap).

## Where to go next

- [Ecosystem: layers and relations](EN-Ecosystem)
- [Global roadmap](EN-Roadmap)
- [YARA Channel in depth](EN-YARA-Channel)
- Pages: [MacUSBGuard](EN-App-USB), [MacFirewallGuard](EN-App-Firewall), [MacProcessGuard](EN-App-Process), [MacCoreGuard](EN-App-Core), [Installer Auditor](EN-App-InstallerAuditor), [DesignKit](EN-App-DesignKit)
- [Evidence matrix](EN-Evidence)
