# MacGuard YARA Channel

[Home](EN-Home) · [Sources](EN-YARA-Sources) · [Validation](EN-YARA-Validation) · [Performance](EN-YARA-Performance) · [Quarantine](EN-YARA-Quarantine) · [Publishing](EN-YARA-Publishing) · [Transparency](EN-YARA-Transparency) · [Verify](EN-YARA-Verify) · [Archive](EN-YARA-Archive) · [Limits](EN-YARA-Limits)

## In 30 seconds

MacGuard YARA Channel is a system that collects, validates, prepares and distributes verifiable YARA rules to help identify suspicious patterns in files.

Every day an automated job downloads rules from two public repositories, checks them with static checks and with real measurements of the YARA engine, sets aside the ones that fail, and publishes only the ones that pass, with a signature anyone can check. It helps recognise known patterns; it does **not** guarantee that a file is safe or that a new threat will be detected. {{ev:EV-YC-20}}

## What YARA is, for a 12-year-old

Imagine searching a library for every book that mentions the phrase "buried treasure". A YARA rule is that instruction written for a computer: "look for these words or these chunks of bytes inside a file, and tell me if this condition holds". YARA does not "understand" the file: it only checks whether certain patterns appear. That is why it is useful for flagging things that are already known, and also why it can be wrong.

## What a YARA rule is

A rule has a name, a `strings` section (the patterns to look for: text, bytes or regular expressions) and a `condition` (when the rule counts as "fired"). The example below was made up for this wiki; it detects nothing real:

```yara
// EXAMPLE made up for this wiki. It detects no real program.
rule Example_Harmless_Marker
{
    strings:
        $marker = "HELLO-MACGUARD-EXAMPLE"
    condition:
        $marker
}
```

The rule fires only if the file contains exactly that text. Real rules combine many patterns and conditions (`any of them`, file size, modules such as `pe` for Windows executables).

## An everyday example

It is like a customs officer's checklist: "if the suitcase has A and B, look closer". Other people write the checklists; the channel checks that each one is well written, does not take forever to apply and does not flag innocent suitcases, and hands out only the checklists that pass. It cannot know what is in a kind of suitcase nobody has described yet.

## The journey of a rule

{{diagram:architecture}}

## Step by step

| Step | What happens | Page |
|---|---|---|
| 1. Collect | Rules are downloaded from two public repositories, pinning the commit of each run | [Sources](EN-YARA-Sources) |
| 2. Validate | Static check, compilation and engine measurements; decides what gets in | [Validation](EN-YARA-Validation) |
| 3. Measure cost | CPU, memory and latency are measured against the previous version | [Performance](EN-YARA-Performance) |
| 4. Set aside | Anything that fails goes to a private quarantine for human review | [Quarantine](EN-YARA-Quarantine) |
| 5. Publish | Hashes, Merkle root, Sigstore signature and release | [Publishing](EN-YARA-Publishing) |
| 6. Record | Transparency log with counts only | [Transparency](EN-YARA-Transparency) |
| 7. Verify | How a third party checks signature, hashes and log | [Verify](EN-YARA-Verify) |
| 8. Keep | Historical archive across several providers (not operational yet) | [Archive](EN-YARA-Archive) |
| 9. Know the limits | What the channel does not do | [Limits](EN-YARA-Limits) |

## Under the hood

The real order of the programs, per `.github/workflows/daily.yml`: `scripts/prepare.py` (collect), `scripts/rulecheck.py` (static classification), `scripts/dynamic_gate.py` with `scripts/bench.py` (engine measurements), `scripts/decide.py` (decision gate) and, if the set changed, `publish.yml` signs and publishes. The gate is the only point that decides which set is publishable. {{ev:EV-YC-20}}

- What it detects: matches against patterns someone wrote into a rule.
- What it does **not** prevent: malware with no rule, obfuscated malware, or malware whose pattern is not in the rules; nor does it guarantee the absence of false positives.
- Evidence of implementation: the files named above; diagram `docs-src/diagrams/architecture.mmd`.

## Check it yourself

- The repository test suite: `python3 -m unittest discover -s tests` (needs `yara` installed).
- The source list: [config/sources.json](https://github.com/MacGuard/macguard-yara-channel/blob/main/config/sources.json); the policy: [config/policy.json](https://github.com/MacGuard/macguard-yara-channel/blob/main/config/policy.json).
- The daily flow: [daily.yml](https://github.com/MacGuard/macguard-yara-channel/blob/main/.github/workflows/daily.yml).

## Limits

A validated rule set is not the same as a safe file. What the channel does not cover is on [Limits](EN-YARA-Limits). There is no end-to-end performance test with Installer Auditor ({{ev:EV-YC-10}}).

## State

| Capability | State |
|---|---|
| Daily review, decision gate and signed release | operational {{ev:EV-YC-02}} {{ev:EV-YC-03}} |
| Private quarantine panel | operational {{ev:EV-YC-05}} |
| Persistent withdrawals, policies, anchors and source proposals | implemented in `main`, not deployed {{ev:EV-YC-06}} {{ev:EV-YC-07}} |
| Three-provider archive | not operational {{ev:EV-YC-08}} |
| Performance test with the real app | planned {{ev:EV-YC-10}} |
