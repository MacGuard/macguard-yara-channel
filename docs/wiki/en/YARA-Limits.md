# Limits of the YARA channel

[Home](EN-Home) · [Historical archive](EN-YARA-Archive) · [Technology: YARA](EN-Tech-YARA) · [Technology: Sigstore](EN-Tech-Sigstore) · [Technology: Merkle](EN-Tech-Merkle)

## In 30 seconds

A YARA rule is a pattern detector. No detector is right every time: sometimes it **raises an alarm for an innocent file** (false positive) and sometimes it **misses something malicious** (false negative). The channel measures and filters, but cannot promise there are none of either. And the channel's signature shows *who published it and that nothing changed afterwards*, not that the rules are good.

## An everyday example

An airport metal detector beeps for a set of keys (false positive) and may stay silent for a non-metal object (false negative). Tuning the sensitivity shifts the balance, it does not remove it. And an "inspected" stamp does not say the detector is perfect.

{{diagram:dynamic-decision}}

## False positives and false negatives

- **False positives.** The dynamic gate runs each rule set against a **benign corpus** and quarantines a rule that hits too many clean files. In code the limit is a 5% share (`hit_rate_limit=0.05` in `scripts/decide.py`), applied only when the corpus has at least 50 files {{ev:EV-YC-65}}.
- **False negatives.** There is no measure of how many real threats slip through. The only detection check is 5 harmless "canary" files (`MACGUARD-CANARY-n-DETECT-ME`) that must always fire; they show the engine works, not that the rules cover real malware {{ev:EV-YC-64}}.

## Limits of the benign corpus

The corpus built by `build_corpus` in `scripts/bench.py` is **small and synthetic** {{ev:EV-YC-64}}:

| Part | Content |
|---|---|
| Random binaries | 40 files, fixed seed 1234, sizes 512 B to 256 KiB |
| Text | 10 files of the same repeated sentence |
| System binaries | up to 8 (`/bin/ls`, `/bin/cat`, `/bin/sh`, `/usr/bin/awk`...), whichever exist on the runner |
| Canaries | 5 files, kept apart from the false-positive count |

Consequences: it holds no varied real-world software (documents, installers, applications), so an over-generic rule may still pass. And because it includes the runner's system binaries, **changing the runner image can change which files match** {{ev:EV-YC-65}}. A real defect: one benign file was counted once per namespace copy and pushed rules over the 5% limit unfairly; it was fixed by counting distinct files, without changing the limit {{ev:EV-YC-65}}.

## Performance cost

The policy (`config/policy.json`) sets sanity limits for when there is no earlier release: scan p95 2.0 s, scan memory 1500 MB, compile memory 3000 MB and compile time 240 s. Against a previous release, a regression must exceed 3 times the measured noise, 25% relative, and absolute minimums of 0.5 s CPU or 25 MB {{ev:EV-YC-67}}. These are project starting points, not performance guarantees on any Mac. There is no end-to-end performance test with the application {{ev:EV-YC-10}}.

## Source availability

Two rule repositories feed the channel (`Neo23x0/signature-base` and `Yara-Rules/rules`) {{ev:EV-YC-01}}. If they change, vanish or rewrite history, the channel depends on that. Automatic publication refuses to remove more than 15% of the previous release or touch more than 40% (`anomaly` in the policy) and asks for human review {{ev:EV-YC-67}}. Rule licences are only checked automatically by confirming the licence text has not changed; legal review is not done {{ev:EV-YC-66}}.

## Trust in engines

The policy requires YARA 4.3.0 or later; the shipped engine is 4.5.8, but the Linux gate uses Ubuntu's YARA 4.5.0, and the macOS measurement runs in a virtual machine, not on an independent Mac {{ev:EV-YC-66}}. Engines are not identical; a file that compiles on one may fail on another, and the application verifies the shipped engine before using it ([`docs/ENGINE.md`](https://github.com/MacGuard/macguard-yara-channel/blob/main/docs/ENGINE.md)).

## What the signature does NOT prove

The Sigstore signature and the Merkle root show that **that workflow published those bytes** and that the log only grows {{ev:EV-YC-03}} {{ev:EV-YC-04}}. They do not show that the rules detect well, that they have no false positives, or that the review process is right. `manifest.evidence` is the publishing workflow's own statement, not an independent in-toto/SLSA attestation {{ev:EV-YC-66}}.

## What the audit left open (public level)

Summary of `RESIDUAL-RISKS.md`, `SECURITY-FINDINGS.md` and `TEST-MATRIX.md` {{ev:EV-YC-66}}: there is no independent attestation of the review (RR-02); fuzzing uses fixed seeds and was not run with long-running tools (RR-10); Grype, OpenSSF Scorecard and real screen readers were not run (RR-11); ten files of the first release remain withheld (RR-13). Other findings are not summarised here so as not to anticipate unpublished details.

## Check it yourself

```
python3 -m unittest tests.test_bench tests.test_dynamic_gate tests.test_rulecheck
```

## Limits

This page summarises project documents as of their last review; the figures quoted are those in the code that was read, not new measurements.

## State

| Capability | State |
|---|---|
| Dynamic gate with benign corpus and canaries | operational {{ev:EV-YC-65}} |
| Measurement on an independent macOS | not available {{ev:EV-YC-66}} |
| Independent attestation of the review | planned |
