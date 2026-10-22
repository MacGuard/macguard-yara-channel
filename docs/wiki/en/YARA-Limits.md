# Limits of the YARA channel

[Home](EN-Home) · [Historical archive](EN-YARA-Archive) · [Technology: YARA](EN-Tech-YARA) · [Technology: Sigstore](EN-Tech-Sigstore) · [Technology: Merkle](EN-Tech-Merkle)

## In 30 seconds

A YARA rule is a pattern detector. No detector is right every time: sometimes it **raises an alarm for an innocent file** (false positive) and sometimes it **misses something malicious** (false negative). The channel measures and filters, but cannot promise there are none of either. And the channel's signature shows *who published it and that nothing changed afterwards*, not that the rules are good.

## An everyday example

An airport metal detector beeps for a set of keys (false positive) and may stay silent for a non-metal object (false negative). Tuning the sensitivity shifts the balance, it does not remove it. And an "inspected" stamp does not say the detector is perfect.

{{diagram:dynamic-decision-1-compare}}

{{diagram:dynamic-decision-2-isolate}}

{{diagram:dynamic-decision-3-publish}}

## False positives and false negatives

- **False positives.** The dynamic gate runs each rule set against a **benign corpus** and quarantines a rule that hits too many clean files. The limit is a share of the corpus set in the code (`scripts/decide.py`); it is a policy value that can change {{ev:EV-YC-65}}.
- **False negatives.** There is no measure of how many real threats slip through. The only detection check is a canary check that must always fire; it shows the measurement can detect a match, not that the rules cover real malware {{ev:EV-YC-64}}.

## Limits of the benign corpus

The benign corpus is **small and synthetic**; it measures gross genericity, not the real-world false-positive rate {{ev:EV-YC-64}}. It does not represent real-world software, so an over-generic rule may still pass {{ev:EV-YC-65}}. A real defect: one benign file was counted once per namespace copy and pushed rules over the limit unfairly; it was fixed by counting distinct files, without changing the limit {{ev:EV-YC-65}}.

## Performance cost

The policy (`config/policy.json`) sets sanity limits that apply when there is no earlier release to compare with; a candidate that exceeds them is not approved. Against a previous release, an increase counts as a regression only when it exceeds the measured noise and both a relative and an absolute minimum {{ev:EV-YC-67}}. The exact values are listed in context on [Validation](EN-YARA-Validation). They come from policy, can change, and are starting points that protect the machines that scan, not performance guarantees on any Mac and not targets. There is no end-to-end performance test with the application {{ev:EV-YC-10}}.

## Source availability

Two rule repositories feed the channel (`Neo23x0/signature-base` and `Yara-Rules/rules`) {{ev:EV-YC-01}}. If they change, vanish or rewrite history, the channel depends on that. Automatic publication refuses to remove more than 15% of the previous release or touch more than 40% (`anomaly` in the policy) and asks for human review {{ev:EV-YC-67}}. Rule licenses are only checked automatically by confirming the license text has not changed; legal review is not done {{ev:EV-YC-66}}.

## Trust in engines

The policy declares a minimum engine version; some configuration values are declared but not yet applied by the code {{ev:EV-YC-32}}. The shipped engine is 4.5.8, the Linux gate uses Ubuntu's YARA 4.5.0, and the macOS measurement runs in a virtual machine, not on an independent Mac {{ev:EV-YC-66}}. Engines are not identical; a file that compiles on one may fail on another, and the application verifies the shipped engine before using it ([`docs/ENGINE.md`](https://github.com/MacGuard/macguard-yara-channel/blob/main/docs/ENGINE.md)).

## What the signature does NOT prove

The Sigstore signature and the Merkle root show that **that workflow published those bytes** and that the log only grows {{ev:EV-YC-03}} {{ev:EV-YC-04}}. They do not show who wrote the rules, that the rules detect well, that they have no false positives, or that the review process is right. `manifest.evidence` is the publishing workflow's own statement, not an independent in-toto/SLSA attestation {{ev:EV-YC-66}}.

## What the audit left open (public level)

The project keeps an audit with open items {{ev:EV-YC-66}}: there is no independent attestation of the review, fuzzing is limited and some tools have not been run yet.

## Check it yourself

```
python3 -m unittest tests.test_bench tests.test_dynamic_gate tests.test_rulecheck
```

## Limits

This page summarizes project documents as of their last review; the figures quoted are those in the code that was read, not new measurements.

## State

| Capability | State |
|---|---|
| Dynamic gate with benign corpus and canaries | operational {{ev:EV-YC-65}} |
| Measurement on an independent macOS | not available {{ev:EV-YC-66}} |
| Independent attestation of the review | planned |
