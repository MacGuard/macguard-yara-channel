# Technology: YARA

[Home](EN-Home) · [Limits](EN-YARA-Limits) · [Technology: Sigstore](EN-Tech-Sigstore) · [Technology: Merkle](EN-Tech-Merkle) · [Technology: S3 backups](EN-Tech-S3-Backups)

## In 30 seconds

YARA is a language for writing "pattern descriptions" of files, plus a program that searches for those patterns. Its documentation describes it as a tool aimed at (but not limited to) helping malware researchers identify and classify malware samples {{ev:EV-YC-70}}.

## An everyday example

A rule is like a "wanted" poster: "a file containing this phrase and of this size". The engine walks through files and flags the ones matching the poster. A match does not prove danger; it only means the file resembles the poster.

{{diagram:sources-sequence}}

## YARA versus YARA-X

**YARA** is the classic engine. **YARA-X** is presented by VirusTotal as a "re-incarnation" of YARA, written in Rust, that aims to be faster and safer and claims about 99% compatibility with YARA rules {{ev:EV-YC-71}}. In this project the **rule sources** are only two repositories, `Neo23x0/signature-base` and `Yara-Rules/rules`; `VirusTotal/yara-x` appears in `config/sources.json` as an entry of kind `engine` and supplies no rules {{ev:EV-YC-01}}.

## Under the hood

- **Problem:** automatically deciding whether a rule file is safe to publish.
- **Input:** `.yar`/`.yara` files from the two sources. **Output:** a per-file classification (accept, quarantine, reject) with reasons.
- **How:** `scripts/rulecheck.py` analyzes the text (regex risk, loops) and compiles with `yarac`; the policy `config/policy.json` declares a minimum engine version and forbids the `cuckoo`, `magic` and `androguard` modules {{ev:EV-YC-67}}. Then `scripts/bench.py` and `scripts/dynamic_gate.py` measure time, memory and matches against a benign corpus {{ev:EV-YC-64}}.
- **What it does not prevent:** a valid rule may be useless or produce false positives; see [Limits](EN-YARA-Limits).
- **Shipped engine:** the app uses YARA 4.5.8 built with the tooling described in `docs/ENGINE.md`.

## Who else uses it

These rows describe other projects; none implies they use MacGuard.

| Who | Classification | Source |
|---|---|---|
| Security vendors listed in YARA's own README under "Who's using YARA" (among them VirusTotal, ESET, Kaspersky Lab, Trend Micro and Elastic Security) | uses the same technology | {{ev:EV-YC-70}} |
| ClamAV, which processes YARA rules with limitations (no modules, no global rules, no external variables, at most 64 strings per rule) | uses the same technology | {{ev:EV-YC-72}} |
| YARA-X (VirusTotal) | implements a similar solution (another engine for the same language) | {{ev:EV-YC-71}} |

## Check it yourself

```
python3 -m unittest tests.test_rulecheck tests.test_rulecheck_adversarial
python3 scripts/rulecheck.py --help
```

## Limits

YARA matches patterns; it does not understand intent. Engines differ across versions and platforms ({{ev:EV-YC-66}}).

## State

| Capability | State |
|---|---|
| Static and dynamic validation with YARA 4.x in the channel | operational {{ev:EV-YC-67}} |
| YARA-X as the channel's engine | only listed as an `engine` source entry; not used for validation |
