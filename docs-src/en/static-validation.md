---
title: Static validation
summary: How each rule file is classified before it is measured.
---
## States

`rulecheck.py` assigns every examined file one of four final states: **VALIDATED**, **QUARANTINED**, **REJECTED** or **DEPRECATED**. Only VALIDATED can be published.

{{diagram:static-decision}}

## Criteria

| Outcome | Reason |
|---|---|
| REJECTED | Hard criteria: binary, empty, no rules, over 1 MB or content rejected before. |
| QUARANTINED | Truncated, corrupt, compile error, blocked (`cuckoo`, `magic`, `androguard`) or unknown module, costly regular expression, loop over the whole file, changed licence or a dependency that is not validated. |
| DEPRECATED | The file is marked deprecated in its own metadata. |
| VALIDATED | None of the criteria above applies. |

Allowed modules: `pe`, `elf`, `macho`, `math`, `hash`, `dotnet`, `time`, `string`. The `cuckoo` module needs a sandbox report that MacGuard does not produce, so it has no use in the channel. Thresholds live in `config/policy.json`.

## Dependencies between files

Many files use rules from others (`include` or rule names). The candidate keeps that relation as signed `depends_on`; every file is compiled in its own namespace with its dependencies, because 227 files repeat rule names and a single namespace would not compile.

> **LIMIT** "Validated" is not an assessment of detection quality. False positives are not measured beyond the benign-corpus tests and the canaries.
