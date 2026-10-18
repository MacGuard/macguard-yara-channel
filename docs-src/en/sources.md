---
title: Rule sources
summary: Where the rules come from, how each commit is pinned and the role of every source.
---
## Which sources count

| Public source | Technical id | Actual role |
|---|---|---|
| Nextron Systems — signature-base | `Neo23x0/signature-base` | **Effective rule source.** The `yara` directory is downloaded. |
| Comunidad de reglas YARA (Yara-Rules) | `Yara-Rules/rules` | **Effective rule source** (community): `malware`, `packers`, `crypto`, `antidebug_antivm`, `capabilities`, `exploit_kits`, `webshells`. |
| VirusTotal — ecosistema YARA y YARA-X | `VirusTotal/yara-x` | **Reference engine, no rules.** Recorded in `config/sources.json` as kind `engine`; today it contributes no files to the channel. |

> **CURRENT** A forum or community repository is an effective source only if it is in the allow-list `config/sources.json`. Any other source is **PROPOSED** until it is added with its licence reviewed.

## How it is collected

{{diagram:sources-sequence}}

- The newest commit of each source is queried and the tarball of **that exact commit** is downloaded, so the candidate is reproducible.
- Only `.yar` and `.yara` under the allowed paths are kept; files over 1 MB or with NUL bytes are skipped (event `file.skipped`).
- The licence is checked against `config/policy.json`: the "Detection Rule License" marker for Nextron and GPL-2.0 for Yara-Rules. A licence change goes to quarantine.

## What is recorded

Every release carries, in `release.json` and the manifest, the list of sources with repository, commit and licence-check result, so it is possible to reconstruct where each file came from.
