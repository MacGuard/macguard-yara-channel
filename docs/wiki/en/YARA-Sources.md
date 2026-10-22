# YARA Sources: where the rules come from

[Home](EN-Home) · [YARA Channel](EN-YARA-Channel) · [Validation](EN-YARA-Validation) · [Performance](EN-YARA-Performance) · [Quarantine](EN-YARA-Quarantine)

## In 30 seconds

The channel does not write rules: it takes them from **two public repositories** (`Neo23x0/signature-base` and `Yara-Rules/rules`) and also records the `VirusTotal/yara-x` engine, which is an engine and contributes no rules. Every day it downloads the exact state of each repository, keeps which commit and which license it came from, and treats everything downloaded as untrusted until validated. {{ev:EV-YC-21}}

## An everyday example

It is like buying fruit from two different markets and writing on the delivery note which stall and what time each crate came from. Before anything goes on the shelf each crate is inspected; if a stall closes or changes its terms, the note tells you what came from where.

## The download path

{{diagram:sources-sequence-1-commit}}

{{diagram:sources-sequence-2-download}}

{{diagram:sources-sequence-3-inventory}}

## Step by step

1. `scripts/prepare.py` reads `config/sources.json` and, for each source, asks the GitHub API for the newest commit (`commits/HEAD`).
2. It downloads the tarball **of that exact commit** and extracts it with safety checks (see below).
3. If the source is a rules source, it reads the license and compares it with `config/policy.json`.
4. It keeps only `.yar` and `.yara` files under the declared paths, computes the SHA-256 of each file and writes the inventory `dist/candidate.json`.
5. `scripts/rulecheck.py` classifies every file (see [Validation](EN-YARA-Validation)).

## Under the hood

### Sources and provenance

| Id | Repository | Kind | Paths |
|---|---|---|---|
| `nextron` | `Neo23x0/signature-base` | `rules` | `yara` |
| `community` | `Yara-Rules/rules` | `rules` | `malware`, `packers`, `crypto`, `antidebug_antivm`, `capabilities`, `exploit_kits`, `webshells` |
| `yara-x` | `VirusTotal/yara-x` | `engine` | none: it contributes no files |

- **Commit pinned per run, not in the configuration.** `config/sources.json` holds no fixed commit per source: each repository's `HEAD` is followed every day and the commit used is recorded in `candidate.json` and in the release. What is "pinned" is that the tarball comes from that commit rather than from "whatever is latest at that moment". {{ev:EV-YC-22}}
- **Download limits** in `scripts/prepare.py`: caps on download size, number of archive entries and time. Symbolic and hard links, devices, absolute paths and `..` are refused. The GitHub token only travels to the host `api.github.com`. {{ev:EV-YC-22}}
- **Licenses and metadata:** `scripts/licensing.py` queries the license and keeps the SPDX id, a SHA-256 digest of the text and the verdict. The policy expects "Detection Rule License" (DRL-1.1) for `Neo23x0/signature-base` and GPL-2.0 for `Yara-Rules/rules`. If it does not match, **every** file of that source goes to quarantine (`license-changed`) and no human approval lifts it. {{ev:EV-YC-23}}

### If a source fails or disappears

- If the API or the download fails, `prepare.py` exits with an error; `daily.yml` records `run.failed` in the transparency log and **no release is requested**. The previous release stays current. {{ev:EV-YC-36}}
- If only the license read fails, the text is empty and the verdict is "could not be read": the source is quarantined rather than published silently.
- If a file stops existing upstream, `decide.py` marks it retired (`no longer present upstream`). If a large share disappears or changes (more than 15 % removed or more than 40 % touched, `anomaly` in `config/policy.json`; policy values that can change), the change is not publishable until a person reviews and explicitly approves it.

### Normalization and structure of a rule

"Normalization" **does not rewrite rules**: `prepare.py` copies the bytes as they are to `dist/rules/<source id>/<path>`, skipping files over 1,000,000 bytes, files with NUL bytes, and names the signed inventory cannot represent unambiguously. `rulecheck.py` only analyzes: it blanks comments and string contents to locate each `rule name { ... }`, then checks braces, `condition:`, `import` and `include`. {{ev:EV-YC-24}}

### Licenses of third-party rules

Rules downloaded from a source stay under that source's own license; the policy records what it expects from each one. This project does not claim copyright over downloaded rules, and nothing on this wiki grants rights over them. Releases redistribute the downloaded rule files: the conditions for that redistribution are pending legal review, and the repository has no general LICENSE file yet. The automatic license check only detects that a license changed; it is not legal advice. {{ev:EV-YC-85}} {{ev:EV-YC-81}}

### Invalid rules, imports, dependencies and duplicates

- **Invalid:** an unclosed comment, string, regex or rule, unbalanced braces, or a file that ends midway (`truncated`). Control characters in the code, or a rule without `condition` (`corrupt`). No rules, binary, over 1,000,000 bytes or over 3000 rules (`reject`). A compiler error (`compile-error`). Truncated or corrupt files go to quarantine; hard rejections are not reused while the bytes stay the same.
- **`import`:** allowed and blocked modules are listed in [Validation](EN-YARA-Validation). An `include` is a review finding.
- **Dependencies:** if a rule uses the name of a rule from another file, it is compiled together with that file and recorded in `depends_on`. A file whose dependency is not validated is not validated either, transitively. {{ev:EV-YC-24}}
- **Duplicates:** different repositories repeat rule names. When the set is compiled, one namespace per file is used (`bench.compile_set`), so two rules with the same name in different files coexist. {{ev:EV-YC-38}}

### How new sources are admitted

Adding a source needs a reviewed change to `config/sources.json` and `config/policy.json` on `main`; with no license entry in the policy its files are quarantined. Admission control for new sources is implemented in the repository and not yet enabled in production. It is controlled because a new source brings third-party content that ends up on users' machines; a license problem or a compromised upstream repository would spread through the channel. {{ev:EV-YC-31}}

## Check it yourself

- `python3 -m unittest tests.test_admission tests.test_decide tests.test_licensing`
- Read [prepare.py](https://github.com/MacGuard/macguard-yara-channel/blob/main/scripts/prepare.py) and [config/sources.json](https://github.com/MacGuard/macguard-yara-channel/blob/main/config/sources.json).

## Limits

- Being on the list does not make a source "trusted": its rules are validated all the same.
- The commit is not pinned by configuration; a repository can change between runs.
- The license is checked by SPDX id and text marker; it is not legal advice.

## State

| Capability | State |
|---|---|
| Daily download of two rule sources, with commit and license recorded | published {{ev:EV-YC-01}} |
| Admission control for new sources | implemented in the repository, not yet enabled in production {{ev:EV-YC-07}} |
| Additional sources | planned (none active) |
