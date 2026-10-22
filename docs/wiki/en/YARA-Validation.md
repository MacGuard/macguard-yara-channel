# YARA Validation: what is really checked

[Home](EN-Home) · [YARA Channel](EN-YARA-Channel) · [Sources](EN-YARA-Sources) · [Performance](EN-YARA-Performance) · [Quarantine](EN-YARA-Quarantine) · [Publishing](EN-YARA-Publishing)

## In 30 seconds

Before publication, every rule file goes through two automatic filters. The **static** one reads it as text and compiles it without running anything from it. The **dynamic** one loads the whole set into the real YARA engine, tries it on harmless files and compares it with the previous version. Anything doubtful goes to quarantine; only what passes both can be published. A changed set is published only if validation passes and the macOS measurement job succeeds (see Platforms below). {{ev:EV-YC-24}} {{ev:EV-YC-28}}

## An everyday example

It is like proofreading an exam before handing it out: first that it is complete and legible (static), then that it does not take three hours to mark and does not fail everybody (dynamic). Passing the review does not prove the exam is good, only that it lacks the defects we know how to look for.

## The decisions

{{diagram:static-decision}}

{{diagram:dynamic-decision}}

## Step by step

1. `rulecheck.py` analyzes the text, applies the heuristics and compiles each file with `yarac` (together with its dependencies).
2. `dynamic_gate.py` measures the approved set against the previous one (5 repetitions) and, on failure, isolates the culprit files.
3. `decide.py` puts it together: adds the benign-corpus filter, applies the human decisions that are allowed and decides whether the set is publishable.

## Under the hood

### Static checks (`scripts/rulecheck.py`, `config/policy.json`)

| Check | Value | File | Outcome |
|---|---|---|---|
| Maximum file size | 1,000,000 bytes | `policy.json` `limits.max_file_bytes` | hard reject |
| Maximum rules per file | 3000 | `limits.max_rules_per_file` | hard reject |
| NUL bytes | any | `rulecheck.py` | hard reject (`binary`) |
| Allowed modules | `pe`, `elf`, `macho`, `math`, `hash`, `dotnet`, `time`, `string` | `allowed_modules` | — |
| Blocked modules | `cuckoo`, `magic`, `androguard` | `blocked_modules` | `blocked-module`, review (cannot be waived) |
| Any other module | not listed | `rulecheck.py` | `unknown-module`, review (can be waived) |
| Regex risk | score ≥ 7 | `regex.max_risk_score` | `costly-regex`, review |
| `for` loops in one condition | more than 3 | `condition.max_for_loops` | `many-loops`, review |
| Loop over the whole file (`filesize`) | forbidden | `forbid_filesize_loops` | `filesize-loop`, review |

The regex risk score adds points for shapes that tend to be costly: nested quantifiers, repeated open-ended runs (`.*`, `.+`), very wide `{n,m}` gaps (`regex.wide_gap`, 1000 in the policy) and open-ended repetition. A score at or above `regex.max_risk_score` (7 in the policy) sends the file to review. The weights are in `regex_risk` in `scripts/rulecheck.py`. These heuristics **only send a file to quarantine**; the real cost is decided by the dynamic measurement. They are approximate signals for reviewers, not targets. {{ev:EV-YC-25}} {{ev:EV-YC-26}}

Engine compatibility is checked by compiling with the available `yara`/`yarac` engine (`-w` and empty external variables). The engine version actually used is recorded (4.5.0 in the public log of the daily run). {{ev:EV-YC-32}}

### Dynamic checks (`scripts/dynamic_gate.py`, `scripts/bench.py`)

| Parameter | Value | Where |
|---|---|---|
| Repetitions per set | 5 | `dynamic.runs` |
| Limit per scanned file | 10 s | `dynamic.timeout_seconds_per_file` |
| Noise | threshold = max(3 × MAD, 25 % of the median, absolute floor) | `dynamic.regression.*` |
| Absolute floors | CPU 0.5 s; RSS 25 MB | `policy.json` |
| No previous release: scan p95 | 2.0 s | `dynamic.absolute.max_scan_p95_s` |
| No previous release: scan RSS | 1500 MB | `max_scan_rss_mb` |
| No previous release: compile RSS / time | 3000 MB / 240 s | `max_compile_rss_mb`, `max_compile_wall_s` |
| Culprit isolation | delta debugging on the files that make the set worse | `scripts/dynamic_gate.py` |

Measurements: time, CPU and peak memory per child process (`wait4`). {{ev:EV-YC-28}}

These values are read from `config/policy.json` and the scripts named above. They can change and they are limits for review, not targets: a candidate that exceeds them is isolated, quarantined or not published. The "no previous release" limits are generous sanity bounds that apply only when there is nothing to compare with.

**Benign corpus and false positives.** The corpus is deterministic and small: synthetic files, some text files and a few system binaries of the runner, plus a small set of harmless "canary" files. A rule file that fires on too large a share of the clean corpus (a limit set in the code, which can change) is sent to quarantine as `matches-benign-corpus`. All canaries must be detected; otherwise nothing is published ("detection is not demonstrably working"). It is a small corpus: it measures gross genericity, not the real-world false-positive rate. {{ev:EV-YC-29}}

**Acceptance policy (`decide.py`).** A set is publishable only if all of these hold. The approved set is not empty. There is an effective change against the previous release. The change does not exceed the mass-change limits (15 % removed or 40 % touched; policy values) unless a person explicitly approves it. The dynamic measurement was taken on exactly that set (`set_root`), with verdict `ok` or `no-baseline` and every canary detected. The accounting adds up. A human approval lifts only judgment findings (`costly-regex`, `many-loops`, `filesize-loop`, `unknown-module`, `include`, `license-unchecked`, `matches-benign-corpus`, `dependency-not-validated`); never compile errors, truncation, corruption, a blocked module, a changed license or dynamic failures. {{ev:EV-YC-27}}

**Platforms and what gates publication.** The reference engine runs on Linux. If the set is publishable and changed, a `macos-15` job (`macos` in `daily.yml`) repeats the measurements with the engine MacGuard ships. The release request (`request-publish`) runs only if that job succeeded, and `publish.yml` then re-verifies the final set before signing. The `app-compat` job also runs after `macos`, but it only reports and does not gate publication. There is no independent macOS virtual machine: the hosted runner is itself a virtual machine and `required_platforms` in the policy declares the independent one "not available". {{ev:EV-YC-28}} {{ev:EV-YC-89}}

### Adversarial and regression tests

`tests/test_rulecheck_adversarial.py` cuts a valid file at every position and requires every cut inside a rule to produce a blocking finding, applies many random byte-damage cases without the analyzer failing, and tries Unicode and control characters. It also tries pathological inputs (nested regexes, unclosed braces, deeply nested loops) under a time bound, which is a resource limit against hostile input, not an approval criterion. `tests/test_bench.py`, `tests/test_dynamic_gate.py` and `tests/test_decide.py` cover regressions, culprit isolation with the real engine, canaries and the corpus limit. They run before every daily review and on every pull request. {{ev:EV-YC-30}} {{ev:EV-YC-37}}

## Check it yourself

- `python3 -m unittest tests.test_rulecheck tests.test_rulecheck_adversarial tests.test_bench tests.test_dynamic_gate tests.test_decide`
- Read [rulecheck.py](https://github.com/MacGuard/macguard-yara-channel/blob/main/scripts/rulecheck.py), [decide.py](https://github.com/MacGuard/macguard-yara-channel/blob/main/scripts/decide.py), [dynamic_gate.py](https://github.com/MacGuard/macguard-yara-channel/blob/main/scripts/dynamic_gate.py) and [policy.json](https://github.com/MacGuard/macguard-yara-channel/blob/main/config/policy.json).

## Limits

- The heuristics are approximations: they can let a slow regex through or set aside a harmless one.
- A rule that compiles and does not overload the engine is not proven to detect what it claims to detect.
- Some configuration values in `policy.json` are declared but not yet applied by the code.

## State

| Capability | State |
|---|---|
| Static classification, dynamic gate and acceptance policy | operational {{ev:EV-YC-02}} |
| Persistent policy holds in the panel | implemented in the repository, not yet active in production {{ev:EV-YC-06}} |
| Independent macOS virtual machine | not available |
