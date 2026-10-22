# YARA Validation: what is really checked

[Home](EN-Home) · [YARA Channel](EN-YARA-Channel) · [Sources](EN-YARA-Sources) · [Performance](EN-YARA-Performance) · [Quarantine](EN-YARA-Quarantine) · [Publishing](EN-YARA-Publishing)

## In 30 seconds

Before publication, every rule file goes through two automatic filters. The **static** one reads it as text and compiles it without running anything from it. The **dynamic** one loads the whole set into the real YARA engine, tries it on harmless files and compares it with the previous version. Anything doubtful goes to quarantine; only what passes both is published. {{ev:EV-YC-24}} {{ev:EV-YC-28}}

## An everyday example

It is like proofreading an exam before handing it out: first that it is complete and legible (static), then that it does not take three hours to mark and does not fail everybody (dynamic). Passing the review does not prove the exam is good, only that it lacks the defects we know how to look for.

## The decisions

{{diagram:static-decision}}

{{diagram:dynamic-decision}}

## Step by step

1. `rulecheck.py` analyses the text, applies the heuristics and compiles each file with `yarac` (together with its dependencies).
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
| Compile time per file | 20 s | `compile_file` (`timeout`) | `compile timeout` → error |
| Dependency-resolution rounds | 6 | `compile_file` | `compile-dependency` |

A regex score adds: 9 for nested quantifiers, 3 for two or more `.*`/`.+`, 2 for a single leading `.*`, 4 for every `{n,m}` gap with `m` ≥ 1000 (`regex.wide_gap`) and 3 for an open-ended repetition `{n,}`. One nested quantifier (9) is enough to exceed the threshold of 7. These heuristics **only send a file to quarantine**; the real cost is decided by the dynamic measurement. {{ev:EV-YC-25}} {{ev:EV-YC-26}}

Engine compatibility is checked by compiling with the available `yara`/`yarac` engine (`-w` and empty external variables). `config/policy.json` declares `engines[].min_version` `4.3.0`, but no code that reads that value was found; the real version is recorded (4.5.0 in the public log of the daily run). {{ev:EV-YC-32}}

### Dynamic checks (`scripts/dynamic_gate.py`, `scripts/bench.py`)

| Parameter | Value | Where |
|---|---|---|
| Repetitions per set | 5 | `dynamic.runs` |
| Minimum repetitions to compare | 3 (otherwise `inconclusive`) | `bench.compare` |
| Limit per scanned file | 10 s | `bench.measure_set` (`timeout_file`) |
| Abort after failures | 3 (hangs, crashes or errors) | `bench.measure_set` (`max_failures`) |
| Noise | threshold = max(3 × MAD, 25 % of the median, absolute floor) | `regression.*` |
| Absolute floors | CPU 0.5 s; RSS 25 MB; compile 0.5 s; scan p95 0.05 s | `policy.json` / `bench.compare` |
| No previous release: scan p95 | 2.0 s | `dynamic.absolute.max_scan_p95_s` |
| No previous release: scan RSS | 1500 MB | `max_scan_rss_mb` |
| No previous release: compile RSS / time | 3000 MB / 240 s | `max_compile_rss_mb`, `max_compile_wall_s` |
| Culprit isolation | delta debugging, budget 40; at most 3 rounds | `culprits`, `run` |

Measurements: time, CPU and peak memory per child process (`wait4`). {{ev:EV-YC-28}}

**Benign corpus and false positives.** The corpus is deterministic: 40 random files, 10 text files and up to 8 system binaries; plus 5 "canaries" carrying a test string. A rule file that fires on more than 5 % of the clean corpus (`hit_rate_limit=0.05` in `decide.py`, only if the corpus has ≥ 50 files) is sent to quarantine as `matches-benign-corpus`. All 5 canaries must be detected; otherwise nothing is published ("detection is not demonstrably working"). It is a small corpus: it measures gross genericity, not the real-world false-positive rate. {{ev:EV-YC-29}}

**Acceptance policy (`decide.py`).** Publishable only if: the approved set is not empty; there is an effective change against the previous release; the change does not exceed 15 % removed or 40 % touched (unless `allow_large_change`); the dynamic measurement was taken on exactly that set (`set_root`) with verdict `ok` or `no-baseline` and every canary detected; and the accounting adds up. A human approval lifts only judgement findings (`costly-regex`, `many-loops`, `filesize-loop`, `unknown-module`, `include`, `license-unchecked`, `matches-benign-corpus`, `dependency-not-validated`, `new-source`); never compile errors, truncation, corruption, a blocked module, a changed licence or dynamic failures. {{ev:EV-YC-27}}

**Platforms.** The reference engine runs on Linux; a `macos-15` job repeats the measurements with the engine MacGuard ships. There is no independent macOS virtual machine (`required_platforms` in the policy declares it "not available"). {{ev:EV-YC-28}}

### Adversarial and regression tests

`tests/test_rulecheck_adversarial.py` cuts a valid file at every position and requires every cut inside a rule to produce a blocking finding, applies 1500 random byte-damage cases without the analyser failing, tries Unicode and control characters and pathological inputs of up to 1,000,000 characters (nested regexes, unclosed braces, 3000 nested loops) with an 8 s bound that is a resource limit against hostile input, not an approval criterion. `tests/test_bench.py`, `tests/test_dynamic_gate.py` and `tests/test_decide.py` cover regressions, culprit isolation with the real engine, canaries and the 5 % limit. They run before every daily review and on every pull request. {{ev:EV-YC-30}} {{ev:EV-YC-37}}

## Check it yourself

- `python3 -m unittest tests.test_rulecheck tests.test_rulecheck_adversarial tests.test_bench tests.test_dynamic_gate tests.test_decide`
- Read [rulecheck.py](https://github.com/MacGuard/macguard-yara-channel/blob/main/scripts/rulecheck.py), [decide.py](https://github.com/MacGuard/macguard-yara-channel/blob/main/scripts/decide.py), [dynamic_gate.py](https://github.com/MacGuard/macguard-yara-channel/blob/main/scripts/dynamic_gate.py) and [policy.json](https://github.com/MacGuard/macguard-yara-channel/blob/main/config/policy.json).

## Limits

- The heuristics are approximations: they can let a slow regex through or set aside a harmless one.
- A rule that compiles and does not overload the engine is not proven to detect what it claims to detect.
- Keys in `policy.json` with no reader in the code reviewed: `engines.min_version`, `regex.quarantine_nested_quantifiers`, `dynamic.timeout_seconds_per_file` (the effective value, 10 s, is fixed in `bench.py`).

## State

| Capability | State |
|---|---|
| Static classification, dynamic gate and acceptance policy | operational {{ev:EV-YC-02}} |
| Persistent policy holds in the panel | implemented in `main`, not deployed {{ev:EV-YC-06}} |
| Independent macOS virtual machine | not available |
