# YARA Performance: when a correct rule is too slow

[Home](EN-Home) · [YARA Channel](EN-YARA-Channel) · [Sources](EN-YARA-Sources) · [Validation](EN-YARA-Validation) · [Quarantine](EN-YARA-Quarantine) · [Limits](EN-YARA-Limits)

## In 30 seconds

A rule can be well written, compile without errors and still make scanning a file take very long or use a lot of memory. The channel measures that cost with the real YARA engine, per rule file and per set, and sets aside whatever makes it worse. There is **no** end-to-end performance test between Installer Auditor and the live channel (planned, see below). {{ev:EV-YC-10}} {{ev:EV-YC-35}}

## An everyday example

It is like asking someone to compare every page of a book against a list of 1000 words. If one entry on the list says "find this word anywhere, then another one, at any distance", the reader has to go back over the page many more times. The book and the list are both correct; the total time is another matter.

## What is measured

{{diagram:perf-measurement}}

## Step by step

1. A safe, deterministic corpus is built (`bench.build_corpus`).
2. `yarac` compiles the set and the compile cost is measured.
3. `yara -p 1` scans each file (10 s limit per file); wall time, CPU and peak memory of each process are recorded.
4. This is repeated 5 times for the previous release and for the candidate, and the median is compared with the previous one's noise.
5. If there is a regression, the culprit files are isolated and the set is measured again.

## Under the hood

### Why a correct rule can be slow

Three harmless example patterns. They are illustrative; they are not channel rules and were not measured here against a particular file.

```yara
// EXAMPLE 1: nested quantifiers
rule Example_Nested { strings: $a = /(ab+)+c/ condition: $a }
// EXAMPLE 2: two open-ended stretches
rule Example_Open { strings: $a = /ab.*cd.*ef/ condition: $a }
// EXAMPLE 3: walking the whole file
rule Example_Loop { condition: for all i in (0..filesize-1) : ( uint8(i) == 0 ) }
```

- **Nested:** the shape `(x+)+` is the classic one that, in many regular-expression engines, produces an enormous number of combinations when the match fails. How YARA's engine behaves was not measured; the static review treats this shape as a risk signal and sends the file to review.
- **Open-ended stretches** `.*` with no anchor: make the engine keep looking across the file after every possible start. The static review sees such shapes only as approximate signals; the dynamic measurement is what observes the real cost.
- **Loop over the whole file:** a `filesize` of 100 MB means a hundred million iterations for every file scanned. `rulecheck.py` flags it as `filesize-loop`.

The static review (`analyse_text` in `rulecheck.py`) turns shapes like these into risk signals. It is an approximation and cannot replace the measurement with the real engine. Its scoring weights and thresholds are values in the code and in `config/policy.json`; they are explained in context on [Validation](EN-YARA-Validation), they can change, and they are not targets. {{ev:EV-YC-26}}

**Risk.** CPU and memory use on the machine of whoever scans and, if scanning is automatic, a possible **denial of service**: a hostile file or a slow rule that blocks the tool. Hence the time limits, the regression check against the previous release and the culprit isolation.

### What the channel really measures

- `scripts/bench.py`: compilation (time, CPU, RSS), scanning (p50, p95, p99, total CPU, peak RSS, errors, hangs, crashes), canaries and hits on the clean corpus. The corpus is small and synthetic (see [Limits](EN-YARA-Limits)). The report flags whether the percentiles have at least 50 samples (`min_samples_for_percentiles`, field `percentiles_reported`). Thresholds are on [Validation](EN-YARA-Validation). {{ev:EV-YC-28}}
- `scripts/macguard_smoke.py`: runs the `macguard-audit` CLI over the same corpus plus a `.app` bundle, a `.tgz` and a `.zip` built with system tools, with the **candidate** rules installed in a private directory, and reports crashes, hangs, errors, p50/p95/p99, peak memory and canaries detected. It runs in the `app-compat` job of `daily.yml`, which **reports and does not decide** publication. {{ev:EV-YC-34}}
- **Numbers stored in the repository:** the public log (`logs/log.jsonl`) stores, for every daily review with a measurement, `scan_p95_s`, `scan_rss_peak_mb` and `compile_rss_mb`. Across the 10 entries with a measurement (2026-10-18 to 2026-10-22, YARA engine 4.5.0): scan p95 between 0.1676 and 0.1988 s; scan peak RSS between 84.3 and 86.6 MB; compile RSS between 72.7 and 73.7 MB; gate duration between 81 and 174 s. These are measurements on a CI runner, not performance promises for a Mac. {{ev:EV-YC-33}}
- `docs/audit/root-cause-benign-hit-count-2026-10-20.md` stores a comparison in a shared container: scan p95 0.54 s (baseline) and 0.46 s (candidate); compile 6.19 s and 4.94 s; absolute times were about five times worse than on the runner, according to the document itself. {{ev:EV-YC-33}}

### What has NOT been measured

- **There is no end-to-end performance test of Installer Auditor with the live channel.** State: planned. {{ev:EV-YC-10}} {{ev:EV-YC-35}}
- **A rule benchmark does not prove the absence of race conditions.** The bench scans one file per process, sequentially (`-p 1`). Races (updating rules during a scan, two scans at once, atomic install) need their own concurrency tests. What exists in the app is a unit test that a second simultaneous rules update is refused (`testSecondConcurrentUpdateIsRefused`); it is not a test of scanning during an update.

### How it should be tested (proposal, not implemented)

1. Install the latest channel release on a real Mac with the client as people use it, not with hand-copied rules.
2. Scan a representative set (installers, packages, large files, archives) measuring time, CPU and memory, with and without the channel's rules, and compare with the previous channel release.
3. Repeat with several simultaneous scans and with a rule update in the middle of a scan, looking for deadlocks, mixed results or half-written files.
4. Failure criteria based on crashes, hangs, wrong results and degradation against the baseline; a bare duration is not used as an approval criterion.

## Check it yourself

- `python3 -m unittest tests.test_bench tests.test_dynamic_gate` (needs `yara` and `yarac`; includes a rule that blocks the engine and shows up as a hang).
- `python3 scripts/bench.py --help` and `python3 scripts/dynamic_gate.py --help`.
- Entries with measurements in [logs/log.jsonl](https://github.com/MacGuard/macguard-yara-channel/blob/main/logs/log.jsonl).

## Limits

- The corpus is small and synthetic; it does not represent any one person's real files.
- CI figures are not extrapolated to other machines.
- The noise thresholds are documented starting points, not performance guarantees.
- The gates exist to protect the machines that scan. The numeric values come from `config/policy.json`, can change, and are limits for review, not goals for rule authors.

## State

| Capability | State |
|---|---|
| Rule measurement with the real engine (compile, scan, regression, canaries) | operational {{ev:EV-YC-28}} |
| CLI smoke test with the candidate rules | operational (reports, does not decide) {{ev:EV-YC-34}} |
| End-to-end performance test with Installer Auditor and the live channel | planned {{ev:EV-YC-10}} |
| Concurrency tests between scanning and rule updates | planned {{ev:EV-YC-35}} |
