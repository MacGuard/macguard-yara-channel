# Root cause: one benign file counted once per namespace copy (2026-10-20)

Four rule files that pass every technical check were held back from the release by the dynamic gate, with the reason `matches-benign-corpus`
(one file) and `dependency-not-validated` (the three files that depend on it). The cause was a counting defect in `scripts/bench.py`, not a property of
the rules. The names of the affected files are private by policy and are not in this document; the reproduction below uses synthetic rules.

## What was observed

- Release `rules-20261018-39150886414` has 1174 files; the static classification passes 1178 files, and the dynamic gate removed four of them.
- The first quarantine acceptance run (`39491935000`) delivered the reasons to the panel: one file `matches-benign-corpus`, three `dependency-not-validated`
  whose `depends_on` is that file. The three are held back only because of it.
- A local reproduction found no hit on the clean corpus (a Mac has Mach-O system binaries, the runner has ELF ones), so the cause was invisible locally.

## Root cause

1. **The clean corpus contains real system binaries** (`bench.build_corpus`: `/bin/ls`, `/bin/cat`, `/bin/sh`, `/usr/bin/awk`, …). On the hosted runner
   `/usr/bin/awk` is `gawk`; one rule of the file matches that single binary.
2. **`compile_set` loads one namespace per rule file and copies into it every file it depends on.** A file with three dependents is therefore compiled
   four times: in its own namespace and in each dependent's.
3. **`detections` counted one hit per output line of `yara`** and keyed them by bare rule name. One benign file matched through four copies is four lines:
   `4 / 58 = 6.9 %`, above the 5 % limit (`decide.py`, `hit_rate_limit`), although the true figure is `1 / 58 = 1.7 %`.
4. `hits_known` then attributed hits through `by_rule = {rule name: path}`, where the **last** file defining a name wins. Upstream repeats rule names across
   files (hundreds of overlaps), so a rule could be credited to a different file than the one that matched. This is a second defect with the same origin:
   a generic rule could hide behind a same-named rule in another file.

Why the gate stayed green: excluding files is the safe direction. The defect only ever removed rules from a release.

## Reproduction (synthetic, `ubuntu:24.04`, `yara` 4.5.0 from apt)

```
docker run --rm -v "$PWD":/repo -w /repo ubuntu:24.04 bash -c \
  'apt-get update -qq && apt-get install -y -qq yara python3 gawk && \
   python3 -m unittest tests.test_bench tests.test_dynamic_gate'
```

`tests/test_bench.py::HitCountingEngineTests` builds the structure above (a rule file, three files that depend on it, one benign file that matches it) and shows
that the engine prints four lines for that one file. `tests/test_dynamic_gate.py::BenignHitRateTests` runs the real gate on the same structure.

| Code | Run of the new tests on `ubuntu:24.04`, `yara` 4.5.0 |
|---|---|
| before the fix (`main`) | 12 tests: **3 fail** (one benign file makes the rule generic; the 5 % limit counts 16 for 4 files; a generic rule hides behind a same-named one) and 8 cannot run because the functions do not exist |
| with the fix | **12 / 12 pass** |

## The fix

- `rule_owners` maps each namespace to the file that defines each rule in it. `yara -e` prints the namespace, which is how a copy is told apart.
- `detections` returns, per logical rule (`defining path::rule name`), the sorted set of **distinct** corpus files it matched. A match that cannot be placed
  is keyed `?::rule` and merges every namespace, so the count can only be higher than the truth, never lower.
- `benign_hits_by_file` keeps the figure `decide.py` already compared with the limit: the most distinct clean files any one rule of a file matched.
  Nothing else changed: the limit stays at 5 %, the corpus is the same, no case is excluded.

## Proof that the limit still holds

`tests/test_dynamic_gate.py::BenignHitRateTests`: a rule matching four distinct clean files through four namespaces counts **4** (not 16, not 1) and the file
and its dependents are quarantined (4 / 62 = 6.5 %); matching three files counts 3 and stays under the limit (3 / 61 = 4.9 %); a generic rule that matches the
ten text files of the corpus is quarantined even when another file defines a rule with the same name.

## Whole set, before and after (`ubuntu:24.04`, `yara` 4.5.0, `gawk`; same `dist/`, previous release as baseline)

| | before (`main`) | after (fix) |
|---|---|---|
| examined / accepted / quarantined / rejected | 1184 / 1174 / 6 / 4 | 1184 / **1178 / 2** / 4 |
| gate iterations | 2 (the first measure marks four files as too generic) | 1 |
| hits attributed to the affected file | 4 | **1** |
| canaries | 5 / 5 | 5 / 5 |
| culprits | none | none |
| `publishable`, blockers | false, "no effective change" | **true, none** |
| change against the latest release | none | 4 added, 0 modified, 0 removed (0.34 %; limits 15 % removed, 40 % changed) |
| dependency closure of the set | complete (7 files with dependencies, all of what they need is in the set) | complete (10 files with dependencies, all of what they need is in the set) |

Performance, median of 5 runs against the baseline's own noise (the container shared its CPU with another job, so absolute times are about five times
slower than on the runner; the comparison with the baseline measured in the same conditions is what counts):

| | baseline | candidate | verdict |
|---|---|---|---|
| compile wall time | 6.19 s | 4.94 s | not regressed (noise MAD 0.44, threshold 1.55) |
| compile RSS | 72.7 MB | 73.7 MB | not regressed (threshold 25 MB) |
| scan p95 | 0.54 s | 0.46 s | not regressed |
| scan RSS peak | 86.2 MB | 87.0 MB | not regressed |
| compiled size | 19.41 MB | 19.98 MB | +2.9 % |
| errors / timeouts / crashes | 0 / 0 / 0 | 0 / 0 / 0 | |

## Effect in production

With the fix on `main`, the next review reproduces the 1178-file set and, because the set differs from the latest release and `AUTO_PUBLISH=true`, the daily
run requests a release that **adds four rule files** and removes none. Nothing in D1 is changed: the four are `PENDING` candidates in the panel and the
decisions are untouched. To check it first without publishing, run `daily.yml` with `acceptance=true` (`request-publish` is unreachable then) after merging.

## Remaining risks

- The comparison above was measured on a shared machine; the authoritative run is the acceptance run on the hosted runner.
- The corpus still depends on the system binaries of the runner image. A change of image can change which files match; this is unchanged by the fix and is
  visible in `benign_hits_by_file`.
- The counting key relies on `yara -e` (namespace in the output). The tests fail if a future yara stops printing it, and unplaced matches fall back to the
  conservative key.
