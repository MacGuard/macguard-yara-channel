# Python regression runs kept as evidence (none is overwritten or discarded)

Raw logs are preserved outside the temporary directory in `~/macguard-evidence/2026-10-24/` (not in the repository: they contain machine paths and Python resource warnings). This table is the durable summary.

| Run | Interpreter | Tree | Result | Notes |
|---|---|---|---|---|
| `py-regression.log` | system Python 3.9 | `853d182`+ | 545 run, **11 failures, 5 errors**, 10 skipped | 15 are identical at the base commit `78b1132` (3.9 has no `tomllib`; `scripts/rulecheck.py` uses 3.12 f-string syntax). 1 was this work (Community-paths guard), fixed in `fc98933` |
| `py313-regression.log` | Python 3.13 | `fc98933` | **588 run, OK**, 10 skipped | the historical 588 reproduced |
| `py313-final.log` | Python 3.13 | `a243a8f` | 594 run, **2 errors**, 10 skipped | `test_dynamic_gate.BenignHitRateTests` (`KeyError: benign_hits_by_file`), machine load average above 60 (other agents plus my own Node runs). Module alone: 11/11. Not touched by this branch at that time |
| `py313-final2.log` | Python 3.13 | `6b245b3` | **594 run, OK**, 10 skipped | machine quiet |

Root cause of the two errors (found by reading `scripts/dynamic_gate.py`): when a candidate has no baseline, absolute timing limits (`max_scan_p95_s`, per-file timeout) decide the verdict; on an overloaded machine the verdict flips to `regression`, the loop isolates "culprits" and returns a failed result **without** `benign_hits_by_file`. The tests were about hit-rate arithmetic, not speed. Fixed in `e075dcc`: the two tests use generous timing limits, a failed run now has one stable shape with `failure_kind` (`performance` / `functional`) and `load`, and three timing-independent tests cover it. Not changed: publication decisions (a failed run never publishes). Residual: `GateTests` still use tight timing limits on purpose (they test slow-rule isolation) and passed in every run so far, but could flake on a very loaded machine.

## Fifth full pass (2026-10-24, after the performance-limit tests and the staging/offsite tooling)
| Run | Interpreter | Tree | Result | Notes |
|---|---|---|---|---|
| `py313-full-b6a1b73.log` | Python 3.13 | `b6a1b73` (the docs-only commit `88d8bdd` follows it) | **605 run, OK**, 10 skipped | 601 + 4 new tests (`AbsoluteLimitTests`). Taken on a machine at load average 80–160 from other sessions (1,322 s), so it also shows the acceptance tests no longer depend on machine speed. Companion log `py313-gate-bench-47-d6de314.log`: the gate and bench modules alone, 47 OK. |

## Sixth full pass (2026-10-24) on the new SHA
| Run | Interpreter | Tree | Result | Notes |
|---|---|---|---|---|
| `py313-full-550f0c0.log` | Python 3.13 | `550f0c0` (docs-only commit `3810784` follows) | **605 run, OK**, 10 skipped | no Python file changed since `b6a1b73`; run again on the new SHA as asked, 885 s at load 26-41 |

## Seventh full pass (2026-10-24) on `e4bd426`
| Run | Interpreter | Tree | Result | Notes |
|---|---|---|---|---|
| `py313-full-e4bd426.log` | Python 3.13 | `e4bd426` | **608 run, OK**, 10 skipped, `exit=0` | 605 + 3 new tests (`RealMatrixTests`); 1,230 s. Counts read from the log (`Ran 608 tests`, `OK (skipped=10)`, `exit=0`). |

## Eighth full pass (2026-10-24 night): unified branch `feat/unified-pipeline`
| Run | Interpreter | Tree | Result | Notes |
|---|---|---|---|---|
| `py313-full-unified-2422c2c.log` | Python 3.13 | `2422c2c` | **955 run, OK**, 14 skipped, `exit=0` | analytics + intelligence stacks together; 1,168 s at load average 120-165 from other sessions. Node on the same tree: `node-full-unified-2422c2c.log` 212/212; workerd 9/9 (`workerd-unified-2422c2c.log`). An earlier Node run on `0f56770`'s parent failed 1 test (`core.test.js`, 4.6 % false failure by construction); the assertion was fixed and the run above is the clean one. |

## Ninth full pass (2026-10-24 night): `feat/sources-monitoring` at `0865e72`
| Run | Interpreter | Tree | Result | Notes |
|---|---|---|---|---|
| `py313-full-0865e72.log` | Python 3.13 | `0865e72` | **986 run, 1 failure**, 14 skipped, `exit=1` | the failure was the generated-document drift test (`test_premium.RealMatrixTests.test_the_source_matrix_is_current_and_agrees_with_the_gate`): Suricata gained a connector, so `SOURCE-MATRIX.md` had to be regenerated; done, and `tests.test_premium` re-run OK. A clean full pass on the final SHA is recorded in the next row. 1,671 s at load average 85-106 from other sessions. |


## Tenth full pass (2026-10-24 night): `feat/sources-monitoring` at `11c7eab`
| Run | Interpreter | Tree | Result | Notes |
|---|---|---|---|---|
| `py313-full-11c7eab.log` | Python 3.13 | `11c7eab` | **1012 run, OK**, 14 skipped, `exit=0` | 1,600 s. The later commit `0077ab1` only aligns the `sigmahq` registry status and regenerates `web/api/v1` (4 files); on it `source_matrix --check`, `gen_intel_web --check`, `tests.test_premium` and `tests.test_web_intelligence` (70 tests) were re-run and pass. |

## Eleventh full pass (2026-10-25): `feat/community-telemetry` at `c53f005` (+ guard fix `46b069a`)
| Run | Interpreter | Tree | Result | Notes |
|---|---|---|---|---|
| `py313-full-c53f005.log` | Python 3.13, `MG_SURICATA_BIN` set (real engine) | `c53f005` | **1038 run, 1 failure**, 14 skipped, `exit=1` | the failure was a guard test that forbade any workflow naming the premium builder; the owner-authorised Intelligence workflow legitimately does. The guard now allows exactly that one manual-only file (`tests/test_premium_gateway.py`); that test file (7 tests) passes on `46b069a`. 1,448 s |
| Node admin / workerd / UI (3 engines) / UI panel / gateway | Node | `46b069a` | first run **248/250**: two tests assume "an hour ago" is the same UTC day, which is false in the first hour after 00:00 UTC (the run happened at 00:2x UTC). Cause found, not retried: the feeds world now runs on a fixed midday clock and default pipeline tokens follow the world clock (`test/helpers.js`, `test/feeds_helpers.js`). After the fix: admin **250/250 twice**, workerd 16/16; UI feeds 3 engines 18/18, UI panel (Chromium) 19/19 (the previous round reported these two numbers swapped; the logs say 18 and 19); gateway 218/218 | logs `node-admin-46b069a.log` etc. |

## Twelfth full pass (2026-10-25, second part): `feat/community-telemetry` at `f0814c2`
| Run | Tree | Result | Notes |
|---|---|---|---|
| `py313-full-f0814c2.log` (Python 3.13, `MG_SURICATA_BIN` set: real Suricata 8.0.7 and real YARA) | `f0814c2` | **1116 run, OK**, 14 skipped, `exit=0` | 890 s. An earlier full pass at `ebc3d8f` had **3 failures**, all legitimate guards that my change tripped (the production allow-list `PIPELINE_WORKFLOWS` guard ×2 and the "no unexpected CI secret" guard): the production configuration was restored to `daily.yml,publish.yml` and the single new secret `TELEMETRY_REPLAY_KEY` is allowed only in `telemetry-replay.yml` and tested as such (the guards were not relaxed otherwise). |
| Node admin / workerd / UI feeds (3 engines) / UI panel (Chromium) / gateway | `f0814c2` | **265/265**, **16/16**, **21/21** (7 tests × 3 engines, WCAG 2.2 AA), **19/19**, **223/223** | logs `node-admin-f0814c2.log`, `workerd-admin-…`, `ui-feeds-3engines-…`, `ui-panel-chromium-…`, `node-gateway-…` |
| later commits `7efb9d1`, `173fd8b` | – | tests, `.gitignore` and documents only; `tests.test_telemetry_step` and `tests.test_telemetry_replay` re-run OK | the full suites were not repeated for them |
