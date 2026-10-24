# ADR-0002 — Autonomous pipeline with quarantine

Status: accepted for implementation; **autonomous publication is OFF** until the evidence below is produced in production.

> **Note (2026-10-22): superseded in part.** Autonomous publication is no longer OFF: the owner switched `AUTO_PUBLISH=true` on (RR-16, decided 2026-10-19; see `docs/audit/RESIDUAL-RISKS.md`), so `publish.yml` uses `stable-signing-auto` (no required reviewer). The decision record below is kept as written.

## What runs where
| Stage | Where | Output |
|---|---|---|
| Fetch pinned upstream commits, licence evidence | `daily.yml` job `review` (ubuntu) | `candidate.json` |
| Static classification VALIDATED / QUARANTINED / REJECTED / DEPRECATED | `scripts/rulecheck.py` | integrity, truncation, compile, dependencies, modules, regex and condition cost, licences |
| Reviewer decisions | `scripts/quarantine_client.py` → private service | approvals, rejections |
| Decision | `scripts/decide.py` | approved set, exclusions, retired, withheld |
| Dynamic gate | `scripts/dynamic_gate.py` + `scripts/bench.py` | CPU, memory, latency p50/p95/p99, crashes, timeouts, canary detection, benign-corpus hit rate; baseline vs candidate in the same job; culprit isolation (delta debugging), quarantine of only the culprits, re-measure of the new set |
| macOS runner check | `daily.yml` job `macos` | the same measurements with the reference YARA engine on macOS. The MacGuard CLI smoke runs in the separate job `app-compat`, an external report |
| Publish | `publish.yml` | re-verification of the final set, Sigstore keyless signing, draft → public release |
| Site | `site.yml` | verified deployment, live verification |

## Hard rules (each one has an automated test)
* A human approval waives only judgement findings (`costly-regex`, `filesize-loop`, `many-loops`, `unknown-module`, `include`, `license-unchecked`, `matches-benign-corpus`, `dependency-not-validated`). Compile errors, truncation, corruption, crashes, timeouts, a changed licence and an identical previously rejected file cannot be approved away (`tests/test_decide.py`).
* A dynamic result counts only if its `set_root` equals the root of the set being published (`decide.py`, re-checked in `publish.yml`).
* Rejected bytes are never re-admitted; edited bytes are a new candidate linked by path.
* A previously published file that now fails is withheld, never silently kept.
* The quarantine service is optional: if it is unreachable the safe default applies (nothing quarantined is published) and the pipeline reports it.
* Quarantined names, findings, compiler output, culprits and per-rule hit counts never leave the job except to the private service: artifacts of a public repository are public (`scripts/make_public_candidate.py`, tested for leaks). The public log and site carry counts only.

## Publication policy (explicit)
| Check | If it did not run |
|---|---|
| static classification of every file | blocks |
| Linux engine dynamic gate on exactly the final set | blocks |
| detection canaries all detected | blocks |
| macOS runner engine check (`macos`) | blocks (the `request-publish` job needs it) |
| MacGuard CLI smoke (`app-compat`) | does not block: the application is not a requirement for a release |
| independent macOS VM | **not available**: hosted macOS runners are VMs with no nested virtualization (`runner-probe.yml`: `Apple M1 (Virtual)`, 3 CPU, 7 GiB, `hv_vmm_present=1`, no Hypervisor.framework). Not blocking, reported as `not_run` in every dynamic result. A self-hosted bare-metal Mac with Tart/Virtualization.framework is needed to close it. |
| quarantine service reachable | does not block (nothing unreviewed is published either way) |

## Switching human approval off
`publish.yml` runs in environment `stable-signing` (required reviewer) unless the repository variable `AUTO_PUBLISH` is `true`, in which case it uses `stable-signing-auto` (same branch policy, no reviewer). Do it only after: the quarantine service is deployed, one real daily run has produced a decision, a real change has gone through the manual path end to end, and the checks in `docs/OPERATIONS.md` §"Before enabling AUTO_PUBLISH" are green. The signing identity (`publish.yml@refs/heads/main`) and all technical checks are identical in both modes.

## Known limits
* Performance thresholds are measured against the previous release on the same runner with MAD-based noise, not from a fleet of reference machines. Until there are several releases the history is short; with no previous release only generous sanity limits apply.
* The YARA CLI cannot show leaks; only peak RSS and its trend are measured.
* MacGuard does not bundle a YARA engine yet, so "MacGuard with YARA" is approximated by the engine on the same machine plus the MacGuard CLI over the same corpus.
* The corpus is synthetic and system files plus canaries. Detection quality of upstream rules is not measured.
* Licence texts of the upstream sources are checked but not yet bundled in the release.
