# Validation plan per technology (DESIGN)

**Resumen (ES).** Plan de validación por tecnología: para cada una, un validador modular y bancos de prueba SEPARADOS, qué existe hoy en este repositorio (con rutas) y qué está «planned». Hoy el canal valida con YARA clásico (`yarac`) y su manifiesto dice `validation.engine: yara`; YARA-X solo figura como entrada de motor (`kind: engine`) en `config/sources.json`, así que el validador YARA-X se diseña como una puerta ADICIONAL, no como reemplazo. Regla firme: **no se ejecuta malware real en CI compartido**. Se define el material de prueba permitido (EICAR, fixtures sintéticos, benignos parecidos), dónde pueden vivir muestras reales (infraestructura aislada, sin conexión, del propietario) y quién las autoriza. Un resultado de validación se convierte en una «attestation of tests» firmada con Sigstore sin clave desde el workflow de publicación; hoy NO se producen attestations de GitHub/SLSA. Los resultados son PASS/FAIL/SKIP y un SKIP nunca cuenta como PASS. Esto es un diseño: no autoriza construir ni desplegar nada.

Status vocabulary: **operational** = produced and tested by the pipeline in this repository today (path cited); **experimental** = code exists but is unproven or partial; **planned** = design only. Where a claim says "exists", a path is cited. Everything else is planned.

Note on the worktree: other work items are adding an `intel/` package and `config/intel/` (untracked in this worktree when this document was written; its `intel/__init__.py` lists the families yara, yara-x, sigma, ioc, clamav, heuristics, behavior, ml, sandbox). Those files were not reviewed or run for this plan, so none of them is counted as an existing validator here.

## 1. What validation means today (verified)

| Step | Where | What it proves | What it does not prove |
|---|---|---|---|
| Compile every rule file with classic YARA | `scripts/validate.py` (`yarac -w`, externals declared); writes `dist/validation.json` with `"engine": "yara"`; `scripts/seal.py` copies `{checked, engine}` into the signed manifest as `validation` | The rule file parses and compiles with YARA 4.x | Detection quality, false positives, safety |
| Static admission | `scripts/rulecheck.py` (states VALIDATED, QUARANTINED, REJECTED, DEPRECATED; regex-risk, condition-risk, module allow/block-list from `config/policy.json`, truncation/corruption, licence) | Hard criteria; judgement findings only quarantine | Runtime cost |
| Licence evidence | `scripts/licensing.py`, `config/policy.json` `licenses` | Expected SPDX / marker / hash of LICENSE text per source | Legal advice; the README states licence review is not automated |
| Dynamic benchmark | `scripts/bench.py`, `scripts/dynamic_gate.py`, `scripts/decide.py` | Compile cost, load+scan latency, CPU and peak RSS via `wait4` rusage, crashes/timeouts, detection of 5 harmless canary files (`MACGUARD-CANARY-i-DETECT-ME`), hit rate on a deterministic benign corpus, comparison against the last approved set (medians vs MAD) | Detection of real malware |
| Accounting | `scripts/accounting.py` | `examined = accepted + quarantined + rejected + deprecated` per run | |
| Human gate | `publish.yml` environment `stable-signing`; quarantine panel `admin/worker/` | A human approves a release | |
| Signing and log | `publish.yml` (cosign keyless), `scripts/tlog.py`, `scripts/verify_release.py`, `scripts/verify_public_release.py` | Integrity and origin of the published set | Test results (they are not signed as such today) |
| App engine tests | `DMGTrustAuditor/DMGTrustAuditor/Tests/` (`YARAEngineTests.swift`, `TrustAndInstallerTests.swift`, `ContentDetectorTests.swift`, `ChannelVerifierTests.swift` and others), run by `.github/workflows/app-tests.yml` | Engine integrity checks and installer failure matrix on a macOS runner | |

Facts that constrain the design:
- **The channel validates with classic YARA/`yarac`.** `config/sources.json` has `{"id":"yara-x","repo":"VirusTotal/yara-x","kind":"engine"}`: YARA-X is tracked as an engine entry only, never a rule feed, and never used to validate. The released manifest's `validation.engine` is `yara`.
- **There is no Sigma, ClamAV, IOC, heuristic, behaviour, ML or sandbox validator** in the committed code. Searches for `sigma`, `clamav` and `pysigma` in tracked files found nothing outside the untracked `intel/` work above.
- **No test result is attested today.** `publish.yml` signs `manifest.json` and the log checkpoint with `cosign sign-blob` (keyless); it has `id-token: write` for that. It does not call GitHub artifact attestations or a SLSA generator; the manifest records only `{checked, engine}`.

## 2. Architecture of a validator (planned)

Each technology gets two separate things, in separate directories and separate CI jobs, so a bench never changes what a validator decides:

1. **Validator** (`validators/<tech>/`, planned): a pure, deterministic module with the interface `validate(input_set, config) -> Result`. It never fetches the network, never executes sample content, and writes only into its own output directory. Result contains per-item outcomes, tool versions, input hashes and a summary.
2. **Test bench** (`benches/<tech>/`, planned): corpora, fixtures, expected outcomes and performance harnesses. A bench *exercises* a validator; its fixtures are versioned, hashed, and listed in a bench manifest.
3. **Gate**: the rule that turns a Result into block / quarantine / allow, in `config/` policy (planned `config/validation-gates.json`). A gate can be tightened without code changes; loosening it is a critical policy change approved by a human.

Run cadence, following the repository standard: FAST after small changes, INTEGRATION before integrating, FULL before releasing. Measure before adding corpora; never reduce coverage or use a duration as a PASS criterion. Parallel benches are planned with `engctl sched plan` first, each with its own worktree and paths (`CLAUDE.md` rules).

## 3. Reporting: PASS / FAIL / SKIP

- Outcomes: `PASS`, `FAIL`, `SKIP` (with mandatory machine-readable reason), `ERROR` (tool failure, not a verdict on the input), `NOT_IMPLEMENTED`.
- A `SKIP` is **never** counted as a `PASS`. Summaries print the four counters separately and the headline is `incomplete` whenever `SKIP + ERROR + NOT_IMPLEMENTED > 0` in a mandatory gate.
- A gate marked mandatory with `SKIP` blocks publication of that item the same way as `FAIL`, unless a recorded exception exists (`.engineering/exceptions.json`: reason, human approver, expiry).
- This follows the convention already used in the tests: skipped tests carry an explicit "a skipped test is not a pass" reason (`tests/test_bench.py`, `tests/test_archive_providers.py`).
- No technology may display "tested" on the web unless its bench produced PASS for the mandatory gates in the run that is attested (see section 5).

## 4. Test material policy (planned, mandatory)

**Rule: NO real malware is executed on shared CI** (GitHub-hosted runners, any runner shared with other jobs, or any runner that also holds publishing identity). Shared CI never receives real malware samples either as files, as repository content or as downloaded artefacts.

Allowed on shared CI:
- The **EICAR** standard antivirus test string (and its archive variants) for engine plumbing.
- **Synthetic fixtures** authored in this repository: files containing a unique harmless marker, like the `MACGUARD-CANARY-i-DETECT-ME` canaries already used by `scripts/bench.py`; synthetic event logs; synthetic IOC lists using reserved or documentation ranges (RFC 5737 IPs, `.example`/`.invalid` domains, hashes of synthetic bytes).
- **Benign look-alikes**: harmless files that share structure with malware (packed but benign installers, scripts using sensitive APIs, signed system binaries such as the ones `bench.py` already uses as a clean corpus) to measure false positives.
- Pre-generated *detection fixtures* that are inert by construction (a rule matches a marker string in a text file, not live code).

Real samples:
- May exist only on **isolated, offline, owner-controlled infrastructure** (an air-gapped or egress-denied host or VM that is not a CI runner and holds no signing identity or secrets). They are never committed, never uploaded as workflow artefacts, never mirrored to Pages.
- Authorisation: **the repository owner (Diego Muiño) must approve in writing, per corpus**, recording purpose, source, legal basis, storage location, retention and who has access. The approval is a file in the private evidence store, referenced by hash from the bench manifest; the authorisation itself is not an automated decision and nobody else (including an agent report) can grant it.
- Results from such an isolated bench enter the pipeline only as a **summary document** (counts, rule ids, hashes of sample IDs) that the owner signs or places via a reviewed change. The public record says "evaluated offline on an owner-held corpus" and never claims CI evidence for it.
- Samples handled by hash only wherever possible; defanged storage; no execution outside the sandbox bench (section 6.8).

Sample authorisation, hashing and access logs are an open point (see final report).

## 5. From a validation result to an attestation of tests (planned)

Today nothing of this exists. Design:

1. A validator run produces `results.json` (per-item outcomes, summary counts including SKIP/ERROR, wall-clock timestamps in UTC).
2. The publishing workflow assembles an **attestation of tests** document, canonical JSON, containing:
   - **Tool versions**: validator version, engine versions (e.g. YARA from `yarac --version`, YARA-X, pySigma, ClamAV), OS image, Python version.
   - **Inputs' hashes**: SHA-256 of each rule/IOC/signature set validated (the same hashes the manifest already carries per file), of the fixtures and corpora (bench manifest hash), of the gate policy, and the git commit of the validator.
   - **Result summary**: counters PASS/FAIL/SKIP/ERROR/NOT_IMPLEMENTED per gate, the headline verdict, and the list of skipped gates with reasons.
   - **Scope statement**: what was *not* tested (for example "detection of real malware not evaluated on CI").
   - **Predicate subject**: the manifest SHA-256 (and `rules_root`) the tests were run against, so a result cannot be reused for another set (the same principle `decide.py` applies: "the dynamic result must belong to exactly the final set").
3. The document is signed **keylessly with Sigstore from the publishing workflow** (`cosign sign-blob --bundle`, identity `publish.yml@refs/heads/main`), exactly like `manifest.json` today, and shipped as a release asset (planned name `tests-attestation.json` + `tests-attestation.sigstore.json`). It is appended to the transparency log (`scripts/tlog.py`) as a new entry type (planned).
4. Verification: planned extension of `scripts/verify_release.py` / `scripts/verify_public_release.py`, plus `mgctl attest verify` (currently planned, exits 4).
5. **GitHub artifact attestations and SLSA provenance are NOT produced today.** If adopted later, they would be additional, not a replacement: an in-toto statement with the above as predicate. Until then the Web must not display "SLSA" or "GitHub attested" anywhere.
6. An attestation says "these tests ran on these inputs with these tools and gave this result". It does not say the rules detect anything well.

## 6. Per-technology design

Common columns used below: **Gate** (what blocks), **Bench** (separate corpus/harness), **Evidence** (artefact stored and attested), **Today**.

### 6.1 YARA (classic) and YARA-X

**Classic YARA (exists, operational).** `validate.py` + `rulecheck.py` + `bench.py` + `dynamic_gate.py` (cited in section 1). Stays the authoritative gate. The manifest keeps `validation.engine: yara`.

**YARA-X (planned, additional gate; not a replacement).**
- Rationale: YARA-X is VirusTotal's Rust reimplementation, tracked as an engine entry in `config/sources.json`. Its compatibility with the rule corpus is unknown until measured. Adopting it as the only validator would change the guarantee published in every manifest; therefore it runs *in addition*, reports separately (`validation.yara_x`, planned manifest field, additive), and a rule that compiles in YARA but not in YARA-X is marked `yara_x: incompatible`, **not rejected**.
- Validator modules (planned):
  1. *compile*: compile each file with YARA-X; record warnings and errors with codes.
  2. *compatible rules*: per file, set `compat = both | yara_only | yara_x_only | neither`; list the incompatibility class (module not supported, syntax difference, external variable handling).
  3. *behavioural parity*: scan the same corpora with both engines and compare match sets rule by rule; any difference is a finding with both outputs.
  4. *false positives*: scan a benign corpus (as `bench.py` already does for classic YARA) and count hits.
  5. *latency and memory*: measured per process through `wait4` rusage as `bench.py` does; compared against the classic-YARA baseline under the same conditions; no fixed time is a PASS criterion.
  6. *tests with Installer Auditor*: run the YARA-X engine behind the same interface the DMGTrustAuditor app uses (`Core/` engine abstraction; engine checks documented in `docs/ENGINE.md`) against the installer fixtures in `DMGTrustAuditor/DMGTrustAuditor/Tests/` (`TrustAndInstallerTests.swift`, `ContentDetectorTests.swift`). Today the app ships a pinned, ad-hoc-signed classic YARA 4.5.8; shipping YARA-X in the app would be a separate decision with its own engine manifest.
- Bench: benign corpus (shared with classic bench), detection fixtures (synthetic marker files and EICAR), installer fixtures.

### 6.2 Sigma
- Validators (planned): *syntax/schema* (YAML parse, Sigma specification schema, required fields, UUID id, dates); *pySigma compatibility* (parse with pySigma, record version, errors); *supported backends* (convert with each chosen backend and pipeline; record per-backend `convertible | unsupported | error` instead of dropping rules silently); *event replay* (run converted/native evaluation of the rule over recorded synthetic event logs, expected match / no-match per case); *temporal order and correlation* (Sigma correlation rules: ordering, time windows, group-by, thresholds on synthetic timelines including edge timestamps).
- Bench: synthetic event logs (EVTX-like JSON, macOS unified-log-like JSON, Linux auditd-like JSON) with expected outcomes; benign logs for false positives.
- Today: none.

### 6.3 ClamAV
- Validators (planned): *verify original CVD/CLD signatures* (verify the vendor digital signature of `main/daily/bytecode` CVD files with `sigtool`/ClamAV and compare against the mirror's hashes; never repack or edit); *integrity* (SHA-256 per file, size, header fields `sigtool --info`); *engine compatibility* (functionality level vs the pinned `clamscan`/`libclamav` version); *load test* (database loads, no warnings, memory footprint); *detection test* (EICAR and synthetic ClamAV-compatible fixtures such as a harmless LDB/NDB test signature on a marker file); *benchmarks* (load time, scan time, peak RSS via `wait4`); *redistribution review* (see below).
- **Redistribution review is a human gate, not a script**: the ClamAV engine is GPL-2.0, while signature databases are distributed by Cisco/Talos under their own terms and the official mirrors ask users not to mirror via unofficial channels. Before the channel ever redistributes CVD files, the owner reviews the current terms, records the decision and the source/date, and the licence registry marks `redistribution: unknown` until then. Default plan: the channel **points to the official mirrors and verifies, it does not rehost**.
- Bench: EICAR, synthetic marker fixtures, benign look-alike corpus.
- Today: none.

### 6.4 IOC (indicators)
- Validators (planned): *format* (type-specific: IPv4/IPv6, domain per IDNA, URL parse, hash length/hex, with explicit rejection of private/reserved ranges unless flagged); *normalisation* (lowercase, strip trailing dots, defang/refang, canonical URL, punycode); *dedupe* (by normalised value+type, merging provenance and keeping the highest-confidence source); *reputation* (cross-check against allow-lists of known-benign infrastructure such as major CDNs and public resolvers); *source confidence* (per-source score from policy, never invented per item); *TTL/expiry* (`first_seen`, `last_seen`, `expires`; expired items are excluded from the active set and reported); *false positives* (replay against a benign corpus of domains/IPs/hashes).
- Bench: synthetic IOC lists using documentation ranges and `.example` domains, benign allow-list fixtures.
- Today: none in committed code (untracked `intel/ioc.py` in this worktree is not reviewed here).

### 6.5 Heuristics
- Validators (planned): *unit tests* per heuristic with named inputs and expected score; *benign/malicious test files* (benign look-alikes and synthetic marker files only on CI); *thresholds* (the threshold and its justification are data in policy; changing a threshold re-runs the whole bench); *explainability* (every positive result must list the contributing signals; a result with no explanation fails the gate); *regressions* (a frozen set of past decisions; any flip needs a recorded reason).
- Bench: labelled fixture set with expected score ranges and a benign corpus for false-positive rate.
- Today: no heuristic engine in committed code. `ContentDetectorTests.swift` tests the app's content detector (existing, macOS); whether it counts as a heuristic is for the owner to decide.

### 6.6 Behaviour
- Validators (planned): *event sequences* (rule over an ordered list of events with expected verdict); *temporal correlation* (windows, ordering, partial matches); *duplicate events* (idempotent counting); *missing events* (a missing mandatory event yields "insufficient data", not a match and not clean); *out-of-order events* (re-ordering by event time, tolerance policy); *macOS/Linux sensor compatibility* (per-sensor field mapping: macOS Endpoint Security / unified log vs Linux auditd / eBPF; a rule lists the sensors it needs, validator reports `supported | partial | unsupported` per platform).
- Bench: synthetic timelines per platform, including shuffled, duplicated and truncated variants of each.
- Today: none.

### 6.7 ML models
- Validators (planned): *model integrity* (SHA-256 of weights, safe serialisation format; pickle-style formats rejected); *version and provenance* (training data reference, code commit, training date, licence of model and data); *independent metrics* (precision/recall/ROC on a held-out set that was never used for training or threshold tuning, computed by a separate script from the model author's); *false positives* (benign corpus); *drift* (distribution comparison between the training set and recent inputs; alert thresholds); *latency and memory* (per process, as `bench.py`).
- Bench: held-out labelled set (inert or feature-level only on CI), benign corpus, drift reference.
- Today: none.

### 6.8 Sandbox
- Validators (planned): *verifiable isolation* (the sandbox proves, with tests, no network egress, no access to host paths outside its mount, no shared credentials, and that the checks themselves pass on a canary before each run); *execution limits* (CPU, memory, wall time, process count, file size, with enforcement tested by a harmless resource-stress program); *repeatability* (the same synthetic sample yields the same behavioural summary across N runs; variance reported); *evidence capture* (what was recorded: process tree, file operations, network attempts as denied, hashes; stored hash-linked); *restore policy* (VM/container is reverted to a known snapshot hash after every run; the run fails if the restored image hash differs).
- This is the **only** place where executing samples is ever contemplated, and only on the isolated, offline, owner-controlled infrastructure of section 4. A hosted CI runner cannot be a sandbox for real malware. On CI the bench runs the sandbox with synthetic, inert programs only.
- Today: none. (The existing "dynamic validation" in `docs-src/en/dynamic-validation.md` is a YARA performance benchmark on safe files; it is not a behavioural sandbox. Its name must not be reused for one.)

## 7. Summary table

| Technology | Gate | Bench (separate) | Evidence artefact | Status today |
|---|---|---|---|---|
| YARA (classic) | `yarac` compiles (`scripts/validate.py`); static admission (`scripts/rulecheck.py`); dynamic gate (`scripts/dynamic_gate.py`, `scripts/decide.py`) | `scripts/bench.py` canaries + benign corpus; `tests/test_rulecheck*.py`, `tests/test_bench.py` | `dist/validation.json`, `dist/classification.json`, `dist/dynamic.json`, manifest `validation: {checked, engine: yara}` | operational (compile and performance only; says nothing about detection quality) |
| YARA-X | compile + compat + parity as additional, non-blocking-then-blocking gate | shared benign corpus, detection fixtures, installer fixtures | planned `validation.yara_x` summary in the attestation | planned (engine entry only in `config/sources.json`) |
| Sigma | schema, pySigma, backends, replay, correlation | synthetic event logs | planned results + attestation | planned |
| ClamAV | CVD signature verification, integrity, load, detection | EICAR + synthetic fixtures | planned results + human redistribution decision | planned |
| IOC | format, normalise, dedupe, reputation, TTL, FP | synthetic IOC lists, benign allow-lists | planned results + attestation | planned |
| Heuristics | unit, thresholds, explainability, regression | labelled fixtures + benign corpus | planned results + attestation | planned |
| Behaviour | sequences, correlation, dup/missing/out-of-order, sensor compat | synthetic timelines per platform | planned results + attestation | planned |
| ML | integrity, provenance, independent metrics, drift, latency | held-out set, drift reference | planned model card + results | planned |
| Sandbox | isolation, limits, repeatability, evidence, restore | inert programs on CI; real samples only offline by owner | planned run log, hash-linked | planned |
| Attestation of tests | keyless Sigstore from the publishing workflow | n/a | planned `tests-attestation.json` + bundle | planned (GitHub/SLSA attestations are not produced today) |

## 8. Rollout order (suggested, subject to owner decision)

1. Reporting model (PASS/FAIL/SKIP/ERROR/NOT_IMPLEMENTED) and the attestation document for the YARA gates that already run, because their inputs exist.
2. YARA-X compile+compat as a *report-only* gate, until its false-compatibility rate is understood.
3. IOC and Sigma validators (pure data, no engines to ship).
4. ClamAV verification (after the redistribution decision).
5. Heuristics, behaviour, ML, sandbox (each needs product decisions first).

Each step needs its own tests written first (a failing test that reproduces the gap), a documented bench manifest, and the owner's approval before any workflow or release change.
