---
title: Dynamic validation
summary: How the set is measured with the YARA engine and how problematic rules are isolated.
---
## What is measured

`dynamic_gate.py` builds a safe corpus (random files, text, system files and detection canaries), compiles the approved set and runs it with YARA against every corpus file measuring CPU, peak memory and time (on Linux with the Ubuntu YARA; in the macOS job with the engine MacGuard ships, {{tool.yara}}). It compares the candidate with the previous release in the same job, alternating runs.

{{diagram:dynamic-sequence}}

## Decision

{{diagram:dynamic-decision}}

- Each set is measured 5 times and medians are compared against the baseline noise; a regression needs to exceed 3 times the noise and at least 25 %, 0.5 s of CPU or 25 MB.
- Without a previous release absolute limits apply: scan p95 2.0 s, 1500 MB of memory scanning, 3000 MB compiling and 240 s of compile time.
- Timeout per file: 10 s. Every canary must be detected.
- If anything fails, delta debugging (ddmin) isolates the new or changed files responsible, they go to quarantine and the set is measured again, up to 3 rounds.
- The measured set must be exactly the one that is published (`set_root` equals the Merkle root); `publish.yml` checks it again before signing.

## On macOS

The `macos` job of `daily.yml` builds the reference YARA engine (the same pinned build MacGuard ships) on a macOS runner and repeats the measurements with the candidate set; that job gates publication. The separate `app-compat` job also runs the MacGuard CLI over the safe corpus (`macguard_smoke.py`), but it is an external compatibility report: it never blocks a release, because the application is not a requirement for publishing rules. The exact values are in `config/policy.json`.

> **LIMIT** GitHub macOS runners are virtual machines (Apple M1 Virtual, `hv_vmm_present=1`, no Hypervisor.framework). **There is no independent macOS virtual machine**: `dynamic.json` declares it as `not_run: independent-macos-vm`. That needs a self-hosted physical Mac.

> **LIMIT** The Linux gate uses Ubuntu YARA (4.5.0) while the app ships {{tool.yara}}. Static classification of the whole set gave the same result with both engines (checked 2026-10-18), but dynamic measurements may differ between engines and systems; see [Limits and pending work](page:limits).

No real malware is run at any point: the corpus is made of synthetic data, text and benign files.
