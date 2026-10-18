---
title: Log and checkpoints
summary: What is recorded, how checkpoints are signed and how rollbacks are detected.
---
## The log

`logs/log.jsonl` is an append-only log with one JSON line per event (`time`, `level`, `event`, `message` and details). A readable view is on the transparency page. Events carry counts only: never names or findings of quarantined rules.

## Checkpoints

A checkpoint is a three-line text: the origin `macguard-rules-log v1`, the number of entries and the root in base64. `publish.yml` signs it with Sigstore (`checkpoint.sigstore.json`) and attaches it to the release (`checkpoint.txt`).

{{diagram:checkpoint-sequence}}

{{diagram:checkpoint-evolution}}

The signed manifest includes the log head (`log.origin`, `log.size`, `log.root`) and must match the attached checkpoint. In the latest release the size is {{release.log_size}} and the log root `{{release.log_root}}`.

## Events

These are the event codes emitted by the workflows and scripts. A documentation test checks that each one appears in the file shown.

{{events_table}}
