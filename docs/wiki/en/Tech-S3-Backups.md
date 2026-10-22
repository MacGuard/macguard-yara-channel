# Technology: S3 storage and backups

[Home](EN-Home) · [Historical archive](EN-YARA-Archive) · [Limits](EN-YARA-Limits) · [Technology: Merkle](EN-Tech-Merkle) · [Technology: Sigstore](EN-Tech-Sigstore)

> **State: planned.** The three-provider archive is not operational and no real restore has been tested {{ev:EV-YC-62}} {{ev:EV-YC-08}}.

## In 30 seconds

"S3" is the way of talking to cloud object stores (you keep files in "buckets"). Many providers understand it. With **versioning** (old versions are kept) and **Object Lock** (cannot be deleted or overwritten for a while) you get an "append-only" copy, useful against mistakes and deletions.

## An everyday example

It is a safe with a slot: you can put documents in, but for a set period nobody can take them out or change them. If the master-key holder decides to open it (governance mode), they can. With the strict mode (compliance) not even they can.

{{diagram:archive-triple-storage-1-write}}

{{diagram:archive-triple-storage-2-verify}}

## Under the hood

- **Problem:** keeping the history even if a provider fails, corrupts data or is tampered with.
- **Pieces:** versioning; Object Lock retention; identity rules giving the write key upload-only permission; read-back with another key; per-object SHA-256 hashes {{ev:EV-YC-60}}.
- **Governance versus compliance:** in governance, whoever holds the special permission can bypass the lock; in compliance nobody can during retention, not even the account owner (except by deleting the account, in AWS's case) {{ev:EV-YC-78}} {{ev:EV-YC-79}}.
- **Three providers:** Cloudflare R2, Backblaze B2 and Scaleway, one bucket each. The specification notes that lock strength depends on each provider's settings, and that the feature must be confirmed on test buckets {{ev:EV-YC-63}}.
- **Implementation in the repository:** `scripts/archive/providers.py` (local directory and a command-line S3 adapter), `store.py`, `restore.py`, entry point `scripts/archivectl.py` {{ev:EV-YC-61}}.
- **Cost:** the specification estimates cents to tens of dollars in total in almost all scenarios, using prices read on 2026-10-21 that may change {{ev:EV-YC-60}}.
- **Does not prevent:** a compromised write origin uploading false data with a valid signature; nor loss of the decryption key.

{{diagram:archive-provider-outage}}

## Who else uses it

No row implies that these organizations use MacGuard.

| Who | Classification | Source |
|---|---|---|
| Amazon S3: Object Lock ("write once, read many" model) with governance and compliance modes, requiring versioning | uses the same technology | {{ev:EV-YC-78}} |
| Backblaze B2: Object Lock with governance and compliance modes, which must be enabled on the bucket and cannot be disabled afterwards | implements a similar solution | {{ev:EV-YC-79}} |

## Check it yourself

```
python3.12 -m unittest tests.test_archive_providers tests.test_archive_store
python3 scripts/archivectl.py --help
```

The tests use a local-directory provider and simulated hostile providers; they touch no real service.

## Limits

Copies on three providers do not protect against whoever controls the signing origin, the DNS or the owner's device. A mistake uploaded under compliance retention cannot be withdrawn {{ev:EV-YC-60}}.

## State

| Capability | State |
|---|---|
| Archive and local restore tools | implemented-not-deployed {{ev:EV-YC-61}} |
| Buckets with versioning and Object Lock on all three providers | planned |
| Compliance mode | planned, not authorized |
