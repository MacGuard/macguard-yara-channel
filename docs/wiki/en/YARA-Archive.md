# Historical archive on three providers

[Home](EN-Home) · [Limits](EN-YARA-Limits) · [Technology: S3 and backups](EN-Tech-S3-Backups) · [Technology: Merkle](EN-Tech-Merkle) · [Technology: Sigstore](EN-Tech-Sigstore)

> **State: NOT operational.** This is a design plus local tooling. No archive workflow in `main` writes to any provider. Nothing has been written to or restored from a provider, and **no restoration from any real provider has been tested** {{ev:EV-YC-62}} {{ev:EV-YC-08}}. The phase 1 tools are in `main`.

## In 30 seconds

The channel publishes signed rules on GitHub. If GitHub lost the history, could anyone still prove what was published and when? The plan is to keep a permanent copy on **three independent storage providers** (Cloudflare R2, Backblaze B2 and Scaleway Object Storage), one bucket each, so that the failure or decision of one provider cannot delete or forge the history. All three share one write origin; see Limits. {{ev:EV-YC-60}}

## An everyday example

It is like keeping the minutes of a meeting at three notary offices in different countries. If one burns down, two remain. If someone alters one copy, the other two reveal the difference. It does not stop the original minutes from containing a mistake: it only preserves what was written.

{{diagram:archive-triple-storage-1-write}}

{{diagram:archive-triple-storage-2-verify}}

## What would be kept

| Item | What it is for |
|---|---|
| Rule bundles (`rules-release.tar.gz`) and manifests | The exact content of each release |
| SHA-256 hashes and Sigstore signatures | Checking integrity and origin |
| Checkpoints, Merkle proofs and public logs (`logs/`) | Showing that the history only grows |
| Encrypted private audit, with monthly seals | Keeping the decision chain without exposing its content |

Source of the list: section 3 of the specification {{ev:EV-YC-60}}. Bucket names, service endpoints and account ids are not published.

## Step by step

1. Before writing, the object is checked for secrets and private rule names, and its SHA-256 is computed.
2. Private audit data is encrypted with `age` **before** it leaves the process; the provider never sees plaintext.
3. It is written to all three providers with write-only credentials that cannot delete.
4. It is read back with a different read-only credential and the hashes are compared. If all three do not match, an alert is raised and nothing is pruned.
5. A manifest of manifests, signed with Sigstore, chains each archive run to the previous one.

## Under the hood

**Versioning and Object Lock.** Versioning keeps old versions instead of overwriting them. Object Lock prevents deleting or overwriting a version during a retention period. There are two modes {{ev:EV-YC-78}} {{ev:EV-YC-79}}:

- **Governance:** protects against most users, but an identity with the right permission **can bypass the lock**. It does not stop an authorized identity that has been compromised.
- **Compliance:** nobody can remove it during retention. It is irreversible: an upload mistake (for example a secret) could not be withdrawn.

> **Compliance is NOT enabled** and enabling it needs explicit owner authorization {{ev:EV-YC-60}}. How strong the lock is depends on each provider's settings and on the permissions of the keys used; provider capabilities still have to be confirmed on test buckets {{ev:EV-YC-63}}.

**Independent replication.** Three accounts, three legal entities and jurisdictions, separate credentials. Acknowledged limit: all three depend on a single write origin (GitHub Actions) and a single owner; "independent" does not mean immune to whoever controls the signing origin {{ev:EV-YC-63}}.

**Client-side encryption (principles).** `age` encrypts to public keys; the archiving process only knows the public key, so it can encrypt but not decrypt. The private key is kept offline under human control. Without it the detail cannot be read, although the seals remain verifiable {{ev:EV-YC-60}} {{ev:EV-YC-61}}.

**Restore.** Designed as an independent rehearsal per provider: restore from just one and verify with the public verifier. The `restore` and `rehearse` commands exist in `scripts/archivectl.py`, tested with local directories, **not** with a real provider {{ev:EV-YC-61}}.

{{diagram:archive-provider-outage}}

## Check it yourself

```
python3.12 -m unittest tests.test_archive_segments tests.test_archive_providers tests.test_archive_store
```

These are fast tests with no network. The test using the real `age` binary only runs with `ARCHIVE_REAL_AGE=1`; without it, it is recorded as not run {{ev:EV-YC-61}}. Code: [`scripts/archive/`](https://github.com/MacGuard/macguard-yara-channel/tree/main/scripts/archive), [specification](https://github.com/MacGuard/macguard-yara-channel/blob/main/docs/audit/historical-archive-triple-spec.md).

## Limits

- An immutable copy of wrong data is still wrong; the archive preserves, it does not validate rule content.
- Provider prices, free tiers and features can change; the specification read prices on 2026-10-21 and they are not a guarantee.
- The setup guide is not yet in the repository, so this page relies on the specification {{ev:EV-YC-62}}.
- Compliance retention, database pruning and any restore using the real decryption key need owner authorization.

## State

| Capability | State |
|---|---|
| Phase 1 archive tools (segments, seals, `age`, local restore) | implemented-not-deployed {{ev:EV-YC-61}} |
| Provider setup | not started |
| Writing to providers and restoration | planned |
| Compliance-mode lock | planned, not authorized |
| Restore tested from a real provider | not done |
| Pruning audit rows | dry-run report only; not executable |
