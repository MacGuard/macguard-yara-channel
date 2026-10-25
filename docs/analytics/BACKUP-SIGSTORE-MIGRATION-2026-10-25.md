# Backup signing: Sigstore keyless + GitHub Actions OIDC (2026-10-25)

Decision (owner): new backups are signed by the `backup.yml` workflow with Sigstore keyless; the Ed25519 key stays only to verify history; age still encrypts and its identity never goes to GitHub.

## How it works (jobs and GitHub environments)
GitHub Actions allows one environment per job, so the workflow has one job per environment. Environment names, secrets and variables were read from GitHub (names only) on 2026-10-25.

| Job | Environment | Secrets it can read | Does |
|---|---|---|---|
| `fetch` (b2, scaleway, r2) | `archive-<p>-read` | `ARCHIVE_ACCESS_KEY_ID`, `ARCHIVE_SECRET_ACCESS_KEY` | newest signed statement the provider holds (statement only) |
| `export` | `macguard-backup-production` | `CLOUDFLARE_API_TOKEN` (environment or repository) | choose the predecessor, export D1, verify, age-encrypt, sign ANCHOR and CHECKPOINT with Sigstore keyless; no storage credential |
| `write` (b2, scaleway, r2) | `archive-<p>-write` | the same two names | copy write-once; an existing key with other bytes is a conflict |
| `read` (b2, scaleway, r2) | `archive-<p>-read` | the same two names | prove the READ credential cannot write, download from the provider, compare with the package, verify as a clean machine |
| `redundancy` | none | none | "three verified copies" only if write and read succeeded for all three |
| `selftest` (manual) | none | none | signs a synthetic statement with the workflow identity: proves the keyless path |

Each of the six `archive-*` environments has the secrets `ARCHIVE_ACCESS_KEY_ID` and `ARCHIVE_SECRET_ACCESS_KEY` and the variables `ARCHIVE_BUCKET`, `ARCHIVE_ENDPOINT`, `ARCHIVE_REGION`, `ARCHIVE_S3_PROVIDER`, and only the branch `main` may deploy to them. Buckets: `macguard-archive-b2` (eu-central-003), `macguard-archive-scw` (fr-par), `macguard-archive-r2` (auto). Every job checks that the environment's bucket and endpoint are the ones in `backup-destinations.json`. The objstore tool reads those generic names when `MG_ARCHIVE_PROVIDER` names the provider.

Between jobs only **age ciphertext and public signed statements** travel, as artifacts kept one day. **This repository is public: those artifacts are readable by anyone with a GitHub login.** The SQL is never in an artifact (a guard step checks the age header and the absence of `.sql`/config files); the ciphertext is encrypted to a recipient whose identity is not in GitHub. Residual risk: a public ciphertext, for a day, is exposed to "download now, decrypt if the identity ever leaks". Mitigation to decide: a transit layer with a second age key held as a repository secret (not done: it needs a new key).

1. `fetch` x3 reads the provider heads; `export` picks the highest valid statement (Sigstore or historical Ed25519, or the repository's genesis statement `backup-genesis/`) and refuses equivocation.
2. `export` builds `ANCHOR.json` (sequence = previous + 1, previous head hash), signs it with `cosign sign-blob --bundle` (Fulcio certificate for the workflow identity, Rekor entry in the bundle), same for `CHECKPOINT.json`. Signing is all-or-nothing: temp dir, verification against the pinned identity/issuer/repository, then publish.
3. `write` x3 copies the package, `read` x3 downloads from each provider with its own READ credential and verifies; `redundancy` aggregates.
4. Decrypting needs the age identity (Keychain and Bitwarden only): restores are done off GitHub from the `read-<p>` artifacts.

## Trust policy (also in the offline kit)
| Sequence | Valid signature | Why |
|---|---|---|
| 1 .. 1 | Ed25519 `SHA256:O+m9SD…hw9o`, namespaces `macguard-backup/1`, `macguard-backup-checkpoint/1` | the historical, frozen range |
| 2 and later | Sigstore bundle for exactly `https://github.com/MacGuard/macguard-yara-channel/.github/workflows/backup.yml@refs/heads/main`, issuer `https://token.actions.githubusercontent.com`, repository `MacGuard/macguard-yara-channel` | no pattern is ever accepted |
No downgrade: above the freeze point an Ed25519 signature is refused, so a leaked old key cannot sign new history. `MACGUARD_BACKUP_SIGNING_KEY` in GitHub is no longer used by anything (checked by `test/backup_workflow.test.js`); it is deleted only after the first end-to-end run and a check of the historical backup.

## Independent copies of the checkpoint
Rekor holds every signed checkpoint publicly (outside the Mac and the three buckets); the workflow artifact keeps it one day only; the owner places the kit and the latest `CHECKPOINT.json` + bundle in a Bitwarden note and on paper at another address (human step). A copy counts only if `recover_verify.sh` accepts it from a clean directory.

## Evidence status
See the matrix section appended by each run. Unit tests use a cosign stand-in for the policy logic; the verifier was also run with the real cosign on a real Community release bundle (genuine OK; wrong identity, other repository, tampered body and truncated bundle refused). A real Sigstore signature of a backup exists only after the first workflow run.

## Open items
The D1 export token: no environment holds one; the export job falls back to the repository secret `CLOUDFLARE_API_TOKEN` (the Pages token), whose D1 scope is unknown until the job runs. `sh gateway/tools/set_backup_secrets.sh --report` lists what exists and asks only for what is missing. WRITE credentials that can also delete (B2 `macguard-b2-write` can delete and bypass governance; Scaleway cannot separate delete from write): compensating controls are the two other independent copies, the external checkpoint, the read-back verification and the bucket's file lock; not removed.
