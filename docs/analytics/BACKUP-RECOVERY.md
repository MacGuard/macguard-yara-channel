# Backup and recovery of the gateway

## What is covered
| Asset | How it is protected | Evidence |
|---|---|---|
| D1 data (policy, admins, tenants, keys, ledger, audit, analytics) | `node gateway/tools/d1_backup.mjs`: **read-only** `wrangler d1 export --remote`, saved to `~/macguard-backups/gateway/<UTC>/` (mode 700/600, never a temp folder), with `manifest.json` (row counts, SHA-256, deployed versions, secret *names*) and `SHA256SUMS`; then restored into an **isolated in-memory** database and verified | real run 2026-10-23: 8/8 checks, audit chain intact on the actual production audit rows, row counts equal the manifest |
| Worker configuration | tracked `gateway/environments/*.wrangler.toml` (identifiers only) + a copy inside every backup | dry-run validated |
| Worker code | the git commit that was deployed (`DEPLOYMENT.md` records it) and the Cloudflare version list in the manifest | — |
| Secrets (`KEY_PEPPER`, `ADMIN_PEPPER`, `TOTP_SEAL_KEY`, admin key, TOTP seed, id) | macOS Keychain service `macguard-gateway-prod`; **`node gateway/tools/secrets_backup.mjs --recipient age1… --out FILE`** writes one `age`-encrypted file for a public key the owner holds (values never printed; refuses temporary folders) | round-trip test with a throwaway Keychain service and key |
| D1 point-in-time | Cloudflare D1 Time Travel (bookmark recorded in the manifest era: `00000005-00000000-0000510d-…`) | `wrangler d1 time-travel info` (read-only) |

Cloudflare cannot return secret values, so a Worker secret exists only in the Worker and in the Keychain/age backup. Nothing depends on the session scratchpad any more: the environment configs, helper tools and procedures are in the repository, and the verified backup is outside any temporary directory.

## What the restore verification checks
Export loads into an empty database · every table of `schema.sql` exists with the same columns (a table that only an unapplied migration creates is reported as *pending*, not as loss) · SQLite `integrity_check` · no dangling foreign keys · audit hash chain · policy version hashes and chain · policy pointer · row counts equal the manifest. Tests: truncated export, tampered audit row, tampered policy, missing table, manifest mismatch, source untouched.

## Disaster recovery (procedure; the destructive steps were NOT rehearsed)
1. Stop writes if the old database is still live (suspend tenants or take the hostname off).
2. New database: `wrangler d1 create <new name>`; load the latest verified export with `wrangler d1 execute <new> --remote --file d1-export.sql`; run the migrations in `gateway/migrations/` that the export lacks (the verifier lists them as pending).
3. Point `environments/*.wrangler.toml` at the new `database_id`; deploy; set the three secrets from the Keychain or the age backup (`wrangler secret put`).
4. Verify with the health, 401, redirect and administrator checks; run `tools/restore_verify.mjs` on a fresh export of the new database.
5. If the secrets are lost: rotate all (new peppers invalidate every API key and the administrator), re-bootstrap the administrator with `tools/bootstrap_remote.mjs`, reissue keys through the admin routes.
Emergency in-place rollback of the data is `wrangler d1 time-travel restore` to a bookmark: it **overwrites** the live database, so it is a last resort and was not run.

## Automation (added 2026-10-24)
`tools/d1_backup.mjs` is now an automated, verified, **encrypted** backup: read-only export → isolated restore verification of the plaintext → `age` encryption (recipient from `--age-recipient` or `MACGUARD_BACKUP_AGE_RECIPIENT`; the plaintext exists only in a private temp directory that is removed) → manifest and checksums → `status.json` updated on success **and** failure. `tools/backup_check.mjs` turns that state into alarms (`backup.missing`, `.never_succeeded`, `.stale` > 30 h, `.last_attempt_failed`, `.integrity`, `.unencrypted`) and exits 1 when one fires; `tools/guardops_emit.mjs` reports FIRING alarms to GuardOps. `tools/backup_prune.mjs` applies a keep-7-daily / 4-weekly / 12-monthly policy as a **dry run** unless `--apply`; the newest backup, the one `status.json` points at, and anything pinned in `protected.json` are never removed. `tools/launchd/com.macguard.gateway-backup.plist.template` schedules it daily (a template, **not installed**). `tools/restore_to_staging.mjs` prepares a rehearsal on a *staging* D1 (dry run by default; it refuses `macguard-gateway`, requires a name ending in `-staging|-restore-test|-scratch` and an explicit confirmation); **it has not been run**.
Real run, 2026-10-24: encrypted backup `20261024T050235Z` (40,638 bytes) verified 8/8 by isolated restore from the ciphertext; the alarms are all OK. The first export (`20261023T200122Z`, plaintext, 30,051 bytes) is preserved and pinned. **Interim key:** the age recipient currently in `recipient.txt` was generated on this machine and its private half is in the same Keychain as the other secrets — protection against a stolen file, not against loss of the machine. Replace it with a key the owner keeps offline (`--age-recipient age1…`) and re-encrypt if desired.

## Open items
No schedule exists for backups (a local launchd job or a CI job with a read-only token is the owner's decision); the age recipient for the secrets backup must come from the owner; the restore into a *remote* scratch database was not done (the isolated local restore was).

## Update 2026-10-24 (second closing round, `b6a1b73`)
Added: ciphertext-only off-machine sync, restore drill from the copy, and custody alarms (`KEY-CUSTODY.md`, last section); a staging rehearsal of the whole release path including the restore into a staging D1 (`STAGING-SEQUENCE.md`, steps S2–S5). The existing backups were not touched or re-encrypted. Still open and owner-only: choosing the destination, escrowing the key offline, replacing the interim key, installing the schedule.

## Added 2026-10-25
Authentication of backups that survives losing the Mac (signed anchor, sequence and chain, recovery kit, independent shell verifier): `BACKUP-AUTHENTICATION-AND-RECOVERY-2026-10-25.md`. Audit of the age restore flow: `BACKUP-RESTORE-AUDIT-2026-10-25.md`.
