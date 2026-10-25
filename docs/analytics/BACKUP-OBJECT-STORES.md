# Backups: three independent object stores (owner decision, 2026-10-24)

The only backup destinations are **Backblaze B2**, **Scaleway Object Storage** and **Cloudflare R2**. External disks are not part of the strategy (the earlier `backup_offsite.mjs` directory mode remains as a generic tool and for local rehearsals; it is no longer the plan). Private keys stay in the macOS Keychain until the owner configures the Bitwarden CLI; Bitwarden will hold the recovery copy of the identities. Bitwarden's absence blocks nothing here.

## Flow

```
D1 export ─► integrity check + isolated restore ─► age encryption (recipient = public key) ─► manifest + SHA256SUMS
   ─► for each destination, independently:  HEAD/GET (write-once) ─► PUT ─► GET back ─► compare SHA-256  ─► record success
   ─► restore drill FROM EACH destination:  download ─► SHA256SUMS ─► age -d (identity FILE) ─► restore checks in memory
```

* Code: `gateway/tools/backup_objstore.mjs` (`plan | sync [--apply] | verify | drill --identity FILE | check`), alarms in `backup_check.mjs --objstore`, per-provider panels in the `cas_backups` dashboard (`backup_providers`, `backup_three_copies`). Tests: `gateway/test/objstore.test.js` (7) and `dashboards_extra.test.js`.
* **Only ciphertext leaves the machine.** A backup directory without `d1-export.sql.age` is plaintext and is reported, never uploaded.
* **Write-once.** An existing key with different bytes is a conflict that stops that backup at that destination; nothing is overwritten and nothing is deleted by this tool.
* **Independent destinations.** A failing, unconfigured or hostile destination never stops or alters another. State per destination lives in `objstore.json` (timestamps, backup name, drill results; no credentials). "Three copies" (`backup.three_copies`) is claimed only when all three have a verified copy younger than 48 h; a restore claim needs a passing drill from that destination within 35 days.
* **Credentials** are read from environment variables named in the destinations file (`MG_B2_KEY_ID`/`MG_B2_SECRET`, `MG_SCW_KEY_ID`/`MG_SCW_SECRET`, `MG_R2_KEY_ID`/`MG_R2_SECRET`), at the moment of use, and are never printed, logged or stored. The signing code is a minimal SigV4 client checked against the published AWS test-suite vector.
* **CAS is not this.** The historic CAS (`scripts/archive/`) protects archive objects with its own multi-cloud replication and manifests. D1 dumps, configuration and key metadata are *recoverable backups* and are handled here; they are not deduplicated by the CAS and nothing already protected by the CAS is duplicated by this flow.

## Destinations: what actually exists (read-only audit, 2026-10-24)

| Destination | Bucket | Evidence | State |
|---|---|---|---|
| Backblaze B2 | `macguard-archive-b2` (`eu-central-003`, private, SSE-B2, **file lock enabled**, no default retention, no lifecycle) | MCP listing + `s3_get_bucket_location` | reachable; **not yet written with a D1 backup** |
| Cloudflare R2 | `macguard-archive-r2` (and `macguard-premium-private`, which is NOT a backup target) | Cloudflare API listing | exists; the bindings connector answers 403 "enable R2", the API connector lists it; **not yet written** |
| Scaleway | `macguard-archive-scw`, region `fr-par` (`https://s3.fr-par.scw.cloud`), **versioning disabled**, owner = the connector's account | MCP `object_bucket_get` (the bucket **list** call returned empty, so the list is not a reliable test; a direct read by name is) | exists; named in `gateway/environments/backup-destinations.json`; **not yet written** |

The GitHub environments `archive-{b2,r2,scaleway}-{read,write}` already hold keys for the CAS workflow (write-only, readable only by a workflow on `main`). This machine has none of the `MG_*` variables set, so **no real upload, verification or restore from any provider has been executed**. That is BLOCKED on credentials in this environment, not on code.

Found while verifying the destinations (read-only): B2 has file lock enabled with no default retention; R2 has no versioning by design; **Scaleway versioning is off**. None of these three settings is changed by this work; the plan below lists them as owner actions because they decide whether an overwritten or deleted object can be recovered.

## Protection against the listed failure modes

| Risk | Control | Proven |
|---|---|---|
| accidental deletion | the tool never deletes; B2 has file lock enabled (retention to be chosen); R2/Scaleway object-lock/versioning to be configured by the owner | the tool: yes (tests). Bucket-side settings: B2 lock flag read; others UNKNOWN |
| lost versions / overwrite | write-once keys, content compared before and after upload | yes (local fakes + HTTP server) |
| corruption | SHA-256 read-back at upload, `verify`, SHA256SUMS + manifest checked in every drill | yes (local) |
| compromised credentials | one credential per provider (never shared); read and write separated by the GitHub environments; the backup key is age (public recipient only on the machine that uploads) | design; real key scopes UNKNOWN |
| loss of one provider | each provider restorable on its own; losing one leaves two (tested: wiped B2 store, R2 and Scaleway still restore) | yes (local) |
| wrong key | a non-recipient identity cannot decrypt (tested) | yes |

## Cost and retention

Measured: the newest real encrypted D1 dump is 40,638 bytes (+ 3.1 KB of manifest and checksums). Three copies a day is about 130 KB/day, roughly 47 MB/year before any pruning; the price per provider was not re-checked in this round, so no cost figure is claimed. The existing cost policy in `docs/monetization/COSTS.md` and `docs/backup/` applies.

## Procedure once credentials exist (owner)

1. Export the six variables in a shell that is closed afterwards (never in a file in the repository).
2. `node tools/backup_objstore.mjs plan` – shows what each destination lacks.
3. `node tools/backup_objstore.mjs sync --apply` – uploads; `verify` re-reads; `drill --identity <key file exported from the Keychain to a private temp path, removed afterwards>`.
4. `node tools/backup_check.mjs --objstore` from the scheduler. Only then may the dashboards and reports say "three verified copies".
5. Restore on another computer: install `age`, fetch one provider's `<stamp>/` objects, `age -d -i KEY d1-export.sql.age`, verify `plaintext_sha256` of `manifest.json`, import into a scratch D1 (`restore_to_staging.mjs`). Never over the production D1.

## Plan of the first synchronisation (nothing has been uploaded; each step names what it changes)

What would be sent, per provider: only ciphertext, manifest and checksums, two backups in two roots (about 77 KB in total per provider, so three copies are about 0.23 MB):

| Root | Backup | Files | Bytes |
|---|---|---|---|
| `~/macguard-backups/gateway` | `20261024T050235Z` (taken encrypted) | `d1-export.sql.age`, `manifest.json`, `SHA256SUMS` | 40,638 + 2,940 + 164 |
| `~/macguard-backups/gateway-legacy-encrypted` | `20261023T200122Z` (the encrypted copy of the plaintext backup, see below) | same three files | 30,251 + 3,350 + 164 |

The plaintext directory `20261023T200122Z` in the first root is skipped by the tool ("no encrypted export: plaintext never leaves the machine"). Keys are `gateway-d1/<stamp>/<file>` in each bucket, so the two roots do not collide.

1. **Owner, once:** create one access key per provider scoped to its bucket with read and write but **no delete and no bucket administration**, and export the six variables (`MG_B2_KEY_ID`, `MG_B2_SECRET`, `MG_SCW_KEY_ID`, `MG_SCW_SECRET`, `MG_R2_KEY_ID`, `MG_R2_SECRET`) only in the shell that runs the next steps. Never in a file of the repository, never in the chat.
2. **Optional hardening, owner approval (remote change):** enable versioning on `macguard-archive-scw`; set a default retention (or Object Lock where available) on B2 and R2 so an object cannot be deleted for N days.
3. `node tools/backup_objstore.mjs plan` and `plan --root ~/macguard-backups/gateway-legacy-encrypted`: reads the destinations (GET by key), uploads nothing, prints what each destination lacks.
4. `sync --apply` for each root: HEAD/GET first, `PUT` only an absent key, then GET back and compare SHA-256. An existing key with different bytes stops that backup at that destination and is reported; nothing is overwritten.
5. `verify` for each root, then `drill --identity <key file>` (the key file comes from the Keychain into a mode-600 file in a private directory removed afterwards; or use `backup_encrypt_legacy.mjs verify --identity-from-keychain` which does exactly that) once per provider: **each restore must come from that provider's own copy**.
6. `backup_check.mjs --objstore` from the scheduler. Only after 3 to 5 pass for all three may a report say "three verified copies".

Telemetry: with `MG_TELEMETRY_DIR` and `MG_TELEMETRY_URL` set, every step above also writes a run record per destination (`backup:b2`, `backup:scaleway`, `backup:r2`) that the panel shows (Sources and downloads, Backups tab).

## The plaintext backup `20261023T200122Z`

Authorised by the owner on 2026-10-24: an **additional** age-encrypted copy was made and verified by isolated restore; **the original was not deleted or modified** (its files hash identically before and after).

* Tool: `gateway/tools/backup_encrypt_legacy.mjs` (`encrypt`, `verify`; test `gateway/test/legacy_encrypt.test.js`). Copy: `~/macguard-backups/gateway-legacy-encrypted/20261023T200122Z/` (`d1-export.sql.age` 30,251 bytes, `manifest.json`, `SHA256SUMS`; modes 700/600).
* Checks that passed on the real copy with the Keychain identity (never printed): checksums, decryption, plaintext hash equals the manifest, **byte-identical to the original**, load into an empty database, schema columns, SQLite integrity, foreign keys, audit hash chain, policy chain, policy pointer, row counts.

### Procedure to retire the plaintext original (to be run by the owner, only after the three providers restored this copy)

Why "secure erase" is not offered: on an APFS volume on an SSD, overwriting a file does not overwrite the old blocks (copy-on-write, wear levelling, TRIM, snapshots). `rm -P` and `srm` do not give the guarantee they imply. What this Mac has today (read on 2026-10-24): **FileVault is on**, so every block at rest is encrypted; the volume is APFS on a solid-state disk; **no Time Machine destination** is configured and the only local snapshots are macOS update snapshots, which predate the backup.

1. Preconditions: step 5 above passed for B2, Scaleway and R2 for this stamp; the encrypted copy exists in all three; the owner has recorded the decision.
2. Check no snapshot or sync copy holds the file: `tmutil listlocalsnapshots /` (expect only OS-update snapshots), no iCloud Drive or Dropbox folder contains `~/macguard-backups` (`brctl status` / the sync client's folder list).
3. Delete the directory with a normal `rm -r ~/macguard-backups/gateway/20261023T200122Z` (or move it to the Trash and empty it). Do not run a "secure empty trash": it is not secure on this volume.
4. Rely on FileVault for the remaining risk, and treat the contents as exposed only if the Mac was unlocked and compromised while the file existed. The file held tenant records, salted hashes of administrators and HMAC hashes of API keys, and sealed TOTP seeds, but **no key material in the clear**; a pepper rotation would be the answer to a confirmed compromise, not to this deletion.
5. Record the deletion date in `KEY-CUSTODY.md`. Keep the encrypted copies.

## Not done

Real writes and restores at any provider; versioning/retention settings on the three buckets; retention/lifecycle choice; Bitwarden recovery copy; a restore on a second computer; deleting the plaintext original (the encrypted copy exists and is verified; deletion waits for the three-provider restore and the owner).

## Verification of the three destinations, 2026-10-25 (read-only calls; nothing created, nothing written)

| Provider | Call | Result | Meaning |
|---|---|---|---|
| Backblaze B2 | list buckets | one bucket, `macguard-archive-b2`, private, File Lock enabled (no default retention), server-side encryption SSE-B2, no lifecycle rules, no CORS | the destination exists and is configured as planned; no object was listed or read |
| Scaleway | `object_bucket_get macguard-archive-scw` (fr-par); the `object_bucket_list` call answered an empty list, which is NOT evidence of absence (it needs the project id) | bucket **exists**: region fr-par, endpoint `https://s3.fr-par.scw.cloud`, versioning off, owner = the connected identity | the destination is there; versioning/retention settings remain an owner decision. (A first version of this table, written from the empty list, wrongly said the bucket did not exist; corrected the same day after the direct get.) |
| Cloudflare R2 | (1) the Cloudflare connector of this session: list buckets → HTTP 403, code 10042; (2) the stored read-only key, `backup_objstore.mjs plan` against `https://9e96e19f….r2.cloudflarestorage.com/macguard-archive-r2` → **READY** | the connector authenticates as another Cloudflare context and cannot see the account `9e96e19f…` (it lists one unrelated Worker and no D1); the real account's R2 is enabled and its bucket answers to the stored key. So the 403 above says nothing about the real account (a first draft of this table wrongly concluded R2 was not enabled) |

**2026-10-25 read-only `plan` with the three stored read keys (Keychain, never printed): B2 READY, Scaleway READY, R2 READY, nothing yet stored in any of them (`already_there` empty for all three; the newest encrypted backup `20261024T050235Z`, 3 files, is what a first sync would upload; the plaintext export is skipped by design).** Write permission is not checked until the owner authorises the first sync (a check would have to write). Consequence: today the `three_copies` claim is false and stays false (the tooling only makes it when all three verify). Next step for the first sync, once the owner authorises it (the read keys exist; the write keys are in the Keychain too and have never been used): the section "Plan of the first synchronisation" above (age encryption, per-object checksum, write-once, no overwrites, independent isolated restore from each provider).

## First encrypted synchronisation: prepared, NOT executed (2026-10-25, third part)
Environment: LOCAL. Nothing was written to B2, Scaleway or R2. No object was overwritten or deleted by this work.

| Item | State |
|---|---|
| Candidate | `~/macguard-backups/gateway/20261024T050235Z`: `d1-export.sql.age` (40,638 bytes), `manifest.json` (2,940), `SHA256SUMS` (164). Created 2026-10-24T05:02:35Z by the encrypted backup flow, status `ok` |
| Ciphertext integrity | **VERIFIED**: the SHA-256 of `d1-export.sql.age` equals the one in `SHA256SUMS` (`7c8cda6b…`), checked locally |
| Plaintext export | `20261023T200122Z` is plaintext and is **skipped by the tool** ("plaintext never leaves the machine"); it is not a candidate |
| `plan` | run with no credentials in the environment: all three destinations `UNCONFIGURED`, no network contact. Destination description (bucket, endpoint, region) is in `gateway/environments/backup-destinations.json` |
| Read access to the three buckets | **VERIFIED earlier** (HEAD bucket with the stored read keys); **write permission is NOT confirmed** for any of them |
| Local decrypt-and-restore drill | **NOT_RUN**. The age identity is in the Keychain under a name I could not resolve (`BACKUP_AGE_IDENTITY` as a service name returned nothing) and a broader Keychain search was refused by the permission layer, correctly. The ciphertext check above is all that was proven |
| Restore drill per destination (`drill`) | **NOT_RUN** (needs the copies to exist) |
| "Three copies" | **not claimed**: it requires all three destinations to have verified the same bytes |

### What the first sync would write (write-once keys; existing keys with different bytes are conflicts, never overwritten)
`gateway-d1/20261024T050235Z/d1-export.sql.age`, `…/manifest.json`, `…/SHA256SUMS` in `macguard-archive-b2`, `macguard-archive-scw` and `macguard-archive-r2`: 3 objects, about 43.7 KB per destination. Cost is negligible; the real constraint is that a read-only key cannot write.

### Commands for you to run (they read the keys from your environment; none prints a secret)
```
cd gateway
node tools/backup_objstore.mjs plan   --root ~/macguard-backups/gateway          # dry run: what each destination lacks
node tools/backup_objstore.mjs sync   --root ~/macguard-backups/gateway --apply  # uploads only what is missing, per destination, independent
node tools/backup_objstore.mjs verify --root ~/macguard-backups/gateway          # re-reads every object from each destination
node tools/backup_objstore.mjs drill  --root ~/macguard-backups/gateway --identity <age identity file>   # per destination: download, hash, decrypt in isolation, restore into memory
```
Run `drill` with an identity file you create from the Keychain yourself, then delete it. Authorise `sync --apply` explicitly (it is the first remote write) and tell me which keys have write scope.
