# Custody of the backup key and the gateway secrets (audit of 2026-10-24)

## What exists and where (facts checked on this machine, no secret read)
| Material | Location | Also elsewhere? |
|---|---|---|
| `KEY_PEPPER`, `ADMIN_PEPPER`, `TOTP_SEAL_KEY` | macOS login Keychain, service `macguard-gateway-prod` | uploaded to the Worker as secrets (Cloudflare cannot return them) |
| Administrator key, TOTP seed, id | same service (`ADMIN_KEY`, `ADMIN_TOTP_SEED`, `ADMIN_ID`) | only a salted hash / sealed seed in D1 |
| **Backup private key** (interim `age` identity) | same Keychain, account `BACKUP_AGE_IDENTITY` | **nowhere else** |
| Backup public recipient | `~/macguard-backups/gateway/recipient.txt` (mode 600) | not secret |
| Encrypted backups | `~/macguard-backups/gateway/<stamp>/d1-export.sql.age` (dirs 700, files 600) | **only on this machine** |
| First plaintext export | `…/20261023T200122Z/` (pinned, 700/600) | only on this machine |
Format checked: `age-encryption.org/v1` with a single X25519 recipient stanza (ChaCha20-Poly1305 payload); no passphrase mode. The Keychain item lives in `login.keychain-db`, is not marked synchronisable (so it is **not** in iCloud Keychain), and no plaintext copy of the private key exists in the backup or evidence folders (searched; Desktop and Documents were deliberately not searched).

## The finding
Everything needed to read the backups — the ciphertext, the private key, and the secrets — sits on **one machine and one Keychain**. A lost, wiped or stolen Mac loses all copies at once: the encrypted backups become unreadable *and* the secrets are gone. The interim key protects the files against casual copying, not against that failure. This is a custody gap, not a cryptography flaw.

## Loss scenarios
| If this is lost | Consequence | Recovery |
|---|---|---|
| the machine (everything above) | no readable backup, no secrets, no admin credentials | D1 data survives in Cloudflare (Time Travel window); rotate all secrets, re-bootstrap the administrator (`tools/bootstrap_remote.mjs`), reissue every API key; no tenant exists yet so nothing customer-visible breaks today |
| only the Keychain item `BACKUP_AGE_IDENTITY` | encrypted backups unreadable | take a new backup with a new key (the live D1 is intact) |
| only the backup files | secrets and key remain | take a new backup |
| the Worker secrets | the gateway cannot verify keys / admin | `wrangler secret put` from the Keychain |

## Recommended custody (owner actions; none was done on the owner's behalf)
1. **Escrow the backup private key offline**, protected by a passphrase you choose: `security find-generic-password -s macguard-gateway-prod -a BACKUP_AGE_IDENTITY -w | age -p -o /Volumes/<USB>/macguard-backup-key.age` (age asks for the passphrase interactively; I cannot do it for you). Keep a second copy with a second custodian; a printed copy of the 74-character key line is acceptable if stored physically.
2. **Move a copy of the encrypted backups off the machine** (external disk, or a bucket you authorise). They are encrypted, so storing them elsewhere does not expose data.
3. **Replace the interim key** with one generated and held by the owner: `age-keygen -o key.txt`, then `node gateway/tools/backup_rekey.mjs --dir <backup dir> --identity <old key file> --recipient <new age1…> --new-identity key.txt`. The old backup is never modified; the new copy is written only after the old ciphertext decrypts to the verified bytes, restores in isolation, and the new key opens the new ciphertext. Set `MACGUARD_BACKUP_AGE_RECIPIENT` (or `--age-recipient`) to the new recipient for future backups.
4. **Back up the secrets** with `node gateway/tools/secrets_backup.mjs --recipient age1… --out <file outside the temp folders>` for a recipient you hold. It deliberately does **not** include `BACKUP_AGE_IDENTITY` (a key must never be stored only inside a file it alone can open).
5. Decide the rotation interval (suggested: yearly, and on any suspected exposure).

## Restoring from another machine (procedure, and what was proven)
Carry three things: `d1-export.sql.age`, `manifest.json`, and the private key text saved to a file. Then, with Node ≥ 22 and `age` installed: `node gateway/tools/restore_verify.mjs d1-export.sql.age manifest.json --identity key.txt` → expect `RESTORE VERIFIED (isolated copy)`. To rebuild a database: `tools/restore_to_staging.mjs` (dry run first; it refuses the production name).
**Proven by test** (`test/key_custody.test.js`, local): with an empty home directory, a minimal `PATH` and only those three files, the restore verifies; the tools contain no Keychain access; nothing is written to the home directory; without the key nothing is restored; key rotation works and leaves the original intact. **Not proven**: an actual second computer, and a restore into a remote staging database.

## Off-machine copy and periodic restore drill (tools added in `b6a1b73`; local, nothing configured yet)
`gateway/tools/backup_offsite.mjs` closes the *mechanism* side of the gap; the choice of destination and the key escrow stay with the owner.
| Command | What it does | Guarantees (tested in `test/offsite.test.js`) |
|---|---|---|
| `sync --dest /Volumes/X/macguard` | dry run; with `--apply` copies each encrypted backup (`d1-export.sql.age`, `manifest.json`, `SHA256SUMS`) | only ciphertext leaves the machine (the pinned plaintext first export is skipped and reported); an existing different file is a conflict, never overwritten; every copied file is re-hashed; the destination must be absolute, not temporary, not the backup folder or inside/containing it |
| `drill --dest … --identity KEYFILE` | restores the newest **copy** (not the original) in an isolated in-memory database and appends the result to `drills.json` | needs only the copy and a key *file* (no Keychain); still passes when the original directory is deleted; a wrong key, a missing key or a tampered copy fails and is recorded; no key material is written |
| `check`, or `backup_check.mjs --custody` | alarms `backup.offsite_stale` (> 48 h), `backup.drill_stale` (> 35 days without a passing drill), `backup.drill_failed` | `macguard.alert/1`; opt-in in `backup_check` because with no destination they fire permanently |
**Real state on this machine (2026-10-24, read-only `backup_check.mjs --custody`): `backup.offsite_stale` and `backup.drill_stale` are FIRING**, which is the truth: no off-machine copy and no drill from one exist. They clear only when the owner mounts a destination, runs `sync --apply`, and runs `drill` with the escrowed key from a copy.
Suggested cadence once configured: `sync --apply` after each daily backup (same launchd job), `drill` monthly from the copy with the key restored from the offline escrow (this also proves the escrow). A second physical computer is still the strongest drill and is **not proven**.

## Audit of 2026-10-24 (evening, third round)
Facts checked on this Mac; no secret was printed or copied (the identity was read from the Keychain into a mode-600 temporary file that was deleted immediately).
| Check | Result |
|---|---|
| `recipient.txt` equals the recipient derived from the Keychain identity `BACKUP_AGE_IDENTITY` | **yes** |
| The newest real backup (`20261024T050235Z`, encrypted, 122 rows) decrypts with that identity and its SHA-256 equals `plaintext_sha256` in the manifest | **yes** |
| Permissions of the backup root, directories, ciphertext, manifest, checksums, `recipient.txt`, `protected.json` | 700 / 600 |
| The first export `20261023T200122Z` is plaintext (with a copy of a wrangler config) | still local only, protected from pruning; **the off-machine tool skips it by design** |
| Recovery identity from Bitwarden | **BLOCKED**: the `bw` CLI is not installed and no vault is unlocked in this session, so a decrypt with a Bitwarden-held identity could not be tried. Procedure when available: save the identity to a 0600 temporary file (`bw get notes <item> > "$F"`), run `node gateway/tools/backup_offsite.mjs drill --dest <external copy> --identity "$F"`, delete `$F`; the drill passes only if that identity opens the copy. |
| A second destination | **BLOCKED (physical)**: the only volume mounted is `Muky HD`, which is the internal boot volume (`/Volumes/Muky HD` is a symlink to `/`). The off-machine tool now **refuses** a destination on the same device as the backups (`--allow-same-volume` exists only for rehearsals), so this cannot be mistaken for a second copy. |
| Restore on another computer | **BLOCKED (physical)**: needs a second machine; the tested procedure (three carried files, empty home, no Keychain) is in the section above. |
Nothing was replaced, rotated or deleted: the interim key, `recipient.txt` and every backup are as they were.

## Update of 2026-10-24 (night): destinations
The owner fixed the destinations as **Backblaze B2, Scaleway Object Storage and Cloudflare R2**; external disks are not part of the strategy, and the absence of the Bitwarden CLI does not block development. The earlier sections that speak of an external disk describe the generic directory tool (`backup_offsite.mjs`), kept for local rehearsals. The plan, the commands and the honest state are in `BACKUP-OBJECT-STORES.md`. The private identity stays in the macOS Keychain until the owner configures Bitwarden.

