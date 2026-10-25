# Runbook: first copy to B2, Scaleway and R2, and three independent restores (2026-10-25)

Status: **PREPARED, NOT EXECUTED.** Every step marked OWNER needs a person; every command is shown, none was run against a provider. Read-only facts below were taken from the B2 account (key names and capabilities, no secrets), the provider pricing pages (read 2026-10-25) and the local backup directory.

## 0. Where things stand (checked today)
| Item | State |
|---|---|
| Candidate | `20261024T050235Z`: 3 files, 43,742 bytes; ciphertext, manifest and checksums agree (**PASS**); the age header addresses **one X25519 recipient** and nothing else (**PASS**) |
| Plaintext export `20261023T200122Z` | never sent (the tool skips it) |
| Signed anchor / chain / external checkpoint | **absent**: no signing key exists yet |
| Preflight (`backup_preflight.mjs`) on the real directory | **NO_GO**: `anchor`, `anchor_chain`, `recipient_vs_kit` not passed. This is the intended answer today. Evidence: `preflight-real-2026-10-25.json` (private directory) |
| Real restore with your identity | **NOT_RUN** |
| Staging | prepared, not deployed: the gateway staging sequence passes its 10 invariants; panel template passes the placeholder guard |

## 1. Permissions found (B2, read-only listing) and what to do about them
| Key (name) | Scope | Can | Assessment |
|---|---|---|---|
| `Mac-Guard` | **whole account** | everything, including deleting keys and buckets | far more than a backup needs; keep it off the Mac or retire it after the setup |
| `macguard-admin` | bucket `macguard-archive-b2` | write, delete, bypass retention, change lifecycle | an administrator key |
| `macguard-b2-write` | bucket `macguard-archive-b2` | write **and delete**, **bypass governance retention** | works for the sync, but a stolen copy could erase backups; the sync never deletes |
| `macguard-b2-read` | bucket `macguard-archive-b2` | read only | right key for `verify`, `heads` and `drill` |
The bucket is private, encrypted by default (SSE-B2) and **File Lock is enabled** with no default retention. **Recommendation (OWNER):** create a new write key limited to this bucket with only `listBuckets`, `listFiles`, `readFiles`, `writeFiles` (+ `writeFileRetentions` if you adopt retention) and no delete or bypass; use the read key for everything else; consider a default retention (for example governance, 30 days) so even a leaked write key cannot erase a recent backup. Scaleway and R2 key scopes could **not** be read from here: confirm in their consoles that the write key is limited to its bucket and cannot delete.

## 2. Costs (provider pages read 2026-10-25; they change)
3 objects, about 43.7 KB (about 45 KB with the anchor) per destination. One month of storage: **B2 0.0000 USD** and **R2 0.0000 USD** (both inside the free 10 GB); **Scaleway about 0.016 EUR** (it bills per started GB-hour and has no free storage; its own page bills 1 KB for 1 second as 1 GB-hour, so expect one GB's worth). Requests: about 3 writes and 9 reads per destination for sync, verify and a drill: inside every free allowance (R2 1 M writes and 10 M reads a month; B2 class A/B/C free; Scaleway requests included). Egress for a restore of 45 KB is nothing. These are orders of magnitude, not a quote.

## 3. The sequence (each gate must pass before the next)
| # | Gate | Who | Command / action | Stop if |
|---|---|---|---|---|
| G0 | create the signing key and the kit; store them per `BACKUP-KEY-CUSTODY-2026-10-25.md` | OWNER | `ssh-keygen -t ed25519 -f <path>` (with a passphrase); `backup_kit.mjs …` | the kit is not stored in two places, or `verify_custody.sh` reports a MISMATCH or WARNING |
| G1 | sign the backup and make the first checkpoint | OWNER | `backup_anchor.mjs sign --dir <stamp dir> --signing-key <key>`; `backup_anchor.mjs checkpoint --dir <stamp dir> --signing-key <key> --out <cp dir>`; keep copies of the checkpoint outside the Mac | signing fails |
| G2 | **preflight must say GO** | me / OWNER | `node gateway/tools/backup_preflight.mjs --root ~/macguard-backups/gateway --trust-key <pub> --kit kit.txt --identity <identity file> --capabilities caps.json --checkpoint-dir <cp dir>` | any `NO_GO`; `recipient_vs_kit` or `identity_matches_recipient` FAIL means the backups are not encrypted to the key you hold |
| G3 | **authorisation to write**, one destination at a time | OWNER | export the write credentials in your shell (names `MG_B2_KEY_ID`/`MG_B2_SECRET`, etc.; never in chat) | you have not said yes to that destination |
| G4 | first sync | OWNER or me on your word | `backup_objstore.mjs sync --root … --apply` (dry run first without `--apply`) | a `conflicts` entry (different bytes under an existing key: nothing is overwritten) or an error; report, do not retry blindly |
| G5 | verify | | `backup_objstore.mjs verify` | any destination `ok: false` |
| G6 | **three independent restores**, each from ONE destination | OWNER supplies the identity file | `backup_objstore.mjs drill --identity <file> --trust-key <pub> --min-sequence <n> --checkpoint-dir <cp dir>`; then `heads --stamp <s> --trust-key <pub> --checkpoint-dir <cp dir>` | any destination fails; `rollback_everywhere`; `anchor` other than `signature` |
| G7 | restore into staging | OWNER, after staging exists | `restore_to_staging.mjs` (refuses non-staging names) | the target name does not end in `-staging` |
| G8 | "three copies" | | claimed only when G5 and G6 pass for all three and the checkpoint matches the newest head | |
Cleanup: the identity file made for G6 is deleted afterwards; nothing is deleted at any provider.

## 4. Rollback and failure handling
Writes are write-once, so a failed sync leaves some objects in place: that is safe, the next run sees them as `already_there`. A conflict is investigated (someone wrote different bytes), never overwritten. Removing a test object is a deletion and needs its own authorisation. If a provider key leaks: revoke it; the signed anchor stops a forged backup from authenticating, and the checkpoint exposes a rollback.

## 5. Decisions for the owner (strictly what is needed)
1. Create the signing key (with passphrase) and the kit; store them in two failure domains. 2. A write key per provider limited to its bucket without delete (B2 recommendation above) and confirmation for Scaleway and R2. 3. A yes, per destination, for the first write. 4. An identity **file** for the restores, deleted afterwards. 5. Whether to adopt File Lock retention on B2.
