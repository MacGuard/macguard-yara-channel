# Custody of the backup keys: Bitwarden plus an independent second copy (2026-10-25)

Status: **instructions, not executed.** No key was created, read, copied or printed by this work. The Bitwarden CLI (`bw` 2026.10.0) is installed; its status is `locked` (a login exists, the vault is closed). I did not unlock it. The commands below come from the CLI's documented behaviour and **were not run here**: check each with `bw <command> --help` before use. The only things tested are the scripts of this repository (`verify_custody.sh`, `backup_kit.mjs`) with throw-away keys.

## What must be protected, and what may be public
| Item | Secret? | Why it matters |
|---|---|---|
| age **identity** (the private key that decrypts backups) | **yes** | lose every copy and all backups are unreadable, permanently |
| backup **signing private key** | **yes** | lets someone sign a backup as yours; losing it means you cannot sign new backups with that identity |
| signing **public** key, age **recipient**, newest sequence and head (the kit), the checkpoint files | no | they authenticate backups and detect rollback; they must exist in several places |
| bucket credentials | yes | recreate if lost |

## Rules that never bend
1. A private key never enters the repository (the patterns are ignored and a test fails if one is tracked), a log, a chat message, a ticket, a shell command line or an environment variable. Move keys as **files**, with mode 600, and keep them outside any git working tree. `verify_custody.sh` warns about both mistakes.
2. Two failure domains at least. The Mac's Keychain, the password manager and a paper copy fail for different reasons; a second copy that fails with the first is not a second copy.
3. A copy that has never been restored is not a copy. Each is restored and checked on a schedule (below).

## Bitwarden (owner's hands; the master password stays with you)
```
export BW_SESSION="$(bw unlock --raw)"          # asks for the master password on the terminal; the session key lives in this shell only
bw sync
# the PUBLIC kit as a secure note (safe to share with a trusted person)
bw get template item | jq --rawfile kit kit.txt '.type=2 | .name="MacGuard backup recovery kit (public)" | .notes=$kit | .secureNote={type:0}' | bw encode | bw create item
# the age identity: as the note text (a few lines), or as a file attachment where your plan supports attachments
bw get template item | jq --rawfile id /path/to/age-identity '.type=2 | .name="MacGuard age identity (PRIVATE)" | .notes=$id | .secureNote={type:0}' | bw encode | bw create item
# the signing key, same way, with its passphrase kept in a SEPARATE item
bw lock; unset BW_SESSION
```
Generate the kit with `node gateway/tools/backup_kit.mjs --public-key "$(cut -d' ' -f1,2 signing.pub)" --age-recipient <age1…> --head-dir <newest backup>` (it refuses private material). Keep `history` out of it: pass files and stdin, never the secret as an argument.

## The independent second copy (pick at least one that fails differently from Bitwarden)
* **Paper in a sealed envelope, kept at another physical address.** An age identity is two short lines; an SSH signing key is a few lines. Print from an offline session or write by hand, then **restore it by typing it back and running `verify_custody.sh`** before sealing.
* **A second person or account** with Bitwarden Emergency Access, or an organisation collection with a second owner. This protects against you being unavailable, not against Bitwarden failing.
* Not a second item in the same account, not the same Mac, not an unencrypted file in cloud storage.
The earlier architecture decision (no external disks for **backups**) is about backup data; it says nothing against a paper copy of a key, and I am not proposing a disk.

## Verifying a copy (prints only OK, MISMATCH or WARNING)
```
sh gateway/tools/verify_custody.sh kit.txt --age-identity /path/to/restored-identity --signing-key /path/to/restored-signing-key
```
It derives the public halves from the private copy and compares them with the kit, and warns about open permissions or a key inside a git tree. For the real test, also run the clean-machine path of `BACKUP-AUTHENTICATION-AND-RECOVERY-2026-10-25.md` on a downloaded backup.

## Schedule
At creation; after every rotation; then every six months, and whenever Bitwarden, the Mac or the paper's location changes: restore **each** copy to a temporary file with mode 600, run `verify_custody.sh`, then delete the temporary file.

## Loss and compromise
| Event | Consequence | Action |
|---|---|---|
| the Mac is lost | none for the data if the copies and the kit exist | clean-machine restore; make a new Mac's Keychain entries from the copies |
| every copy of the age identity is lost | **backups are permanently unreadable** | none possible; this is why two failure domains are required |
| the signing key is lost | old backups still verify; no new one can be signed with that identity | create a new key, new kit and a new first statement; record the change by a note signed by the OLD key if it still exists, otherwise by the owner out of band |
| the signing key is stolen | someone can sign backups as you | rotate immediately; treat every statement signed after the theft as untrusted; publish a new kit |
| the age identity is stolen | whoever also gets a bucket object can decrypt it | new identity, re-encrypt with `rekeyBackup`, rotate bucket credentials |
| a bucket credential leaks | write or read access to that bucket | revoke and recreate; the signed anchor stops a forged backup from authenticating |

## What I did not do
No key was generated, no Keychain item was read or searched, `bw` was not unlocked, nothing was sent anywhere. The age identity's Keychain item name is still unresolved; that is yours to look up.
