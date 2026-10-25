# Backup signing and recovery: local closure (2026-10-25)

Scope: the local signed backup `20261024T050235Z` and its independent recovery path. **Not covered: any restore from B2, Scaleway or R2 (nothing was written to them).** Status of the module: **LOCAL_VERIFIED**. Production use waits on the human steps at the end.

## What exists now (real files, public material only in the last two)
| Item | Where | Fact |
|---|---|---|
| signed anchor | `~/macguard-backups/gateway/20261024T050235Z/ANCHOR.json(.sig)` | namespace `macguard-backup/1`, sequence 1, head `1852836f…8ef4`; the three encrypted-backup files are byte-identical to before signing |
| first checkpoint | `~/macguard-backups/checkpoints/0001/CHECKPOINT.json(.sig)` | namespace `macguard-backup-checkpoint/1`, sequence 1, same head as the anchor |
| public recovery kit | `~/macguard-backups/recovery-kit/recovery-kit.txt` (mode 600) | fingerprint `SHA256:O+m9SD…hw9o`, recipient, schemas, namespaces, hashes of the five artifacts, checkpoint anchor, restore steps; scanned for private material (none) |

## Signing is now all-or-nothing (`4ba3ec4`)
A statement is signed inside a private temp directory, verified against the trusted public key, and only then linked into the backup: signature first, statement last. A failure, a truncated signature, a wrong key or a SIGKILL leaves the directory as it was; an existing anchor or checkpoint is never replaced; an empty key file is refused; the CLI will not sign without `--public-key`. A stray signature without its statement (a trace of an interrupted publication) is cleaned by the next run; a stray statement without signature is never removed automatically.

## Protecting the key (owner, one time) and signing unattended afterwards
The key file on this Mac currently has **no passphrase** (checked: `ssh-keygen -y` derives the public key without prompting). To protect it without changing the pair:
```
export BW_SESSION="$(bw unlock --raw)"
sh gateway/tools/protect_signing_key.sh ~/.local/share/macguard/backup-signing/backup-ed25519 "<existing key note>" "MacGuard backup signing passphrase"
```
It asks for the passphrase twice with no echo, protects a copy, edits the existing note, stores the passphrase in a separate login item, proves that the note recovered from Bitwarden, unlocked with the stored passphrase, derives the same public key, and only then replaces the local file atomically (mode 400). If the Bitwarden proof fails it puts the note back and leaves the local file alone. Tested against a **stand-in** for `bw` (the real one is locked here), so run it once while watching the OK lines; `restore` of the key later uses `bw get notes … | sh gateway/tools/install_signing_key.sh KEY` (never `> KEY`).

Unattended signing without disabling the passphrase and without a plaintext password: use `ssh-agent`. Once, interactively: `ssh-add --apple-use-keychain KEY` (the passphrase goes to the macOS Keychain, not to a file). In the launchd job: `ssh-add --apple-load-keychain` then `node gateway/tools/backup_anchor.mjs sign --dir … --signing-key KEY.pub --agent --public-key "<line>"`. The signing code only touches the **public** key file in this mode. Tested here with a throw-away agent and key (the private file deleted before signing); **not tested with the real protected key**. Honest limit: while the key is loaded, any process of your user session can ask the agent to sign, though none can read the key; weekly manual signing is the stricter alternative.

## Independent checkpoint copies
The checkpoint is public (a sequence, a stamp, a hash) and must live where an attacker of the buckets cannot reach: (1) a Bitwarden secure note holding the text of `CHECKPOINT.json` and `.sig`; (2) a printout with the kit, at another address; (3) a second person or Emergency Access contact holding the same note. Refresh after each confirmed backup. A copy only counts if `recover_verify.sh` accepts it from a clean directory. Putting it in a repository is possible (it is public) but is a push, so it waits.

## Matrix
| SHA | File | Function | Evidence | Result | State | Residual risk |
|---|---|---|---|---|---|---|
| `4ba3ec4` | `gateway/tools/backup_anchor.mjs` | `signAtomic`, `signBackup`, `signCheckpoint`, CLI | `backup_signing_safety.test.js` 9 tests (empty key, wrong key, signing error, truncated signature at two lengths, existing anchor, SIGKILL, key never written, checkpoint, agent mode, rollback/fork/wrong sequence); disabling the verification made 3 fail | PASS | LOCAL_VERIFIED | agent mode not run with the real protected key |
| `61f174a` | `gateway/tools/install_signing_key.sh` | atomic key restore | `install_signing_key.test.js` | PASS | LOCAL_VERIFIED | the `bw` side is documented behaviour, not run |
| `caec9de` | `gateway/tools/protect_signing_key.sh` | add passphrase, update Bitwarden, prove, replace | `protect_signing_key.test.js` 3 tests against a `bw` stand-in | PASS (stand-in) | NOT_RUN against real `bw` | real `bw edit/create` argument handling unverified |
| `d8bc571` | `gateway/tools/recover_verify.sh` | checkpoint mandatory | `backup_recovery`, `backup_checkpoint` tests (old test inverted, stricter) | PASS | LOCAL_VERIFIED | needs `ssh-keygen`, `age`, `python3` on the clean machine |
| `d8bc571` | `gateway/tools/backup_preflight.mjs` | `checkpoint` is REQUIRED for GO | `backup_preflight.test.js` | PASS | LOCAL_VERIFIED | `GO` here means "ready for the first sync", not "restored" |
| `d8bc571` | `gateway/tools/backup_kit.mjs` | fingerprint, artifacts, checkpoint anchor, output scan | `backup_custody.test.js` | PASS | LOCAL_VERIFIED | the kit is only as good as its off-Mac copies |
| real data | anchor + checkpoint | rehearsal on copies | 8 attacks refused (altered ciphertext, anchor/checkpoint with another sequence, truncated signature, cross-namespace both ways) | PASS | LOCAL_VERIFIED | none beyond the above |
| real data | clean-environment restore | `env -i`, empty HOME, copies only | genuine copy decrypts and SHA-256 equals `plaintext_sha256`; refused and nothing decrypted for: no checkpoint, rollback (known sequence 2), altered ciphertext, missing signature, forged checkpoint, other public key | PASS | LOCAL_VERIFIED | not a second computer |
| real data | preflight with kit, checkpoint and Keychain identity | `backup_preflight.mjs` | verdict GO, no failures; identity matches recipient | PASS | LOCAL_VERIFIED | write permission and cloud restore NOT_RUN |
| real data | Bitwarden copies | identity and signing key | `bw` locked in this session | NOT_RUN | BLOCKED (owner unlocks) | the Bitwarden copy of the age identity was never decrypted by me |
| gateway suite | all | `node --test test/*.test.js` | 273/273 (was 259), `test_secret_hygiene` 3/3, gitleaks clean on the 4 commits | PASS | LOCAL_VERIFIED | |

## Local signed backup versus restore from providers
Done: the local backup is signed, a checkpoint and kit exist, and a clean-environment restore **from copies on this Mac** works. Not done and not claimed: any upload, any download from B2/Scaleway/R2, any restore on a second computer.

## Needs a human
1. Run `protect_signing_key.sh` (adds the passphrase), then decide between the agent job and weekly manual signing.
2. Unlock Bitwarden and run the verification of the stored age identity and signing key (`verify_custody.sh`) from the Bitwarden copies.
3. Put the kit and checkpoint copies in the independent places above.
4. Per destination: approve the first `sync --apply`, with write-once keys (B2 `macguard-b2-write` can delete and bypass retention; the account-wide `Mac-Guard` key should not be used; Scaleway and R2 scopes are unknown).
5. After the sync: the three restores from the providers (`drill`), which are what moves the module from LOCAL_VERIFIED to production.
