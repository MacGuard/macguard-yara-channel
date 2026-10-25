# Audit of the age backup and restore flow (2026-10-25)

Method: reading `gateway/tools/backup_flow.mjs`, `backup_objstore.mjs` and `backup_lib.mjs`, running their tests, and one targeted mutation. No Keychain search, no identity printed or read, nothing sent to a provider. Environment: LOCAL.

## What the flow does right (checked in code and tests)
| Property | Where | Evidence |
|---|---|---|
| Plaintext never leaves the machine: a stamp without an `.age` file is skipped by `plan` and `sync` | `backup_objstore.mjs` | real `plan` output on this Mac: `20261023T200122Z` skipped with that reason |
| Only the ciphertext, its manifest and `SHA256SUMS` are uploaded | `FILES` constant | test `objstore.test.js` |
| The age identity is used only as a file path for `age -d -i FILE`; it is never read into an environment variable, a log or a state file | `drillCore` | code read |
| The decrypted export lives in memory; the temporary ciphertext file is mode 600 and removed in a `finally` | `drillCore` | code read |
| Write-once keys: an existing key with different bytes is a conflict; nothing is deleted | `syncAll` | tests |
| A destination that fails does not stop or touch the others | `syncAll`, `drillOne` | tests |
| "Three copies" is claimed only when all three verified the same bytes recently | `objstoreCheck` alarm `backup.three_copies` | test |
| Restore is checked against the manifest's plaintext SHA-256 and an isolated in-memory SQLite (`verifyRestore`) | `drillCore` | tests |

## Finding and fix: the drill did not authenticate the backup (fixed)
`SHA256SUMS`, `manifest.json` and the ciphertext all came from the same bucket, and age encrypts to a **public** key. Anyone able to write to one bucket could upload a different, perfectly self-consistent backup and the drill would have reported `ok`. **Fix:** when the local record of the same stamp exists, the drill requires the destination's `SHA256SUMS` to equal the local one, and every result now carries `anchored: true|false`. Test `restore drill: a different but self-consistent backup planted in one bucket is caught…` (and a mutation check: with the new check disabled that test fails; with it enabled all 8 tests pass).

## Remaining gaps
1. **No sender authentication: addressed the same day** by a signed anchor with a sequence and a chain, verified with only a public key kept outside the buckets and the Mac (`BACKUP-AUTHENTICATION-AND-RECOVERY-2026-10-25.md`). Until the owner creates a signing key and signs a real backup, real backups are still only anchored to the local record (`anchored: false` once the Mac is gone).
2. **Interim key.** The recipient is an interim age key whose private half is in the Keychain; the long-term custody (Bitwarden CLI) is not set up. The Keychain item name for the identity could not be resolved by name, so **no decrypt or restore was run in this audit: `NOT_RUN`**. What is proven locally is only the ciphertext integrity against `SHA256SUMS`.
3. **Write permission** of the three keys is unconfirmed; the only remote verification so far is read access to the three buckets.
4. A crash between writing and removing the temporary ciphertext leaves an encrypted file in the backup root (not a secret; the next run overwrites it).
