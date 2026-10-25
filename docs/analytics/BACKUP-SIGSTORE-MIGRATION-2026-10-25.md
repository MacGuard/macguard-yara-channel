# Backup signing: Sigstore keyless + GitHub Actions OIDC (2026-10-25)

Decision (owner): new backups are signed by the `backup.yml` workflow with Sigstore keyless; the Ed25519 key stays only to verify history; age still encrypts and its identity never goes to GitHub.

## How it works
1. `backup.yml` (manual or daily, only from `main`, environment `macguard-backup-production`) exports the D1, verifies the export in an isolated restore, encrypts with age to the public recipient in `gateway/environments/backup-trust.json`.
2. It downloads the predecessor (newest signed backup the destinations hold, verified with the pinned policy), builds `ANCHOR.json` (sequence = previous + 1, previous head hash) and signs it with `cosign sign-blob --bundle`: Fulcio issues a short certificate for the workflow identity, Rekor records the signature, the bundle `ANCHOR.json.sigstore.json` carries both. Same for `CHECKPOINT.json`.
3. Signing is all-or-nothing: temp dir, verification against the pinned identity/issuer/repository, then publish. A run from another workflow, branch or repository publishes nothing.
4. The pair is copied write-once to B2, Scaleway and R2; every object is read back; then a second job downloads the copy from each provider alone and verifies it with the clean-machine script (`recover_verify.sh`).
5. Decrypting a restore needs the age identity, which lives in the Keychain and Bitwarden only; restores are done off GitHub.

## Trust policy (also in the offline kit)
| Sequence | Valid signature | Why |
|---|---|---|
| 1 .. 1 | Ed25519 `SHA256:O+m9SD…hw9o`, namespaces `macguard-backup/1`, `macguard-backup-checkpoint/1` | the historical, frozen range |
| 2 and later | Sigstore bundle for exactly `https://github.com/MacGuard/macguard-yara-channel/.github/workflows/backup.yml@refs/heads/main`, issuer `https://token.actions.githubusercontent.com`, repository `MacGuard/macguard-yara-channel` | no pattern is ever accepted |
No downgrade: above the freeze point an Ed25519 signature is refused, so a leaked old key cannot sign new history. `MACGUARD_BACKUP_SIGNING_KEY` in GitHub is no longer used by anything (checked by `test/backup_workflow.test.js`); it is deleted only after the first end-to-end run and a check of the historical backup.

## Independent copies of the checkpoint
Rekor holds every signed checkpoint publicly (outside the Mac and the three buckets); the workflow artifact keeps it 90 days; the owner places the kit and the latest `CHECKPOINT.json` + bundle in a Bitwarden note and on paper at another address (human step). A copy counts only if `recover_verify.sh` accepts it from a clean directory.

## Evidence status
See the matrix section appended by each run. Unit tests use a cosign stand-in for the policy logic; the verifier was also run with the real cosign on a real Community release bundle (genuine OK; wrong identity, other repository, tampered body and truncated bundle refused). A real Sigstore signature of a backup exists only after the first workflow run.

## Human steps that cannot be automated
Credentials of the environment (least privilege, `sh gateway/tools/set_backup_secrets.sh`): the D1 export token, a B2 key without delete, a Scaleway key, an R2 token. Scaleway cannot separate delete from write, so its residual risk is a compromised workflow credential deleting objects: mitigated by the two other independent copies, the checkpoint and the read-back verification, not removed.
