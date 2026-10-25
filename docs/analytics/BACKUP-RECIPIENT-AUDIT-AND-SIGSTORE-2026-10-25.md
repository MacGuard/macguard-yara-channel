# Backup 20261024T050235Z: recipient audit and Sigstore evaluation (2026-10-25)

Read-only. No secret was read, printed or copied; no identity was generated; nothing was overwritten, synced or pushed.

## 1. Which public recipient was used
| Evidence | Finding |
|---|---|
| `gateway/tools/d1_backup.mjs` | the recipient comes from `--age-recipient` or `MACGUARD_BACKUP_AGE_RECIPIENT`; nothing else |
| `gateway/tools/backup_flow.mjs:31-33` | `execFileSync(age, ['-r', recipient])`; the recipient is validated as `age1…` and is **not** written to the manifest (`encrypted: true` only), which is why the manifest does not name it |
| `~/macguard-backups/gateway/recipient.txt` (mode 600, written 24 Oct 07:01 local, one minute before the backup) | `age1a2zctslrq22y3gpqndgcq7f46g49lagl2xvvvrdsjrvyqttp890swhjfay` |
| `status.json` | `last_status: ok`, `encrypted: true`, `last_dir: 20261024T050235Z`; no recipient field |
| age header of the file | one `X25519` stanza. An age stanza carries an ephemeral share, **not** the recipient, so the file alone cannot prove which recipient it was made for |

Conclusion: the recipient is **`recipient.txt` above, by code path and timing**. That is strong circumstantial evidence, not a cryptographic proof. The proof is a successful decryption with the matching identity (section 2).

## 2. Where the identity is
* Named Keychain item **exists** (attributes only, `-w` not used): login keychain, service `macguard-gateway-prod`, account `BACKUP_AGE_IDENTITY`, created 2026-10-24 05:01:59Z, 36 s before the backup (05:02:35Z).
* My earlier lookup used `-s BACKUP_AGE_IDENTITY` (the account name as service) and found nothing: wrong query, not a missing item.
* `docs/analytics/KEY-CUSTODY.md` already records that on 2026-10-24 this identity's derived recipient equalled `recipient.txt` and that the backup decrypted to the manifest's `plaintext_sha256`. That is a **prior claim of mine/the earlier session, not re-run today**.
* Not done today: derive the recipient from the identity and decrypt. Both need the secret value; you said not to extract values without authorization. Status of the real decrypt in this round: **NOT_RUN**, pending your yes. The Camino Seguro identity is a different key, so its failure is expected.
* Recovery status: **not BLOCKED on evidence** (item exists, timing and prior audit agree) but **not re-verified**; it becomes VERIFIED only after the test below.
* Fallback that exists today: `20261023T200122Z` is a plaintext export of the same D1 (pinned, local only). It is older, and being plaintext it must not leave the Mac.

Test to authorize (one command, prints only OK/MISMATCH): read the item into a mode-600 file in a private temp dir, `verify_custody.sh kit.txt --age-identity FILE`, decrypt to a pipe and compare SHA-256 with `plaintext_sha256`, delete the file.

## 3. Sigstore keyless instead of the permanent SSH signing key
What it replaces: only `ANCHOR.json.sig` / `CHECKPOINT.json.sig` (authenticity). age stays for confidentiality; the decrypt identity is unaffected.

How it would work from our real process (a Mac, not a CI runner):
1. After `runBackup`, `cosign sign-blob ANCHOR.json --bundle ANCHOR.json.sigstore` (no `--key`). cosign opens a browser OIDC login (Google, GitHub or Microsoft), Fulcio issues a certificate valid ~10 minutes whose SAN is the account email, Rekor logs the signature, and the bundle holds certificate, signature and the Rekor inclusion proof.
2. Verification, offline or on a clean machine: `cosign verify-blob --bundle … --certificate-identity <exact email> --certificate-oidc-issuer <issuer> ANCHOR.json`. The pinned identity+issuer replace the pinned public key. The bundle proves the signing time even though the certificate has expired.
3. GitHub Actions is only one OIDC source. For a local run the identity is a **person's account**, so security rests on that account's MFA, not on a file.

Trade-offs, honestly:
| | SSH key | Sigstore keyless |
|---|---|---|
| Long-lived secret to protect | yes (the thing you want to drop) | none; the account takes that role |
| Unattended daily backup | works | **needs an interactive browser login** per signing; a launchd job cannot do it. Unattended needs a CI/OIDC workload identity, which brings back a runner |
| Privacy | none | the email and the time go to the public Rekor log |
| Dependencies at verification | `ssh-keygen` | `cosign` plus the trust root (TUF) fetched or pinned |
| Loss of the Mac | key lost unless escrowed | nothing to lose; identity is the account |
| Compromise | rotate key | an account takeover signs anything; mitigated by MFA and by the checkpoint |

Recommendation: **do not drop the SSH key for the daily job**. Keep it, but make it a dedicated signing key with the custody in section 5. Add Sigstore as an **optional second signature on the checkpoint** (weekly, hands on, from the Mac): a different failure domain, no extra secret, and it still verifies when the Mac and the SSH key are gone. Nothing was implemented or tested here: `cosign` was not run, so every statement above about its behaviour is from its documented design, not from a run.

## 4. Independent checkpoint, rollback, clean machine (already built and tested; unchanged)
`CHECKPOINT.json(.sig)` (sequence, head SHA-256, confirmed_at) copied to places that fail separately from the three buckets; `checkAgainstCheckpoint` flags rollback, fork and loss; `recover_verify.sh` needs only `ssh-keygen`, `age`, SHA-256 and python3. With a Sigstore second signature the clean machine would additionally need `cosign`. The real chain still has no anchor, kit or checkpoint (preflight NO_GO).

## 5. Minimal Bitwarden custody (owner's hands)
Three items, nothing else: (a) secure note **age identity** (private), (b) secure note **signing key + separate passphrase item** if the SSH key is kept, (c) secure note **public kit** (recipient, signing public key, newest sequence/head). Plus one second-domain copy of (a) (paper at another address or an Emergency Access contact). Verify each with `verify_custody.sh` before relying on it. Detail: `BACKUP-KEY-CUSTODY-2026-10-25.md`.
