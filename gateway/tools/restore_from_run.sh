#!/bin/sh
# OWNER MACHINE: restores, in isolation, the copy that EACH provider served to a backup.yml run, with the age identity kept OUTSIDE GitHub. Never touches production.
#
#   restore_from_run.sh RUN_ID [IDENTITY_FILE]           (set MG_RECORD=1 to also report each PASS to record-restore.yml; otherwise the exact commands are printed)
#
# For b2, scaleway and r2 it downloads the artifact read-<provider> (what the READ credential of that provider downloaded), the checkpoint from the artifact `package`, verifies the Sigstore identity, hashes, sequence and
# checkpoint with recover_verify.sh, decrypts to a private temp file, compares the SHA-256 with the manifest and runs the isolated SQLite restore check (restore_verify.mjs). It then compares the three plaintext hashes.
# The identity is IDENTITY_FILE, or the Keychain item (service macguard-gateway-prod, account BACKUP_AGE_IDENTITY) copied to a private temp file that is removed on exit. Output: verdicts and hashes only.
set -u
umask 077
RUN=${1:-}; IDENT=${2:-}; [ -n "$RUN" ] || { echo "usage: $0 RUN_ID [IDENTITY_FILE]" >&2; exit 2; }
HERE=$(cd "$(dirname "$0")" && pwd); T=$(mktemp -d); trap 'rm -rf "$T"' EXIT INT TERM
TRUST="$HERE/../environments/backup-trust.json"
ED_PUB=$(jq -r .ed25519.public_key "$TRUST"); ED_MAX=$(jq -r .ed25519.max_sequence "$TRUST"); SIG_ID=$(jq -r .sigstore.identity "$TRUST"); SIG_REPO=$(jq -r .sigstore.repository "$TRUST")
if [ -z "$IDENT" ]; then security find-generic-password -s macguard-gateway-prod -a BACKUP_AGE_IDENTITY -w > "$T/id" 2>/dev/null || { echo "BLOCKED: no identity file given and the Keychain item could not be read"; exit 1; }; IDENT="$T/id"; fi
[ "$(age-keygen -y "$IDENT" 2>/dev/null)" = "$(jq -r .age_recipient "$TRUST")" ] || { echo "BLOCKED: the identity does not match the recipient in backup-trust.json"; exit 1; }
gh run download "$RUN" -n package -D "$T/package" >/dev/null 2>&1 || { echo "BLOCKED: artifact 'package' of run $RUN is not available (expired or the run did not get that far)"; exit 1; }
BAD=0; HASHES=""; RECORDS=""; REPO=MacGuard/macguard-yara-channel
for p in b2 scaleway r2; do
  T0=$(date +%s)
  if ! gh run download "$RUN" -n "read-$p" -D "$T/read-$p" >/dev/null 2>&1; then echo "FAIL  $p: no read-$p artifact (the provider was not read back)"; BAD=1; continue; fi
  S=$(ls "$T/read-$p" | grep -E '^[0-9]{8}T[0-9]{6}Z$' | head -1); D="$T/read-$p/$S"
  MG_CHECKPOINT_DIRS="$T/package/checkpoint" MG_SIGSTORE_IDENTITY="$SIG_ID" MG_SIGSTORE_REPO="$SIG_REPO" MG_ED25519_MAX_SEQUENCE="$ED_MAX" sh "$HERE/recover_verify.sh" "$D" "$ED_PUB" 1 "$IDENT" "$T/$p.sql" > "$T/$p.out" 2>&1 || { echo "FAIL  $p: $(tail -1 "$T/$p.out")"; BAD=1; continue; }
  grep -E "ANCHORED OK|DECRYPTED OK" "$T/$p.out" | sed "s/^/  $p: /" | cut -c1-160
  node "$HERE/restore_verify.mjs" "$D/d1-export.sql.age" "$D/manifest.json" --identity "$IDENT" > "$T/$p.rv" 2>&1 && echo "PASS  $p: $(grep -m1 -E 'RESTORE VERIFIED' "$T/$p.rv" | cut -c1-100)" || { echo "FAIL  $p: isolated SQLite restore: $(tail -1 "$T/$p.rv" | cut -c1-120)"; BAD=1; }
  HASHES="$HASHES $(shasum -a 256 "$T/$p.sql" | cut -d' ' -f1)"
  H=$(shasum -a 256 "$T/$p.sql" | cut -d' ' -f1); RECORDS="$RECORDS
gh workflow run record-restore.yml --repo $REPO --ref main -f run_id=$RUN -f provider=$p -f plaintext_sha256=$H -f duration_s=$(( $(date +%s) - T0 )) -f mode=drill"
done
[ "$(echo $HASHES | tr ' ' '\n' | sort -u | wc -l | tr -d ' ')" = 1 ] && [ "$(echo $HASHES | wc -w | tr -d ' ')" = 3 ] && echo "PASS  the three restored plaintexts are identical (sha256 $(echo $HASHES | cut -d' ' -f1))" || { echo "FAIL  the three providers did not all restore to the same plaintext"; BAD=1; }
if [ -n "$RECORDS" ]; then
  if [ "$BAD" = 0 ] && [ "${MG_RECORD:-}" = 1 ]; then echo "$RECORDS" | sed '/^$/d' | while read -r c; do sh -c "$c" >/dev/null && echo "RECORDED: ${c#*provider=}" | cut -d' ' -f1; done
  else echo "To record a PASS as evidence (a repo admin; the hash must equal the signed manifest's):$RECORDS"; fi
fi
exit $BAD
