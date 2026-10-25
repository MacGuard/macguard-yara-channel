#!/bin/sh
# OWNER PROCEDURE: loads the CI credentials of the backup workflow into the GitHub environment `macguard-backup-production`, without echoing them, putting them in an argument, an environment variable of a child process
# or a file. Each value is typed (or pasted) at a silent prompt, or piped on stdin for a single name, and handed to `gh secret set` through its standard input. Output: names and OK/SKIPPED only.
#
#   sh set_backup_secrets.sh                 asks for every missing secret in turn (press Enter to skip one)
#   sh set_backup_secrets.sh MG_B2_SECRET    sets just that one (reads the value silently, or from stdin if piped)
#
# What each credential must be (least privilege; create them in the provider's console and paste once):
#   CLOUDFLARE_API_TOKEN       token limited to the MacGuard account: D1 read/export on the gateway database only (Account > D1; add Workers Scripts:Read only if you want the deployments list in the manifest)
#   MG_B2_KEY_ID / MG_B2_SECRET        B2 application key restricted to bucket macguard-archive-b2 with listBuckets, listFiles, readFiles, writeFiles ONLY (no deleteFiles, no bypassGovernance, no writeBucket*)
#   MG_SCW_KEY_ID / MG_SCW_SECRET      Scaleway IAM application key for the project, policy ObjectStorageObjectsRead + ObjectStorageObjectsWrite on bucket macguard-archive-scw (Scaleway cannot separate delete from write: see the residual risk in the docs)
#   MG_R2_KEY_ID / MG_R2_SECRET        R2 S3 token restricted to bucket macguard-archive-r2 with "Object Read & Write" (not Admin)
# The age IDENTITY and the old Ed25519 key are never set here.
set -u
ENV_NAME=macguard-backup-production
NAMES="CLOUDFLARE_API_TOKEN MG_B2_KEY_ID MG_B2_SECRET MG_SCW_KEY_ID MG_SCW_SECRET MG_R2_KEY_ID MG_R2_SECRET"
command -v gh >/dev/null 2>&1 || { echo "missing tool: gh" >&2; exit 2; }
gh auth status >/dev/null 2>&1 || { echo "gh is not authenticated" >&2; exit 2; }
have() { gh secret list --env "$ENV_NAME" 2>/dev/null | cut -f1 | grep -qx "$1"; }
setone() {
  n=$1
  case " $NAMES " in *" $n "*) ;; *) echo "REFUSED: $n is not one of the backup credentials"; return 1;; esac
  if [ -t 0 ]; then printf '%s (hidden, Enter to skip): ' "$n" >&2; stty -echo 2>/dev/null; IFS= read -r v; stty echo 2>/dev/null; printf '\n' >&2; else IFS= read -r v; fi
  [ -n "$v" ] || { echo "SKIPPED: $n"; return 0; }
  if printf '%s' "$v" | gh secret set "$n" --env "$ENV_NAME" >/dev/null 2>&1; then echo "OK: $n set in $ENV_NAME"; else echo "FAILED: $n could not be set"; fi
  v=
}
if [ $# -ge 1 ]; then for n in "$@"; do setone "$n"; done; exit 0; fi
for n in $NAMES; do if have "$n"; then echo "PRESENT: $n"; else setone "$n"; fi; done
echo "Retired, to be deleted ONLY after the first end-to-end Sigstore run: MACGUARD_BACKUP_SIGNING_KEY ($(have MACGUARD_BACKUP_SIGNING_KEY && echo present || echo absent))"
