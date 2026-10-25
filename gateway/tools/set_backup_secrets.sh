#!/bin/sh
# Inspects the GitHub environments that the backup workflow uses and asks ONLY for what is really missing. It never recreates a credential that exists and never copies a secret from one environment to another.
#
#   sh set_backup_secrets.sh              report; then ask (hidden prompt) for each missing credential
#   sh set_backup_secrets.sh --report     report only, ask nothing
#
# Existing layout (names only are read, never values):
#   archive-<b2|scaleway|r2>-read / -write   secrets ARCHIVE_ACCESS_KEY_ID, ARCHIVE_SECRET_ACCESS_KEY; variables ARCHIVE_BUCKET, ARCHIVE_ENDPOINT, ARCHIVE_REGION, ARCHIVE_S3_PROVIDER
#   macguard-backup-production               the export job: needs CLOUDFLARE_API_TOKEN (D1 export of the gateway database only) unless the repository already provides one
# A missing value is typed (or piped on stdin) at a silent prompt and handed to `gh secret set` on its standard input: never in an argument, a variable of a child process, a file or the output.
set -u
REPO=${GH_REPO:-MacGuard/macguard-yara-channel}; EXPORT_ENV=macguard-backup-production
command -v gh >/dev/null 2>&1 || { echo "missing tool: gh" >&2; exit 2; }
gh auth status >/dev/null 2>&1 || { echo "gh is not authenticated" >&2; exit 2; }
names() { gh "$1" list --env "$2" --repo "$REPO" 2>/dev/null | cut -f1; }
bad=0
for p in b2 scaleway r2; do for d in read write; do
  e=archive-$p-$d; s=$(names secret "$e"); v=$(names variable "$e")
  miss=""; for n in ARCHIVE_ACCESS_KEY_ID ARCHIVE_SECRET_ACCESS_KEY; do echo "$s" | grep -qx "$n" || miss="$miss $n"; done; for n in ARCHIVE_BUCKET ARCHIVE_ENDPOINT ARCHIVE_REGION; do echo "$v" | grep -qx "$n" || miss="$miss var:$n"; done
  if [ -z "$miss" ]; then echo "PRESENT: $e (2 secrets, 3+ variables)"; else echo "MISSING in $e:$miss (ask the owner; this script does not recreate keys)"; bad=1; fi
done; done
if names secret "$EXPORT_ENV" | grep -qx CLOUDFLARE_API_TOKEN; then echo "PRESENT: CLOUDFLARE_API_TOKEN in $EXPORT_ENV"; NEED_CF=0
elif gh secret list --repo "$REPO" 2>/dev/null | cut -f1 | grep -qx CLOUDFLARE_API_TOKEN; then echo "PRESENT at repository level: CLOUDFLARE_API_TOKEN (its scope for the D1 export is unknown until the export job runs)"; NEED_CF=0
else echo "MISSING: CLOUDFLARE_API_TOKEN for the export job"; NEED_CF=1; fi
if names secret "$EXPORT_ENV" | grep -qx MACGUARD_BACKUP_SIGNING_KEY; then echo "RETIRED but still present: MACGUARD_BACKUP_SIGNING_KEY in $EXPORT_ENV (delete it only after the first end-to-end Sigstore run)"; fi
[ "${1:-}" = "--report" ] && exit $bad
[ "$NEED_CF" = 1 ] || exit $bad
if [ -t 0 ]; then printf 'CLOUDFLARE_API_TOKEN, D1 export only (hidden, Enter to skip): ' >&2; stty -echo 2>/dev/null; IFS= read -r v; stty echo 2>/dev/null; printf '\n' >&2; else IFS= read -r v; fi
[ -n "$v" ] || { echo "SKIPPED: CLOUDFLARE_API_TOKEN"; exit 1; }
if printf '%s' "$v" | gh secret set CLOUDFLARE_API_TOKEN --env "$EXPORT_ENV" --repo "$REPO" >/dev/null 2>&1; then echo "OK: CLOUDFLARE_API_TOKEN set in $EXPORT_ENV"; else echo "FAILED: CLOUDFLARE_API_TOKEN could not be set"; exit 1; fi
v=
exit $bad
