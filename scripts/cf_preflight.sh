#!/usr/bin/env bash
# Classifies a Cloudflare credential problem without ever printing the secrets.
# Reads CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID from the environment and the
# expected (public) account id from config/cloudflare_account_id.txt.
# Prints one status line; exit 0 only when the token authenticates for the account.
set -u
expected="$(tr -d '[:space:]' < "$(dirname "$0")/../config/cloudflare_account_id.txt")"
tok="${CLOUDFLARE_API_TOKEN:-}"; acc="${CLOUDFLARE_ACCOUNT_ID:-}"
say() { echo "cf-preflight: $1"; }
[ -n "$tok" ] || { say "FORMAT: token secret is empty"; exit 2; }
[ -n "$acc" ] || { say "FORMAT: account id secret is empty"; exit 2; }
case "$tok$acc" in *[[:space:]]*) say "FORMAT: whitespace inside a secret"; exit 2;; esac
printf '%s' "$tok" | grep -Eq '^[A-Za-z0-9_-]+$' || { say "FORMAT: token has characters outside [A-Za-z0-9_-] (length ${#tok})"; exit 2; }
if [ "$acc" = "$expected" ]; then say "ACCOUNT-ID: matches expected account"; else say "ACCOUNT-ID: MISMATCH with config/cloudflare_account_id.txt (secret length ${#acc})"; exit 3; fi
call() { curl -sS --max-time 20 -H "Authorization: Bearer $tok" "https://api.cloudflare.com/client/v4$1" -o /tmp/cf.out -w '%{http_code}'; }
code=$(call "/accounts/$acc/tokens/verify"); kind=account
if ! grep -q '"success":true' /tmp/cf.out 2>/dev/null; then code=$(call "/user/tokens/verify"); kind=user; fi
if grep -q '"success":true' /tmp/cf.out; then
  st=$(grep -o '"status":"[a-z]*"' /tmp/cf.out | head -1); say "VALIDITY: ok ($kind token, $st)"
else
  codes=$(grep -o '"code":[0-9]*' /tmp/cf.out | tr '\n' ' '); say "VALIDITY: rejected by Cloudflare (http $code, error codes: $codes) — token revoked, expired, truncated or not an API token"; rm -f /tmp/cf.out; exit 4
fi
code=$(call "/accounts/$acc/pages/projects")
if grep -q '"success":true' /tmp/cf.out; then say "PERMISSION: Pages read ok for the account"; rm -f /tmp/cf.out; exit 0; fi
codes=$(grep -o '"code":[0-9]*' /tmp/cf.out | tr '\n' ' '); say "PERMISSION/OWNERSHIP: token valid but cannot list Pages projects (http $code, codes: $codes)"; rm -f /tmp/cf.out; exit 5
