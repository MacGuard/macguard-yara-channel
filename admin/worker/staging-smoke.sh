#!/usr/bin/env bash
# Black-box checks of a DEPLOYED quarantine service that need no credentials: nothing private is reachable anonymously, forged pipeline tokens are refused,
# the login redirect is bound to the browser, the UI carries its security headers. Read-only (GET and refused POSTs). usage: staging-smoke.sh https://admin-host
set -uo pipefail
base="${1:?usage: $0 https://admin-host}"; base="${base%/}"; fail=0
case "$base" in https://*|http://127.0.0.1:*) ;; *) echo "refusing a non-https URL (only http://127.0.0.1 is allowed, for testing this script)"; exit 2;; esac
ok()  { printf 'PASS %s\n' "$1"; }
bad() { printf 'FAIL %s\n' "$1"; fail=1; }
code() { curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$@"; }
for p in /api/candidates /api/stats /api/audit /api/audit/verify /api/members /api/me /api/pipeline/decisions; do
  [ "$(code "$base$p")" = 401 ] && ok "anonymous GET $p -> 401" || bad "anonymous GET $p is not 401"
done
[ "$(code -X POST -H 'Content-Type: application/json' -d '{}' "$base/api/decisions")" = 401 ] && ok "anonymous POST /api/decisions -> 401" || bad "anonymous POST /api/decisions"
[ "$(code -X POST -H 'Authorization: Bearer a.b.c' -H 'Content-Type: application/json' -d '{}' "$base/api/pipeline/submit")" = 401 ] && ok "forged pipeline token -> 401" || bad "forged pipeline token"
body="$(curl -s --max-time 20 "$base/public/stats")"; echo "$body" | python3 -c "
import json,sys; d=json.load(sys.stdin)
def nums(x): return all(isinstance(v,(int,float)) or (isinstance(v,dict) and nums(v)) for v in x.values())
sys.exit(0 if nums(d) else 1)" && ok "/public/stats returns counts only" || bad "/public/stats returns more than counts: $body"
h="$(curl -s -D - -o /dev/null --max-time 20 "$base/")"
for want in 'content-security-policy: default-src' 'x-content-type-options: nosniff' 'cache-control: no-store' 'strict-transport-security'; do
  echo "$h" | tr 'A-Z' 'a-z' | grep -q "$want" && ok "UI header $want" || bad "UI header missing: $want"
done
l="$(curl -s -D - -o /dev/null --max-time 20 "$base/auth/login")"
echo "$l" | grep -qi '^location: https://github.com/login/oauth/authorize?.*client_id=[A-Za-z0-9]' && ok "login redirects to GitHub with a client_id" || bad "login redirect"
echo "$l" | grep -qi '^set-cookie: __Host-mg_oauth=.*HttpOnly' && ok "login state cookie is __Host-, HttpOnly" || bad "login state cookie"
[ "$(code "$base/auth/callback?code=x&state=y")" = 302 ] && ok "callback without the browser's state cookie -> 302 back to the sign-in screen" || bad "callback without cookie"
[ "$(code "$base/does-not-exist")" = 404 ] && ok "unknown path -> 404" || bad "unknown path"
exit $fail
