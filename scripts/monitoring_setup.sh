#!/bin/sh
# Owner helper to configure the usage monitor WITHOUT any secret value passing through arguments, logs or a chat.
#   sh scripts/monitoring_setup.sh status         what is configured (secret NAMES and the enable variable; never values)
#   sh scripts/monitoring_setup.sh secrets        create the missing secrets of the macguard-monitoring environment (gh asks for each value and does not echo it)
#   sh scripts/monitoring_setup.sh telegram-chat  find the Telegram chat id: asks for the bot token silently and prints ONLY chat ids and types
#   sh scripts/monitoring_setup.sh test           send ONE fixed Telegram test message through the real workflow (manual run; needs all four secrets)
# It never sets USAGE_MONITOR_ENABLED: turning the monitor on is a decision to take AFTER you have received the test message on your phone
# (docs/operations/USAGE-MONITOR-SETUP.md section 3b). It never accepts a value on its command line.
#
# Failing safe: if the secrets cannot be LISTED (gh not logged in, no network, no access) every command stops. It never reads that as "all four are missing", which would make `secrets`
# ask for new values and overwrite valid ones.
set -eu
REPO=${MG_REPO:-MacGuard/macguard-yara-channel}; ENVNAME=macguard-monitoring
NAMES="CLOUDFLARE_ANALYTICS_TOKEN CLOUDFLARE_ACCOUNT_ID TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID"

list_secrets() {
  out=$(gh secret list --env "$ENVNAME" --repo "$REPO" 2>&1) || { echo "could not list the secrets of $ENVNAME on $REPO (is gh logged in with access to the repository?): nothing was changed" >&2; return 1; }
  echo "$out" | awk '{print $1}'
}
missing() { present=$(list_secrets) || return 1; for n in $NAMES; do echo "$present" | grep -qx "$n" || echo "$n"; done; }

cmd=${1:-status}
case "$cmd" in
  status)
    present=$(list_secrets) || exit 1; echo "environment $ENVNAME on $REPO:"
    for n in $NAMES; do if echo "$present" | grep -qx "$n"; then echo "  present  $n"; else echo "  MISSING  $n"; fi; done
    v=$(gh variable list --repo "$REPO" 2>/dev/null | awk '$1=="USAGE_MONITOR_ENABLED"{print $2}') || v=""
    echo "variable USAGE_MONITOR_ENABLED: ${v:-(not set: the scheduled jobs stay skipped, state NOT_CONFIGURED)}"
    m=$(missing) || exit 1; if [ -n "$m" ]; then echo "next: sh scripts/monitoring_setup.sh secrets   (missing: $(echo $m | tr '\n' ' '))"; else echo "next: sh scripts/monitoring_setup.sh test   and check your phone"; fi ;;
  secrets)
    m=$(missing) || exit 1
    for n in $m; do
      echo "-- $n  (type or paste the value when asked; it is not shown)"
      gh secret set "$n" --env "$ENVNAME" --repo "$REPO"
    done
    left=$(missing) || exit 1; echo "done. $(echo "$left" | grep -c . || true) still missing." ;;
  telegram-chat)
    # The token goes to curl through a config on stdin, so it never appears in the process list or in this script's output. Echo is restored on ANY exit (Ctrl-C, EOF, error).
    trap 'stty echo 2>/dev/null || true' EXIT INT TERM HUP
    printf 'Telegram bot token (hidden): '; stty -echo 2>/dev/null || true; TOKEN=""; read -r TOKEN || true; stty echo 2>/dev/null || true; echo
    [ -n "$TOKEN" ] || { echo "no token given"; exit 1; }
    echo "First send any message to your bot from your phone, then this lists the chats that talked to it."
    reply=$(printf 'url = "https://api.telegram.org/bot%s/getUpdates"\n' "$TOKEN" | curl -sS -K - 2>/dev/null) || reply=""
    unset TOKEN
    printf '%s' "$reply" | python3 -c 'import json,sys
try: d=json.loads(sys.stdin.read())
except Exception: print("could not reach Telegram or got an unreadable answer: nothing was changed"); sys.exit(1)
if not d.get("ok"): print("Telegram refused the request (error_code %s): check the bot token" % d.get("error_code","?")); sys.exit(1)
seen={}
for u in d.get("result",[]):
    c=(u.get("message") or u.get("channel_post") or {}).get("chat")
    if c: seen[c["id"]]=c.get("type","?")
print("chats:", seen if seen else "none yet: message the bot first and run again")' ;;
  test)
    m=$(missing) || exit 1; [ -z "$m" ] || { echo "refused: missing $(echo $m | tr '\n' ' '). Run: sh scripts/monitoring_setup.sh secrets"; exit 1; }
    gh workflow run usage-monitor.yml --repo "$REPO" --ref main -f test_message=true
    echo "dispatched a manual run that sends ONE fixed test message. Check your phone; if it arrives you can enable the monitor (section 3b)." ;;
  *) echo "usage: sh scripts/monitoring_setup.sh status|secrets|telegram-chat|test" >&2; exit 2 ;;
esac
