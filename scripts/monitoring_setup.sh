#!/bin/sh
# Owner helper to configure the usage monitor WITHOUT any secret value passing through arguments, logs or a chat.
#   sh scripts/monitoring_setup.sh status         what is configured (secret NAMES and the enable variable; never values)
#   sh scripts/monitoring_setup.sh secrets        create the missing secrets of the macguard-monitoring environment (gh asks for each value and does not echo it)
#   sh scripts/monitoring_setup.sh telegram-chat  find the Telegram chat id: asks for the bot token silently and prints ONLY chat ids and types
#   sh scripts/monitoring_setup.sh test           send ONE fixed Telegram test message through the real workflow (manual run; needs all four secrets)
# It never sets USAGE_MONITOR_ENABLED: turning the monitor on is a decision to take AFTER you have received the test message on your phone
# (docs/operations/USAGE-MONITOR-SETUP.md section 3b). It never accepts a value on its command line.
set -eu
REPO=${MG_REPO:-MacGuard/macguard-yara-channel}; ENVNAME=macguard-monitoring
NAMES="CLOUDFLARE_ANALYTICS_TOKEN CLOUDFLARE_ACCOUNT_ID TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID"

have_secrets() { gh secret list --env "$ENVNAME" --repo "$REPO" 2>/dev/null | awk '{print $1}'; }
missing() { present=$(have_secrets); for n in $NAMES; do echo "$present" | grep -qx "$n" || echo "$n"; done; }

cmd=${1:-status}
case "$cmd" in
  status)
    present=$(have_secrets); echo "environment $ENVNAME on $REPO:"
    for n in $NAMES; do if echo "$present" | grep -qx "$n"; then echo "  present  $n"; else echo "  MISSING  $n"; fi; done
    v=$(gh variable list --repo "$REPO" 2>/dev/null | awk '$1=="USAGE_MONITOR_ENABLED"{print $2}')
    echo "variable USAGE_MONITOR_ENABLED: ${v:-(not set: the scheduled jobs stay skipped, state NOT_CONFIGURED)}"
    m=$(missing); if [ -n "$m" ]; then echo "next: sh scripts/monitoring_setup.sh secrets   (missing: $(echo $m | tr '\n' ' '))"; else echo "next: sh scripts/monitoring_setup.sh test   and check your phone"; fi ;;
  secrets)
    for n in $(missing); do
      echo "-- $n  (type or paste the value when asked; it is not shown)"
      gh secret set "$n" --env "$ENVNAME" --repo "$REPO"
    done
    echo "done. $(missing | wc -l | tr -d ' ') still missing." ;;
  telegram-chat)
    # The token goes to curl through a config on stdin, so it never appears in the process list or in this script's output.
    printf 'Telegram bot token (hidden): '; stty -echo 2>/dev/null || true; read -r TOKEN; stty echo 2>/dev/null || true; echo
    [ -n "$TOKEN" ] || { echo "no token given"; exit 1; }
    echo "First send any message to your bot from your phone, then this lists the chats that talked to it."
    printf 'url = "https://api.telegram.org/bot%s/getUpdates"\n' "$TOKEN" | curl -sS -K - 2>/dev/null \
      | python3 -c 'import json,sys; d=json.load(sys.stdin); seen={}
for u in d.get("result",[]):
    c=(u.get("message") or u.get("channel_post") or {}).get("chat")
    if c: seen[c["id"]]=c.get("type","?")
print("chats:", seen if seen else "none yet: message the bot first and run again")' ;;
  test)
    m=$(missing); [ -z "$m" ] || { echo "refused: missing $(echo $m | tr '\n' ' '). Run: sh scripts/monitoring_setup.sh secrets"; exit 1; }
    gh workflow run usage-monitor.yml --repo "$REPO" --ref main -f test_message=true
    echo "dispatched a manual run that sends ONE fixed test message. Check your phone; if it arrives you can enable the monitor (section 3b)." ;;
  *) echo "usage: sh scripts/monitoring_setup.sh status|secrets|telegram-chat|test" >&2; exit 2 ;;
esac
