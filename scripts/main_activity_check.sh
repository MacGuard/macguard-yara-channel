#!/bin/sh
# READ-ONLY detective control for main (docs/operations/MAIN-PROTECTION-DESIGN.md, section 4). It changes nothing: it asks the repository activity API whether anyone force-pushed or deleted a protected branch.
#   sh scripts/main_activity_check.sh [--since 2026-10-28T00:00:00Z] [--ref refs/heads/main]...
# Default window: the last 48 hours. Default ref: refs/heads/main.
#   exit 0  no force-push and no deletion in the window
#   exit 1  at least one event: the lines printed say when, what and who (a person decides what it means; this script never "fixes" anything)
#   exit 2  the question could NOT be answered (no access, API error, bad argument): never read that as "no events"
# Needs `gh` logged in with read access to the repository. It writes nothing, anywhere.
set -uf   # -f: no pathname expansion of the ref list
REPO=${MG_REPO:-MacGuard/macguard-yara-channel}; SINCE=""; REFS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --since) SINCE=${2:-}; shift 2 ;;
    --ref) REFS="$REFS ${2:-}"; shift 2 ;;
    *) echo "usage: main_activity_check.sh [--since ISO8601Z] [--ref refs/heads/NAME]..." >&2; exit 2 ;;
  esac
done
[ -n "$REFS" ] || REFS=refs/heads/main

if [ -z "$SINCE" ]; then SINCE=$(python3 -c 'import datetime as d; print((d.datetime.now(d.timezone.utc)-d.timedelta(hours=48)).strftime("%Y-%m-%dT%H:%M:%SZ"))') || { echo "cannot compute the window" >&2; exit 2; }; fi
case "$SINCE" in [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z) ;; *) echo "--since must look like 2026-10-28T00:00:00Z" >&2; exit 2 ;; esac
FOUND=0
REFS=$(echo $REFS)   # trims the list
for ref in $REFS; do
  printf '%s\n' "$ref" | grep -Eq '^refs/heads/[A-Za-z0-9._/-]+$' || { echo "refused ref: $ref" >&2; exit 2; }   # anchored: nothing that could add a query parameter or reach a shell
  for type in force_push branch_deletion; do
    out=$(gh api "repos/$REPO/activity?ref=$ref&activity_type=$type&per_page=100" --jq ".[] | select(.timestamp >= \"$SINCE\") | \"\(.timestamp) $type \(.ref) by \(.actor.login)\"" 2>&1) || { echo "could not query the activity of $ref ($type): $(echo "$out" | head -1 | cut -c1-120)" >&2; exit 2; }
    if [ -n "$out" ]; then echo "$out"; FOUND=1; fi
  done
done
if [ "$FOUND" -eq 0 ]; then echo "no force-push or deletion on: $REFS since $SINCE"; exit 0; fi
exit 1
