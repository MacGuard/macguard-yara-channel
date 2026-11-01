#!/bin/sh
# Appends evidence and pushes it, safely under concurrent writers. On a rejected push it does NOT rebase (two appends to the end of the same file always conflict): it resets to the current origin/main and
# runs the append command again, so every attempt starts from the latest log and the command validates against it.
#   evidence_retry.sh "commit message" -- command args...
set -eu
MSG=$1; shift; [ "${1:-}" = -- ] && shift
i=1
while [ "$i" -le 6 ]; do
  "$@"
  if MG_EVIDENCE_NO_REBASE=1 sh "$(dirname "$0")/commit_evidence.sh" "$MSG"; then exit 0; fi
  echo "push rejected (attempt $i); regenerating the record on the newest main" >&2
  git fetch -q origin main; git reset -q --hard origin/main
  sleep "$i"; i=$((i + 1))
done
echo 'Could not record the evidence after 6 attempts' >&2; exit 1
