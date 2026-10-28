#!/bin/sh
# Appends evidence and pushes it, safely under concurrent writers. On a rejected push it does NOT rebase (two appends to the end of the same file always conflict): it resets to the current origin tip and
# runs the append command again, so every attempt starts from the latest log and the command validates against it.
#   evidence_retry.sh "commit message" -- command args...
# Same defaults as commit_evidence.sh (today: the current checkout, branch main). For the evidence branch: MG_EVIDENCE_DIR (its working tree) and MG_EVIDENCE_BRANCH.
set -eu
MSG=$1; shift; [ "${1:-}" = -- ] && shift
DIR=${MG_EVIDENCE_DIR:-.}; BRANCH=${MG_EVIDENCE_BRANCH:-main}
i=1
while [ "$i" -le 6 ]; do
  "$@"
  rc=0; MG_EVIDENCE_NO_REBASE=1 sh "$(dirname "$0")/commit_evidence.sh" "$MSG" || rc=$?
  [ "$rc" -ne 0 ] || exit 0
  if [ "$rc" -eq 2 ]; then echo 'refused (integrity or missing branch), not a push conflict: not retrying' >&2; exit 2; fi
  echo "push rejected (attempt $i); regenerating the record on the newest $BRANCH" >&2
  git -C "$DIR" fetch -q origin "$BRANCH"; git -C "$DIR" reset -q --hard "origin/$BRANCH"
  sleep "$i"; i=$((i + 1))
done
echo 'Could not record the evidence after 6 attempts' >&2; exit 1
