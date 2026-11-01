#!/bin/sh
# Writes ONE evidence record to the places the transition mode says, and says EXACTLY what happened (never a silent partial write):
#   evidence_write.sh MODE "commit message" -- node gateway/tools/backup_record.mjs <backup|restore> ARGS...
#   MODE=dual    the evidence branch first (the record is built once, there); then the SAME bytes are copied to main, so both copies are identical and a later reconciliation sees no false conflict.
#                If the branch side failed, main still gets the record (built there) so it is never lost for want of one side.
#   MODE=branch  the evidence branch only
#   (MODE=main is today's behaviour and is handled by the workflows themselves, without this script)
# Outcome, on the last line (EVIDENCE_STATUS=...) and as a GitHub annotation, with the exit code:
#   CONFIRMED     0  every place the mode asks for has the record
#   PENDING_SYNC  3  the record is in ONE place only; the other must be brought up to date with evidence_reconcile.mjs (the job fails on purpose so that it is seen)
#   ERROR         1  the record is in no place, or the two copies contradict each other (reconcile exit 4): nothing was resolved by choosing a side
# The evidence branch must already be checked out in $EVIDENCE_WT (default evidence-wt). Each side goes through evidence_retry.sh (a concurrent writer is handled by regenerating on the newest tip), and
# backup_record.mjs refuses a record that is already there, so a re-run of the job writes nothing new.
set -u
HERE=$(cd "$(dirname "$0")" && pwd); MODE=${1:?mode}; MSG=${2:?message}; shift 2; [ "${1:-}" = -- ] && shift
WT=${EVIDENCE_WT:-evidence-wt}; EBR=${EVIDENCE_BRANCH_NAME:-evidence}   # the branch name is only overridden by tests/labs
case "$MODE" in dual|branch) ;; *) echo "evidence_write.sh: unsupported mode '$MODE'" >&2; exit 2 ;; esac
say() { echo "EVIDENCE_STATUS=$1"; [ -z "${GITHUB_STEP_SUMMARY:-}" ] || echo "- evidence write ($MODE): **$1** $2" >> "$GITHUB_STEP_SUMMARY"; }

BR=0; MG_EVIDENCE_DIR="$WT" MG_EVIDENCE_BRANCH="$EBR" sh "$HERE/evidence_retry.sh" "$MSG" -- "$@" --file "$WT/evidence/backups.jsonl" || BR=$?
[ "$BR" -eq 0 ] || echo "::warning::evidence branch write failed (status $BR)"
if [ "$MODE" = branch ]; then
  if [ "$BR" -eq 0 ]; then say CONFIRMED "(evidence branch)"; exit 0; fi
  echo "::error::evidence record NOT written"; say ERROR "(evidence branch failed, status $BR)"; exit 1
fi

MN=0
if [ "$BR" -eq 0 ]; then   # copy the very same record to main
  MG_EVIDENCE_DIR= MG_EVIDENCE_BRANCH= sh "$HERE/evidence_retry.sh" "$MSG" -- node "$HERE/evidence_reconcile.mjs" --from "$WT/evidence/backups.jsonl" --to evidence/backups.jsonl --apply || MN=$?
else                       # the branch side failed: build the record on main so it is not lost
  MG_EVIDENCE_DIR= MG_EVIDENCE_BRANCH= sh "$HERE/evidence_retry.sh" "$MSG" -- "$@" || MN=$?
fi
[ "$MN" -eq 0 ] || echo "::warning::main evidence write failed (status $MN)"
if [ "$MN" -eq 4 ]; then echo "::error::the evidence copies contradict each other (same record, different content); nothing was resolved automatically"; say ERROR "(copies contradict each other)"; exit 1; fi
if [ "$BR" -eq 0 ] && [ "$MN" -eq 0 ]; then say CONFIRMED "(evidence branch + main)"; exit 0; fi
if [ "$BR" -ne 0 ] && [ "$MN" -ne 0 ]; then echo "::error::evidence record NOT written anywhere"; say ERROR "(both sides failed)"; exit 1; fi
if [ "$BR" -eq 0 ]; then echo "::error::sync pending: the record is on the evidence branch only; run evidence_reconcile.mjs --from branch --to main --apply"; say PENDING_SYNC "(main behind)"; else echo "::error::sync pending: the record is on main only; run evidence_reconcile.mjs --from main --to branch --apply"; say PENDING_SYNC "(evidence branch behind)"; fi
exit 3
