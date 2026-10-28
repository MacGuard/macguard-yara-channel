#!/bin/sh
# Writes ONE evidence record to the places the transition mode says, and reports failure if ANY of them failed (never a silent partial write):
#   evidence_write.sh MODE "commit message" -- node gateway/tools/backup_record.mjs <backup|restore> ARGS...
#   MODE=dual    the evidence branch first, then main; main is written even when the branch side failed (a record is never lost for want of one side); the exit code is non-zero if either failed
#   MODE=branch  the evidence branch only
#   (MODE=main is today's behaviour and is handled by the workflows themselves, without this script)
# The evidence branch must already be checked out in $EVIDENCE_WT (default evidence-wt). Each side goes through evidence_retry.sh, so a concurrent writer is handled by regenerating on the newest tip, and
# backup_record.mjs refuses to add a record that is already there, so running this twice (a re-run of the job) writes nothing new.
set -u
HERE=$(cd "$(dirname "$0")" && pwd); MODE=${1:?mode}; MSG=${2:?message}; shift 2; [ "${1:-}" = -- ] && shift
WT=${EVIDENCE_WT:-evidence-wt}; EBR=${EVIDENCE_BRANCH_NAME:-evidence}; RC=0   # the branch name is only overridden by tests/labs
case "$MODE" in dual|branch) ;; *) echo "evidence_write.sh: unsupported mode '$MODE'" >&2; exit 2 ;; esac
MG_EVIDENCE_DIR="$WT" MG_EVIDENCE_BRANCH="$EBR" sh "$HERE/evidence_retry.sh" "$MSG" -- "$@" --file "$WT/evidence/backups.jsonl" || { RC=$?; echo "evidence branch write FAILED (status $RC)" >&2; }
if [ "$MODE" = dual ]; then
  MG_EVIDENCE_DIR= MG_EVIDENCE_BRANCH= sh "$HERE/evidence_retry.sh" "$MSG" -- "$@" || { r=$?; echo "main write FAILED (status $r)" >&2; [ "$RC" -ne 0 ] || RC=$r; }
fi
exit "$RC"
