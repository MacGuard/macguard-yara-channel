#!/bin/sh
# Commits evidence/backups.jsonl back to the repository (append-only, retries on a concurrent push). Only that path is ever staged. Used by backup.yml (record) and record-restore.yml.
#   commit_evidence.sh "message"
set -eu
git config user.name 'macguard-evidence[bot]'; git config user.email 'macguard-evidence@users.noreply.github.com'
git add evidence/backups.jsonl
if git diff --cached --quiet; then echo 'No evidence change'; exit 0; fi
git commit -q -m "evidence: ${1:-backup record}"
if [ "${MG_EVIDENCE_NO_REBASE:-}" = 1 ]; then git push; exit $?; fi   # the caller regenerates on a rejected push (evidence_retry.sh)
i=0; while [ "$i" -lt 3 ]; do if git push; then exit 0; fi; i=$((i+1)); git pull --rebase -q; done
echo 'Could not push the evidence after 3 attempts' >&2; exit 1
