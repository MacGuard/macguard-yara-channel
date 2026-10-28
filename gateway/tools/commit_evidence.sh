#!/bin/sh
# Commits evidence/backups.jsonl back to the repository (append-only, retries on a concurrent push). Only the evidence files are ever staged. Used by backup.yml (record) and record-restore.yml.
#   commit_evidence.sh "message"
# Defaults are today's behaviour (the checkout in the current directory, pushed to its own branch). For the evidence branch the caller sets:
#   MG_EVIDENCE_DIR     the working tree that holds the evidence branch (a second checkout; the code checkout stays untouched)
#   MG_EVIDENCE_BRANCH  the branch to push to; a rejected push is then rebased on THAT branch
# When evidence/backups.chain exists (the evidence branch has one) the hash chain is brought up to date in the same commit.
set -eu
TOOLS=$(cd "$(dirname "$0")" && pwd); BRANCH=${MG_EVIDENCE_BRANCH:-}
cd "${MG_EVIDENCE_DIR:-.}"
git config user.name 'macguard-evidence[bot]'; git config user.email 'macguard-evidence@users.noreply.github.com'
if [ -f evidence/backups.chain ]; then node "$TOOLS/evidence_chain.mjs" update --dir evidence; fi
git add evidence/backups.jsonl
if [ -f evidence/backups.chain ]; then git add evidence/backups.chain; fi
if git diff --cached --quiet; then echo 'No evidence change'; exit 0; fi
git commit -q -m "evidence: ${1:-backup record}"
push() { if [ -n "$BRANCH" ]; then git push -q origin "HEAD:refs/heads/$BRANCH"; else git push; fi; }
if [ "${MG_EVIDENCE_NO_REBASE:-}" = 1 ]; then push; exit $?; fi   # the caller regenerates on a rejected push (evidence_retry.sh)
i=0; while [ "$i" -lt 3 ]; do if push; then exit 0; fi; i=$((i+1)); if [ -n "$BRANCH" ]; then git pull --rebase -q origin "$BRANCH"; else git pull --rebase -q; fi; done
echo 'Could not push the evidence after 3 attempts' >&2; exit 1
