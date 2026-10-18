#!/usr/bin/env bash
# Commit logs/ back to the repository (append-only). Retries on a concurrent push.
set -euo pipefail
git config user.name 'macguard-log[bot]'
git config user.email 'macguard-log@users.noreply.github.com'
git add logs
if git diff --cached --quiet; then echo 'No log changes'; exit 0; fi
git commit -q -m "log: ${1:-update transparency log}"
for attempt in 1 2 3; do
  if git push; then exit 0; fi
  git pull --rebase -q
done
echo 'Could not push the log after 3 attempts' >&2; exit 1
