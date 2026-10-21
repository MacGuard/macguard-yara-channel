#!/usr/bin/env bash
# Commit logs/ to the `logs` branch (append-only). It never writes main. Run scripts/logs_branch.sh materialize first: that records the commit logs/ was read from.
# The three jobs that call this share one concurrency group (macguard-log), so the branch cannot have moved; if it did, this refuses instead of overwriting
# someone else's entries (a rebase of an append-only log would silently reorder or drop them), and the job fails loudly.
set -euo pipefail
branch="${LOGS_BRANCH:-logs}"
gitdir="$(git rev-parse --git-dir)"
[ -f "$gitdir/logs-base" ] || { echo 'logs/ was not materialized from the logs branch (run scripts/logs_branch.sh materialize first)' >&2; exit 1; }
base="$(cat "$gitdir/logs-base")"
git config user.name 'macguard-log[bot]'
git config user.email 'macguard-log@users.noreply.github.com'
wt="$(mktemp -d)"
# shellcheck disable=SC2329
cleanup() { git worktree remove --force "$wt" >/dev/null 2>&1 || true; rm -rf "$wt"; }
trap cleanup EXIT
for attempt in 1 2 3; do
  git fetch -q origin "+refs/heads/$branch:refs/remotes/origin/$branch"
  head="$(git rev-parse "refs/remotes/origin/$branch")"
  if [ "$head" != "$base" ]; then echo "the $branch branch moved since logs/ was read ($base -> $head): refusing to overwrite it" >&2; exit 1; fi
  git worktree remove --force "$wt" >/dev/null 2>&1 || true
  git worktree add -q --detach "$wt" "$head"
  rm -rf "$wt/logs"
  cp -R logs "$wt/logs"
  git -C "$wt" add logs
  if git -C "$wt" diff --cached --quiet; then echo 'No log changes'; exit 0; fi
  git -C "$wt" commit -q -m "log: ${1:-update transparency log}"
  if git -C "$wt" push -q origin "HEAD:refs/heads/$branch"; then exit 0; fi   # fast-forward only: a plain push, never forced
  sleep "$attempt"
done
echo "Could not push the log after 3 attempts" >&2; exit 1
