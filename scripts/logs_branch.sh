#!/usr/bin/env bash
# The transparency log lives on the `logs` branch (directory logs/), not on main, so that main can refuse every direct push (docs/audit/source-proposals-spec.md 9.4).
#   logs_branch.sh materialize   put the current logs/ of origin/logs into the working tree, byte for byte, and remember which commit it came from
# Run it right after actions/checkout in every job that reads or writes logs/. It never touches the index, never commits and never writes a ref.
# main keeps logs/ frozen at the move, so a checkout of main always has a (stale) logs/; this replaces it in the working tree only.
set -euo pipefail
branch="${LOGS_BRANCH:-logs}"
[ "${1:-}" = materialize ] || { echo "usage: $0 materialize" >&2; exit 2; }
git fetch -q --depth=1 origin "+refs/heads/$branch:refs/remotes/origin/$branch" || { echo "the $branch branch of origin could not be fetched: the log has not been moved yet (scripts/migrate_logs_branch.sh)" >&2; exit 1; }
base="$(git rev-parse "refs/remotes/origin/$branch")"
git cat-file -e "$base:logs" 2>/dev/null || { echo "origin/$branch has no logs/ directory" >&2; exit 1; }
rm -rf logs
git archive "$base" logs | tar -x
printf '%s\n' "$base" > "$(git rev-parse --git-dir)/logs-base"
echo "logs/ materialized from origin/$branch at $base"
