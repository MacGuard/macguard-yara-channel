#!/usr/bin/env bash
# Owner runbook: move the transparency log from main to its own branch WITHOUT losing, duplicating or rewriting anything.
#   migrate_logs_branch.sh check    read-only: origin/main's logs/ is a sound log (structure, Merkle roots of every checkpoint, consistency between checkpoints)
#   migrate_logs_branch.sh create   check, then create origin/logs: ONE new commit on top of origin/main whose tree is exactly {logs/} (the subtree object of main),
#                                   pushed as a plain create of refs/heads/logs. Nothing else is pushed; main is not touched; no force.
#   migrate_logs_branch.sh verify   read-only: origin/logs descends from the same root as main, its logs/ equals main's frozen logs/ (checkpoints and bundles
#                                   byte-identical; log.jsonl starts with exactly main's bytes) and is a sound log
# Why this keeps the cryptographic continuity: the checkpoints are signed over the exact bytes of logs/checkpoints/N.txt and cover entries 0..N-1 of log.jsonl.
# The branch commit points at the SAME git tree object as main:logs (so every byte is identical by construction) and every old commit stays reachable
# unchanged. main keeps logs/ frozen at the move, so every URL that served a checkpoint from main still serves the same bytes.
# Run from a clean clone of the repository whose `origin` is the real GitHub remote. Rollback: delete the branch (gh api -X DELETE repos/R/git/refs/heads/logs)
# before any workflow writes to it; after that, revert the workflow change instead (the branch can stay).
set -euo pipefail
cmd="${1:-}"; branch="${LOGS_BRANCH:-logs}"; here="$(cd "$(dirname "$0")" && pwd)"
case "$cmd" in check|create|verify) ;; *) echo "usage: $0 check|create|verify" >&2; exit 2 ;; esac
git rev-parse --git-dir >/dev/null
fetch_main() { git fetch -q origin "+refs/heads/main:refs/remotes/origin/main"; }
sound() {   # sound REF: is <REF>:logs a sound log? (extract it, check it with the log's own code; Sigstore bundles are proven identical elsewhere)
  local d; d="$(mktemp -d)"; git archive "$1" logs | tar -x -C "$d"
  python3 "$here/tlog.py" --logs "$d/logs" verify --structure-only || { rm -rf "$d"; return 1; }
  rm -rf "$d"
}
remote_has_branch() { git ls-remote --exit-code --heads origin "$branch" >/dev/null 2>&1; }

if [ "$cmd" = check ] || [ "$cmd" = create ]; then
  fetch_main
  git cat-file -e origin/main:logs || { echo "origin/main has no logs/" >&2; exit 1; }
  sound origin/main || { echo "REFUSED: the log on origin/main is not sound; nothing was changed" >&2; exit 1; }
  echo "OK: origin/main logs/ is sound ($(git cat-file -p origin/main:logs/log.jsonl | wc -l | tr -d ' ') entries, checkpoints: $(git ls-tree --name-only origin/main logs/checkpoints/ | grep -c '\.txt$'))"
  if remote_has_branch; then echo "note: origin/$branch already exists"; fi
fi

if [ "$cmd" = create ]; then
  remote_has_branch && { echo "REFUSED: origin/$branch already exists; nothing was changed (use verify)" >&2; exit 1; }
  main_sha="$(git rev-parse origin/main)"; tree="$(git rev-parse origin/main:logs)"
  new_tree="$(printf '040000 tree %s\tlogs\n' "$tree" | git mktree)"
  [ "$(git rev-parse "$new_tree:logs")" = "$tree" ] || { echo "internal error: subtree differs" >&2; exit 1; }
  commit="$(GIT_AUTHOR_NAME='macguard-log[bot]' GIT_AUTHOR_EMAIL='macguard-log@users.noreply.github.com' GIT_COMMITTER_NAME='macguard-log[bot]' GIT_COMMITTER_EMAIL='macguard-log@users.noreply.github.com' \
    git commit-tree "$new_tree" -p "$main_sha" -m "logs: the transparency log now lives on this branch (cut over from main at $main_sha; logs/ is byte-identical)")"
  git push origin "$commit:refs/heads/$branch"       # a plain create: refused if the branch exists, never forced
  echo "created origin/$branch at $commit on top of $main_sha"
fi

if [ "$cmd" = verify ]; then
  fetch_main; git fetch -q origin "+refs/heads/$branch:refs/remotes/origin/$branch"
  [ "$(git rev-list --max-parents=0 origin/main | sort)" = "$(git rev-list --max-parents=0 "origin/$branch" | sort)" ] || { echo "FAIL: the branch does not share main's history" >&2; exit 1; }
  git cat-file -e "origin/$branch:logs" || { echo "FAIL: no logs/ on origin/$branch" >&2; exit 1; }
  # main's frozen logs/ must be reproduced exactly: same blob for every file except the ones a log grows by appending
  fail=0
  while read -r _ _ blob path; do
    case "$path" in logs/log.jsonl|logs/LOG.md|logs/checkpoint.txt|logs/checkpoint.sigstore.json) continue ;; esac
    b="$(git rev-parse "origin/$branch:$path" 2>/dev/null || true)"
    if [ "$b" != "$blob" ]; then echo "FAIL: $path differs from main (frozen) on the branch" >&2; fail=1; fi
  done < <(git ls-tree -r origin/main logs)
  LOGS_BRANCH="$branch" python3 - <<'PY' || fail=1
import os, subprocess, sys
show = lambda ref: subprocess.run(['git', 'cat-file', 'blob', ref], capture_output=True, check=True).stdout
old, new = show('origin/main:logs/log.jsonl'), show(f"origin/{os.environ['LOGS_BRANCH']}:logs/log.jsonl")
if not new.startswith(old): print('FAIL: log.jsonl on the branch does not start with exactly the bytes main froze', file=sys.stderr); sys.exit(1)
print(f'log.jsonl: {old.count(10)} entries frozen on main, {new.count(10)} on the branch (append-only)')
PY
  sound "origin/$branch" || fail=1
  [ "$fail" = 0 ] || { echo "VERIFY FAILED" >&2; exit 1; }
  echo "VERIFIED: origin/$branch continues main's log without loss, duplication or rewriting"
fi
