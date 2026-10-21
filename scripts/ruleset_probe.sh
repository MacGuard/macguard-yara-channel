#!/usr/bin/env bash
# Real-repository proof that GitHub Actions cannot get around the mandatory review. RUN BY THE OWNER, against a SANDBOX repository, never by an agent and never
# against MacGuard/macguard-yara-channel (the script refuses it). It writes only to the sandbox: it installs a probe workflow, applies the two rulesets of
# docs/audit/repo-hardening/, dispatches the probe and reads its verdict. Procedure and rollback: docs/audit/repo-hardening/OPERATIONS.md section "Sandbox proof".
#
#   scripts/ruleset_probe.sh OWNER/macguard-ruleset-sandbox --yes-this-is-the-sandbox [--keep]
#
# The sandbox must be a PRIVATE repository whose name contains "sandbox", with a default branch that has at least one commit, created by the owner beforehand
# (`gh repo create ... --private` is the owner's decision; this script never creates a repository). Needs: gh (authenticated with repository administration on
# the sandbox), python3. Exit 0 only when every attempt to bypass the rules was refused, the log bot could still write `logs`, and the live rulesets pass
# scripts/ruleset_check.py. PROBE_DRY=1 prints the plan and calls nothing.
set -uo pipefail
REAL='macguard/macguard-yara-channel'
here="$(cd "$(dirname "$0")" && pwd)"; repo_root="$(cd "$here/.." && pwd)"; hard="$repo_root/docs/audit/repo-hardening"
repo="${1:-}"; confirm="${2:-}"; keep=0; [ "${3:-}" = "--keep" ] && keep=1
lc="$(printf '%s' "$repo" | tr '[:upper:]' '[:lower:]')"
die() { echo "REFUSED: $*" >&2; exit 2; }
[ -n "$repo" ] || die "usage: $0 OWNER/sandbox-repo --yes-this-is-the-sandbox [--keep]"
printf '%s' "$repo" | grep -Eq '^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$' || die "not an OWNER/NAME repository: $repo"
[ "$lc" != "$REAL" ] || die "$repo is the real repository; this probe only runs on a sandbox"
printf '%s' "$lc" | grep -q 'sandbox' || die "the repository name must contain the word sandbox"
[ "$confirm" = "--yes-this-is-the-sandbox" ] || die "pass --yes-this-is-the-sandbox to confirm that $repo is a throwaway repository"

NAMES="main-direct-push main-contents-api logs-push logs-force-push logs-delete pr-branch-push merge-without-review merge-admin-flag pr-stays-unmerged"
if [ "${PROBE_DRY:-0}" = 1 ]; then
  echo "DRY RUN: would verify $repo is private, install probe.yml and CODEOWNERS, create the logs branch, apply ruleset-main-v2.json and ruleset-logs-branch.json,"
  echo "  check the live rulesets with scripts/ruleset_check.py, dispatch the probe, require: $NAMES, then delete the rulesets it created (unless --keep)."
  exit 0
fi
command -v gh >/dev/null || die "gh is required"; command -v python3 >/dev/null || die "python3 is required"
gh_() { gh api "$@"; }
priv="$(gh_ "repos/$repo" --jq .private)" || die "cannot read $repo"
[ "$priv" = true ] || die "the sandbox must be private"
default="$(gh_ "repos/$repo" --jq .default_branch)"
existing="$(gh_ "repos/$repo/rulesets" --jq 'length')"
[ "$existing" = 0 ] || die "the sandbox already has $existing ruleset(s); delete them first so the proof starts from a known state"
created=()
cleanup() {
  if [ "$keep" = 0 ]; then for id in "${created[@]:-}"; do [ -n "$id" ] && gh_ -X DELETE "repos/$repo/rulesets/$id" >/dev/null 2>&1 && echo "cleanup: deleted ruleset $id"; done; fi
}
trap cleanup EXIT

put_file() {   # put_file REMOTE_PATH LOCAL_FILE: create or update a file on the default branch (before the rulesets exist)
  local rp="$1" lf="$2" sha=""; sha="$(gh_ "repos/$repo/contents/$rp?ref=$default" --jq .sha 2>/dev/null || true)"
  if [ -n "$sha" ]; then gh_ -X PUT "repos/$repo/contents/$rp" -f message="probe: $rp" -f content="$(base64 < "$lf" | tr -d '\n')" -f branch="$default" -f sha="$sha" >/dev/null
  else gh_ -X PUT "repos/$repo/contents/$rp" -f message="probe: $rp" -f content="$(base64 < "$lf" | tr -d '\n')" -f branch="$default" >/dev/null; fi
}
echo "== 1. sandbox set-up (no ruleset yet)"
put_file .github/workflows/probe.yml "$hard/probe/probe.yml"
put_file .github/CODEOWNERS "$repo_root/.github/CODEOWNERS"
put_file config/sources.json "$repo_root/config/sources.json"
head_sha="$(gh_ "repos/$repo/git/ref/heads/$default" --jq .object.sha)"
gh_ "repos/$repo/git/ref/heads/logs" >/dev/null 2>&1 || gh_ -X POST "repos/$repo/git/refs" -f ref=refs/heads/logs -f sha="$head_sha" >/dev/null
gh_ -X PUT "repos/$repo/actions/permissions/workflow" -f default_workflow_permissions=read -F can_approve_pull_request_reviews=true >/dev/null   # worst case for the proof: Actions may create AND approve pull requests

echo "== 2. apply the two rulesets"
for f in ruleset-main-v2.json ruleset-logs-branch.json; do
  id="$(gh_ -X POST "repos/$repo/rulesets" --input "$hard/$f" --jq .id)" || die "could not create $f"
  created+=("$id"); echo "created ruleset $id from $f"
done

echo "== 3. the live rulesets say what the spec requires"
live="$(mktemp)"; python3 - "$repo" "${created[@]}" > "$live" <<'PY'
import json, subprocess, sys
repo, ids = sys.argv[1], sys.argv[2:]
print(json.dumps([json.loads(subprocess.run(['gh', 'api', f'repos/{repo}/rulesets/{i}'], capture_output=True, text=True, check=True).stdout) for i in ids]))
PY
python3 "$here/ruleset_check.py" live "$live" || { echo "FAIL: the live rulesets differ from the spec"; exit 1; }
errors="$(gh_ "repos/$repo/codeowners/errors" --jq '.errors | length')"; [ "$errors" = 0 ] || { echo "FAIL: CODEOWNERS has $errors error(s) in the sandbox"; exit 1; }
echo "live rulesets OK, CODEOWNERS errors: 0"

echo "== 4. dispatch the probe and wait (bounded: 12 minutes)"
gh workflow run probe.yml --repo "$repo" --ref "$default" || die "could not dispatch the probe"
sleep 8; run_id=""; i=0
while [ $i -lt 72 ]; do
  run_id="$(gh run list --repo "$repo" --workflow probe.yml --limit 1 --json databaseId --jq '.[0].databaseId' 2>/dev/null || true)"
  st="$(gh run view "$run_id" --repo "$repo" --json status --jq .status 2>/dev/null || true)"
  [ "$st" = completed ] && break; i=$((i + 1)); sleep 10
done
[ "${st:-}" = completed ] || { echo "FAIL: the probe did not finish in 12 minutes (run $run_id); nothing is concluded from it"; exit 1; }
log="$(gh run view "$run_id" --repo "$repo" --log 2>/dev/null | grep -o 'PROBE .*' || true)"
echo "$log"

echo "== 5. verdict"
bad=0
for n in $NAMES; do
  if ! printf '%s\n' "$log" | grep -q "^PROBE $n "; then echo "FAIL: no result for $n"; bad=1; fi
done
if printf '%s\n' "$log" | grep -Eq 'actual=(ACCEPTED|REFUSED)'; then echo "FAIL: at least one attempt behaved against the expectation"; bad=1; fi
concl="$(gh run view "$run_id" --repo "$repo" --json conclusion --jq .conclusion)"; [ "$concl" = success ] || { echo "FAIL: the probe job concluded $concl"; bad=1; }
if [ "$bad" = 0 ]; then echo "PASS: no Actions job could change $default or merge without review, and the log bot could still write logs (run $run_id)"; else exit 1; fi
