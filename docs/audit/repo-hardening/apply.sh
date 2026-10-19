#!/usr/bin/env bash
# Repository protections for MacGuard/macguard-yara-channel.
#   apply.sh verify   read-only: prints the current state of every control (safe to run any time)
#   apply.sh plan     prints the exact changes, changes nothing (default)
#   apply.sh apply    makes the changes. Needs a token with repository administration; run it only with the owner's explicit approval.
# Order matters: apply the scanners first, then CI on a pull request must have run once so the required check names exist, then the rulesets.
set -uo pipefail
R="${REPO:-MacGuard/macguard-yara-channel}"; here="$(cd "$(dirname "$0")" && pwd)"; mode="${1:-plan}"
j() { gh api "$@" 2>&1; }
verify() {
  echo "== security_and_analysis"; j "repos/$R" --jq '.security_and_analysis|to_entries[]|"\(.key)\t\(.value.status)"'
  echo "== immutable releases"; j "repos/$R/immutable-releases"
  echo "== rulesets"; j "repos/$R/rulesets" --jq '.[]|"\(.id)\t\(.name)\t\(.target)\t\(.enforcement)"'
  echo "== branch protection (classic)"; j "repos/$R/branches/main/protection" --jq '{required_status_checks:.required_status_checks,required_pull_request_reviews:.required_pull_request_reviews,enforce_admins:.enforce_admins.enabled,allow_force_pushes:.allow_force_pushes.enabled}'
  echo "== code scanning alerts (open)"; j "repos/$R/code-scanning/alerts?state=open" --jq 'length'
  echo "== dependabot alerts (open)"; j "repos/$R/dependabot/alerts?state=open" --jq 'length'
}
steps=(
  "gh api -X PATCH repos/$R -F 'security_and_analysis[secret_scanning][status]=enabled' -F 'security_and_analysis[secret_scanning_push_protection][status]=enabled'"
  "gh api -X PUT repos/$R/vulnerability-alerts"
  "gh api -X PUT repos/$R/automated-security-fixes"
  "gh api -X PUT repos/$R/immutable-releases"
  "gh api -X POST repos/$R/rulesets --input $here/ruleset-main.json"
  "gh api -X POST repos/$R/rulesets --input $here/ruleset-release-tags.json"
)
case "$mode" in
  verify) verify ;;
  plan)   printf '%s\n' "${steps[@]}" ;;
  apply)  for s in "${steps[@]}"; do echo "+ $s"; eval "$s" >/dev/null || { echo "FAILED: $s"; exit 1; }; done; echo; verify ;;
  *) echo "usage: $0 verify|plan|apply"; exit 2 ;;
esac
