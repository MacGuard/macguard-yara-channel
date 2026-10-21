# Owner runbook: reviewed sources, no Actions bypass on main

Nothing in this runbook has been run. Every command changes GitHub or Cloudflare and is the **owner's** to run; agents only prepared the files. Variables used below:

```bash
R=MacGuard/macguard-yara-channel
H=docs/audit/repo-hardening            # run from a clean checkout of main after the merges named in each step
```

Decisions this implements (owner, 2026-10-21): B1 option Q (transparency logs leave `main`, the Actions bypass for code and configuration is removed); B3 REVIEWER and ADMIN may propose a source, only ADMIN authorizes; B4 a source is incorporated only by a pull request with CODEOWNERS, a valid licence, provenance verification, CI and a human approval; B5 new sources start in probation. Design: `docs/audit/source-proposals-spec.md`. The old `ruleset-main.json` (Actions app bypass, 0 approvals) is **superseded** by `ruleset-main-v2.json` and must not be applied once the logs have moved; `apply.sh` still refers to the old file on purpose and is not changed.

## 0. Baseline (read-only, safe at any time)

```bash
bash $H/apply.sh verify
gh api repos/$R/rulesets --jq '.[]|"\(.id)\t\(.name)\t\(.target)\t\(.enforcement)"'
gh api repos/$R/actions/permissions/workflow
gh api repos/$R/branches/main/protection --jq '{reviews:.required_pull_request_reviews,checks:.required_status_checks,enforce_admins:.enforce_admins.enabled}'
```

Write down the id of every existing ruleset: the rollbacks below need them.

## 1. Merge the Phase 1 pull request (CODEOWNERS, Worker code, admission hold)

It changes no workflow and nothing the pipeline publishes. After the merge:

```bash
gh api repos/$R/codeowners/errors --jq '.errors'           # expect []
python3 scripts/ruleset_check.py codeowners .github/CODEOWNERS --root .   # expect OK
```

Rollback: revert the merge commit by pull request. CODEOWNERS has no effect until a ruleset requires code-owner review (step 6).

## 2. Sandbox proof (B7). Do this before touching the real repository

The owner creates a private repository whose name contains `sandbox` (the script never creates one), then:

```bash
gh repo create MacGuard/macguard-ruleset-sandbox --private --add-readme
PROBE_DRY=1 bash scripts/ruleset_probe.sh MacGuard/macguard-ruleset-sandbox --yes-this-is-the-sandbox     # prints the plan only
bash scripts/ruleset_probe.sh MacGuard/macguard-ruleset-sandbox --yes-this-is-the-sandbox                # the real proof; deletes the rulesets it created when done
```

What it proves, with the token every workflow receives (`contents: write`, `pull-requests: write`) and with "Actions may create and approve pull requests" switched **on** (the worst case): a direct push and the contents API are refused on the default branch; a pull request cannot be merged by the job (plain, `--admin`, `--auto`); the log bot still writes `logs`, and cannot force-push or delete it; the live rulesets pass `scripts/ruleset_check.py`; CODEOWNERS has no errors. Expected last line: `PASS`. Any other outcome means the rulesets are **not** applied to the real repository; report the `PROBE` lines. Rollback of the sandbox: `gh repo delete MacGuard/macguard-ruleset-sandbox --yes`.

## 3. Worker: migration 0005 and the feature flag (nothing else changes)

Order matters; the feature stays off (`404`) until the variable is set.

```bash
# record the active version first (rollback)
npx wrangler@4.149.0 deployments list
# apply the migration to the real D1 (additive only; see admin/worker/migrations/0005_source_proposals.sql)
npx wrangler@4.149.0 d1 execute macguard-quarantine --remote --file admin/worker/migrations/0005_source_proposals.sql
# deploy from the checked per-environment copy, keeping the variables
WRANGLER_CONFIG=<your untracked copy> npm --prefix admin/worker run deploy -- --keep-vars
```

Switch the feature on only when you want it: set `SOURCE_PROPOSALS_ENABLED = "1"` in the per-environment copy and deploy again. Add `source-proposals.yml` to `PIPELINE_WORKFLOWS` only in step 7.

Rollback: set `SOURCE_PROPOSALS_ENABLED` to `"0"` (all proposal endpoints answer 404); `npx wrangler@4.149.0 rollback <previous version id>`; then, only if the tables must go, export `SELECT * FROM source_proposal_events` and run `admin/worker/migrations/0005_rollback.sql` the same way. The audit chain is not touched by the rollback.

## 4. Phase 2 (publication and repository guarantees): needs your specific acceptance

Do not merge Phase 2 without it. It moves the transparency log to the `logs` branch. Run the migration **from a clean clone**, read its output, then merge:

```bash
bash scripts/migrate_logs_branch.sh check        # read-only: proves the log tree and the checkpoints verify as they are
bash scripts/migrate_logs_branch.sh create       # creates branch logs from main, byte-identical logs/, pushes ONLY refs/heads/logs
bash scripts/migrate_logs_branch.sh verify       # fetches logs and proves it equals main's logs/ and that the verifier accepts it
# merge the Phase 2 pull request (workflows now read and write the logs branch)
gh workflow run daily.yml --repo $R -f acceptance=true       # confirm the log commit lands on branch logs and main is untouched
gh api repos/$R/commits/logs --jq '.commit.message'
```

Rollback: revert the Phase 2 merge (workflows write `main/logs` again). The `logs` branch can stay: nothing reads it after the revert. `main/logs` was never edited by the migration, so it is intact up to the cut-over commit.

## 5. Rulesets (only after step 4 shows `logs` receiving the log commits)

Create the `logs` ruleset first (it protects what now exists), then replace the main ruleset.

```bash
# 5a. logs branch: only the log bot writes, no force push, no deletion
gh api -X POST repos/$R/rulesets --input $H/ruleset-logs-branch.json --jq '.id'          # note it: LOGS_ID
# 5b. main: find the current main ruleset (if any) and replace it
MAIN_ID=$(gh api repos/$R/rulesets --jq '.[] | select(.target=="branch" and (.name|startswith("main:"))) | .id')
echo "main ruleset id: ${MAIN_ID:-none}"
if [ -n "$MAIN_ID" ]; then gh api -X PUT repos/$R/rulesets/$MAIN_ID --input $H/ruleset-main-v2.json --jq '.id'; else gh api -X POST repos/$R/rulesets --input $H/ruleset-main-v2.json --jq '.id'; fi
# 5c. read back what GitHub actually enforces and compare with the spec
gh api repos/$R/rulesets --jq '.[].id' | while read -r id; do gh api repos/$R/rulesets/$id; done | jq -s . > /tmp/live-rulesets.json     # needs jq
python3 scripts/ruleset_check.py live /tmp/live-rulesets.json                              # expect OK
gh api repos/$R/rules/branches/main                                                       # the effective rules on main
```

Rollback (any problem with the daily run, the log commit or merging): `gh api -X DELETE repos/$R/rulesets/<id>` for the ruleset in question. To return exactly to the previous state, re-create the old main ruleset with `gh api -X POST repos/$R/rulesets --input $H/ruleset-main.json` **and** revert Phase 2 (that ruleset needs the Actions bypass because the old workflows push logs to `main`).

Trade-off to decide knowingly (spec 9.6, open decision 15): `ruleset-main-v2.json` keeps the repository **Admin** role as a `pull_request`-mode bypass so that you, the only human, can merge your own reviewed pull requests; GitHub does not let an author approve their own pull request. That bypass does not let a workflow push to `main`, but it means a pull request you author is mergeable without a second approver. Remove the bypass actor from the JSON if you prefer forced approval and have a second account to approve with.

## 6. Branch protection for the pull workflow (Phase 2 only)

```bash
# repository setting "Allow GitHub Actions to create and approve pull requests" (needed to open the proposal pull request). It also lets Actions approve:
# the ruleset still demands a code-owner approval, which github-actions[bot] is not.
gh api -X PUT repos/$R/actions/permissions/workflow -f default_workflow_permissions=read -F can_approve_pull_request_reviews=true
# environment limited to main
gh api -X PUT repos/$R/environments/source-proposals --input - <<'JSON'
{"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}
JSON
gh api -X POST repos/$R/environments/source-proposals/deployment-branch-policies -f name=main -f type=branch
```

Rollback: `gh api -X PUT repos/$R/actions/permissions/workflow -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false`; `gh api -X DELETE repos/$R/environments/source-proposals`.

## 7. Let the workflow read approved proposals

In the per-environment `wrangler.toml` copy set `PIPELINE_WORKFLOWS = "daily.yml,publish.yml,source-proposals.yml"` and deploy with `--keep-vars` as in step 3. Without it the Worker answers 401 to the workflow. Rollback: remove the entry and redeploy.

## 8. Final verification

```bash
bash $H/apply.sh verify
gh api repos/$R/codeowners/errors --jq '.errors'
gh workflow run daily.yml --repo $R -f acceptance=true && gh run watch --repo $R
gh api repos/$R/commits/main --jq '.commit.message'        # unchanged by the daily run
```

A source is incorporated only when a pull request that touches `config/sources.json` is approved by the code owner and its checks are green. Until then nothing can fetch it.
