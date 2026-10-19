# Repository protections: exact diff and effect on each workflow

Nothing below has been applied. Current state (read-only, `apply.sh verify`, 2026-10-19): secret scanning, push protection, validity checks and Dependabot security updates **disabled**; Dependabot alerts **disabled**; immutable releases `enabled:false`; **no rulesets**; classic protection of `main` has no required checks or reviews, no force pushes, no deletions, `enforce_admins:false`.

## Diff (six calls, `apply.sh plan`)
| # | Call | Before → after |
|---|---|---|
| 1 | `PATCH repos/R` secret_scanning, secret_scanning_push_protection | disabled → enabled |
| 2 | `PUT vulnerability-alerts` | Dependabot alerts disabled → enabled |
| 3 | `PUT automated-security-fixes` | disabled → enabled (security-update PRs only) |
| 4 | `PUT immutable-releases` | false → true (affects **new** releases only; published ones are untouched) |
| 5 | `POST rulesets` `ruleset-main.json` | none → on the default branch: no deletion, no force push, changes by pull request (0 approvals, threads resolved, stale reviews dismissed on push) with required checks `python-tests` and `quarantine-service` (from `ci.yml`, no path filters). **Bypass: GitHub Actions app (id 15368), mode always** |
| 6 | `POST rulesets` `ruleset-release-tags.json` | none → tags `rules-*` and `v*` cannot be updated, deleted or force-moved; no bypass |

Not changed: classic branch protection, environments, secrets, variables (`AUTO_PUBLISH` stays `true`).

## Effect per workflow
| Workflow | What it does to the repo | Effect of the rulesets / immutability | Status |
|---|---|---|---|
| `daily.yml` | `contents: write` job pushes `logs/` to `main` through `scripts/commit_logs.sh` (token = GitHub Actions app) | The push is a direct commit to `main`; rule 5 would reject it **unless** the Actions app bypasses. The bypass actor is that app | **Bypass is the one assumption not provable before applying** (GitHub documents that `GITHUB_TOKEN` pushes act as the Actions app; I did not apply to prove it). Rollback is `DELETE rulesets/{id}`; first test = manual `daily.yml` run after applying |
| `publish.yml` | creates a **draft**, uploads all assets, checks the count, publishes (`--draft=false --latest`), then commits `logs/` | Immutability is compatible: assets are complete before publication (`test_publish_failures` pins the order). Tags `rules-*` become permanent: the run never moves or deletes one. Log commit: same bypass assumption | compatible, bypass to confirm |
| `site.yml` | reads releases, deploys Pages, commits `logs/` (job `contents: write`) | Only reads releases (immutability irrelevant). Log commit: same bypass | compatible, bypass to confirm |
| transparency-log commit (`commit_logs.sh`) | `git push` with 3 retries, `git pull --rebase` | Same as above. If the bypass failed the script exits 1 with "Could not push the log": loud, not silent. The log chain would stay consistent because nothing is lost, only delayed | to confirm |
| `ci.yml` | `pull_request` only | Supplies the two required check names; a PR from this repo can merge when both are green | ok (run 39274617820) |
| `chain-test.yml` | created a non-draft prerelease with assets and deleted it with `--cleanup-tag` | **Incompatible with immutable releases as written**: a tag cannot be deleted while its release exists and a published release's assets are locked. **Fixed** (see below) | fixed and re-run |

## The chain test and immutable releases
GitHub's documentation (immutable releases): once published, the tag and assets are locked; the release can still be deleted, after which the tag can be deleted but its name can never be reused. Fix in `scripts/chain_test.py` (commit after a017f1b): create as draft, upload, publish, then at the end delete the release and, as a separate call, its tag; a leftover tag prints `WARN cleanup`. The tag name carries the run id so it is never reused. Pinned by `ChainTestSurvivesImmutableReleases`. Re-run on the current tree: run 39293983475, 27/27, no `chain-test-*` tag left.
**Not proven:** the chain test has not run *with* immutability on (it is off). After you authorize step 4, run `chain-test.yml` once: expect 27/27 and, with immutability, possibly one leftover tag (reported by `WARN cleanup`) if GitHub refuses the tag deletion. That would be cosmetic, and the test still passes.

## Suggested order, with checks
1. Steps 1–3 (scanners, alerts). Nothing can break; expect Dependabot to react to its open PRs.
2. Step 6 (tag rule). Check: next `publish.yml` creates a new tag fine (creation is allowed).
3. Step 5 (main rule) → immediately dispatch `daily.yml` and confirm the log commit lands. If it does not: delete the ruleset (`gh api -X DELETE repos/R/rulesets/<id>`), no data lost.
4. Step 4 (immutable releases) → dispatch `chain-test.yml`; the next real publish will be the first immutable release.
