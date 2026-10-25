# Merge proposal (NOT executed: no merge and no push without the owner's go-ahead)

Facts checked on 2026-10-23 (read-only): local `main` = `89162af`, `origin/main` = `82b4cb6` (4 commits ahead of the local one). Open PRs form two independent stacks plus dependabot: the **intelligence stack** `#34 mgctl → main`, `#36 intelligence-live → mgctl`, `#37 intelligence-eu → intelligence-live`, `#38 alerts → intelligence-eu`; the **wiki stack** `#29 wiki-d1 → main`, `#30 d2`, `#31 d3`, `#32 d4`; plus `#33`, `#26`, `#27`, `#23`. The work in this proposal is a **third line** that has no PR yet.

## What is on the table
| Branch | Based on | Ahead of `origin/main` | Content |
|---|---|---|---|
| `feat/backup-archive` | main | 6 | historic CAS and `tar.zst` archive (no real writes ever made) |
| `feat/monetization` | backup-archive | 12 (6 own) | gateway Worker, licence matrix, Premium builder, Stripe against a local fake |
| `feat/analytics-guardops` | monetization | 38 | analytics, KPIs, cost, CRM, dashboards, admin API, retention, backup tooling, hardening, Premium families, E2E |
| `docs/analytics-roadmap` | monetization-roadmap + analytics | — | roadmap row and kanban cards (generated web data) |
| `docs/wiki-analytics` | wiki-monetization + analytics | — | wiki pages |
`feat/analytics-guardops` already contains `feat/backup-archive` and `feat/monetization` (verified with `git merge-base --is-ancestor`), so **one merge request for the stack is the natural unit**; it is 177 files, +14.1k lines (2026-10-24), mostly `gateway/`, `contracts/`, `docs/`.

## Conflicts (dry runs with `git merge-tree --write-tree`, nothing written; re-run 2026-10-24 against `origin/main` `793c451`)
`origin/main` keeps moving through automated `log:` commits (daily review, site deploy), so it must be merged into the stack (not rebased) just before the MR.
`feat/analytics-guardops` with `origin/main`: 0 conflicts · with `feat/alerts` (top of the intelligence stack): 0 · `docs/analytics-roadmap` with `feat/alerts`: 0 · `docs/wiki-analytics` with `docs/wiki-d4`: 0 · `feat/monetization` with `feat/alerts`: 0. **No textual conflicts.** The semantic risk is in *generated* files: `web/api/v1/*.json`, `docs/intelligence/KANBAN.md` and the roadmap rows are generated from sources that both lines edit, so after whichever line merges second, run `python3 scripts/gen_intel_web.py` and `python3 scripts/gen_kanban.py` again and commit the regenerated files.

## Proposed order
1. Intelligence stack and wiki stack as already planned by the owner (they are independent of this work; the Premium builder will later consume the intelligence connectors).
2. This stack as one MR to `main` **after** rebasing nothing: merge `origin/main` into it (not a rebase, no history rewrite), re-run the three suites on the merge result, regenerate the web data, then merge.
3. `docs/analytics-roadmap` and `docs/wiki-analytics` last, regenerated on top of the merged `main` (their only content is derived data and pages).
Nothing in the gateway deployment depends on this merge: the Worker is already running from `feat/analytics-guardops` at the commit in `DEPLOYMENT.md`. Merging only makes `main` match what is deployed.

## Validation to repeat on the merge result
`cd gateway && node --test test/*.test.js` · `node test/runtime/runtime.test.mjs` · `python3.13 -m unittest discover -s tests` · `node tools/gen_openapi.mjs --check` · `node tools/gen_kpi_catalog.mjs --check` · `python3.13 scripts/wiki_check.py` · `python3.13 scripts/gen_kanban.py --check`. The historical suite count (588 Python, 10 skipped) must not fall.

## Rollback
Before merging record `origin/main`'s SHA. The merge is a normal merge commit: `git revert -m 1 <merge sha>` restores `main` exactly; the deployed Worker is independent and has its own rollback (`wrangler rollback`, see `DOMAIN-MIGRATION.md` and `DEPLOYMENT.md`). The local branches are kept; nothing is deleted.

## Evidence to attach to the MR
`docs/analytics/MATRIX.md` (status per feature, commits, tests), `DEPLOYMENT.md` (resources, versions, what was and was not verified remotely), `SECURITY-REVIEW.md`, `BACKUP-RECOVERY.md`, the green logs of the three suites on the merge result.

## Decisions needed from the owner before merging
Whether `main` should carry a Worker that is already deployed from a branch; whether the stack is one MR or split (backup / monetization / analytics); and the licence question about Community redistributing DRL and GPL material (`docs/monetization/LICENSES.md` §4), which this work does not resolve.

## Update 2026-10-24 (second closing round)
Stack tips now: `feat/analytics-guardops` `550f0c0` + docs; `docs/analytics-roadmap` and `docs/wiki-analytics` carry the matching docs (roadmap/kanban/web data regenerated as a whole, wiki 23/23). Validation on the stack tip: Node 198/198, workerd 9/9, Python 3.13 605 OK (10 skipped), drift checks current. Conflict dry runs were not repeated after the new commits; repeat them just before the MR (see above). Nothing was pushed or merged.
