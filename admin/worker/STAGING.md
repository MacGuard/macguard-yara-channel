# Deploying the quarantine service: staging first, then production

Nothing here has been run against Cloudflare or GitHub OAuth: what exists is the service, its tests on a Node shim (`npm test`, 38) and on the real Workers runtime with a real D1 and a faked GitHub (`npm run test:runtime`, 12), and the black-box script `staging-smoke.sh` (validated against the local runtime). This file lists exactly what a person has to do and what proves it worked.

## Human actions (credentials, cannot be automated)
| # | Who | Action | Output to keep |
|---|---|---|---|
| 1 | Cloudflare account owner (`mac_guard@proton.me`) | Create an API token with **Workers Scripts:Edit** and **D1:Edit** (account scope; the Pages token is separate). Export it only in the shell that deploys: `export CLOUDFLARE_API_TOKEN=…` | nothing written to disk |
| 2 | GitHub org owner | Create an OAuth App **for staging**: callback `https://<staging host>/auth/callback`. A second one for production later (never share a client secret between environments) | client id (not secret), client secret (shown once) |
| 3 | owner | Decide the hostnames (a `workers.dev` name is disabled in `wrangler.toml`; use a route or custom domain you control) | the two URLs |

## The integration environment is temporary
No permanent staging is kept. Create it only to run the real-OAuth acceptance below, then delete it: `wrangler delete --config wrangler.staging.toml`, `wrangler d1 delete macguard-quarantine-staging`, delete the staging OAuth App, and revoke the Workers/D1 token (or let it expire). Production is then deployed with its own OAuth App and the same commands. The Workers/D1 token is used only to provision or update the backend; approving rules needs only a GitHub login with push/admin on the repository, and CI never holds that token (`test_workers_and_d1_credentials_never_live_in_a_workflow`).

## Deploy to staging (copy `wrangler.toml` to `wrangler.staging.toml`, never commit real ids)
```
cd admin/worker && npm ci
wrangler d1 create macguard-quarantine-staging                       # put the id into wrangler.staging.toml
wrangler d1 execute macguard-quarantine-staging --remote --file schema.sql --config wrangler.staging.toml
# in wrangler.staging.toml: name, PUBLIC_URL and OIDC_AUDIENCE = the staging URL, database_id
printf %s "$CLIENT_ID"     | wrangler secret put GITHUB_CLIENT_ID     --config wrangler.staging.toml
printf %s "$CLIENT_SECRET" | wrangler secret put GITHUB_CLIENT_SECRET --config wrangler.staging.toml
wrangler deploy --config wrangler.staging.toml
```
Note the version id printed by `wrangler deploy` (rollback: `wrangler rollback`).

## Prove it (each line is evidence; paste the output into `docs/audit/evidence/`)
1. `bash staging-smoke.sh https://<staging host>` → all PASS (anonymous 401s, forged token 401, counts-only public endpoint, headers on the UI, login redirect, state cookie).
2. **Pipeline identity with a real Actions token:** set the repository variable `QUARANTINE_URL` to the *staging* URL only for a manual `daily.yml` dispatch; its log must show `quarantine: N new`; `GET /api/pipeline/decisions` is then answered. Unset the variable afterwards. (Staging receives real candidate text; it is private.)
3. **Roles with real accounts** (one person per row, or one person and a second GitHub account):
   | Account | Expect |
   |---|---|
   | repo collaborator with *read* only | sign-in works, `/api/candidates` → 403 |
   | collaborator with *write* | list/view OK; approve/reject a batch OK; `/api/members` → 403 |
   | repo admin | all of the above plus `/api/audit/verify` → `ok:true` |
   | sign out, then reuse the old cookie | 401 |
   | remove write access on GitHub, wait 60 s, retry a decision | 403 |
4. **Batch and persistence:** reject 3 candidates in one batch with the exact count, reload, check the audit tab shows who/when/why; `wrangler deploy` again (new version) and check the data is still there.
5. **The assumption in OPERATIONS.md step 6:** `GET /repos/{repo}` with the user's OAuth token returns `permissions` — confirm with the real OAuth app (the code relies on it; the tests fake it).
6. **Isolation:** with the staging URL known, `curl` the public site and the Cloudflare mirror for any candidate path or hash: nothing from quarantine may appear (`scripts/make_public_candidate.py` already strips it; this checks the deployed result).

## Production
Repeat with the production names, a different OAuth app and a different D1; set `QUARANTINE_URL`; add Cloudflare rate-limiting rules for `/auth/*` and `/api/decisions`; run `staging-smoke.sh` against it; then tick the checklist in `docs/OPERATIONS.md`.

## What this does not cover
Real OAuth (steps 2–5 above are the only way), Cloudflare rate limits, and D1 behaviour under production load.
