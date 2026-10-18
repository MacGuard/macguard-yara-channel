# Operations

## Roles of the private panel
| Role | Comes from | May |
|---|---|---|
| VIEWER | explicit grant by an ADMIN | read candidates, content, decisions, stats |
| REVIEWER | GitHub `write` or `maintain` on the repository | everything a VIEWER may, plus approve, reject, mark under review, request retest, read the audit trail |
| ADMIN | GitHub `admin` on the repository | everything, plus members and the audit-chain verification |
Reading a public repository grants nothing. The role is recomputed from GitHub on every protected request (cached 60 s; if GitHub cannot be asked for more than 10 minutes access is denied). Nobody can change their own role.

## What the panel guarantees
* Sessions are server-side; the GitHub token never reaches the browser. Cookie `__Host-` prefixed, `HttpOnly; Secure; SameSite=Strict`.
* State-changing calls need the per-session CSRF token and a same-origin `Origin`.
* Every decision carries `request_id` (idempotent), the versions the reviewer saw (a stale view is refused, nothing changes) and, for more than one rule, the exact count (`confirm_count`).
* Decisions, their audit entry and a guard that aborts everything if any update did not apply are one atomic D1 batch.
* The audit log is hash-chained (`prev_hash`, `hash`, unique `prev_hash`): an edit, removal or reordering fails `/api/audit/verify`.
* Rule code is returned as JSON and rendered with `textContent` only; CSP forbids inline script and style.

## Deploying the private service (needs a human: credentials)
1. Cloudflare: a token with Workers Scripts:Edit and D1:Edit on the account in `config/cloudflare_account_id.txt` (the Pages token is separate).
2. `cd admin/worker && wrangler d1 create macguard-quarantine` → put the id in `wrangler.toml`; `wrangler d1 execute macguard-quarantine --remote --file schema.sql`.
3. GitHub: create an OAuth app (Settings → Developer settings) with callback `https://<admin host>/auth/callback`; `wrangler secret put GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`.
4. Set `PUBLIC_URL` and `OIDC_AUDIENCE` in `wrangler.toml` to the admin host; `wrangler deploy`.
5. In the repository: variable `QUARANTINE_URL` = the same URL. The workflows prove who they are with their OIDC token (`daily.yml` may submit, `publish.yml` may mark releases); there is no shared secret.
6. Verify `GET /api/me` with a collaborator: the code relies on `GET /repos/{repo}` returning `permissions` for the signed-in user's token; confirm that with your OAuth app type before trusting roles.
Until then the pipeline reports the service as unavailable and publishes only what passes every automatic check.

## Before enabling AUTO_PUBLISH
- [ ] `QUARANTINE_URL` set and `daily.yml` shows `quarantine: N new` in its log.
- [ ] A real change has been published through the manual path (approval) and `site.yml` `verify-live` passed.
- [ ] A rule was quarantined, rejected by a reviewer, and did not come back on the next daily run.
- [ ] The macOS job passed on that release; `dynamic.json` of the release shows `not_run: ["independent-macos-vm"]` and you accept it.
- [ ] GitHub immutable releases are enabled.
- [ ] Create environment `stable-signing-auto` (deployments only from `main`), then set variable `AUTO_PUBLISH=true`. Reverting is deleting the variable.

## Resolving a quarantined rule
Open the panel → Quarantine → the rule. Read the reasons, resources and source. Approve (only judgement findings can be waived) or reject with a reason. Approved rules go through the technical checks again in the next run; if they fail they return to PENDING with the reason. Rejected content never returns; an edited upstream version appears as a new candidate linked to the old one.

## Cloudflare Pages mirror (automatic, from GitHub Actions only)
`site.yml` deploys the same build to GitHub Pages and to the Cloudflare Pages project `macguard-rules`, using only repository secrets; nothing depends on a maintainer's Mac or `wrangler` login. The `cloudflare-pages` job runs `scripts/cf_preflight.sh` first and never tries to deploy with a credential that failed it.

State on 2026-10-18: **working** since the secrets were replaced (the first token was not a Cloudflare token: the preflight printed `FORMAT: token has characters outside [A-Za-z0-9_-] (length 88)`). The workflow deploys to `macguard-rules.pages.dev` and `verify_live.py` passes there. If it breaks again, replace exactly these two repository secrets:
| Secret | Value |
|---|---|
| `CLOUDFLARE_API_TOKEN` | a Custom API token (dash.cloudflare.com → My Profile → API Tokens), permission **Account → Cloudflare Pages → Edit**, account = the one in `config/cloudflare_account_id.txt` (`9e96e19f…`, the login `mac_guard@proton.me`) |
| `CLOUDFLARE_ACCOUNT_ID` | the id in `config/cloudflare_account_id.txt` |
Set the token without printing it: `pbpaste | tr -d '[:space:]' | gh secret set CLOUDFLARE_API_TOKEN -R MacGuard/macguard-yara-channel`. Then run `site.yml` once (Actions → Deploy site → Run workflow) and check that the log has `site.cloudflare_deployed` and that `scripts/verify_live.py https://macguard-rules.pages.dev/ …` passes. Until then every run logs `site.cloudflare_blocked` and writes the instructions to the job summary; no failing deployments are attempted. A site published to `pages.dev` by hand is not evidence that this automation works.

Account change (2026-10-18): the first mirror was deployed by hand from the account `070e63e8…` (login `dmuino.emergencias@gmail.com`, via a local `wrangler` OAuth session, now logged out). The mirror belongs in `9e96e19f…` (`mac_guard@proton.me`), which is the account `config/cloudflare_account_id.txt` now names. The workflow creates the Pages project `macguard-rules` there on the first run with a valid token. A `pages.dev` name is unique across Cloudflare: while the old project still exists in `070e63e8…` the new one may be given a suffixed address. If so, delete the old project from that account first (`wrangler pages project delete macguard-rules` while logged in to it) and re-run `site.yml`. The Cloudflare MCP session is limited to read access (it cannot create tokens or Pages projects: error 9109/10000), so the token has to be created in the dashboard.
