# Quarantine service: what you create, what I do afterwards (no secret passes through chat)

## You create (4 things)
1. **Cloudflare API token for provisioning** (dash.cloudflare.com → My Profile → API Tokens → Create Custom Token): permissions *Account · Workers Scripts · Edit* and *Account · D1 · Edit*, scoped to the one account, with an expiry of a few days. It is **not** the Pages token and must never be added to GitHub secrets (`test_workers_and_d1_credentials_never_live_in_a_workflow`). If you need a zone route also add *Zone · Workers Routes · Edit* on that zone only.
2. **Hostname** you control (route or custom domain on a zone in the same account). `workers.dev` is disabled in `wrangler.toml`.
3. **GitHub OAuth App**: https://github.com/organizations/MacGuard/settings/applications/new
   * Application name: `MacGuard quarantine (integration)`; Homepage URL: `https://<host>`
   * Authorization callback URL: exactly `https://<host>/auth/callback` (the code sends the same value; a mismatch makes GitHub refuse)
   * Device flow: off. Permissions: none beyond the default; the service asks the `read:user` scope and nothing else (no `repo`: the repository is public, and write access is read from `GET /repos/MacGuard/macguard-yara-channel` with the user's own token).
   * Generate a client secret; the secret is shown once.
4. **Store the secrets yourself, in your terminal, not in chat** (from `admin/worker/`, after `export CLOUDFLARE_API_TOKEN=…` typed in that shell):
   ```
   wrangler secret put GITHUB_CLIENT_ID     --config wrangler.staging.toml     # paste when prompted
   wrangler secret put GITHUB_CLIENT_SECRET --config wrangler.staging.toml     # paste when prompted
   ```
   The client secret then lives only as a Worker secret. It is never in a repo, a GitHub secret, a variable or `wrangler.toml`; the browser never sees it (token exchange is server-side).

## I do afterwards (you only tell me "listo" and the hostname)
You run the deploy block of `STAGING.md` yourself in the shell where you exported the token (I never receive the token; if you prefer, run `! <command>` in this session so only the output lands here). Then I run: `staging-smoke.sh` (18 checks), a manual `daily.yml` run with `QUARANTINE_URL` pointing at the integration host (submission with a test rule), the role table with the real OAuth app, a reject and an approve, the next daily run to show revalidation, evidence into `docs/audit/evidence/`, and finally **teardown**: `wrangler delete`, `wrangler d1 delete`, delete the OAuth App, revoke the token. Production repeats the same with its own OAuth App, D1 and a token with its own expiry.

## Least privilege summary
| Credential | Holder | Can do | Cannot do |
|---|---|---|---|
| Workers/D1 token | you, temporarily | deploy, migrate | approve rules; lives outside CI |
| Pages token | GitHub secret (`site.yml` only) | deploy Pages | touch Workers/D1 |
| OAuth client secret | Worker secret | exchange login codes | anything else |
| Reviewer | GitHub login (write/admin) | approve/reject for the *next* run | start a release |
| Pipeline | Actions OIDC (no stored secret) | submit, read decisions, mark released | decide |
