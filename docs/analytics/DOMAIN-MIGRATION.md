# Domain separation and migration plan (prepared, NOT executed)

Owner's design: `rules.mac-guard.com` free Community channel · `panel.mac-guard.com` Quarantine · `quarantine-api.mac-guard.com` Quarantine API only · **`api.mac-guard.com` the commercial gateway (Intelligence REST/MCP, analytics, monetization)** · `ingest.mac-guard.com` reserved. Today the gateway was deployed on `quarantine-api.mac-guard.com` (2026-10-23), which breaks that separation. **Nothing below has been applied remotely: it needs the owner's specific authorisation.**

## Read-only audit (2026-10-23, Cloudflare account `9e96e19f6dc0ccdd53e02f7c3b5cacab`, zone `mac-guard.com` active)
| Hostname | DNS | Worker route | Custom Domain | Serves |
|---|---|---|---|---|
| `rules.mac-guard.com` | CNAME → `macguard-rules.pages.dev` (proxied) | — | — | Pages (Community) |
| `panel.mac-guard.com` | AAAA `100::` (proxied) | — | → `macguard-quarantine` | Quarantine panel |
| `quarantine-api.mac-guard.com` | AAAA `100::` (proxied) | — | → **`macguard-gateway`** | the gateway (to be released) |
| `api.mac-guard.com` | none | none | none | **free** |
| `ingest.mac-guard.com` | none | none | none | free, reserved |

Workers in the account: `macguard-gateway`, `macguard-quarantine`. Zone routes: none. CAA records allow ssl.com, Google (pki.goog) and Let's Encrypt, so managed certificates issue.

## Isolation between Quarantine and the gateway (verified from the Worker settings API)
| | `macguard-quarantine` | `macguard-gateway` |
|---|---|---|
| D1 | `4c9f258a…` | `92207c74…` (different database) |
| R2 | none (static assets binding) | `macguard-premium-private` |
| Secrets | `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `TOKEN_ENC_KEY` | `KEY_PEPPER`, `ADMIN_PEPPER`, `TOTP_SEAL_KEY` (generated separately, Keychain service `macguard-gateway-prod`) |
| Admin identity | its own OAuth/OIDC | its own administrator + TOTP |
No binding, secret, database or permission is shared; the migration must keep it that way (no secret is copied between them, and `quarantine-api` must be re-pointed to the Quarantine Worker by its own deployment, not by this one).

## Prepared artefacts (all validated with `wrangler deploy --dry-run`, local only)
`gateway/environments/production.wrangler.toml` (current state), `production-transition.wrangler.toml` (both hostnames), `production-target.wrangler.toml` (`api.mac-guard.com` only, `PUBLIC_BASE=https://api.mac-guard.com`). `gateway/tools/d1_backup.mjs` for the pre-change backup. Edge rules for the new hostname: `gateway/hardening/cloudflare-rulesets.api.mac-guard.com.json` (not applied).

## Steps, each reversible
1. **Authorisation** (owner): explicit yes for creating the Custom Domain `api.mac-guard.com` and later releasing `quarantine-api.mac-guard.com`.
2. **Backup**: `node gateway/tools/d1_backup.mjs` (read-only), note the current version id (`wrangler deployments list`).
3. **Add the new hostname (transition)**: `CLOUDFLARE_ACCOUNT_ID=9e96e19f6dc0ccdd53e02f7c3b5cacab npx wrangler@4.149.0 deploy --config environments/production-transition.wrangler.toml`. Cloudflare creates one new proxied DNS record for `api`; no existing record is edited. The old hostname keeps answering.
4. **Prove it** against `https://api.mac-guard.com` with the same checks used on 2026-10-23 (health over TLS, 401s without credentials, redirect + validation, administrator view with key + TOTP), and confirm `panel` and `rules` still answer 200 and the Quarantine Worker's settings are unchanged. Abort here if anything differs.
5. **Release the old hostname**: deploy `production-target.wrangler.toml`; the gateway no longer owns `quarantine-api…`. Then the Quarantine project attaches the name to its own Worker with its own deployment.
6. **Rollback at any point**: redeploy `production.wrangler.toml` (re-attaches `quarantine-api…`) or `wrangler rollback <previous version id>`; remove the `api` Custom Domain in the dashboard if it must disappear. Data is untouched: the D1 and R2 do not change during the migration.

## Risks and notes
- Clients: none exist yet (no tenant or key), so no client has to change. `PUBLIC_BASE` appears in signed-download URLs issued by the gateway; URLs issued before the change point at the old name and expire after `DOWNLOAD_TTL_SECONDS` (120 s).
- Between steps 5 and the Quarantine deployment the name `quarantine-api…` has no Worker: coordinate with the Quarantine owner so it is not left dangling.
- Not verified: the behaviour of Custom Domain re-assignment in this account (no dry run exists for it). That is why step 3 keeps both names first.
