# Cloudflare and in-Worker hardening

Status: **prepared and tested locally; nothing applied to Cloudflare.** Applying edge rules is a remote change that needs the owner's authorisation, and the number of rate-limiting rules and the allowed periods depend on the account's plan, which has not been checked.

## In the Worker (deployed or in the branch)
| Control | Where | Evidence |
|---|---|---|
| Bounded streaming body reads (JSON 64 KiB, MCP 256 KiB, Stripe webhook 256 KiB, admin JSON 20 KB, cost CSV 1 MB): a declared length over the limit is refused unread, a lying or chunked body is cut off | `readBounded` in `src/util.js` | `test/security.test.js` (413 on every route) |
| Method restriction: `/mcp` POST only (405), webhook POST only, admin routes answer 404 for unknown method/path | router | existing tests + `security.test.js` |
| Authentication: key id and secret failures are indistinguishable (no oracle); malformed keys do the same work as real ones | `auth.js`, `admin.js` | `security.test.js` |
| Administrator: key **and** TOTP on every call, one use per time step (replay refused); tenant keys never accepted on `/admin` | `admin.js` | `security.test.js` |
| No D1 write for administrator attempts with an unknown id (removes a free write-amplification lever); attempts naming a real administrator are audited | `admin.js` | `security.test.js` |
| Webhook: signature over the raw body, event-id dedupe, 5-minute tolerance | `stripe.js` | `stripe.test.js` |
| Tenant identity only from the verified key; per-key scopes; per-tenant quotas and budget | `context.js`, `pipeline.js` | existing suites |
| Input validation: JSON Schema subset on every operation; Community redirect validates the release tag and asset name | `schema.js`, `index.js` | tests |
| R2 bucket is private and reachable only through the binding; downloads need an authenticated key plus a one-time signed token | `downloads.js` | `api.test.js`, workerd suite |

## At the edge (prepared, `gateway/hardening/`)
`rules.js` holds the rules as data; `tools/gen_hardening.mjs <host>` writes `cloudflare-rulesets.<host>.json` (Rulesets API payload, `applied: false`). Rules are scoped to the gateway **host**, so Quarantine and Pages are untouched.
- Firewall (custom) rules: block disallowed methods on `/admin/` (GET/POST/PUT only), `/stripe/webhook` and `/mcp` (POST only), and TRACE/CONNECT/TRACK anywhere.
- Rate limits per IP: `/admin/` 20/min (10-minute block), `/stripe/webhook` 120/min, `/mcp` 300/min, other `/v1/` paths 600/min.
- **Community is never limited or blocked**: `/v1/community/*` and `/v1/health` are excluded explicitly; `test/hardening.test.js` evaluates the rule data against Community requests of every method and fails if any rule matches. The public Community channel itself (GitHub Releases, `rules.mac-guard.com`) is not behind these rules at all.
- Not proposed, and why: IP allow-listing of `/admin` (the owner's addresses are unknown; Cloudflare Access in front of `/admin` is the stronger option and needs a decision), a managed challenge on the API (it would break non-browser clients), per-identity limits at the edge (the Worker already enforces per-key limits; edge rules see IPs).

## Added 2026-10-24
- **Hostname gate** in the Worker: `ALLOWED_HOSTS` (the Worker answers only on its own names, 404 elsewhere) and optional `ADMIN_HOSTS` (confine `/admin` to specific hostnames); set in `gateway/environments/*.wrangler.toml`. Tested, including case-insensitivity and look-alike hosts.
- **Cloudflare Access payload** (`hardening/rules.js`, `gen_hardening.mjs`): an Access application for `api.mac-guard.com/admin` only (strict cookie, 12 h session, identity placeholder for the owner to fill). It is a second gate in front of the application's key + TOTP; `/stripe/webhook`, `/mcp`, `/v1/*` and `/x402/*` are never behind it. **Not applied.**
- **Per-route WAF regression** (`test/hardening.test.js` over the generated `ROUTE-INVENTORY.md`): before applying anything, every documented route/method was checked against the rules — no method rule touches a legitimate call, Community and health are untouched, administrator routes get only the rate rule, authenticated REST only the 600/min rule.
- **Webhook replay**: Stripe events are deduplicated by event id and the signature has a 5-minute tolerance (existing tests); the body is bounded to 256 KiB.

## Still to do (owner / remote)
Check the plan's rule limits, apply the payload to the zone in a staging order (log-only first if the plan allows), enable the managed WAF ruleset on the host, review Workers observability/log retention, and decide on Cloudflare Access for `/admin`.
