# Multi-domain architecture (prepared locally; nothing applied remotely)

Supersedes the single-domain framing of `DOMAIN-MIGRATION.md`. Seven hostnames, **not seven backends**: a hostname is an address and a security boundary, a service is a deployable unit, and the two are decided separately.

## The hostnames and who owns them
| Hostname | Responsibility | Backend today | Exists in Cloudflare (read-only audit 2026-10-24) |
|---|---|---|---|
| `rules.mac-guard.com` | free Community channel (static, signed releases mirrored to Pages) | Pages `macguard-rules` | yes (CNAME → pages.dev) |
| `panel.mac-guard.com` | Quarantine panel | Worker `macguard-quarantine` | yes (Custom Domain) |
| `quarantine-api.mac-guard.com` | Quarantine API only | Worker `macguard-quarantine` (to be attached by its own deployment) | **today it points at `macguard-gateway`, which is wrong by design** |
| **`api.mac-guard.com`** | public general API: Intelligence REST/MCP, tenant self-service, billing webhook, signed downloads | Worker `macguard-gateway` (this repository) | no (free) |
| `ingest.mac-guard.com` | GuardOps event ingestion | GuardOps (not built) | no (free) |
| `guardops.mac-guard.com` | monitoring UI | GuardOps (not built) | no |
| `alerts.mac-guard.com` | subscriptions and preferences | alerts service (reference backend exists on a draft PR stack) | no |
| `escalate.mac-guard.com` | incidents, on-call, escalation | GuardOps (not built) | no |
| `auth.mac-guard.com` | Keycloak / SSO | none | no |

## Recommendation: shared modular backends, split only where isolation demands it
1. **MacGuard commercial gateway = one Worker, one hostname (`api`)**, already modular (REST, MCP, billing, downloads, admin, analytics). Splitting it per hostname would duplicate the authentication, policy, quota and ledger code that must stay one.
2. **Quarantine stays its own Worker, D1 and secrets** (audited as fully disjoint from the gateway). It is the one place where isolation is a security requirement, not a convenience.
3. **GuardOps hostnames** (`ingest`, `guardops`, `alerts`, `escalate`) are one project that does not exist yet. Start as **one modular backend routing by hostname**; promote `escalate` (or `ingest`) to its own service only when one of three things is measured: it needs to stay up when the dashboard is down (escalation must outlive the UI), its credentials/blast radius differ (ingest accepts data from many tenants, escalate sends costly messages), or its load profile differs (bursty ingestion). `auth` is Keycloak and a separate product by nature.
4. **Hostname gate in code** (`ALLOWED_HOSTS`, `ADMIN_HOSTS`, tested): each Worker answers only on its own names, so a Custom Domain attached by mistake cannot expose a service under another's name. The environment configs set it (`environments/*.wrangler.toml`).

## Responsibility boundaries between the hostnames (checked, not just stated)
| Concern | Rule | Evidence |
|---|---|---|
| Cookies | The gateway sets **none** and authenticates by header (API key / admin key + TOTP). No cookie can leak or be shared across `*.mac-guard.com`. When `auth.` (Keycloak) and `guardops.` (UI) exist they must use **host-only** cookies (no `Domain=.mac-guard.com`), otherwise a compromise of one subdomain reaches the others. | `test/tenant_isolation.test.js` (no `Set-Cookie` on any documented public route) |
| CORS | No CORS header is ever sent by the gateway (clients are native agents and servers; `/mcp` also checks `Origin`). | same test; `security.test.js` |
| Tokens | A token is valid for one service: API keys (`mgk_`) only on the gateway; admin keys (`mga_`) only on `/admin`; the GuardOps ingest credential is a different secret sent only to its allow-listed host; Keycloak tokens will need a per-service audience. A tenant key is refused on `/admin`. | `security.test.js`, `guardops.test.js` |
| Secrets and data | Gateway: its own D1, R2, peppers. Quarantine: its own D1, secrets (audited from Worker settings, 2026-10-24: no shared binding). GuardOps: its own store (Postgres in its plan). Nothing is shared by hostname. | `DOMAIN-MIGRATION.md` audit |
| Names | Each Worker answers only on its own hostnames (`ALLOWED_HOSTS`); `/admin` can be confined to its own hostname (`ADMIN_HOSTS`). | `security.test.js` |
| Edge rules | Rules are scoped by `http.host`; applying them to `api.` cannot touch `panel.`, `rules.` or `quarantine-api.`. | `hardening.test.js` |
| Events | MacGuard → GuardOps only through `ingest.` with an ingest-only token; MacGuard never receives from GuardOps. SaaS default `https://ingest.mac-guard.com`; self-hosted installations set `GUARDOPS_INGEST_URL` and `GUARDOPS_ALLOWED_HOSTS` to their own https host. | `guardops.test.js` |

## What moves to `api.mac-guard.com` and what does not
Only the gateway routes listed in `ROUTE-INVENTORY.md` (generated and drift-tested) move, and they move **together** because they share state. Nothing from Quarantine moves; the future GuardOps routes are not part of this Worker; the gateway only *sends* events to `ingest` (see `GUARDOPS-ADAPTER.md`). `/admin/*` stays on `api` for now, behind the application's key + TOTP; `ADMIN_HOSTS` lets it move to a hostname protected by Cloudflare Access without a code change (the Access application itself is prepared in `HARDENING.md`, not applied).

## Migration (each step reversible; needs the owner's specific authorisation)
1. Run `tools/d1_backup.mjs`; note the live version id. 2. Apply the D1 migrations (`migrations/0001`, `0002`) — additive, tested against the deployed schema. 3. Deploy `environments/production-transition.wrangler.toml` (`api` added, `quarantine-api` kept, both in `ALLOWED_HOSTS`). 4. Smoke tests per area (`ROUTE-INVENTORY.md`) on `api`; confirm `panel`, `rules` and the Quarantine Worker are unchanged. 5. Deploy `production-target.wrangler.toml` (the gateway releases `quarantine-api`). 6. Quarantine attaches its own name. **Rollback:** redeploy `production.wrangler.toml` (re-attaches `quarantine-api` to the gateway) or `wrangler rollback`; the D1 and R2 do not change during the migration, and the migrations are additive.

## Risks and open points
Custom Domain re-assignment between Workers was not dry-run (it cannot be): hence the transition step that keeps both names first. Between steps 5 and 6 the name has no Worker. TLS certificates are issued per hostname (CAA allows Let's Encrypt, Google, SSL.com). DNS changes are exactly: one new proxied record for `api`, then the release of the `quarantine-api` record by the gateway deployment and its re-creation by Quarantine's. Nothing else in the zone changes.

## Route ownership audit (2026-10-24; source-level, `gateway/test/route_ownership.test.js`)
Read from the code of both Workers, no remote call. **Quarantine** (`admin/worker/src/index.js`) owns `/api/*` (panel API, pipeline, policies, members, source proposals, decisions), `/auth/*` (GitHub sign-in), `/public/stats` and its static assets. The **gateway** owns only `/v1/*`, `/admin/v1/*`, `/mcp`, `/stripe/*`, `/x402/*`. The sets are disjoint and the test fails if either Worker ever claims a path under the other's prefixes; it also checks that the gateway answers 404 (no cookie) for every Quarantine path, so a Custom Domain attached to the wrong Worker cannot serve the other's functions.
**What this does and does not establish.** It proves the *code* keeps responsibilities apart. It does **not** prove what is live on the zone: in the read-only audit of 2026-10-24 `api.mac-guard.com` had no Custom Domain, route or Worker, so there is no existing public API on that name to preserve or break (whether some other provider answers it outside Cloudflare is UNKNOWN; DNS was not queried beyond the Cloudflare account). `quarantine-api.mac-guard.com` currently points at the **gateway**, not at Quarantine; `ingest.mac-guard.com` is reserved for GuardOps and attached to nothing. A functional migration of any route between Workers would need its own decision and a smoke test per area (`ROUTE-INVENTORY.md`); none is proposed.
