# Subscriptions and Alerts: architecture

*Resumen: un motor independiente del frontend (ingesta → normalización → deduplicación → validación → coincidencia → cola → entrega → auditoría) con un almacén SQLite, un servidor de referencia y páginas estáticas. Estado: EXPERIMENTAL. Nada está desplegado. La única fuente que hoy se puede redistribuir es la propia de MacGuard (versiones de reglas YARA).*

## 1. What exists, by phase (honest status)

| Phase | Scope | Status | Evidence |
|---|---|---|---|
| **P0** | normalisation, basic filters, Explore, public RSS, sources page | **works as static files**; real data = MacGuard's own YARA release alerts (3 today) | `scripts/gen_alerts_site.py --check`, `tests/test_alerts_web.py`, `tests/test_alerts_engine.py` |
| P0 | vulnerability alerts from CISA KEV, ENISA EUVD, EU exploited list, CERT-EU | **pipeline proven end to end on real downloads; not published** (sources not cleared) | `docs/alerts/TEST-REPORT.md`, section "first milestone" |
| **P1** | accounts, personal subscriptions, private RSS, e-mail, history | **implemented in the reference backend, tested, not deployed** | `tests/test_alerts_api.py`, `test_alerts_tenancy.py`, `test_alerts_delivery.py`, `test_alerts_e2e.py` |
| **P2** | organisations, memberships, RBAC, units, device groups, MSP, audit, webhooks | **core implemented and tested; no external identity provider**; MFA (TOTP) required for administration | same tests |
| **P3** | asset correlation | **contract + reference matcher only** (`alerts/exposure.py`); no inventory, no Cloud | `tests/test_alerts_exposure.py` |

## 2. Flow

```
 sources ──► intel channels (originals kept) ──► merge (intel.vulns) ──► IntelligenceAlert v1 ──► store (versions, events)
                                                                                  │
                     publish view (only cleared sources) ◄────────────────────────┤
                          │                                                       ▼
   public feeds, Explore, API ◄── query(filter) ◄──────────── MATCH: material event × active subscription ──► alert_matches (unique)
                                                                                  │
                                                            queue ──► delivery worker ──► e-mail (.eml/SMTP) · webhook (signed) · private RSS · web inbox
                                                                                  │
                                                                       audit log (hash chain) · metrics
```

## 3. IntelligenceAlert v1 (`alerts/model.py`, schema `docs/intelligence/schemas/intelligence-alert.schema.json`)

* Immutable `alert_id` (`MGA-` + 20 hex, derived from the first key, never reused); CVE/EUVD/GHSA identifiers; `record_version`; `record_hash` (SHA-256 of the canonical record; staleness is **not** part of it).
* **Every source's observation is kept** (evidence file, position and hash, dates, severity, references). Top-level fields are *derived* from the observations: severity is the highest score given (differences go to `discrepancies`), exploitation is per source (`asserted_by`), regions come from the **scope of the source** (never from a guess about the vulnerability), sectors are empty unless a source states them.
* Mitigations and fixes are only what a source states; "no fix stated" is `null` (unknown), never `false`.
* Licence block per source (status, owner confirmation, attribution). The **publish view** (`publish_view`) is derived again from only the cleared observations, so nothing from a withheld source reaches a page, feed, e-mail or webhook.

## 4. Deduplication and updates (`alerts/engine.py`)

* Identifiers join records (via `intel.vulns.merge`); similar titles never do. An identifier that would join two stored alerts is a conflict: nothing is merged, it is audited.
* An update is a new **record version** of the same alert. A change is *material* only for: new alert, exploitation asserted, another source asserting it, a fix stated, severity band moved, a new source or product, a mitigation. Wording and extra references bump the version and notify nobody.
* Matching is incremental over events; `(subscription, alert, record version, kind)` is unique, so re-running sends nothing twice.

## 5. Filters (`alerts/filters.py`, `docs/alerts/FILTERS.md`)

A closed JSON language (all / any / not over 26 fields), validated on the server, evaluated by the server, and mirrored in `web/intelligence/alerts/filter.js`. 92 shared vectors run in Python and JavaScript, **including the reasons** each side gives. Missing data never matches.

## 6. Multi-tenancy and roles (`alerts/authz.py`, `tenancy.py`, `subs.py`)

Entities: User, Organization, OrganizationMembership, OrganizationUnit, DeviceGroup, Subscription, SubscriptionFilter (versioned), SubscriptionRecipient, NotificationChannel, NotificationDelivery, AlertMatch, AuditLog (plus MSP links, RSS tokens, webhook keys). Scopes: PERSONAL, ORGANIZATION, ORGANIZATION_UNIT, DEVICE_GROUP, MSP_CUSTOMER.

* The caller's memberships are loaded from the database on every request; a request can only *name* an organisation, and naming one the caller has no right in is refused (403 to act, 404 to read: existence is not leaked).
* Roles: owner, administrator, security_manager, auditor, operator, viewer, msp_administrator, each an explicit permission list (the 11 of the brief plus `organization.manage_members` and `organization.manage`). A unit-limited membership grants nothing outside its unit and sub-units. An MSP acts in a customer organisation only through an accepted link and a role the customer delegated; delegation never includes members, organisation management or audit.
* Compatibility with MacGuard Cloud: `organization_id` is the same idea as in `cloud-tenant.schema.json`. The alerts permissions are a separate domain from `cloud-identity-permission.schema.json` (which covers inventory and baselines); mapping them is a Cloud-time decision.
* OIDC/SSO and fine-grained engines: `users` has no provider-specific column; adding `external_subject` and replacing `identity.py` is the planned path. Authorisation goes through `authz.can(principal, permission, org, unit)`, one function a policy engine can replace.

## 7. Delivery channels

| Channel | Implementation | Notes |
|---|---|---|
| Web inbox/history | `alert_matches`, `/api/v1/matches` | read, acknowledge |
| Public RSS | `alerts/rss.py`, `web/feeds/public/*.xml`, `feeds/index.json` with SHA-256 | only cleared sources; validated before writing |
| Private RSS | 256-bit random tokens, only the SHA-256 stored, expiry, rotation with grace, revocation, rate limit, `no-store`, `noindex`, token redacted from logs | scopes: one subscription, an organisation, personal |
| E-mail | confirmation (double opt-in, POST to confirm), ES/EN templates, digests, immediate critical, limits, bounces, one-click unsubscribe (RFC 8058) | transport: `.eml` files (default) or SMTP with mandatory STARTTLS; **no relay is configured here** |
| Webhook | https only, public host name, every resolved address public, **pinned connection**, HMAC-SHA256 with rotating keys, stable event id, backoff 1 min to 6 h, dead-letter, auto-disable | see `SECURITY.md` |
| Telegram, Teams, Slack, SIEM | **not implemented**: delivery is a channel `kind` with a sender; adding one is a sender plus a validator | |

## 8. Reference backend and web

`python3 -m alerts serve` serves the API and the static site from one origin on 127.0.0.1 (cookies and CSRF without CORS). The pages (`web/intelligence/alerts/`) are generated from one string table plus the versioned taxonomies and degrade gracefully: with no backend they offer Explore, filter building with preview on the public snapshot, Sources and the public feeds, and say that saving needs the service.

## 9. Not done, on purpose

No hosted service, no production e-mail relay, no OIDC provider, no IP-reputation or captcha layer, no Telegram/Teams/Slack/SIEM adapters, no OSV/NVD/CCN-CERT/Debian/Ubuntu adapters, no asset inventory, nothing published or merged.
