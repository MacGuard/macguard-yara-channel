# MacGuard quarantine service

Private API and admin UI (Cloudflare Worker + D1). The public site never calls it. Roles, deployment and guarantees: `docs/OPERATIONS.md`. Architecture: `docs/ADR-0002-autonomous-pipeline.md`.

```
npm test                    # roles, CSRF, batches, concurrency, idempotency, failures, OIDC forgery, audit chain, members by immutable id, migration 0002
npm run test:ui             # the real UI in Chromium, Firefox and WebKit against the real handler over TLS: sign-in states, roles, decisions, members,
                            # layout at iPhone/tablet/desktop, WCAG 2.2 AA (axe) in light/dark, ES/EN. UI_SHOTS=/dir saves a screenshot of every screen.
```
`wrangler.toml` still has placeholders: it is not deployed. See "Deploying the private service".
