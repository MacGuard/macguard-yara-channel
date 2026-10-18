# MacGuard quarantine service

Private API and admin UI (Cloudflare Worker + D1). The public site never calls it. Roles, deployment and guarantees: `docs/OPERATIONS.md`. Architecture: `docs/ADR-0002-autonomous-pipeline.md`.

```
npm test                    # 26 tests: roles, CSRF, batches, concurrency, idempotency, failures, OIDC forgery, audit chain
test/run_ui_check.sh        # the real UI in headless Chrome against the real handler (15 checks)
```
`wrangler.toml` still has placeholders: it is not deployed. See "Deploying the private service".
