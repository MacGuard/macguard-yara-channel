---
title: Private panel
summary: The review service: roles, authentication and guarantees.
---
## Roles

| Role | Comes from | May |
|---|---|---|
| VIEWER | Explicit grant by an ADMIN. | Read candidates, content, decisions and statistics. |
| REVIEWER | GitHub `write` or `maintain` permission on the repository. | Everything a VIEWER may, plus approve, reject, mark under review, request retest and read the audit trail. |
| ADMIN | GitHub `admin` permission on the repository. | Everything, plus members and audit-chain verification. |

Reading a public repository grants nothing. The role is recomputed from GitHub on every protected request (60 s cache); if GitHub cannot be asked for more than 10 minutes access is denied. Nobody can change their own role.

## Guarantees

- Server-side sessions; the GitHub token never reaches the browser. `__Host-` prefixed cookie, `HttpOnly; Secure; SameSite=Strict`.
- State-changing calls need the per-session CSRF token and a same-origin `Origin`.
- Every decision carries an idempotent `request_id` and the versions the reviewer saw; a stale view is refused and nothing changes.
- Decisions, their audit entry and a guard that aborts everything if any update did not apply are one atomic D1 batch.
- The audit log is hash-chained: editing, removing or reordering an entry fails `/api/audit/verify`.
- Workflows prove who they are with their OIDC token (`daily.yml` may submit, `publish.yml` may mark releases, `main` only); there is no shared secret.

> **CURRENT** The panel is deployed and in use (production check recorded by the owner on 2026-10-21; `QUARANTINE_URL` is set and `daily.yml` and `publish.yml` use it). The code and tests are in `admin/worker/`; the first-deployment steps (Cloudflare Workers and D1 credentials, a GitHub OAuth app) are in `docs/OPERATIONS.md`. Confirm with the OAuth app type that `GET /repos/{repo}` returns `permissions` before trusting roles.
>
> **LIMIT** Features added after the first deployment are in `main` but **not deployed**: persistent policies (migration 0003), audit anchors (0004) and source proposals (0005). Those migrations are not applied in production, and the pipeline does not read policies yet.
