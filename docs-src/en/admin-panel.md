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

> **LIMIT** The code and tests exist in `admin/worker/`. It is **not deployed**: a person with Cloudflare (Workers and D1) credentials must create it and a GitHub OAuth app must be registered; the steps are in `docs/OPERATIONS.md`. Confirm with the OAuth app type that `GET /repos/{repo}` returns `permissions` before trusting roles.
