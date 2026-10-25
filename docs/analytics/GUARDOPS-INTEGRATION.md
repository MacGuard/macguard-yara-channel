# GuardOps integration points (optional; MacGuard does not depend on it)

GuardOps is a **separate project**. The MacGuard gateway (CVE/IOC/YARA rules, Premium, API/MCP) works, is deployed and is monitored by its own analytics without it. Everything below is a courtesy for the day GuardOps exists and wants to consume MacGuard's contracts; the owner has said it is not part of this product, so nothing here is on MacGuard's critical path. The hostname `ingest.mac-guard.com` is reserved for it and was not created.

Audit of the local GuardOps checkout (read-only, 2026-10-23): it contains only planning documents (`docs/00…02`, `ROADMAP-KANBAN.md`); **no code, no repository, nothing DONE**. Its plan is Go + PostgreSQL with leases, an outbox, RLS and a Flutter client. Open owner decisions there: new repo, Go vs Dart, hosting. This repository does **not** implement GuardOps and must not be reported as having done so.

What this repository provides, so GuardOps can adopt it without rework:

| Contract / API | Where | Consumer-side use |
|---|---|---|
| `macguard.event/1` | `contracts/v1/event.schema.json` | Ingest envelope for business/technical events (neutral JSON Schema). |
| `macguard.alert/1` | `contracts/v1/alert.schema.json` | An **evaluated** alert (rule, severity, state FIRING/OK/INSUFFICIENT_DATA, dedupe key). GuardOps turns FIRING into incidents; this service sends nothing. |
| `macguard.kpi-catalog/1` | `contracts/v1/kpi-catalog.json` | Canonical KPI definitions (numerator, denominator, window, source, accuracy, limitations, owner). |
| `macguard.dashboard/1`, `macguard.report/1` | `GET /admin/v1/analytics/dashboards/{id}`, `/reports/{kind}` | Panels as data: state, source, accuracy — renderable by Flutter or any UI. |
| incident / notification / escalation-policy | `contracts/v1/*.schema.json` | **Proposals** for GuardOps to accept or replace; untested by any consumer. Timer origin is explicit (`incident_opened` or `previous_step`). |
| Gateway events | `docs/monetization/OBSERVABILITY-GUARDOPS.md` | Twelve existing gateway event types. |

## Gaps that need an owner decision (not implemented)

1. **Machine-to-machine access.** The admin API needs admin key **and** a fresh TOTP per call; that suits people, not a poller. Options: (a) a read-only service credential with an `analytics.read` scope (new auth surface), (b) push of alert/event batches to a GuardOps ingest endpoint (needs an authorised destination), (c) manual export. Not chosen; nothing built.
2. **Role model.** One administrator role. GuardOps' Platform Admin / Org Admin / Operator / Reviewer / Read Only need a role column and per-tenant grants.
3. **Delivery.** `alerts.js` evaluates; delivery, dedupe state, ACK, escalation and watchdog are GuardOps modules (PLANNED there). No real notification channel is active here.

The former open question about a "canonical line" is closed by the owner: MacGuard is the rules product; GuardOps is separate.

Version rule: additive changes keep `…/1`; anything else takes `…/2`.
