# RBAC matrix: five roles, explicit permissions

Generated from `admin/worker/src/rbac.js` by `node tools/gen_rbac_matrix.mjs`. A test fails when this file and the code differ.

**Rules**

* Permissions are explicit. A role never receives something because another role has it; there is no rank and no inheritance. A person's permissions are the union of the roles they hold.
* GitHub repository permission confers only the two roles that already existed (`admin` → ADMIN, `maintain`/`write` → REVIEWER). **PUBLISHER and SECURITY_ADMIN exist only as explicit grants** by an ADMIN to a verified GitHub account.
* Default deny: a route that is not in the route table, a role or a permission that this file does not know, and a role-less person all get a refusal.
* `critical` operations ask GitHub again at the moment of the request and need a recent sign-in; `dual` operations need a second, different identity (enforced by the module that owns the operation).
* ADMIN keeps every permission the previous ADMIN had: nothing is removed from anyone by this change.

## Permissions by module and role

### dashboard

| Permission | What it allows | VIEWER | REVIEWER | PUBLISHER | SECURITY_ADMIN | ADMIN | Flags |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `dashboard.read` | Panel, statistics and pipeline activity | ✔ | ✔ | ✔ | ✔ | ✔ |  |

### quarantine

| Permission | What it allows | VIEWER | REVIEWER | PUBLISHER | SECURITY_ADMIN | ADMIN | Flags |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `quarantine.read` | List and open quarantined YARA candidates | ✔ | ✔ | ✔ | ✔ | ✔ |  |
| `quarantine.decide` | Approve, reject or hold a candidate (YARA review) |  | ✔ |  |  | ✔ |  |
| `quarantine.retest` | Ask for a candidate to be tested again |  | ✔ |  |  | ✔ |  |
| `quarantine.authorise_new_source` | Approve a candidate that introduces a new source |  |  |  |  | ✔ | critical |

### publications

| Permission | What it allows | VIEWER | REVIEWER | PUBLISHER | SECURITY_ADMIN | ADMIN | Flags |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `publication.read` | Published inventory, rule sheet, withdrawal policies (read) | ✔ | ✔ | ✔ | ✔ | ✔ |  |
| `publication.adopt` | Register a published file the panel never saw so it can be managed |  |  | ✔ |  | ✔ | critical |
| `publication.withdraw.request` | Request the withdrawal of a published rule (standard criticality) |  |  | ✔ |  | ✔ | critical |
| `publication.revoke.request` | Ask for a suspension to become a definitive revocation (needs an independent approval) |  |  |  | ✔ | ✔ | critical |
| `publication.revoke.approve` | Approve, as a different identity, the definitive revocation of a suspended rule |  |  |  | ✔ | ✔ | critical, dual |
| `publication.lift.request` | Request to lift a withdrawal |  |  | ✔ |  | ✔ | critical |
| `publication.lift.authorize` | Authorise a lift as a SECOND, different identity |  |  |  | ✔ | ✔ | critical, dual |
| `publication.lift.breakglass` | Execute an emergency lift after its delay |  |  |  |  | ✔ | critical |
| `publication.lift.review` | Review an emergency lift afterwards (not the person who executed it) |  |  |  | ✔ | ✔ | critical, dual |
| `publication.reconcile` | Re-read the public release and confirm pending withdrawals |  |  | ✔ |  | ✔ |  |

### security

| Permission | What it allows | VIEWER | REVIEWER | PUBLISHER | SECURITY_ADMIN | ADMIN | Flags |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `security.suspend` | Order an urgent preventive suspension of a published rule (critical or by content), with a justification |  |  |  | ✔ | ✔ | critical |
| `incidents.manage` | Open and manage security incidents |  |  |  | ✔ |  | planned (no endpoint yet) |
| `alerts.manage` | Manage alerts, silences and escalation |  |  |  | ✔ |  | planned (no endpoint yet) |

### yara

| Permission | What it allows | VIEWER | REVIEWER | PUBLISHER | SECURITY_ADMIN | ADMIN | Flags |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `yara.inspect` | Read the original content of YARA rules and their evidence |  | ✔ | ✔ | ✔ | ✔ |  |

### suricata

| Permission | What it allows | VIEWER | REVIEWER | PUBLISHER | SECURITY_ADMIN | ADMIN | Flags |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `suricata.inspect` | Read Suricata rules, verdicts and evidence |  | ✔ | ✔ | ✔ | ✔ |  |

### sigma

| Permission | What it allows | VIEWER | REVIEWER | PUBLISHER | SECURITY_ADMIN | ADMIN | Flags |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `sigma.inspect` | Read Sigma rules, verdicts and evidence |  | ✔ | ✔ | ✔ | ✔ |  |

### ioc

| Permission | What it allows | VIEWER | REVIEWER | PUBLISHER | SECURITY_ADMIN | ADMIN | Flags |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `ioc.inspect` | Read indicators of compromise |  | ✔ | ✔ | ✔ | ✔ |  |

### hashes

| Permission | What it allows | VIEWER | REVIEWER | PUBLISHER | SECURITY_ADMIN | ADMIN | Flags |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `hashes.inspect` | Read hash records |  | ✔ | ✔ | ✔ | ✔ |  |

### vulnerabilities

| Permission | What it allows | VIEWER | REVIEWER | PUBLISHER | SECURITY_ADMIN | ADMIN | Flags |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `vulns.inspect` | Read CVE, KEV, EPSS, advisories and ATT&CK records |  | ✔ | ✔ | ✔ | ✔ |  |

### intelligence

| Permission | What it allows | VIEWER | REVIEWER | PUBLISHER | SECURITY_ADMIN | ADMIN | Flags |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `intel.sources.read` | Sources, runs and statistics of the intelligence store |  | ✔ | ✔ | ✔ | ✔ |  |
| `intel.decide` | Hold, quarantine or reject records of every family but YARA (each also needs that family's inspect permission) |  | ✔ |  |  | ✔ |  |
| `intel.approve` | Approve records of every family but YARA for the NEXT publication. It never publishes: only the signed pipeline does |  | ✔ |  |  | ✔ |  |

### logs

| Permission | What it allows | VIEWER | REVIEWER | PUBLISHER | SECURITY_ADMIN | ADMIN | Flags |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `logs.read` | Structured operational logs |  | ✔ | ✔ | ✔ | ✔ |  |

### sources

| Permission | What it allows | VIEWER | REVIEWER | PUBLISHER | SECURITY_ADMIN | ADMIN | Flags |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `sources.read` | Upstream sources and proposals (read) | ✔ | ✔ | ✔ | ✔ | ✔ |  |
| `sources.propose` | Propose a new upstream source, or ask to add or retire one of any family (and cancel your own request) |  | ✔ |  |  | ✔ |  |
| `sources.requests.read` | See the requests to add or retire sources |  | ✔ | ✔ | ✔ | ✔ |  |
| `sources.review` | Verify, approve, reject or retire a source proposal |  |  |  |  | ✔ | critical |

### audit

| Permission | What it allows | VIEWER | REVIEWER | PUBLISHER | SECURITY_ADMIN | ADMIN | Flags |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `audit.read` | Read the audit trail |  | ✔ |  | ✔ | ✔ |  |
| `audit.verify` | Verify the audit hash chain |  |  |  | ✔ | ✔ |  |
| `audit.export` | Export authorised audit evidence |  |  |  | ✔ |  | planned (no endpoint yet) |

### backups

| Permission | What it allows | VIEWER | REVIEWER | PUBLISHER | SECURITY_ADMIN | ADMIN | Flags |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `backups.read` | Backup and recovery status |  | ✔ |  | ✔ | ✔ |  |

### restores

| Permission | What it allows | VIEWER | REVIEWER | PUBLISHER | SECURITY_ADMIN | ADMIN | Flags |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `restore.guide` | Recovery procedures and the guided assistant |  | ✔ |  | ✔ | ✔ |  |
| `restore.drill.record` | Record steps of a recovery drill |  | ✔ |  | ✔ | ✔ |  |
| `restore.real.record` | Record steps of a real, protected recovery |  |  |  |  | ✔ | critical |
| `restore.real.request` | Request authorisation of a real recovery (exact target, chosen backup, rollback plan) |  |  |  |  | ✔ | critical |
| `restore.real.authorize` | Authorise a real recovery as a different identity from the requester |  |  |  | ✔ | ✔ | critical, dual |
| `restore.real.breakglass` | Exceptional emergency path for a real recovery when no second approver exists (delay, long reason, review afterwards) |  |  |  |  | ✔ | critical |

### approvals

| Permission | What it allows | VIEWER | REVIEWER | PUBLISHER | SECURITY_ADMIN | ADMIN | Flags |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `approvals.read` | See pending and past approvals |  |  |  | ✔ | ✔ |  |
| `approvals.review` | Review an emergency (break-glass) approval afterwards, as someone who did not execute it |  |  |  | ✔ | ✔ | critical, dual |

### administration

| Permission | What it allows | VIEWER | REVIEWER | PUBLISHER | SECURITY_ADMIN | ADMIN | Flags |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `admin.members.read` | List users, roles and their history |  |  |  |  | ✔ |  |
| `admin.members.manage` | Grant or revoke roles to verified GitHub identities (privileged roles need reinforced or dual approval) |  |  |  |  | ✔ | critical |
| `admin.members.approve` | Approve, as a different identity, the grant of a privileged role |  |  |  |  | ✔ | critical, dual |
| `admin.members.breakglass` | Exceptional emergency grant of a privileged role when no second administrator exists |  |  |  |  | ✔ | critical |
| `admin.permissions.read` | See the permission matrix |  |  |  |  | ✔ |  |

## Role totals

| Role | Permissions |
|---|---:|
| VIEWER | 4 |
| REVIEWER | 22 |
| PUBLISHER | 17 |
| SECURITY_ADMIN | 29 |
| ADMIN | 46 |

## Route table

| Method | Pattern | Permission |
|---|---|---|
| GET | `^/api/stats$` | `dashboard.read` |
| GET | `^/api/ops/overview$` | `dashboard.read` |
| GET | `^/api/candidates$` | `quarantine.read` |
| GET | `^/api/candidates/[0-9a-f-]{8,64}$` | `quarantine.read` |
| POST | `^/api/decisions$` | `quarantine.decide` |
| POST | `^/api/candidates/[0-9a-f-]{8,64}/retest$` | `quarantine.retest` |
| GET | `^/api/published$` | `publication.read` |
| GET | `^/api/published/file$` | `publication.read` |
| POST | `^/api/published/adopt$` | `publication.adopt` |
| GET | `^/api/policies$` | `publication.read` |
| GET | `^/api/policies/[0-9a-f-]{8,64}$` | `publication.read` |
| GET | `^/api/policies/preview$` | `publication.withdraw.request` |
| POST | `^/api/policies/withdrawals$` | `publication.withdraw.request` |
| POST | `^/api/policies/suspensions$` | `security.suspend` |
| POST | `^/api/policies/reconcile$` | `publication.reconcile` |
| POST | `^/api/policies/[0-9a-f-]{8,64}/lifts$` | `publication.lift.request` |
| POST | `^/api/policies/lifts/[A-Za-z0-9-]{8,64}/authorize$` | `publication.lift.authorize` |
| POST | `^/api/policies/lifts/[A-Za-z0-9-]{8,64}/execute$` | `publication.lift.breakglass` |
| POST | `^/api/policies/lifts/[A-Za-z0-9-]{8,64}/cancel$` | `publication.lift.request` |
| POST | `^/api/policies/lifts/[A-Za-z0-9-]{8,64}/review$` | `publication.lift.review` |
| GET | `^/api/intel/families$` | `intel.sources.read` |
| GET | `^/api/intel/(sources|runs|stats)$` | `intel.sources.read` |
| GET | `^/api/intel/events$` | `logs.read` |
| GET | `^/api/intel/records$` | `INTEL_BY_FAMILY` |
| GET | `^/api/intel/records/.+$` | `INTEL_BY_FAMILY` |
| GET | `^/api/audit$` | `audit.read` |
| GET | `^/api/audit/verify$` | `audit.verify` |
| GET | `^/api/audit/anchors$` | `audit.read` |
| POST | `^/api/intel/decisions$` | `INTEL_DECISION` |
| GET | `^/api/source-requests$` | `sources.requests.read` |
| POST | `^/api/source-requests$` | `sources.propose` |
| POST | `^/api/source-requests/[0-9a-f-]{8,64}/(accept|reject)$` | `sources.review` |
| POST | `^/api/source-requests/[0-9a-f-]{8,64}/cancel$` | `sources.propose` |
| GET | `^/api/restore/status$` | `backups.read` |
| GET | `^/api/restore/procedures$` | `restore.guide` |
| POST | `^/api/restore/event$` | `restore.drill.record` |
| GET | `^/api/source-proposals$` | `sources.read` |
| GET | `^/api/source-proposals/.+$` | `sources.read` |
| POST | `^/api/source-proposals$` | `sources.propose` |
| POST | `^/api/source-proposals/[0-9a-f-]{8,64}/verify$` | `sources.propose` |
| POST | `^/api/source-proposals/.+$` | `sources.review` |
| GET | `^/api/members$` | `admin.members.read` |
| GET | `^/api/members/lookup$` | `admin.members.read` |
| GET | `^/api/members/\d{1,12}/history$` | `admin.members.read` |
| POST | `^/api/members$` | `admin.members.manage` |
| GET | `^/api/permissions$` | `admin.permissions.read` |
| GET | `^/api/approvals$` | `approvals.read` |
| GET | `^/api/approvals/[0-9a-f-]{8,64}$` | `approvals.read` |
| POST | `^/api/approvals$` | `APPROVAL_BY_OP` |
| POST | `^/api/approvals/[0-9a-f-]{8,64}/(approve|execute|cancel)$` | `APPROVAL_BY_OP` |
| POST | `^/api/approvals/[0-9a-f-]{8,64}/review$` | `approvals.review` |
| GET | `^/api/members/migration-plan$` | `admin.members.read` |

## Conditions of approval: status

| # | Condition | Status | Where it is enforced / proved |
|---|---|---|---|
| 1 | ADMIN keeps today's capabilities but no bypass of gates, separation of duties or critical approvals | done | grants in `rbac.js`; `approvals_api.test.js` (ADMIN cannot approve own request, no bypass in recovery events) |
| 2 | PUBLISHER manages publication, withdrawal, replacement and lift requests; cannot approve its own review or publish alone what it approved elsewhere | done | grants; adopt separation-of-duties guard; `rbac_api.test.js` |
| 3 | SECURITY_ADMIN orders an urgent preventive suspension; definitive revocation needs another identity; no private-key access | done | `POST /api/policies/suspensions` (`kind=SUSPENSION`), `policy.revoke_confirm` approval; no role holds a key permission |
| 4 | Separation by identity + operation, not by role | done | `approvals.approve` compares GitHub account ids (DB check too); tested with a person holding every role |
| 5 | Lift: request + second authorisation by distinct identities; SECURITY_ADMIN preferred; ADMIN only by audited emergency procedure | done | policy engine (unchanged), grants `publication.lift.*`, break-glass delay and review |
| 6 | Privileged grants (PUBLISHER, SECURITY_ADMIN, ADMIN): reinforced; double approval once two administrators exist; initial-admin recovery without backdoor | done | `POST /api/members` returns `approval_required`; single-admin mode needs typed login + sign-in <= 10 min and is recorded as `SINGLE_ADMIN`. Recovery: the GitHub repository ADMIN permission is the root of trust (see below) |
| 7 | 30-minute recent session, real re-authentication, identity check | done | `CRITICAL_REAUTH_S=1800` gate; identity proof via `GET /user` on fresh sessions; tests for expiry |
| 8 | Real restore: two identities, bound to operation, exact target, backup and rollback plan; no ADMIN bypass; traceable break-glass | done | `restore.real` approvals; `/api/restore/event` verifies `authorization_id` for protected procedures; `approvals_api.test.js` |
| 9 | GitHub mapping not widened; migration to explicit grants by stable id prepared | prepared | `GET /api/members/migration-plan` (read-only); materialising grants is a later, reviewed step |
| 10 | Migration 0006 only after verified encrypted D1 backup and isolated trial with representative data | **pending (gate)** | `tools/migration_trial.sh` + `test/migration_0006.test.js`; the real-D1 trial and backup are run before any deploy; blocked on the D1 Edit token for the backup |
| 11 | Every grant, revocation, denial and approval is a structured audit event in the verifiable chain; transparency not claimed without proofs | done / limited | audit chain verifies in every test. This is a hash chain, **not** a transparency log: inclusion/consistency proofs and an independent checkpoint belong to Observability V2 |
| 12 | Test matrix: roles x operations, combinations, SoD, escalation, IDOR, CSRF, expired sessions, changed identities, default deny | done | `rbac.test.js`, `rbac_api.test.js`, `approvals_api.test.js`, `migration_0006.test.js`, UI tests |

## Initial-administrator recovery (no permanent backdoor)

There is no hard-coded account and no recovery key. The root of trust is the **GitHub repository permission**: whoever the repository owner makes a repository administrator is ADMIN at their next request. Losing every explicit grant therefore never locks the panel out; losing the repository administrator permission is a GitHub account recovery, outside this panel. ADMIN by GitHub cannot be removed from the panel (no endpoint revokes it), and it never confers PUBLISHER or SECURITY_ADMIN.

## Still open for the owner

1. Whether `ADMIN` should *lose* some publication powers to PUBLISHER once there are people in those roles (today nothing is removed).
2. When to move from the GitHub-permission mapping to explicit grants (review `migration-plan` first).
3. `audit.export`, `incidents.manage`, `alerts.manage` are reserved for SECURITY_ADMIN but have no endpoint yet (marked planned).
4. Migration 0006 rebuilds `members`, `policies` and `policy_lifts` and **refuses to run if a policy or a lift exists**; production state must be checked, backed up and trialled first (condition 10).
