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
| `publication.revoke.request` | Request a critical revocation (by content) of a published rule |  |  | ✔ | ✔ | ✔ | critical |
| `publication.lift.request` | Request to lift a withdrawal |  |  | ✔ |  | ✔ | critical |
| `publication.lift.authorize` | Authorise a lift as a SECOND, different identity |  |  |  | ✔ | ✔ | critical, dual |
| `publication.lift.breakglass` | Execute an emergency lift after its delay |  |  |  |  | ✔ | critical |
| `publication.lift.review` | Review an emergency lift afterwards (not the person who executed it) |  |  |  | ✔ | ✔ | critical, dual |
| `publication.reconcile` | Re-read the public release and confirm pending withdrawals |  |  | ✔ |  | ✔ |  |

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

### logs

| Permission | What it allows | VIEWER | REVIEWER | PUBLISHER | SECURITY_ADMIN | ADMIN | Flags |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `logs.read` | Structured operational logs |  | ✔ | ✔ | ✔ | ✔ |  |

### sources

| Permission | What it allows | VIEWER | REVIEWER | PUBLISHER | SECURITY_ADMIN | ADMIN | Flags |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `sources.read` | Upstream sources and proposals (read) | ✔ | ✔ | ✔ | ✔ | ✔ |  |
| `sources.propose` | Propose a new upstream source |  | ✔ |  |  | ✔ |  |
| `sources.review` | Verify, approve, reject or retire a source proposal |  |  |  |  | ✔ | critical |

### audit

| Permission | What it allows | VIEWER | REVIEWER | PUBLISHER | SECURITY_ADMIN | ADMIN | Flags |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `audit.read` | Read the audit trail |  | ✔ |  | ✔ | ✔ |  |
| `audit.verify` | Verify the audit hash chain |  |  |  | ✔ | ✔ |  |
| `audit.export` | Export authorised audit evidence |  |  |  | ✔ |  | planned (no endpoint yet) |

### security

| Permission | What it allows | VIEWER | REVIEWER | PUBLISHER | SECURITY_ADMIN | ADMIN | Flags |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `incidents.manage` | Open and manage security incidents |  |  |  | ✔ |  | planned (no endpoint yet) |
| `alerts.manage` | Manage alerts, silences and escalation |  |  |  | ✔ |  | planned (no endpoint yet) |

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
| `restore.real.authorize` | Co-authorise a real recovery (never alone) |  |  |  | ✔ | ✔ | critical, dual, planned (no endpoint yet) |

### administration

| Permission | What it allows | VIEWER | REVIEWER | PUBLISHER | SECURITY_ADMIN | ADMIN | Flags |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `admin.members.read` | List users, roles and their history |  |  |  |  | ✔ |  |
| `admin.members.manage` | Grant or revoke roles to verified GitHub identities |  |  |  |  | ✔ | critical |
| `admin.permissions.read` | See the permission matrix |  |  |  |  | ✔ |  |

## Role totals

| Role | Permissions |
|---|---:|
| VIEWER | 4 |
| REVIEWER | 19 |
| PUBLISHER | 17 |
| SECURITY_ADMIN | 24 |
| ADMIN | 35 |

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

## Decisions for the owner before this is merged

1. **ADMIN keeps every previous power** (publication, withdrawal, lifts, audit verification, restores, sources, members). Nothing is removed. If PUBLISHER and SECURITY_ADMIN are meant to *take over* some of these, say which and ADMIN will lose them explicitly.
2. **Revocation by content or critical** (`publication.revoke.request`) is granted to PUBLISHER, SECURITY_ADMIN and ADMIN; a standard withdrawal (`publication.withdraw.request`) to PUBLISHER and ADMIN. Confirm that SECURITY_ADMIN may revoke but not withdraw.
3. **Second identity to lift a block** (`publication.lift.authorize`): ADMIN or SECURITY_ADMIN, always a different identity from the requester (enforced by the policy engine). Confirm.
4. **Granting a role needs a second approval?** Today one ADMIN grants any role. With a single ADMIN a second approval cannot exist (deadlock). Options: (a) keep single-admin grants and audit them; (b) require a second ADMIN or SECURITY_ADMIN once two exist; (c) break-glass with delay like the policy lifts. **Not implemented: needs your choice.**
5. **Real recovery** (`restore.real.authorize`, dual) is in the matrix but has **no endpoint yet**: today a real recovery is recorded step by step by an ADMIN (`restore.real.record`). The co-authorisation by ADMIN + SECURITY_ADMIN is the next delivery.
6. **Recent sign-in for critical operations**: 30 minutes (`CRITICAL_REAUTH_S`). Critical writes also ask GitHub again at that moment. Confirm the window.
7. **Migration 0006** rebuilds `members`, `policies` and `policy_lifts` to widen their role constraints. It refuses to run if a policy or a lift exists; apply after a verified backup of the panel database (tested on a copy and with its rollback).
8. `audit.export`, `incidents.manage`, `alerts.manage` are reserved for SECURITY_ADMIN but have **no endpoint yet** (marked planned).
