// Writes docs/rbac/MATRIX.md from src/rbac.js, so the document cannot drift from the code (a test compares them).
import { writeFileSync } from 'node:fs';
import { matrix, ROUTES, GRANTS, ROLES } from '../src/rbac.js';

export function render() {
  const m = matrix(), L = [];
  L.push('# RBAC matrix: five roles, explicit permissions', '', 'Generated from `admin/worker/src/rbac.js` by `node tools/gen_rbac_matrix.mjs`. A test fails when this file and the code differ.', '',
    '**Rules**', '',
    '* Permissions are explicit. A role never receives something because another role has it; there is no rank and no inheritance. A person\'s permissions are the union of the roles they hold.',
    '* GitHub repository permission confers only the two roles that already existed (`admin` → ADMIN, `maintain`/`write` → REVIEWER). **PUBLISHER and SECURITY_ADMIN exist only as explicit grants** by an ADMIN to a verified GitHub account.',
    '* Default deny: a route that is not in the route table, a role or a permission that this file does not know, and a role-less person all get a refusal.',
    '* `critical` operations ask GitHub again at the moment of the request and need a recent sign-in; `dual` operations need a second, different identity (enforced by the module that owns the operation).',
    '* ADMIN keeps every permission the previous ADMIN had: nothing is removed from anyone by this change.', '');
  L.push('## Permissions by module and role', '');
  for (const [mod, perms] of Object.entries(m.modules)) {
    L.push(`### ${mod}`, '', `| Permission | What it allows | ${ROLES.join(' | ')} | Flags |`, `|---|---|${ROLES.map(() => ':-:').join('|')}|---|`);
    for (const p of perms) { const d = m.permissions[p]; L.push(`| \`${p}\` | ${d.desc} | ${ROLES.map((r) => (d.roles.includes(r) ? '✔' : '')).join(' | ')} | ${[d.critical && 'critical', d.dual && 'dual', d.planned && 'planned (no endpoint yet)'].filter(Boolean).join(', ')} |`); }
    L.push('');
  }
  L.push('## Role totals', '', '| Role | Permissions |', '|---|---:|', ...ROLES.map((r) => `| ${r} | ${GRANTS[r].length} |`), '', '## Route table', '', '| Method | Pattern | Permission |', '|---|---|---|', ...ROUTES.map(([me, re, p]) => `| ${me} | \`${re.source.replace(/\\\//g, '/')}\` | \`${p}\` |`), '');
  L.push('## Conditions of approval: status', '', '| # | Condition | Status | Where it is enforced / proved |', '|---|---|---|---|',
    '| 1 | ADMIN keeps today\'s capabilities but no bypass of gates, separation of duties or critical approvals | done | grants in `rbac.js`; `approvals_api.test.js` (ADMIN cannot approve own request, no bypass in recovery events) |',
    '| 2 | PUBLISHER manages publication, withdrawal, replacement and lift requests; cannot approve its own review or publish alone what it approved elsewhere | done | grants; adopt separation-of-duties guard; `rbac_api.test.js` |',
    '| 3 | SECURITY_ADMIN orders an urgent preventive suspension; definitive revocation needs another identity; no private-key access | done | `POST /api/policies/suspensions` (`kind=SUSPENSION`), `policy.revoke_confirm` approval; no role holds a key permission |',
    '| 4 | Separation by identity + operation, not by role | done | `approvals.approve` compares GitHub account ids (DB check too); tested with a person holding every role |',
    '| 5 | Lift: request + second authorisation by distinct identities; SECURITY_ADMIN preferred; ADMIN only by audited emergency procedure | done | policy engine (unchanged), grants `publication.lift.*`, break-glass delay and review |',
    '| 6 | Privileged grants (PUBLISHER, SECURITY_ADMIN, ADMIN): reinforced; double approval once two administrators exist; initial-admin recovery without backdoor | done | `POST /api/members` returns `approval_required`; single-admin mode needs typed login + sign-in <= 10 min and is recorded as `SINGLE_ADMIN`. Recovery: the GitHub repository ADMIN permission is the root of trust (see below) |',
    '| 7 | 30-minute recent session, real re-authentication, identity check | done | `CRITICAL_REAUTH_S=1800` gate; identity proof via `GET /user` on fresh sessions; tests for expiry |',
    '| 8 | Real restore: two identities, bound to operation, exact target, backup and rollback plan; no ADMIN bypass; traceable break-glass | done | `restore.real` approvals; `/api/restore/event` verifies `authorization_id` for protected procedures; `approvals_api.test.js` |',
    '| 9 | GitHub mapping not widened; migration to explicit grants by stable id prepared | prepared | `GET /api/members/migration-plan` (read-only); materialising grants is a later, reviewed step |',
    '| 10 | Migration 0006 only after verified encrypted D1 backup and isolated trial with representative data | **pending (gate)** | `tools/migration_trial.sh` + `test/migration_0006.test.js`; the real-D1 trial and backup are run before any deploy; blocked on the D1 Edit token for the backup |',
    '| 11 | Every grant, revocation, denial and approval is a structured audit event in the verifiable chain; transparency not claimed without proofs | done / limited | audit chain verifies in every test. This is a hash chain, **not** a transparency log: inclusion/consistency proofs and an independent checkpoint belong to Observability V2 |',
    '| 12 | Test matrix: roles x operations, combinations, SoD, escalation, IDOR, CSRF, expired sessions, changed identities, default deny | done | `rbac.test.js`, `rbac_api.test.js`, `approvals_api.test.js`, `migration_0006.test.js`, UI tests |', '',
    '## Initial-administrator recovery (no permanent backdoor)', '',
    'There is no hard-coded account and no recovery key. The root of trust is the **GitHub repository permission**: whoever the repository owner makes a repository administrator is ADMIN at their next request. Losing every explicit grant therefore never locks the panel out; losing the repository administrator permission is a GitHub account recovery, outside this panel. ADMIN by GitHub cannot be removed from the panel (no endpoint revokes it), and it never confers PUBLISHER or SECURITY_ADMIN.', '',
    '## Still open for the owner', '',
    '1. Whether `ADMIN` should *lose* some publication powers to PUBLISHER once there are people in those roles (today nothing is removed).',
    '2. When to move from the GitHub-permission mapping to explicit grants (review `migration-plan` first).',
    '3. `audit.export`, `incidents.manage`, `alerts.manage` are reserved for SECURITY_ADMIN but have no endpoint yet (marked planned).',
    '4. Migration 0006 rebuilds `members`, `policies` and `policy_lifts` and **refuses to run if a policy or a lift exists**; production state must be checked, backed up and trialled first (condition 10).', '');
  return L.join('\n');
}
if (import.meta.url === `file://${process.argv[1]}`) { writeFileSync(new URL('../../../docs/rbac/MATRIX.md', import.meta.url), render()); console.log('written'); }
