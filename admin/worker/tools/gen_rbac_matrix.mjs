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
  L.push('## Decisions for the owner before this is merged', '',
    '1. **ADMIN keeps every previous power** (publication, withdrawal, lifts, audit verification, restores, sources, members). Nothing is removed. If PUBLISHER and SECURITY_ADMIN are meant to *take over* some of these, say which and ADMIN will lose them explicitly.',
    '2. **Revocation by content or critical** (`publication.revoke.request`) is granted to PUBLISHER, SECURITY_ADMIN and ADMIN; a standard withdrawal (`publication.withdraw.request`) to PUBLISHER and ADMIN. Confirm that SECURITY_ADMIN may revoke but not withdraw.',
    '3. **Second identity to lift a block** (`publication.lift.authorize`): ADMIN or SECURITY_ADMIN, always a different identity from the requester (enforced by the policy engine). Confirm.',
    '4. **Granting a role needs a second approval?** Today one ADMIN grants any role. With a single ADMIN a second approval cannot exist (deadlock). Options: (a) keep single-admin grants and audit them; (b) require a second ADMIN or SECURITY_ADMIN once two exist; (c) break-glass with delay like the policy lifts. **Not implemented: needs your choice.**',
    '5. **Real recovery** (`restore.real.authorize`, dual) is in the matrix but has **no endpoint yet**: today a real recovery is recorded step by step by an ADMIN (`restore.real.record`). The co-authorisation by ADMIN + SECURITY_ADMIN is the next delivery.',
    '6. **Recent sign-in for critical operations**: 30 minutes (`CRITICAL_REAUTH_S`). Critical writes also ask GitHub again at that moment. Confirm the window.',
    '7. **Migration 0006** rebuilds `members`, `policies` and `policy_lifts` to widen their role constraints. It refuses to run if a policy or a lift exists; apply after a verified backup of the panel database (tested on a copy and with its rollback).',
    '8. `audit.export`, `incidents.manage`, `alerts.manage` are reserved for SECURITY_ADMIN but have **no endpoint yet** (marked planned).', '');
  return L.join('\n');
}
if (import.meta.url === `file://${process.argv[1]}`) { writeFileSync(new URL('../../../docs/rbac/MATRIX.md', import.meta.url), render()); console.log('written'); }
