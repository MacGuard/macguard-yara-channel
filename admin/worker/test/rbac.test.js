// The RBAC matrix itself: explicit grants, separation of duties, no privilege lost by anyone who has a role today, default deny, route coverage of the Worker, and a document that cannot drift.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ROLES, PERMISSIONS, GRANTS, can, permissionsOf, rolesFor, primaryRole, permissionFor, ROUTES, familyPermission, GITHUB_DERIVED_ROLES, isCritical, OP_PERMISSIONS } from '../src/rbac.js';
import { render } from '../tools/gen_rbac_matrix.mjs';

test('five roles; every grant names a known permission; every route names a known permission (or the per-family marker)', () => {
  assert.deepEqual(ROLES, ['VIEWER', 'REVIEWER', 'PUBLISHER', 'SECURITY_ADMIN', 'ADMIN']);
  for (const [r, list] of Object.entries(GRANTS)) { assert.ok(ROLES.includes(r)); for (const p of list) assert.ok(PERMISSIONS[p], `${r}: ${p}`); assert.equal(new Set(list).size, list.length, `${r} lists a permission twice`); }
  for (const [, , p] of ROUTES) assert.ok(PERMISSIONS[p] || p === 'INTEL_BY_FAMILY' || p === 'APPROVAL_BY_OP', p);
  for (const [op, ps] of Object.entries(OP_PERMISSIONS)) for (const p of [ps.request, ps.approve, ps.breakglass].filter(Boolean)) assert.ok(PERMISSIONS[p], `${op}: ${p}`);
});

test('no inheritance: no role is a superset by accident, and each role holds exactly what its line says', () => {
  const has = (r, p) => GRANTS[r].includes(p);
  for (const [a, b] of [['PUBLISHER', 'REVIEWER'], ['SECURITY_ADMIN', 'PUBLISHER'], ['REVIEWER', 'SECURITY_ADMIN'], ['PUBLISHER', 'SECURITY_ADMIN']]) assert.ok(GRANTS[a].some((p) => !GRANTS[b].includes(p)) && GRANTS[b].some((p) => !GRANTS[a].includes(p)), `${a} and ${b} differ in both directions`);
  for (const r of ROLES.filter((x) => x !== 'ADMIN')) for (const p of Object.keys(PERMISSIONS).filter((q) => q.startsWith('admin.'))) assert.equal(has(r, p), false, `${r} must not hold ${p}`);
});

test('separation of duties: the publisher does not review, the reviewer does not publish, the security administrator cannot restore, publish, review or administer users alone', () => {
  const no = (r, ...ps) => { for (const p of ps) assert.equal(can(r, p), false, `${r} must not have ${p}`); };
  no('PUBLISHER', 'quarantine.decide', 'quarantine.authorise_new_source', 'audit.verify', 'restore.real.record', 'restore.real.authorize', 'admin.members.manage', 'sources.review');
  no('REVIEWER', 'publication.adopt', 'publication.withdraw.request', 'publication.revoke.request', 'restore.real.record', 'audit.verify', 'admin.members.manage');
  no('SECURITY_ADMIN', 'restore.real.record', 'quarantine.decide', 'publication.adopt', 'publication.withdraw.request', 'publication.lift.breakglass', 'admin.members.manage', 'admin.members.read', 'sources.review');
  no('VIEWER', ...Object.keys(PERMISSIONS).filter((p) => !GRANTS.VIEWER.includes(p)));
  assert.ok(can('SECURITY_ADMIN', 'restore.real.authorize') && PERMISSIONS['restore.real.authorize'].dual, 'a security administrator may co-authorise a recovery, and it is flagged dual');
  assert.ok(Object.entries(PERMISSIONS).filter(([, d]) => d.dual).length >= 3, 'dual operations are marked');
});

test('compatibility: whoever could do something before can still do it (the previous three roles lose nothing)', () => {
  // The route guard of the Worker BEFORE this change: minimum role per operation (VIEWER < REVIEWER < ADMIN).
  const OLD = { VIEWER: ['GET /api/stats', 'GET /api/ops/overview', 'GET /api/candidates', 'GET /api/published', 'GET /api/published/file', 'GET /api/policies', 'GET /api/source-proposals'],
    REVIEWER: ['POST /api/decisions', 'GET /api/audit', 'GET /api/restore/status', 'GET /api/restore/procedures', 'POST /api/restore/event', 'GET /api/intel/sources', 'GET /api/intel/records', 'POST /api/source-proposals'],
    ADMIN: ['GET /api/audit/verify', 'GET /api/members', 'POST /api/members', 'POST /api/published/adopt', 'POST /api/policies/withdrawals', 'POST /api/policies/reconcile', 'GET /api/policies/preview'] };
  const rank = { VIEWER: 1, REVIEWER: 2, ADMIN: 3 };
  for (const [min, ops] of Object.entries(OLD)) for (const op of ops) {
    const [m, path] = op.split(' '), perm = permissionFor(m, path.replace('/api/intel/records', '/api/intel/records')); assert.ok(perm, `${op} is in the route table`);
    for (const role of ['VIEWER', 'REVIEWER', 'ADMIN']) if (rank[role] >= rank[min]) { const needed = perm === 'INTEL_BY_FAMILY' ? 'yara.inspect' : perm; assert.ok(can(role, needed), `${role} could ${op} and still can (${perm})`); }
  }
});

test('GitHub permission confers only REVIEWER and ADMIN; PUBLISHER and SECURITY_ADMIN come only from an explicit grant; the union of roles is used and unknown roles are ignored', () => {
  assert.deepEqual(GITHUB_DERIVED_ROLES, ['REVIEWER', 'ADMIN']);
  assert.deepEqual(rolesFor({ repoRole: 'PUBLISHER', manualRole: null }), [], 'a repository can never confer PUBLISHER');
  assert.deepEqual(rolesFor({ repoRole: 'SECURITY_ADMIN' }), []); assert.deepEqual(rolesFor({ repoRole: 'ADMIN', manualRole: null }), ['ADMIN'], 'a repository administrator is ADMIN as before and nothing more');
  assert.deepEqual(rolesFor({ repoRole: 'REVIEWER', manualRole: 'PUBLISHER' }).sort(), ['PUBLISHER', 'REVIEWER']);
  const both = rolesFor({ repoRole: 'REVIEWER', manualRole: 'PUBLISHER' }); assert.ok(can(both, 'quarantine.decide') && can(both, 'publication.withdraw.request'), 'the union'); assert.equal(can(both, 'admin.members.manage'), false);
  assert.equal(primaryRole(['REVIEWER', 'PUBLISHER']), 'PUBLISHER'); assert.equal(primaryRole([]), null); assert.deepEqual(rolesFor({ manualRole: 'ROOT' }), []);
});

test('default deny: unknown roles, permissions, methods and paths are refused; a role-less person has nothing', () => {
  assert.equal(can('ROOT', 'quarantine.read'), false); assert.equal(can(null, 'quarantine.read'), false); assert.equal(can([], 'quarantine.read'), false); assert.equal(can('ADMIN', 'made.up'), false); assert.equal(can('ADMIN', undefined), false);
  assert.equal(can(['ROOT', 'VIEWER'], 'quarantine.read'), true, 'an unknown role next to a real one does not poison it'); assert.deepEqual(permissionsOf('ROOT'), []);
  for (const [m, p] of [['DELETE', '/api/members'], ['PUT', '/api/decisions'], ['GET', '/api/secret'], ['GET', '/api/members/../audit'], ['POST', '/api/policies/anything'], ['GET', '/api/intel'], ['GET', '/api/']]) assert.equal(permissionFor(m, p), null, `${m} ${p}`);
  assert.equal(familyPermission('suricata'), 'suricata.inspect'); assert.equal(familyPermission('weapon'), null); assert.equal(isCritical('admin.members.manage'), true); assert.equal(isCritical('quarantine.read'), false);
});

test('every API path literal the Worker handles is covered by the route table (or is one of the few answered before a role exists)', () => {
  const src = readFileSync(new URL('../src/index.js', import.meta.url), 'utf8').split('// ---- authenticated API ----')[1].split('// ---- UI assets ----')[0];
  const lits = [...new Set([...src.matchAll(/'(\/api\/[a-z0-9/_-]+)'/g)].map((m) => m[1]))].filter((p) => p !== '/api/' && !p.endsWith('/'));
  const exempt = new Set(['/api/me', '/api/logout']); const missing = [];
  for (const p of lits) { if (exempt.has(p)) continue; if (!['GET', 'POST'].some((m) => permissionFor(m, p))) missing.push(p); }
  assert.deepEqual(missing, [], 'every handled path has a permission');
});

test('the generated document is current', () => { assert.equal(readFileSync(new URL('../../../docs/rbac/MATRIX.md', import.meta.url), 'utf8'), render()); });
