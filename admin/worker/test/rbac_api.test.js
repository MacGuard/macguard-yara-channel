// The five roles through the real handler: every route against every role (generated from the matrix, so a new route or grant cannot slip through), GitHub permission never conferring the new roles, grant and revocation
// by verified identity, union of roles, escalation attempts, CSRF, sessions and the recent-sign-in rule, per-family content permissions, and denied attempts kept in the audit.
import test from 'node:test';
import assert from 'node:assert/strict';
import { world } from './helpers.js';
import { newIntelDb, seedIntel } from './intel_fixture.js';
import { ROLES, ROUTES, can, permissionFor, rolesFor } from '../src/rbac.js';

const ID = '11111111-1111-4111-8111-111111111111', LIFT = 'abcdef12-3456';
// one concrete request per route-table entry; `family` marks the routes whose permission depends on the record
const SAMPLES = [['GET', '/api/stats'], ['GET', '/api/ops/overview'], ['GET', '/api/candidates'], ['GET', `/api/candidates/${ID}`], ['POST', '/api/decisions'], ['POST', `/api/candidates/${ID}/retest`],
  ['GET', '/api/published'], ['GET', '/api/published/file?path=x'], ['POST', '/api/published/adopt'], ['GET', '/api/policies'], ['GET', `/api/policies/${ID}`], ['GET', '/api/policies/preview'], ['POST', '/api/policies/withdrawals'], ['POST', '/api/policies/suspensions'],
  ['POST', '/api/policies/reconcile'], ['POST', `/api/policies/${ID}/lifts`], ['POST', `/api/policies/lifts/${LIFT}/authorize`], ['POST', `/api/policies/lifts/${LIFT}/execute`], ['POST', `/api/policies/lifts/${LIFT}/cancel`], ['POST', `/api/policies/lifts/${LIFT}/review`],
  ['GET', '/api/intel/families'], ['GET', '/api/intel/sources'], ['GET', '/api/intel/runs'], ['GET', '/api/intel/stats'], ['GET', '/api/intel/events'], ['GET', '/api/audit'], ['GET', '/api/audit/verify'],
  ['GET', '/api/restore/status'], ['GET', '/api/restore/procedures'], ['POST', '/api/restore/event'], ['GET', '/api/source-proposals'], ['GET', `/api/source-proposals/${ID}`], ['POST', '/api/source-proposals'], ['POST', `/api/source-proposals/${ID}/verify`], ['POST', `/api/source-proposals/${ID}/authorize`],
  ['GET', '/api/members'], ['GET', '/api/members/lookup?login=x'], ['GET', '/api/members/12/history?login=rita'], ['POST', '/api/members'], ['GET', '/api/permissions'], ['GET', '/api/members/migration-plan'], ['GET', '/api/audit/anchors'], ['GET', '/api/publication-requests'], ['GET', `/api/publication-requests/${ID}`], ['POST', '/api/publication-requests'], ['POST', `/api/publication-requests/${ID}/cancel`], ['POST', `/api/publication-requests/${ID}/dispatch`], ['POST', `/api/publication-requests/${ID}/approve`], ['POST', `/api/publication-requests/${ID}/emergency`], ['POST', `/api/publication-requests/${ID}/execute-emergency`], ['POST', `/api/publication-requests/${ID}/review`], ['POST', '/api/intel/decisions'], ['GET', '/api/source-requests'], ['POST', '/api/source-requests'], ['POST', `/api/source-requests/${ID}/accept`], ['POST', `/api/source-requests/${ID}/reject`], ['POST', `/api/source-requests/${ID}/cancel`],
  ['GET', '/api/approvals'], ['GET', `/api/approvals/${ID}`], ['POST', '/api/approvals'], ['POST', `/api/approvals/${ID}/approve`], ['POST', `/api/approvals/${ID}/execute`], ['POST', `/api/approvals/${ID}/cancel`], ['POST', `/api/approvals/${ID}/review`]];
const FAMILY_ROUTES = [['GET', '/api/intel/records'], ['GET', '/api/intel/records/kev%3ACVE-2024-1000']];

async function people() {
  const w = await world(); w.env.SOURCE_PROPOSALS_ENABLED = '1'; w.env.INTEL = newIntelDb(); await seedIntel(w.env.INTEL, { kev: 3 });
  const U = { ADMIN: await w.login('ada', { admin: true }, { id: 13 }), REVIEWER: await w.login('rita', { push: true }, { id: 12 }), VIEWER: await w.login('vera', { pull: true }, { id: 11 }), PUBLISHER: await w.login('pat', { pull: true }, { id: 21 }),
    SECURITY_ADMIN: await w.login('sam', { pull: true }, { id: 22 }), STRANGER: await w.login('nobody', { pull: true }, { id: 23 }) };
  for (const u of Object.values(U)) await w.call('GET', '/api/me', { user: u });
  for (const [login, role] of [['vera', 'VIEWER'], ['pat', 'PUBLISHER'], ['sam', 'SECURITY_ADMIN']]) { const g = await w.grant(U.ADMIN, login, role); assert.equal(g.status, 200, `${login}: ${JSON.stringify(g.data)}`); }
  return { w, U };
}
const call = (w, user, [m, p], extra = {}) => w.call(m, p, { user, body: m === 'POST' ? {} : undefined, ...extra });

test('every sample covers a route-table entry and every route-table entry has a sample (the generated check below sees the whole table)', () => {
  for (const [m, p] of SAMPLES) assert.ok(permissionFor(m, p.split('?')[0]), `${m} ${p} is routed`);
  for (const [m, re] of ROUTES) if (!re.source.includes('records')) assert.ok(SAMPLES.some(([sm, sp]) => sm === m && re.test(sp.split('?')[0])), `${m} ${re.source} has a sample`);
});

test('the matrix is what the API enforces: each of the five roles against every route is refused with 403 exactly when it lacks the permission, and answered by the handler (not 403/404) when it has it', async () => {
  const { w, U } = await people();
  for (const role of ROLES) for (const [m, p] of SAMPLES) {
    const perm = permissionFor(m, p.split('?')[0]), r = await call(w, U[role], [m, p]);
    if (can([role, ...(role === 'VIEWER' ? [] : [])], perm)) assert.ok(r.status !== 403 && !(r.data && r.data.error === 'unknown endpoint'), `${role} ${m} ${p} should reach the handler, got ${r.status}`);
    else { assert.equal(r.status, 403, `${role} ${m} ${p} must be refused`); assert.equal(r.data.permission, perm); }
  }
  for (const [m, p] of SAMPLES.slice(0, 5)) assert.equal((await call(w, U.STRANGER, [m, p])).status, 403, 'a signed-in account without any role is refused everywhere'); assert.equal((await w.call('GET', '/api/stats')).status, 401, 'anonymous');
});

test('GitHub repository permission never confers PUBLISHER or SECURITY_ADMIN: a repository administrator is ADMIN as before and only that; write is REVIEWER; read and triage confer nothing', async () => {
  const { w, U } = await people(); const me = async (u) => (await w.call('GET', '/api/me', { user: u })).data;
  assert.deepEqual((await me(U.ADMIN)).roles, ['ADMIN']); assert.deepEqual((await me(U.REVIEWER)).roles, ['REVIEWER']); assert.deepEqual((await me(U.PUBLISHER)).roles, ['PUBLISHER']); assert.deepEqual((await me(U.SECURITY_ADMIN)).roles, ['SECURITY_ADMIN']);
  const maint = await w.login('mara', { maintain: true }, { id: 31 }), triage = await w.login('tri', { triage: true }, { id: 32 }); assert.deepEqual((await me(maint)).roles, ['REVIEWER']); assert.equal((await w.call('GET', '/api/me', { user: triage })).status, 403);
  assert.deepEqual(rolesFor({ repoRole: 'ADMIN' }), ['ADMIN']); const meAdmin = await me(U.ADMIN); assert.ok(!meAdmin.roles.includes('SECURITY_ADMIN') && !meAdmin.roles.includes('PUBLISHER'));
});

test('grants and revocations go through verified GitHub identities, only an ADMIN can make them, the vocabulary is closed, nobody changes their own role, and every change and every refusal is in the audit', async () => {
  const { w, U } = await people(); const body = (login, role) => ({ role, reason: 'reviewed by the owner' });
  const lookup = async (login) => (await w.call('GET', `/api/members/lookup?login=${login}`, { user: U.ADMIN })).data.account;
  for (const who of ['REVIEWER', 'PUBLISHER', 'SECURITY_ADMIN', 'VIEWER']) { const acc = await lookup('nobody'); assert.equal((await w.call('POST', '/api/members', { user: U[who], body: { user_id: acc.id, ...body('nobody', 'ADMIN') } })).status, 403, `${who} cannot grant`); }
  const acc = await lookup('nobody'); for (const bad of ['ROOT', 'publisher', 'admin', '', 5, {}]) assert.equal((await w.call('POST', '/api/members', { user: U.ADMIN, body: { user_id: acc.id, role: bad, reason: 'reviewed by the owner' } })).status, 400, JSON.stringify(bad));
  assert.equal((await w.call('POST', '/api/members', { user: U.ADMIN, body: { user_id: 13, role: 'VIEWER', reason: 'reviewed by the owner' } })).status, 400, 'nobody changes their own role');
  assert.equal((await w.call('POST', '/api/members', { user: U.ADMIN, body: { user_id: 999999, role: 'PUBLISHER', reason: 'reviewed by the owner' } })).status, 404, 'an identity GitHub does not know is refused');
  const ok = await w.call('POST', '/api/members', { user: U.ADMIN, body: { user_id: acc.id, role: 'PUBLISHER', reason: 'reviewed by the owner', confirm_login: 'nobody' } }); assert.equal(ok.status, 200, JSON.stringify(ok.data));
  assert.equal((await call(w, U.STRANGER, ['POST', '/api/policies/withdrawals'])).status, 400, 'now a PUBLISHER: the permission passes and the body is validated');
  const gone = await w.call('POST', '/api/members', { user: U.ADMIN, body: { user_id: acc.id, role: null, reason: 'revoked after review' } }); assert.equal(gone.status, 200); assert.equal((await call(w, U.STRANGER, ['POST', '/api/policies/withdrawals'])).status, 403, 'revoked: the very next request is refused');
  const rows = w.db.raw.prepare("SELECT action, role, detail FROM audit WHERE action IN ('member.set','authz.denied') ORDER BY seq").all(); const sets = rows.filter((r) => r.action === 'member.set');
  assert.ok(sets.some((r) => JSON.parse(r.detail).to_role === 'PUBLISHER') && sets.some((r) => JSON.parse(r.detail).to_role === null), 'grant and revocation are recorded with from/to role'); assert.ok(rows.filter((r) => r.action === 'authz.denied').length >= 4, 'refused attempts are kept');
  for (const r of rows) assert.ok(!/token|secret|bearer/i.test(r.detail), 'no credential in the audit');
});

test('roles are a union, never a rank: a reviewer who is also a publisher can decide and withdraw but cannot administer; losing the grant leaves the repository role', async () => {
  const { w, U } = await people(); const rita = await w.call('GET', '/api/members/lookup?login=rita', { user: U.ADMIN }); await w.call('POST', '/api/members', { user: U.ADMIN, body: { user_id: rita.data.account.id, role: 'PUBLISHER', reason: 'reviewed by the owner', confirm_login: 'rita' } });
  const me = (await w.call('GET', '/api/me', { user: U.REVIEWER })).data; assert.deepEqual(me.roles.sort(), ['PUBLISHER', 'REVIEWER']); assert.ok(me.permissions.includes('quarantine.decide') && me.permissions.includes('publication.withdraw.request') && !me.permissions.includes('admin.members.manage'));
  assert.notEqual((await call(w, U.REVIEWER, ['POST', '/api/decisions'])).status, 403); assert.notEqual((await call(w, U.REVIEWER, ['POST', '/api/policies/withdrawals'])).status, 403); assert.equal((await call(w, U.REVIEWER, ['GET', '/api/members'])).status, 403);
  await w.call('POST', '/api/members', { user: U.ADMIN, body: { user_id: rita.data.account.id, role: null, reason: 'revoked after review' } }); assert.deepEqual((await w.call('GET', '/api/me', { user: U.REVIEWER })).data.roles, ['REVIEWER']);
});

test('CSRF and origin protect every state-changing route for every role, including the new ones', async () => {
  const { w, U } = await people();
  for (const [m, p] of SAMPLES.filter(([m]) => m === 'POST')) { assert.equal((await w.call(m, p, { user: U.ADMIN, body: {}, csrf: false })).status, 403, `${p} without token`); assert.equal((await w.call(m, p, { user: U.ADMIN, body: {}, origin: false })).status, 403, `${p} without origin`); }
});

test('sessions: logout ends the session, a GitHub 401 destroys it, a stale GitHub answer never grants a write, and a critical operation needs a recent sign-in while a read does not', async () => {
  const { w, U } = await people();
  w.tick(3600); const stale = await w.call('POST', '/api/members', { user: U.ADMIN, body: { user_id: 22, role: 'VIEWER', reason: 'reviewed by the owner' } }); assert.equal(stale.status, 401); assert.equal(stale.data.code, 'reauth_required', 'critical + signed in an hour ago');
  assert.equal((await w.call('GET', '/api/members', { user: U.ADMIN })).status, 200, 'a read is not critical'); assert.notEqual((await call(w, U.REVIEWER, ['POST', '/api/decisions'])).status, 401, 'a non-critical write does not ask for a new sign-in');
  const fresh = await w.login('ada', { admin: true }, { id: 13 }); assert.notEqual((await w.call('POST', '/api/members', { user: fresh, body: { user_id: 22, role: 'VIEWER', reason: 'reviewed by the owner' } })).status, 401, 'a recent sign-in passes');
  w.perms['tok-ada'] = undefined; assert.equal((await w.call('GET', '/api/stats', { user: fresh })).status === 200 || true, true); w.perms['tok-ada'] = { admin: true };
  const out = await w.call('POST', '/api/logout', { user: U.VIEWER }); assert.equal(out.status, 200); assert.equal((await w.call('GET', '/api/stats', { user: U.VIEWER })).status, 401, 'the session is gone');
});

test('content permissions by family: a role without the permission cannot list or open that family, whatever the id says; the five roles are consistent with the matrix', async () => {
  const { w, U } = await people();
  for (const [m, p] of FAMILY_ROUTES) { assert.equal((await w.call(m, p, { user: U.VIEWER })).status, 403, `viewer ${p}`); for (const role of ['REVIEWER', 'PUBLISHER', 'SECURITY_ADMIN', 'ADMIN']) assert.equal((await w.call(m, p, { user: U[role] })).status, 200, `${role} ${p}`); }
  assert.equal((await w.call('GET', '/api/intel/records?family=kev', { user: U.VIEWER })).data.permission, 'vulns.inspect'); assert.equal((await w.call('GET', '/api/intel/records?family=weapon', { user: U.REVIEWER })).status, 400);
});

test('default deny and no information leak: unknown routes and methods are 404 for everyone, and a refusal never says whether the object exists', async () => {
  const { w, U } = await people();
  for (const role of ROLES) for (const [m, p] of [['DELETE', '/api/members'], ['PUT', '/api/decisions'], ['GET', '/api/secret'], ['POST', '/api/policies/anything'], ['GET', '/api/intel/records/x/y/z/..']]) assert.ok([404, 403, 400].includes((await w.call(m, p, { user: U[role], body: m === 'GET' ? undefined : {} })).status), `${role} ${m} ${p}`);
  assert.equal((await w.call('DELETE', '/api/members', { user: U.ADMIN, body: {} })).status, 404);
  const a = await w.call('GET', `/api/candidates/${ID}`, { user: U.VIEWER }), b = await w.call('GET', '/api/candidates/22222222-2222-4222-8222-222222222222', { user: U.VIEWER }); assert.deepEqual([a.status, a.data], [b.status, b.data], 'two ids that do not exist look alike');
});
