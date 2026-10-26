// Second-identity approvals through the real handler: privileged role grants, real-recovery authorisation, preventive suspension and its definitive revocation. What must hold:
// the approver is a different GitHub identity whatever roles either holds, the request is frozen and bound to its operation, an expired or stale one does nothing, the emergency path is delayed, justified,
// executed by the requester only after the delay and reviewed afterwards by a third identity, and every transition is in the audit chain.
import test from 'node:test';
import assert from 'node:assert/strict';
import { world, cand, rid, ORIGIN } from './helpers.js';
import { verifyChain } from '../src/core.js';
import { auditRows } from '../src/store.js';

const T1 = 'rules-20261021-1', AT1 = '2026-10-21T03:00:00Z';
const callback = async (w, tag, hashes, claims = {}) => w.call('POST', '/api/pipeline/released', { bearer: await w.pipelineToken('publish.yml', { run_id: '5551', run_attempt: '1', ...claims }), body: { tag, hashes, run_url: `${ORIGIN}/runs/5551` } });
const q = (w, sql, ...a) => w.db.raw.prepare(sql).all(...a).map((r) => ({ ...r }));
const actions = (w, action) => q(w, 'SELECT action, actor, detail FROM audit WHERE action = ? ORDER BY seq', action);
const chainOk = async (w) => assert.equal((await verifyChain(await auditRows(w.db, 5000))).ok, true, 'the audit chain verifies');
const ask = (w, user, body) => w.call('POST', '/api/approvals', { user, body: { request_id: rid(), reason: 'access reviewed by the owner', ...body } });
const next = (w, user, id, op, v, over = {}) => w.call('POST', `/api/approvals/${id}/${op}`, { user, body: { request_id: rid(), expect_version: v, reason: 'plan and target checked twice', ...over } });
const recovery = (over = {}) => ({ op: 'restore.real', params: { procedure: 'd1_only', run: '9f2b6a40-1c3d-4e5f-8a7b-0c1d2e3f4a5b', target: 'staging-d1-copy', backup: { stamp: '20261025T224553Z', provider: 'b2' }, rollback_plan: 'keep the current database untouched and swap back', ...over } });

/** ada and bob (ADMIN by GitHub), sam (SECURITY_ADMIN), pat (PUBLISHER), rita (REVIEWER), vera (VIEWER); one published rule. */
async function fx() {
  const w = await world(); const r = await w.submit([cand('a')]); assert.equal(r.status, 200); const id = r.data.results[0].id, c = cand('a');
  w.ada = await w.login('ada', { admin: true }, { id: 9001 }); w.bob = await w.login('bob', { admin: true }, { id: 9002 }); w.rita = await w.login('rita', { push: true }, { id: 9003 });
  w.account('sam', 9004); w.account('pat', 9005); w.account('vera', 9006); w.account('newbie', 9007);
  for (const [l, role] of [['sam', 'SECURITY_ADMIN'], ['pat', 'PUBLISHER'], ['vera', 'VIEWER']]) assert.equal((await w.grant(w.ada, l, role)).status, 200, l);   // while ada is the only administrator known
  w.sam = await w.login('sam', { pull: true }, { id: 9004 }); w.pat = await w.login('pat', { pull: true }, { id: 9005 }); w.vera = await w.login('vera', { pull: true }, { id: 9006 });
  for (const u of [w.bob, w.ada, w.rita]) await w.call('GET', '/api/me', { user: u });   // both administrators are now known to the panel
  await w.release(T1, [c], { publishedAt: AT1 }); assert.equal((await callback(w, T1, [c.sha256])).status, 200);
  return { w, id };
}

test('a privileged role is never granted by one hand once two administrators exist: the direct grant is refused, a second administrator approves, and the effect, the approval and the grant are one trace', async () => {
  const { w } = await fx();
  const l = (await w.call('GET', '/api/members/lookup?login=newbie', { user: w.ada })).data.account;
  const direct = await w.call('POST', '/api/members', { user: w.ada, body: { user_id: l.id, role: 'PUBLISHER', reason: 'reviewed by the owner', confirm_login: 'newbie' } });
  assert.equal(direct.status, 409); assert.equal(direct.data.code, 'approval_required');
  assert.equal((await w.grant(w.ada, 'newbie', 'VIEWER')).status, 200, 'a role with no privileged capability keeps the direct path');
  const req = await ask(w, w.ada, { op: 'role.grant', params: { user_id: l.id, login: 'newbie', role: 'PUBLISHER' } }); assert.equal(req.status, 200, JSON.stringify(req.data)); const a = req.data.approval;
  assert.equal(a.state, 'REQUESTED'); assert.equal((await ask(w, w.ada, { op: 'role.grant', params: { user_id: l.id, login: 'newbie', role: 'PUBLISHER' } })).status, 409, 'an identical open request is not duplicated');
  const own = await next(w, w.ada, a.id, 'approve', a.version); assert.equal(own.status, 403); assert.equal(own.data.code, 'same_identity');
  assert.equal((await next(w, w.pat, a.id, 'approve', a.version)).status, 403, 'a role without admin.members.approve cannot approve');
  assert.equal((await next(w, w.bob, a.id, 'approve', a.version + 7)).status, 409, 'a stale version is refused');
  const done = await next(w, w.bob, a.id, 'approve', a.version); assert.equal(done.status, 200, JSON.stringify(done.data)); assert.equal(done.data.approval.state, 'EXECUTED');
  assert.deepEqual((await w.call('GET', '/api/me', { user: await w.login('newbie', { pull: true }, { id: l.id }) })).data.roles, ['PUBLISHER']);
  const set = actions(w, 'member.set').map((r) => JSON.parse(r.detail)).find((d) => d.to_role === 'PUBLISHER' && d.login === 'newbie'); assert.equal(set.approval_id, a.id); assert.equal(set.requested_by_id, 9001); assert.equal(set.approved_by_id, 9002);
  assert.deepEqual(['approval.requested', 'approval.approved', 'approval.executed'].map((x) => actions(w, x).length), [1, 1, 1]); await chainOk(w);
});

test('the requester can never be the second approver, even holding every role; an identity that changed its login or an account that does not match is refused', async () => {
  const { w } = await fx();
  assert.equal((await w.grant(w.ada, 'sam', 'SECURITY_ADMIN')).status, 409, 'already held');
  const boss = await ask(w, w.ada, { op: 'restore.real', ...recovery() }); assert.equal(boss.status, 200, JSON.stringify(boss.data));
  assert.equal((await next(w, w.ada, boss.data.approval.id, 'approve', boss.data.approval.version)).data.code, 'same_identity', 'ADMIN holds the authorise permission and still cannot approve their own request');
  const l = (await w.call('GET', '/api/members/lookup?login=newbie', { user: w.ada })).data.account;
  const wrong = await ask(w, w.ada, { op: 'role.grant', params: { user_id: l.id, login: 'someone-else', role: 'PUBLISHER' } }); assert.equal(wrong.status, 409, 'the login must belong to that GitHub account id');
  assert.equal((await ask(w, w.ada, { op: 'role.grant', params: { user_id: w.ada && 9001, login: 'ada', role: 'ADMIN' } })).status, 400, 'nobody requests a role for themselves');
  for (const bad of [{ op: 'role.grant', params: { user_id: l.id, login: 'newbie', role: 'VIEWER' } }, { op: 'nope', params: {} }, { op: 'restore.real', params: { procedure: 'drill' } }, { op: 'role.grant', params: { user_id: l.id, login: 'newbie', role: 'ADMIN', extra: 1 } }]) assert.equal((await ask(w, w.ada, bad)).status, 400, JSON.stringify(bad));
  await chainOk(w);
});

test('a real recovery needs two identities and is bound to its procedure, run, target, backup and rollback plan; the ADMIN has no bypass and an expired authorisation does nothing', async () => {
  const { w } = await fx(); const run = recovery().params.run;
  assert.equal((await ask(w, w.rita, { op: 'restore.real', ...recovery() })).status, 403, 'a reviewer cannot request it');
  assert.equal((await ask(w, w.sam, { op: 'restore.real', ...recovery() })).status, 403, 'the security administrator authorises but does not request');
  for (const over of [{ rollback_plan: 'later' }, { backup: { stamp: 'yesterday', provider: 'b2' } }, { target: '' }, { procedure: 'drill' }, { run: 'x' }]) assert.equal((await ask(w, w.ada, { op: 'restore.real', ...recovery(over) })).status, 400, JSON.stringify(over));
  const req = (await ask(w, w.ada, { op: 'restore.real', ...recovery() })).data.approval, post = (user, body) => w.call('POST', '/api/restore/event', { user, body });
  assert.equal((await post(w.ada, { event: 'procedure_started', procedure: 'd1_only', run, authorization_id: req.id })).status, 403, 'not authorised yet: ADMIN has no bypass');
  assert.equal((await next(w, w.sam, req.id, 'approve', req.version)).status, 200);
  assert.equal((await post(w.ada, { event: 'procedure_started', procedure: 'compromise', run, authorization_id: req.id })).status, 403, 'bound to the procedure');
  assert.equal((await post(w.ada, { event: 'procedure_started', procedure: 'd1_only', run: 'another-run-1234', authorization_id: req.id })).status, 403, 'bound to the run');
  assert.equal((await post(w.ada, { event: 'procedure_started', procedure: 'd1_only', run, authorization_id: req.id })).status, 200);
  const old = (await ask(w, w.ada, { op: 'restore.real', ...recovery({ run: 'run-for-expiry-1' }) })).data.approval; w.tick(24 * 3600 + 5);
  const late = await w.login('sam', { pull: true }, { id: 9004 }); assert.equal((await next(w, late, old.id, 'approve', old.version)).status, 409, 'expired'); await chainOk(w);
});

test('the emergency path: long reason, explicit no-second-approver, a six hour delay, execution by the requester on a fresh sign-in, and a review by a third identity', async () => {
  const { w } = await fx(); const body = recovery({ run: 'emergency-run-01' });
  assert.equal((await ask(w, w.ada, { op: 'restore.real', mode: 'BREAKGLASS', ...body, reason: 'urgent' })).status, 400, 'short reason');
  assert.equal((await ask(w, w.ada, { op: 'restore.real', mode: 'BREAKGLASS', ...body, reason: 'the only other administrator is unreachable and the database is corrupted now' })).status, 400, 'no_second_approver is explicit');
  assert.equal((await ask(w, w.sam, { op: 'restore.real', mode: 'BREAKGLASS', ...body, reason: 'the only other administrator is unreachable and the database is corrupted now', no_second_approver: true })).status, 403, 'the emergency permission is the ADMIN\'s');
  const r = await ask(w, w.ada, { op: 'restore.real', mode: 'BREAKGLASS', ...body, reason: 'the only other administrator is unreachable and the database is corrupted now', no_second_approver: true }); assert.equal(r.status, 200, JSON.stringify(r.data)); const a = r.data.approval;
  assert.equal((await next(w, w.sam, a.id, 'approve', a.version)).status, 409, 'an emergency request is executed, not approved');
  const early = await next(w, w.ada, a.id, 'execute', a.version, {}); assert.equal(early.status, 409); assert.equal(early.data.code, 'delay');
  w.tick(6 * 3600 + 5); const stale = await next(w, w.ada, a.id, 'execute', a.version); assert.equal(stale.status, 401, 'the sign-in is older than the recent-sign-in limit'); assert.equal(stale.data.code, 'reauth_required');
  const fresh = await w.login('ada', { admin: true }, { id: 9001 });
  assert.equal((await next(w, w.bob, a.id, 'execute', a.version)).status, 401, 'only the requester executes it (and bob has an old sign-in too)');
  const bobFresh = await w.login('bob', { admin: true }, { id: 9002 }); assert.equal((await next(w, bobFresh, a.id, 'execute', a.version)).status, 403);
  const ran = await next(w, fresh, a.id, 'execute', a.version); assert.equal(ran.status, 200, JSON.stringify(ran.data)); assert.equal(ran.data.approval.state, 'EXECUTED');
  const run = body.params.run; assert.equal((await w.call('POST', '/api/restore/event', { user: fresh, body: { event: 'procedure_started', procedure: 'd1_only', run, authorization_id: a.id } })).status, 200, 'an executed emergency authorisation is usable');
  const ev = ran.data.approval; assert.equal((await next(w, fresh, a.id, 'review', ev.version + 0, { outcome: 'APPROPRIATE' })).status, 403, 'the executor cannot review it'); 
  const samFresh = await w.login('sam', { pull: true }, { id: 9004 }); const rv = await next(w, samFresh, a.id, 'review', ev.version, { outcome: 'APPROPRIATE' }); assert.equal(rv.status, 200, JSON.stringify(rv.data));
  assert.deepEqual(['approval.breakglass_requested', 'approval.breakglass_executed', 'approval.reviewed'].map((x) => actions(w, x).length), [1, 1, 1]); await chainOk(w);
});

test('SECURITY_ADMIN orders an urgent preventive suspension alone; making it definitive needs a different identity; a publisher cannot suspend; a suspension is audited', async () => {
  const { w, id } = await fx(); const sheet = (await w.call('GET', `/api/candidates/${id}`, { user: w.ada })).data;
  const body = (over = {}) => ({ candidate_id: id, scope: 'path', reason: 'new public report of a false positive that blocks users', request_id: rid(), expect_version: sheet.version, confirm_collateral: 0, ...over });
  assert.equal((await w.call('POST', '/api/policies/suspensions', { user: w.pat, body: body() })).status, 403, 'a publisher withdraws through the normal path, not the preventive one');
  assert.equal((await w.call('POST', '/api/policies/suspensions', { user: w.sam, body: body({ reason: 'short' }) })).status, 400, 'a justification is required');
  const s = await w.call('POST', '/api/policies/suspensions', { user: w.sam, body: body() }); assert.equal(s.status, 200, JSON.stringify(s.data));
  const pol = q(w, 'SELECT id, kind, status FROM policies')[0]; assert.equal(pol.kind, 'SUSPENSION'); assert.equal(pol.status, 'ACTIVE');
  assert.ok(actions(w, 'policy.withdrawal_requested').some((r) => r.actor === 'sam' && JSON.parse(r.detail).kind === 'SUSPENSION'), 'the order is in the audit as a suspension by sam');
  const rq = await ask(w, w.sam, { op: 'policy.revoke_confirm', params: { policy_id: pol.id } }); assert.equal(rq.status, 200, JSON.stringify(rq.data)); const a = rq.data.approval;
  assert.equal((await next(w, w.sam, a.id, 'approve', a.version)).data.code, 'same_identity', 'the person who suspended cannot also approve the revocation');
  assert.equal((await next(w, w.pat, a.id, 'approve', a.version)).status, 403);
  const ok = await next(w, w.ada, a.id, 'approve', a.version); assert.equal(ok.status, 200, JSON.stringify(ok.data)); assert.equal(q(w, 'SELECT kind FROM policies WHERE id = ?', pol.id)[0].kind, 'REVOCATION'); await chainOk(w);
});

test('listing and reading approvals follow the matrix, an unknown id is the same answer for everyone, and a refusal is audited', async () => {
  const { w } = await fx();
  assert.equal((await w.call('GET', '/api/approvals', { user: w.vera })).status, 403); assert.equal((await w.call('GET', '/api/approvals', { user: w.sam })).status, 200);
  assert.equal((await w.call('GET', '/api/approvals/00000000-0000-4000-8000-0000000000ff', { user: w.ada })).status, 404);
  assert.equal((await w.call('POST', '/api/approvals', { user: w.vera, body: { op: 'role.grant' } })).status, 403); assert.ok(actions(w, 'authz.denied').length >= 1);
  assert.equal((await w.call('POST', '/api/approvals/00000000-0000-4000-8000-0000000000ff/approve', { user: w.sam, body: { request_id: rid(), expect_version: 1, reason: 'checked twice' } })).status, 404);
  assert.equal((await w.call('POST', '/api/approvals', { user: w.ada, body: { op: 'restore.real' }, csrf: false })).status, 403, 'CSRF is enforced');
});

test('the single-administrator mode is explicit: a privileged grant needs the typed login and a sign-in of the last ten minutes, and is recorded as such', async () => {
  const w = await world(); const ada = await w.login('ada', { admin: true }, { id: 9001 }); w.account('newbie', 9007); await w.call('GET', '/api/me', { user: ada });
  const l = (await w.call('GET', '/api/members/lookup?login=newbie', { user: ada })).data.account, post = (user, over = {}) => w.call('POST', '/api/members', { user, body: { user_id: l.id, role: 'SECURITY_ADMIN', reason: 'reviewed by the owner', ...over } });
  assert.equal((await post(ada)).data.code, 'confirm_required'); assert.equal((await post(ada, { confirm_login: 'someone' })).status, 400);
  w.tick(11 * 60); const late = await post(ada, { confirm_login: 'newbie' }); assert.equal(late.status, 401, 'older than ten minutes'); assert.equal(late.data.code, 'reauth_required');
  const fresh = await w.login('ada', { admin: true }, { id: 9001 }); assert.equal((await post(fresh, { confirm_login: 'newbie' })).status, 200);
  assert.equal(JSON.parse(actions(w, 'member.set')[0].detail).mode, 'SINGLE_ADMIN');
});

test('the migration plan lists, by stable id, who has access only through the GitHub permission and writes nothing', async () => {
  const { w } = await fx(); const before = q(w, 'SELECT COUNT(*) AS n FROM members')[0].n;
  const plan = await w.call('GET', '/api/members/migration-plan', { user: w.ada }); assert.equal(plan.status, 200); assert.equal(plan.data.mapping, 'GITHUB_PERMISSION');
  const logins = plan.data.items.map((i) => i.login); assert.ok(logins.includes('ada') && logins.includes('rita') && !logins.includes('sam') && !logins.includes('vera'), logins.join());
  for (const i of plan.data.items) assert.ok(['ADMIN', 'REVIEWER'].includes(i.proposed_grant), 'nothing wider than today');
  assert.equal(q(w, 'SELECT COUNT(*) AS n FROM members')[0].n, before, 'the plan is read-only'); assert.equal((await w.call('GET', '/api/members/migration-plan', { user: w.sam })).status, 403);
});
