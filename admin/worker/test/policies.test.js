// Persistent administrative policy: withdrawal of a published rule, lift (second authorization, break-glass), confirmation by evidence, snapshot and migration 0003.
import { readFileSync } from 'node:fs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { world, cand, rid, REPO, ORIGIN } from './helpers.js';
import { verifyChain, canonical, sha256hex } from '../src/core.js';
import { auditRows } from '../src/store.js';
import { normalizePath, scopeKey, policyMatches, BREAKGLASS_DELAY_S, BREAKGLASS_WINDOW_S, DUAL_WINDOW_S, REVIEW_WITHIN_S } from '../src/policies.js';

const T1 = 'rules-20261021-1', T2 = 'rules-20261021-2', T3 = 'rules-20261021-3';
const AT1 = '2026-10-21T03:00:00Z', AT2 = '2026-10-21T09:00:00Z', AT3 = '2026-10-22T09:00:00Z';
const callback = async (w, tag, hashes, claims = {}) => w.call('POST', '/api/pipeline/released', { bearer: await w.pipelineToken('publish.yml', { run_id: '5551', run_attempt: '1', ...claims }), body: { tag, hashes, run_url: `${ORIGIN}/runs/5551` } });
const q = (w, sql, ...a) => w.db.raw.prepare(sql).all(...a).map((r) => ({ ...r }));
const audit = async (w, action) => (await auditRows(w.db, 2000)).filter((e) => !action || e.action === action).map((e) => ({ seq: e.seq, actor: e.actor, role: e.role, action: e.action, target: e.target, ...JSON.parse(e.detail) }));
const chainOk = async (w) => assert.equal((await verifyChain(await auditRows(w.db, 5000))).ok, true, 'the audit chain verifies');

/** Three published rules (a, b, c) in release 1, and four people: ada and bob (ADMIN), rita (REVIEWER), vera (VIEWER). */
async function fx(items = ['a', 'b', 'c']) {
  const w = await world(); const r = await w.submit(items.map((c) => cand(c))); assert.equal(r.status, 200);
  const ids = r.data.results.map((x) => x.id), cs = items.map((c) => cand(c));
  w.ada = await w.login('ada', { admin: true }, { id: 9001 }); w.bob = await w.login('bob', { admin: true }, { id: 9002 }); w.rita = await w.login('rita', { push: true });
  w.account('vera', 7); assert.equal((await w.grant(w.ada, 'vera', 'VIEWER')).status, 200); w.vera = await w.login('vera', { pull: true }, { id: 7 });
  await w.release(T1, cs, { publishedAt: AT1 }); assert.equal((await callback(w, T1, cs.map((c) => c.sha256))).status, 200);
  return { w, ids, cs };
}
const sheet = async (w, id, user = w.ada) => (await w.call('GET', `/api/candidates/${id}`, { user })).data;
const wd = async (w, user, id, over = {}) => w.call('POST', '/api/policies/withdrawals', { user, body: { candidate_id: id, scope: 'path', criticality: 'CRITICAL', reason: 'reported as unsafe by the owner', request_id: rid(), expect_version: (await sheet(w, id)).version, confirm_collateral: 0, ...over } });
const lift = async (w, user, pid, over = {}) => w.call('POST', `/api/policies/${pid}/lifts`, { user, body: { kind: 'DUAL', reason: 'the report was a false alarm', request_id: rid(), expect_version: q(w, 'SELECT version FROM policies WHERE id = ?', pid)[0].version, ...over } });
const step = async (w, user, liftId, op, over = {}) => w.call('POST', `/api/policies/lifts/${liftId}/${op}`, { user, body: { reason: 'checked with the second administrator', request_id: rid(), expect_version: q(w, 'SELECT version FROM policy_lifts WHERE id = ?', liftId)[0].version, ...over } });
const relogin = async (w) => { w.ada = await w.login('ada', { admin: true }, { id: 9001 }); w.bob = await w.login('bob', { admin: true }, { id: 9002 }); };
const policyOf = (w, id) => q(w, 'SELECT * FROM policies WHERE candidate_id = ? ORDER BY created_at DESC', id)[0];
const state = (w, id) => q(w, 'SELECT state, version FROM candidates WHERE id = ?', id)[0];
const BG = { kind: 'BREAKGLASS', reason: 'both other administrators are unreachable and the block is hurting users', no_second_admin: true };

// ---- identity -------------------------------------------------------------------------------------------------------------
test('identity is source + normalized path: separators, dots and case never make a second identity, and a traversal has none', () => {
  assert.equal(normalizePath('rules\\x//./A.yar'), 'rules/x/A.yar'); assert.equal(normalizePath('../x.yar'), null); assert.equal(normalizePath('rules/../x.yar'), null); assert.equal(normalizePath(''), null); assert.equal(normalizePath(7), null);
  assert.equal(scopeKey('path', { source: 'Nextron', path: 'Rules/./X/A.yar' }), scopeKey('path', { source: 'nextron', path: 'rules/x/a.yar' }));
  assert.equal(scopeKey('path', { source: 'nextron', path: '../a.yar' }), null); assert.equal(scopeKey('content', { sha256: 'f'.repeat(64) }), `content:${'f'.repeat(64)}`);
  const p = { scope: 'path', scope_key: scopeKey('path', { source: 'nextron', path: 'rules/x/a.yar' }), sha256: 'a'.repeat(64) };
  assert.equal(policyMatches(p, { source: 'nextron', path: 'rules//x/./a.yar', sha256: 'b'.repeat(64) }), true, 'a different SHA-256 at the same identity is covered by a path policy');
  assert.equal(policyMatches(p, { source: 'other', path: 'rules/x/a.yar', sha256: 'a'.repeat(64) }), false);
  assert.equal(policyMatches({ scope: 'content', sha256: 'a'.repeat(64) }, { source: 'z', path: 'q', sha256: 'a'.repeat(64) }), true); assert.equal(policyMatches({ scope: 'content', sha256: 'a'.repeat(64) }, { source: 'nextron', path: 'rules/x/a.yar', sha256: 'b'.repeat(64) }), false);
});

// ---- request a withdrawal ---------------------------------------------------------------------------------------------------
test('an ADMIN requests a withdrawal: the policy, its history and the audit are written together, the release is untouched and the sheet says "pending"', async () => {
  const { w, ids } = await fx(); const before = await state(w, ids[0]);
  const r = await wd(w, w.ada, ids[0], { scope: 'path', criticality: 'CRITICAL', reason: 'reported as unsafe by the owner' }); assert.equal(r.status, 200, JSON.stringify(r.data));
  const p = policyOf(w, ids[0]);
  assert.deepEqual([p.status, p.withdrawal, p.version, p.scope, p.criticality, p.author, p.author_role, p.source, p.path, p.baseline_tag, p.baseline_published_at], ['ACTIVE', 'REQUESTED', 1, 'path', 'CRITICAL', 'ada', 'ADMIN', 'nextron', 'rules/x/a.yar', T1, AT1]);
  assert.equal(p.scope_key, 'path:nextron:rules/x/a.yar'); assert.equal(p.sha256, (await sheet(w, ids[0])).sha256); assert.match(p.baseline_manifest_sha256, /^[0-9a-f]{64}$/); assert.match(p.baseline_rules_root, /^[0-9a-f]{64}$/);
  const after = await state(w, ids[0]); assert.deepEqual([after.state, after.version], ['RELEASED', before.version + 1], 'still RELEASED: a release is only withdrawn by a later release; the version moved to serialize concurrent writers');
  const [e] = await audit(w, 'policy.withdrawal_requested'); assert.equal(e.actor, 'ada'); assert.equal(e.role, 'ADMIN'); assert.equal(e.policy_id, p.id); assert.equal(e.reason, 'reported as unsafe by the owner'); assert.equal(e.baseline.tag, T1); assert.equal(e.candidate_version_after, before.version + 1);
  assert.deepEqual(q(w, 'SELECT event, role, release_tag FROM policy_events WHERE policy_id = ?', p.id), [{ event: 'WITHDRAWAL_REQUESTED', role: 'ADMIN', release_tag: T1 }]);
  const s = await sheet(w, ids[0]); assert.equal(s.publication.publication, 'withdrawal_pending'); assert.equal(s.publication.policy.id, p.id); assert.equal(s.state, 'RELEASED');
  const pubs = (await w.call('GET', '/api/published?pageSize=50', { user: w.rita })).data.items.find((x) => x.path === 'rules/x/a.yar'); assert.equal(pubs.policy.publication, 'withdrawal_pending'); assert.equal(pubs.status, 'published', 'still in the current release');
  assert.equal((await w.call('GET', '/api/published?pageSize=50', { user: w.rita })).data.items.find((x) => x.path === 'rules/x/b.yar').policy, undefined);
  assert.equal(q(w, 'SELECT COUNT(*) AS n FROM candidates WHERE release_tag = ?', T1)[0].n, 3, 'no release record was modified'); await chainOk(w);
});
test('only an ADMIN may request a withdrawal, whatever the UI shows; nothing is written for anyone else', async () => {
  const { w, ids } = await fx(); const base = (await auditRows(w.db, 5000)).length;
  const body = async () => ({ candidate_id: ids[0], scope: 'path', criticality: 'CRITICAL', reason: 'let me do it', request_id: rid(), expect_version: (await sheet(w, ids[0])).version, confirm_collateral: 0 });
  const b1 = await body(), n0 = (await auditRows(w.db, 5000)).length;
  for (const [who, user] of [['reviewer', w.rita], ['viewer', w.vera]]) assert.equal((await w.call('POST', '/api/policies/withdrawals', { user, body: b1 })).status, 403, who);
  assert.equal((await w.call('POST', '/api/policies/withdrawals', { body: b1 })).status, 401, 'anonymous');
  const stranger = await w.login('stranger', { pull: true }); assert.equal((await w.call('POST', '/api/policies/withdrawals', { user: stranger, body: b1 })).status, 403, 'no role');
  assert.equal((await w.call('POST', '/api/policies/withdrawals', { bearer: await w.pipelineToken('publish.yml'), body: b1 })).status, 401, 'a workflow token is not a session');
  assert.equal((await w.call('POST', '/api/policies/withdrawals', { user: w.ada, body: b1, csrf: false })).status, 403, 'no CSRF token'); assert.equal((await w.call('POST', '/api/policies/withdrawals', { user: w.ada, body: b1, origin: false })).status, 403, 'no same-origin');
  w.perms['tok-ada'] = { push: true };   // GitHub permission downgraded after login: the role is re-read on every unsafe call
  assert.equal((await w.call('POST', '/api/policies/withdrawals', { user: w.ada, body: b1 })).status, 403, 'a downgraded administrator'); w.perms['tok-ada'] = { admin: true };
  assert.equal(q(w, 'SELECT COUNT(*) AS n FROM policies')[0].n, 0); assert.equal((await auditRows(w.db, 5000)).length, n0, 'not even an audit entry'); assert.ok(base <= n0);
  for (const user of [w.rita, w.vera]) for (const [m, p] of [['POST', '/api/policies/reconcile'], ['GET', `/api/policies/preview?candidate_id=${ids[0]}&scope=path`]]) assert.equal((await w.call(m, p, { user, ...(m === 'POST' ? { body: {} } : {}) })).status, 403, p);
  assert.equal((await w.call('GET', '/api/policies', { user: w.vera })).status, 200, 'reading is for every role'); assert.equal((await w.call('GET', '/api/policies')).status, 401);
});
test('a request that does not describe the truth is refused before anything is written', async () => {
  const { w, ids } = await fx(); const n = (await auditRows(w.db, 5000)).length; const refuse = async (over, status, code) => { const r = await wd(w, w.ada, ids[0], over); assert.equal(r.status, status, JSON.stringify([over, r.data])); if (code) assert.equal(r.data.code, code); };
  await refuse({ reason: 'no' }, 400); await refuse({ reason: '   ​​  ' }, 400); await refuse({ scope: 'file' }, 400); await refuse({ scope: undefined }, 400); await refuse({ criticality: undefined }, 400); await refuse({ request_id: 'short' }, 400);
  await refuse({ expect_version: 'x' }, 400); await refuse({ expect_version: 1 }, 409); await refuse({ confirm_collateral: 3 }, 409, 'collateral_mismatch'); await refuse({ candidate_id: '00000000-0000-4000-8000-0000000fffff' }, 404);
  const fresh = (await w.submit([cand('z')])).data.results[0].id; await refuse({ candidate_id: fresh }, 409, 'not_released');
  assert.equal(q(w, 'SELECT COUNT(*) AS n FROM policies')[0].n, 0); assert.equal((await auditRows(w.db, 5000)).length >= n, true);
  await w.release(T2, [cand('b'), cand('c')], { publishedAt: AT2 }); await refuse({ candidate_id: ids[0] }, 409, 'not_in_current_release');   // the latest public release no longer lists a: there is nothing to withdraw
  await w.release(T3, [cand('a'), cand('b'), cand('c')], { apiStatus: 503, publishedAt: AT3 }); await refuse({ candidate_id: ids[0] }, 502);   // GitHub down: no state change without evidence
  await w.release(T3, [cand('a'), cand('b'), cand('c')], { tamperRoot: true, publishedAt: AT3 }); await refuse({ candidate_id: ids[0] }, 422);
  assert.equal(q(w, 'SELECT COUNT(*) AS n FROM policies')[0].n, 0); await chainOk(w);
});
test('the same request id is a replay, never a second policy; reusing it for something else is refused', async () => {
  const { w, ids } = await fx(); const id = rid(); const v = (await sheet(w, ids[0])).version;
  const body = { candidate_id: ids[0], scope: 'path', criticality: 'STANDARD', reason: 'reported as unsafe by the owner', request_id: id, expect_version: v, confirm_collateral: 0 };
  const a = await w.call('POST', '/api/policies/withdrawals', { user: w.ada, body }), b = await w.call('POST', '/api/policies/withdrawals', { user: w.ada, body });
  assert.deepEqual([a.status, b.status, b.data.replay, b.data.policy.id], [200, 200, true, a.data.policy.id]);
  assert.equal((await w.call('POST', '/api/policies/withdrawals', { user: w.ada, body: { ...body, scope: 'content' } })).status, 409);
  assert.equal(q(w, 'SELECT COUNT(*) AS n FROM policies')[0].n, 1); assert.equal((await audit(w, 'policy.withdrawal_requested')).length, 1);
  const again = await wd(w, w.ada, ids[0], { scope: 'path' }); assert.equal(again.status, 409); assert.equal(again.data.code, 'already_active');
  assert.equal((await wd(w, w.ada, ids[0], { scope: 'content' })).status, 200, 'a content policy is another scope_key and may coexist'); assert.equal(q(w, "SELECT COUNT(*) AS n FROM policies WHERE status = 'ACTIVE'")[0].n, 2);
});
test('two administrators asking at once: exactly one policy, one audit entry, one winner', async () => {
  const { w, ids } = await fx(); const v = (await sheet(w, ids[0])).version;
  const mk = (user) => w.call('POST', '/api/policies/withdrawals', { user, body: { candidate_id: ids[0], scope: 'path', criticality: 'CRITICAL', reason: 'reported as unsafe by the owner', request_id: rid(), expect_version: v, confirm_collateral: 0 } });
  const rs = await Promise.all([mk(w.ada), mk(w.bob)]); assert.deepEqual(rs.map((r) => r.status).sort(), [200, 409]);
  assert.equal(q(w, 'SELECT COUNT(*) AS n FROM policies')[0].n, 1); assert.equal((await audit(w, 'policy.withdrawal_requested')).length, 1); assert.equal(q(w, 'SELECT COUNT(*) AS n FROM policy_events')[0].n, 1); await chainOk(w);
});
test('the collateral of a withdrawal is previewed and must be confirmed: dependents of the rule leave the next release too', async () => {
  const { w, ids } = await fx(); await w.db.prepare('UPDATE candidates SET depends_on = ? WHERE id = ?').bind(JSON.stringify(['rules/x/a.yar']), ids[1]).run(); await w.db.prepare('UPDATE candidates SET depends_on = ? WHERE id = ?').bind(JSON.stringify(['rules/x/b.yar']), ids[2]).run();
  const pre = await w.call('GET', `/api/policies/preview?candidate_id=${ids[0]}&scope=path`, { user: w.ada }); assert.equal(pre.status, 200); assert.deepEqual(pre.data.collateral.map((c) => c.path), ['rules/x/b.yar', 'rules/x/c.yar'], 'transitive'); assert.equal(pre.data.baseline.tag, T1);
  assert.equal((await wd(w, w.ada, ids[0], { confirm_collateral: 0 })).status, 409); const ok = await wd(w, w.ada, ids[0], { confirm_collateral: 2 }); assert.equal(ok.status, 200); assert.equal(ok.data.collateral.length, 2);
  assert.equal((await audit(w, 'policy.withdrawal_requested'))[0].collateral.length, 2);
});

// ---- confirmation by evidence -----------------------------------------------------------------------------------------------
test('a withdrawal is CONFIRMED only by a later public release whose verified manifest lacks the rule; the audit says from what evidence', async () => {
  const { w, ids, cs } = await fx(); const p = (await wd(w, w.ada, ids[0])).data.policy;
  const rel2 = await w.release(T2, [cs[1], cs[2]], { publishedAt: AT2 }); const r = await callback(w, T2, [cs[1].sha256, cs[2].sha256]); assert.equal(r.status, 200); assert.deepEqual(r.data.policies.confirmed, [p.id]);
  const row = policyOf(w, ids[0]); assert.deepEqual([row.withdrawal, row.status, row.version, row.confirmed_tag, row.confirmed_published_at, row.confirmed_manifest_sha256], ['CONFIRMED', 'ACTIVE', 2, T2, AT2, rel2.manifestSha]);
  const [e] = await audit(w, 'policy.reconciled'); assert.deepEqual([e.tag, e.trigger, e.receipt, e.actor, e.role, e.confirmed[0].policy_id, e.confirmed[0].version_to, e.token_run_id], [T2, 'publish', 'first', 'pipeline:publish.yml', 'PIPELINE', p.id, 2, '5551']);
  assert.equal(e.manifest_sha256, rel2.manifestSha); assert.equal((await sheet(w, ids[0])).publication.publication, 'withdrawn'); assert.equal((await sheet(w, ids[0])).state, 'RELEASED', 'RELEASED keeps its meaning: a verified release listed it at the time');
  assert.equal(q(w, 'SELECT release_tag FROM candidates WHERE id = ?', ids[0])[0].release_tag, T1, 'the historical release record is not rewritten');
  const n = (await audit(w)).length; const again = await callback(w, T2, [cs[1].sha256]); assert.equal(again.status, 200); assert.equal((await audit(w)).filter((x) => x.action === 'policy.reconciled').length, 1, 'a retried callback confirms nothing twice and records nothing new'); assert.equal(policyOf(w, ids[0]).version, 2); assert.ok(n > 0);
  assert.equal(q(w, 'SELECT COUNT(*) AS n FROM policy_events WHERE event = ?', 'WITHDRAWAL_CONFIRMED')[0].n, 1); await chainOk(w);
});
test('a release that still lists the rule, is not newer than the request, or cannot be verified confirms nothing', async () => {
  const { w, ids, cs } = await fx(); const p = (await wd(w, w.ada, ids[0])).data.policy;
  await w.release(T2, cs, { publishedAt: AT2 }); const still = await callback(w, T2, cs.map((c) => c.sha256)); assert.equal(still.status, 200);
  assert.deepEqual(still.data.policies.still_listed.map((s) => s.policy_id), [p.id]); assert.equal(policyOf(w, ids[0]).withdrawal, 'REQUESTED'); assert.deepEqual((await audit(w, 'policy.reconciled'))[0].conflicts, [{ policy_id: p.id, reason: 'listed_after_request' }]);
  await w.release(T3, [cs[1], cs[2]], { publishedAt: AT1 }); const old = await callback(w, T3, [cs[1].sha256]); assert.equal(old.status, 200); assert.equal(policyOf(w, ids[0]).withdrawal, 'REQUESTED', 'absence in a release that is not newer than the baseline proves nothing');
  for (const opt of [{ tamperRoot: true }, { draft: true }, { hidden: true }, { wrongDigest: true }, { noManifestAsset: true }]) {
    await w.release(T3, [cs[1], cs[2]], { publishedAt: AT3, ...opt }); const bad = await callback(w, T3, [cs[1].sha256]); assert.notEqual(bad.status, 200, JSON.stringify(opt)); assert.equal(policyOf(w, ids[0]).withdrawal, 'REQUESTED', JSON.stringify(opt));
  }
  const before = q(w, 'SELECT COUNT(*) AS n FROM audit')[0].n; await w.release(T3, [cs[1], cs[2]], { publishedAt: AT3 }); assert.equal((await callback(w, T3, [cs[1].sha256])).data.policies.confirmed.length, 1); assert.ok(q(w, 'SELECT COUNT(*) AS n FROM audit')[0].n > before);
  await chainOk(w);
});
test('with no policy in force the callback is exactly what it was: same answer, no extra audit entry', async () => {
  const { w, cs } = await fx(); await w.release(T2, [cs[1]], { publishedAt: AT2 }); const n = (await audit(w, 'policy.reconciled')).length;
  const r = await callback(w, T2, [cs[1].sha256]); assert.equal(r.status, 200); assert.equal(r.data.policies, undefined); assert.equal((await audit(w, 'policy.reconciled')).length, n);
});
test('a content-scope withdrawal is confirmed by the absence of that SHA-256, whatever the path; a path-scope one by the absence of the path, whatever the SHA-256', async () => {
  const { w, ids, cs } = await fx(); assert.equal((await wd(w, w.ada, ids[0], { scope: 'content' })).status, 200); assert.equal((await wd(w, w.ada, ids[1], { scope: 'path' })).status, 200);
  const moved = { ...cs[0], path: 'rules/x/a-renamed.yar' }, changed = { ...cs[1], sha256: 'e'.repeat(64) };   // a's bytes still published under another name; b's path published with other bytes
  await w.release(T2, [moved, changed, cs[2]], { publishedAt: AT2 }); const r = await callback(w, T2, [cs[2].sha256]); assert.equal(r.status, 200);
  assert.equal(policyOf(w, ids[0]).withdrawal, 'REQUESTED', 'same bytes under a new name are still published'); assert.equal(policyOf(w, ids[1]).withdrawal, 'REQUESTED', 'the path is still published, with other bytes');
  await w.release(T3, [cs[2]], { publishedAt: AT3 }); assert.equal((await callback(w, T3, [cs[2].sha256])).data.policies.confirmed.length, 2);
});
test('a lift racing the confirmation callback: either one wins, never both, and the chain stays linear', async () => {
  const { w, ids, cs } = await fx(); const p = (await wd(w, w.ada, ids[0], { criticality: 'STANDARD' })).data.policy; await w.release(T2, [cs[1], cs[2]], { publishedAt: AT2 });
  const [cb, lf] = await Promise.all([callback(w, T2, [cs[1].sha256]), lift(w, w.ada, p.id, { kind: 'DIRECT' })]); assert.equal(cb.status, 200);
  const row = policyOf(w, ids[0]), confirmed = q(w, "SELECT COUNT(*) AS n FROM policy_events WHERE event = 'WITHDRAWAL_CONFIRMED'")[0].n;
  if (row.status === 'LIFTED') { assert.equal(lf.status, 200); assert.equal(row.withdrawal, 'CANCELLED'); assert.equal(confirmed, 0, 'a lifted policy was never confirmed'); }
  else { assert.equal(lf.status, 409); assert.equal(row.withdrawal, 'CONFIRMED'); assert.equal(confirmed, 1); }
  await chainOk(w);
});
test('a withdrawal request racing a publish callback never becomes CONFIRMED by a release that lists the rule', async () => {
  const { w, ids, cs } = await fx(); await w.release(T2, cs, { publishedAt: AT2 });
  const [r, cb] = await Promise.all([wd(w, w.ada, ids[0]), callback(w, T2, cs.map((c) => c.sha256))]); assert.equal(cb.status, 200); assert.ok([200, 409].includes(r.status), String(r.status));
  assert.ok(q(w, "SELECT COUNT(*) AS n FROM policies WHERE withdrawal = 'CONFIRMED'")[0].n === 0); await chainOk(w);
});
test('the ADMIN reconcile redoes the confirmation when the callback was lost, from evidence the Worker fetches itself', async () => {
  const { w, ids, cs } = await fx(); await wd(w, w.ada, ids[0]); await w.release(T2, [cs[1], cs[2]], { publishedAt: AT2 });
  const r = await w.call('POST', '/api/policies/reconcile', { user: w.ada, body: {} }); assert.equal(r.status, 200); assert.equal(r.data.tag, T2); assert.equal(r.data.confirmed.length, 1);
  const [e] = await audit(w, 'policy.reconciled'); assert.deepEqual([e.trigger, e.role, e.actor], ['reconcile', 'ADMIN', 'ada']);
  await w.release(T3, [cs[1], cs[2]], { apiStatus: 503, publishedAt: AT3 }); const down = await w.call('POST', '/api/policies/reconcile', { user: w.ada, body: {} }); assert.equal(down.status, 502);
});

// ---- lifting --------------------------------------------------------------------------------------------------------------
test('a STANDARD block is lifted by one ADMIN; a CRITICAL one never is (409), and the DB agrees', async () => {
  const { w, ids } = await fx(); const std = (await wd(w, w.ada, ids[0], { criticality: 'STANDARD' })).data.policy, crit = (await wd(w, w.ada, ids[1], { criticality: 'CRITICAL' })).data.policy;
  const no = await lift(w, w.ada, crit.id, { kind: 'DIRECT' }); assert.equal(no.status, 409); assert.equal(no.data.code, 'critical_needs_second_authorization'); assert.equal(q(w, 'SELECT status FROM policies WHERE id = ?', crit.id)[0].status, 'ACTIVE');
  for (const user of [w.rita, w.vera]) assert.equal((await lift(w, user, std.id, { kind: 'DIRECT' })).status, 403);
  const before = await state(w, ids[0]); const ok = await lift(w, w.ada, std.id, { kind: 'DIRECT', reason: 'the owner re-reviewed it' }); assert.equal(ok.status, 200, JSON.stringify(ok.data));
  const row = q(w, 'SELECT * FROM policies WHERE id = ?', std.id)[0]; assert.deepEqual([row.status, row.withdrawal, row.version, row.lifted_by, row.lifted_via, row.lifted_reason], ['LIFTED', 'CANCELLED', 2, 'ada', 'DIRECT', 'the owner re-reviewed it']);
  assert.deepEqual(await state(w, ids[0]), { state: 'PENDING', version: before.version + 1 }); const d = q(w, "SELECT action, from_state, to_state, actor FROM decisions WHERE candidate_id = ? AND action = 'lift_policy'", ids[0]); assert.deepEqual(d, [{ action: 'lift_policy', from_state: 'RELEASED', to_state: 'PENDING', actor: 'ada' }]);
  assert.equal((await sheet(w, ids[0])).publication.publication, 'lifted'); assert.equal((await audit(w, 'policy.lifted'))[0].via, 'DIRECT');
  assert.throws(() => w.db.raw.prepare("UPDATE policies SET status = 'LIFTED', lifted_by = 'x', lifted_by_id = 1, lifted_reason = 'sneaky lift', lifted_at = 'now', lifted_via = 'DIRECT', lift_id = 'nope', version = version + 1 WHERE id = ?").run(crit.id), /recorded authorization|constraint/i, 'no direct SQL lift of a critical policy without an applied lift record');
  assert.throws(() => w.db.raw.prepare("UPDATE policies SET reason = 'edited', version = version + 1 WHERE id = ?").run(crit.id), /immutable/); assert.throws(() => w.db.raw.prepare('DELETE FROM policies WHERE id = ?').run(crit.id), /never deleted/);
  assert.equal((await lift(w, w.ada, std.id, { kind: 'DIRECT' })).status, 409, 'a lifted policy is final'); assert.equal((await wd(w, w.ada, ids[0])).status, 409, 'and a RELEASED-only request cannot be made for a candidate that is PENDING now'); await chainOk(w);
});
test('lifting a CRITICAL block needs a second, independent administrator, enforced by the server', async () => {
  const { w, ids } = await fx(); const p = (await wd(w, w.ada, ids[0])).data.policy; const before = await state(w, ids[0]);
  const req = await lift(w, w.ada, p.id, { kind: 'DUAL' }); assert.equal(req.status, 200); const lid = req.data.lift.id; assert.equal(req.data.lift.state, 'REQUESTED'); assert.equal(q(w, 'SELECT status FROM policies WHERE id = ?', p.id)[0].status, 'ACTIVE', 'asking lifts nothing');
  assert.equal((await lift(w, w.bob, p.id, { kind: 'DUAL' })).data.code, 'lift_already_requested');
  const self = await step(w, w.ada, lid, 'authorize'); assert.equal(self.status, 403); assert.equal(self.data.code, 'second_authorizer_must_differ');
  const sameAccount = await w.login('ada-alias', { admin: true }, { id: q(w, "SELECT requested_by_id AS id FROM policy_lifts WHERE id = ?", lid)[0].id }); assert.equal((await step(w, sameAccount, lid, 'authorize')).status, 403, 'the same GitHub account under another login is not a second person');
  for (const user of [w.rita, w.vera]) assert.equal((await step(w, user, lid, 'authorize')).status, 403); assert.equal((await w.call('POST', `/api/policies/lifts/${lid}/authorize`, { body: {} })).status, 401);
  assert.equal((await step(w, w.bob, lid, 'authorize', { reason: 'no' })).status, 400); assert.equal((await step(w, w.bob, lid, 'authorize', { expect_version: 9 })).status, 409);
  assert.throws(() => w.db.raw.prepare("UPDATE policy_lifts SET state = 'APPLIED', applied_at = ?, authorized_by = 'ada', authorized_by_id = ?, authorized_reason = 'self approved', authorized_at = ?, version = version + 1 WHERE id = ?").run('2026-10-21T10:00:00.000Z', q(w, 'SELECT requested_by_id AS id FROM policy_lifts WHERE id = ?', lid)[0].id, '2026-10-21T10:00:00.000Z', lid), /constraint/i, 'the DB itself refuses a self-authorization');
  assert.equal(q(w, 'SELECT status FROM policies WHERE id = ?', p.id)[0].status, 'ACTIVE');
  const ok = await step(w, w.bob, lid, 'authorize', { reason: 'confirmed false alarm with the vendor' }); assert.equal(ok.status, 200, JSON.stringify(ok.data));
  const row = q(w, 'SELECT * FROM policies WHERE id = ?', p.id)[0]; assert.deepEqual([row.status, row.lifted_by, row.lifted_via, row.lift_id], ['LIFTED', 'bob', 'DUAL', lid]); const l = q(w, 'SELECT * FROM policy_lifts WHERE id = ?', lid)[0];
  assert.deepEqual([l.state, l.requested_by, l.authorized_by], ['APPLIED', 'ada', 'bob']); assert.deepEqual(await state(w, ids[0]), { state: 'PENDING', version: before.version + 1 });
  const [e] = await audit(w, 'policy.lifted'); assert.deepEqual([e.via, e.requested_by, e.authorized_by, e.reason_requested, e.reason], ['DUAL', 'ada', 'bob', 'the report was a false alarm', 'confirmed false alarm with the vendor']);
  const rid1 = rid(); assert.equal((await step(w, w.bob, lid, 'authorize')).status, 409, 'already applied'); assert.ok(rid1); await chainOk(w);
});
test('the authorization is idempotent for a replayed request id, and a pending request can be cancelled by its author or vetoed by any other ADMIN', async () => {
  const { w, ids } = await fx(); const p = (await wd(w, w.ada, ids[0])).data.policy; const lid = (await lift(w, w.ada, p.id)).data.lift.id; const rq = rid();
  const a = await step(w, w.bob, lid, 'authorize', { request_id: rq }), b = await step(w, w.bob, lid, 'authorize', { request_id: rq, expect_version: 2 }); assert.deepEqual([a.status, b.status, b.data.replay], [200, 200, true]); assert.equal((await audit(w, 'policy.lifted')).length, 1);
  const p2 = (await wd(w, w.ada, ids[1])).data.policy; const l2 = (await lift(w, w.ada, p2.id)).data.lift.id;
  assert.equal((await step(w, w.rita, l2, 'cancel')).status, 403); const veto = await step(w, w.bob, l2, 'cancel', { reason: 'not now, the report stands' }); assert.equal(veto.status, 200);
  assert.deepEqual(q(w, 'SELECT state, closed_by FROM policy_lifts WHERE id = ?', l2)[0], { state: 'CANCELLED', closed_by: 'bob' }); assert.equal(q(w, 'SELECT status FROM policies WHERE id = ?', p2.id)[0].status, 'ACTIVE');
  assert.equal((await step(w, w.bob, l2, 'authorize')).status, 409, 'a cancelled request is final'); assert.equal((await lift(w, w.ada, p2.id)).status, 200, 'but a new one may be made'); await chainOk(w);
});
test('a second authorization that arrives late is refused: the request expires by itself and the expiry is recorded', async () => {
  const { w, ids } = await fx(); const p = (await wd(w, w.ada, ids[0])).data.policy; const lid = (await lift(w, w.ada, p.id)).data.lift.id;
  w.tick(DUAL_WINDOW_S + 5); await relogin(w); const late = await step(w, w.bob, lid, 'authorize'); assert.equal(late.status, 409); assert.equal(late.data.code, 'expired');
  assert.deepEqual(q(w, 'SELECT state, closed_by FROM policy_lifts WHERE id = ?', lid)[0], { state: 'EXPIRED', closed_by: 'system' }); assert.equal(q(w, 'SELECT status FROM policies WHERE id = ?', p.id)[0].status, 'ACTIVE');
  assert.equal((await audit(w, 'policy.lift_expired')).length, 1); assert.deepEqual(q(w, "SELECT event FROM policy_events WHERE event = 'LIFT_EXPIRED'").length, 1);
  assert.throws(() => w.db.raw.prepare("UPDATE policy_lifts SET state = 'APPLIED' WHERE id = ?").run(lid), /final|constraint/i); await chainOk(w);
});

// ---- break-glass ----------------------------------------------------------------------------------------------------------
test('break-glass is a state machine, not a flag: mandatory reason and acknowledgement, a delay, a veto, a closing time, loud audit and a review by ANOTHER administrator', async () => {
  const { w, ids } = await fx(); const p = (await wd(w, w.ada, ids[0])).data.policy; const before = await state(w, ids[0]);
  assert.equal((await lift(w, w.ada, p.id, { ...BG, no_second_admin: false })).status, 400); assert.equal((await lift(w, w.ada, p.id, { ...BG, reason: 'urgent' })).status, 400);
  for (const user of [w.rita, w.vera]) assert.equal((await lift(w, user, p.id, BG)).status, 403);
  const std = (await wd(w, w.ada, ids[1], { criticality: 'STANDARD' })).data.policy; assert.equal((await lift(w, w.ada, std.id, BG)).data.code, 'not_critical');
  const t0 = w.now(); const req = await lift(w, w.ada, p.id, BG); assert.equal(req.status, 200); const l = req.data.lift, lid = l.id;
  assert.equal(Date.parse(l.not_before) - t0 * 1000 >= BREAKGLASS_DELAY_S * 1000 - 1000, true); assert.equal(Date.parse(l.expires_at) - Date.parse(l.not_before), BREAKGLASS_WINDOW_S * 1000);
  const [loud] = await audit(w, 'breakglass.requested'); assert.match(loud.warning, /EMERGENCY/); assert.equal(loud.role, 'ADMIN');
  const early = await step(w, w.ada, lid, 'execute'); assert.equal(early.status, 409); assert.equal(early.data.code, 'delay_not_elapsed'); assert.equal(q(w, 'SELECT status FROM policies WHERE id = ?', p.id)[0].status, 'ACTIVE');
  w.tick(BREAKGLASS_DELAY_S + 5); await relogin(w);
  const other = await step(w, w.bob, lid, 'execute'); assert.equal(other.status, 403); assert.equal(other.data.code, 'not_requester');
  assert.throws(() => w.db.raw.prepare("UPDATE policy_lifts SET state = 'APPLIED', applied_at = ?, review_due_at = ?, version = version + 1 WHERE id = ?").run('2026-10-21T00:00:00.000Z', '2026-10-28T00:00:00.000Z', lid), /constraint/i, 'the DB refuses an application before the delay');
  const done = await step(w, w.ada, lid, 'execute'); assert.equal(done.status, 200, JSON.stringify(done.data)); assert.equal(done.data.via, 'BREAKGLASS');
  const row = q(w, 'SELECT * FROM policies WHERE id = ?', p.id)[0]; assert.deepEqual([row.status, row.lifted_via, row.lifted_by], ['LIFTED', 'BREAKGLASS', 'ada']); assert.deepEqual(await state(w, ids[0]), { state: 'PENDING', version: before.version + 1 }, 'the candidate still has to pass every technical gate again');
  const [ex] = await audit(w, 'breakglass.executed'); assert.equal(ex.second_authorization, false); assert.match(ex.warning, /another administrator must review/); assert.equal(Date.parse(ex.review_due_at) - Date.parse(q(w, 'SELECT applied_at FROM policy_lifts WHERE id = ?', lid)[0].applied_at), REVIEW_WITHIN_S * 1000);
  assert.equal((await step(w, w.ada, lid, 'review', { outcome: 'APPROPRIATE' })).data.code, 'reviewer_must_differ'); assert.equal((await step(w, w.rita, lid, 'review', { outcome: 'APPROPRIATE' })).status, 403);
  assert.equal((await step(w, w.bob, lid, 'review', { outcome: 'maybe' })).status, 400); assert.equal((await step(w, w.bob, lid, 'review', { outcome: 'INAPPROPRIATE', reason: 'no' })).status, 400);
  const rv = await step(w, w.bob, lid, 'review', { outcome: 'APPROPRIATE', reason: 'the vendor confirmed it was a false alarm' }); assert.equal(rv.status, 200);
  assert.deepEqual(q(w, 'SELECT reviewed_by, review_outcome FROM policy_lifts WHERE id = ?', lid)[0], { reviewed_by: 'bob', review_outcome: 'APPROPRIATE' }); assert.equal((await step(w, w.bob, lid, 'review', { outcome: 'APPROPRIATE' })).status, 409, 'reviewed once');
  assert.equal((await audit(w, 'breakglass.reviewed')).length, 1); await chainOk(w);
});
test('an emergency request can be vetoed during the delay and expires by itself if it is not applied in its window', async () => {
  const { w, ids } = await fx(); const p = (await wd(w, w.ada, ids[0])).data.policy; const lid = (await lift(w, w.ada, p.id, BG)).data.lift.id;
  const veto = await step(w, w.bob, lid, 'cancel', { reason: 'a second administrator is available: use the dual path' }); assert.equal(veto.status, 200); assert.equal((await audit(w, 'breakglass.cancelled'))[0].veto, true);
  const l2 = (await lift(w, w.ada, p.id, BG)).data.lift.id; w.tick(BREAKGLASS_DELAY_S + BREAKGLASS_WINDOW_S + 5); await relogin(w);
  const late = await step(w, w.ada, l2, 'execute'); assert.equal(late.status, 409); assert.equal(late.data.code, 'expired'); assert.equal(q(w, 'SELECT state FROM policy_lifts WHERE id = ?', l2)[0].state, 'EXPIRED'); assert.equal((await audit(w, 'breakglass.expired')).length, 1);
  assert.equal(q(w, 'SELECT status FROM policies WHERE id = ?', p.id)[0].status, 'ACTIVE'); assert.throws(() => w.db.raw.prepare("UPDATE policy_lifts SET state = 'APPLIED', applied_at = ?, review_due_at = ?, version = version + 1 WHERE id = ?").run(new Date(w.now() * 1000).toISOString(), '2099-01-01T00:00:00.000Z', l2), /final|constraint/i); await chainOk(w);
});
test('an emergency lift that nobody reviewed in time blocks the next emergency lift, in the service and in the DB', async () => {
  const { w, ids } = await fx(); const p1 = (await wd(w, w.ada, ids[0])).data.policy, p2 = (await wd(w, w.ada, ids[1])).data.policy;
  const l1 = (await lift(w, w.ada, p1.id, BG)).data.lift.id; w.tick(BREAKGLASS_DELAY_S + 5); await relogin(w); assert.equal((await step(w, w.ada, l1, 'execute')).status, 200);
  assert.equal((await lift(w, w.ada, p2.id, BG)).status, 200, 'not overdue yet: allowed'); const l2 = q(w, "SELECT id FROM policy_lifts WHERE policy_id = ?", p2.id)[0].id; assert.equal((await step(w, w.bob, l2, 'cancel')).status, 200);
  w.tick(REVIEW_WITHIN_S + 5); await relogin(w); const blocked = await lift(w, w.ada, p2.id, BG); assert.equal(blocked.status, 409); assert.equal(blocked.data.code, 'review_overdue');
  const list = (await w.call('GET', '/api/policies', { user: w.bob })).data; assert.deepEqual(list.review_overdue, [l1]);
  const snap = (await w.call('GET', '/api/pipeline/policy-snapshot', { bearer: await w.pipelineToken('daily.yml', { exp: w.now() + 300, nbf: w.now() - 10 }) })).data; assert.equal(snap.breakglass_reviews_overdue, 1);
  assert.throws(() => w.db.raw.prepare("INSERT INTO policy_lifts (id, policy_id, kind, state, requested_by, requested_by_id, requested_role, reason, requested_at, request_id, not_before, expires_at, updated_at) VALUES ('zz-direct', ?, 'BREAKGLASS', 'REQUESTED', 'ada', 1, 'ADMIN', 'a long enough emergency reason', ?, 'zz-req-zz-req-zz-req', ?, ?, ?)").run(p2.id, new Date(w.now() * 1000).toISOString(), new Date(w.now() * 1000 + 7 * 3600e3).toISOString(), new Date(w.now() * 1000 + 99 * 3600e3).toISOString(), 'x'), /overdue|constraint/i);
  assert.equal((await step(w, w.bob, l1, 'review', { outcome: 'INAPPROPRIATE', reason: 'no second administrator was actually missing' })).status, 200); assert.equal((await lift(w, w.ada, p2.id, BG)).status, 200, 'reviewed (even late) clears the obligation'); await chainOk(w);
});

// ---- no inheritance, approvals, snapshot ------------------------------------------------------------------------------------------
test('a path policy blocks a NEW version of the same file and its approval; no approval is inherited by a different SHA-256', async () => {
  const { w, ids } = await fx(); const old = await sheet(w, ids[0]); await wd(w, w.ada, ids[0], { scope: 'path' });
  const fresh = cand('a2', 'rules/x/a.yar'); const r = await w.submit([fresh]); assert.equal(r.status, 200); const nid = r.data.results[0].id; assert.notEqual(fresh.sha256, old.sha256);
  const n = await sheet(w, nid); assert.equal(n.state, 'PENDING'); assert.equal(n.publication.publication, 'withdrawal_pending', 'the sheet of the new version shows the block that covers its path');
  const dm = (await w.call('GET', '/api/pipeline/decisions', { bearer: await w.pipelineToken('daily.yml') })).data.decisions; assert.equal(dm[fresh.sha256], undefined, 'the new bytes have no decision at all'); assert.equal(dm[old.sha256].state, 'RELEASED');
  const ap = await w.call('POST', '/api/decisions', { user: w.rita, body: { action: 'approve', ids: [nid], reason: 'looks fine to me', request_id: rid(), expect: { [nid]: n.version } } }); assert.equal(ap.status, 409); assert.equal(ap.data.conflicts[0].code, 'blocked_by_policy');
  assert.equal((await sheet(w, nid)).state, 'PENDING'); const rej = await w.call('POST', '/api/decisions', { user: w.rita, body: { action: 'reject', ids: [nid], reason: 'agreed, keep it out', request_id: rid(), expect: { [nid]: n.version } } }); assert.equal(rej.status, 200, 'rejecting is still possible');
});
test('GET /api/pipeline/policy-snapshot: only daily.yml and publish.yml, the active set with a canonical SHA-256, rejected hashes even when archived, no reasons and no people', async () => {
  const { w, ids, cs } = await fx(); const get = async (bearer) => w.call('GET', '/api/pipeline/policy-snapshot', { bearer });
  assert.equal((await w.call('GET', '/api/pipeline/policy-snapshot')).status, 401); assert.equal((await w.call('GET', '/api/pipeline/policy-snapshot', { user: w.ada })).status, 401, 'a session is not a workflow token');
  assert.equal((await get(await w.pipelineToken('other.yml'))).status, 401); assert.equal((await get(await w.pipelineToken('daily.yml', { ref: 'refs/heads/feature' }))).status, 401);
  const empty = (await get(await w.pipelineToken('daily.yml'))).data; assert.deepEqual([empty.schema, empty.policies, empty.lifted, empty.rejected], [1, [], [], []]); assert.equal(empty.policy_set_sha256, await sha256hex(canonical([])));
  const p = (await wd(w, w.ada, ids[0])).data.policy, q2 = (await wd(w, w.ada, ids[1], { criticality: 'STANDARD', scope: 'content' })).data.policy; assert.equal((await lift(w, w.ada, q2.id, { kind: 'DIRECT' })).status, 200);
  const fresh = (await w.submit([cand('r')])).data.results[0].id; const rv = (await sheet(w, fresh)).version; await w.call('POST', '/api/decisions', { user: w.rita, body: { action: 'reject', ids: [fresh], reason: 'a firm rejection', request_id: rid(), expect: { [fresh]: rv } } });
  await w.db.prepare('UPDATE candidates SET archived_at = ? WHERE id = ?').bind('2026-10-21T00:00:00.000Z', fresh).run();
  const s = (await get(await w.pipelineToken('publish.yml'))).data; assert.deepEqual(s.policies.map((x) => x.id), [p.id]); assert.deepEqual(s.lifted.map((x) => x.id), [q2.id]); assert.deepEqual(s.rejected, [cand('r').sha256], 'an archived rejection is still a rejection');
  assert.equal(s.policy_set_sha256, await sha256hex(canonical(s.policies))); assert.equal(s.rejected_sha256, await sha256hex(canonical(s.rejected)));
  assert.deepEqual(Object.keys(s.policies[0]).sort(), ['created_at', 'criticality', 'id', 'path', 'scope', 'scope_key', 'sha256', 'source', 'version', 'withdrawal']); assert.ok(!JSON.stringify(s).includes('reported as unsafe')); assert.ok(!JSON.stringify(s).includes('ada'));
  assert.equal(s.audit_head.seq, q(w, 'SELECT MAX(seq) AS n FROM audit')[0].n); assert.ok(cs.length);
});
test('the policy endpoints never touch anything outside their tables and the rows they name', async () => {
  const { w, ids } = await fx(); const snap = () => JSON.stringify([q(w, 'SELECT id, sha256, state, release_tag FROM candidates ORDER BY id'), q(w, 'SELECT * FROM members'), q(w, 'SELECT COUNT(*) AS n FROM decisions')]);
  const before = JSON.parse(snap()); await wd(w, w.ada, ids[0]); const after = JSON.parse(snap());
  assert.deepEqual(before[0].filter((c) => c.id !== ids[0]), after[0].filter((c) => c.id !== ids[0])); assert.deepEqual(before[1], after[1]); assert.deepEqual(before[2], after[2]);
  const fetched = []; const f = w.deps.fetch; w.deps.fetch = async (u, init = {}) => { fetched.push([init.method || 'GET', String(u)]); return f(u, init); };
  const c = (await sheet(w, ids[1])); await w.call('GET', `/api/policies/preview?candidate_id=${ids[1]}&scope=path`, { user: w.ada }); await w.call('POST', '/api/policies/reconcile', { user: w.ada, body: {} }); assert.ok(c.id);
  assert.ok(fetched.length > 0 && fetched.every(([m]) => m === 'GET'), 'the Worker only ever reads GitHub');
});

// ---- migration 0003 ---------------------------------------------------------------------------------------------------------------
const MIG = new URL('../migrations/', import.meta.url), SCHEMA_V1 = new URL('./schema_v1.sql', import.meta.url), file = (n) => readFileSync(new URL(n, MIG), 'utf8');
const prod = () => { const db = new DatabaseSync(':memory:'); db.exec(readFileSync(SCHEMA_V1, 'utf8')); db.exec(file('0002_member_identity.sql')); return db; };
const NEW = ['policies', 'policy_lifts', 'policy_events'];
const dump = (db) => JSON.stringify(['candidates', 'decisions', 'audit', 'members', 'blobs', 'sessions', 'metrics', 'pipeline_runs'].map((t) => db.prepare(`SELECT * FROM ${t} ORDER BY 1, 2`).all()));
const shape = (db) => db.prepare("SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name").all().map((r) => ({ ...r }));
async function seedProd(db) {
  const t = '2026-10-20T00:00:00.000Z', ins = db.prepare('INSERT INTO candidates (id, sha256, path, name, source, detected_at, state, updated_at) VALUES (?,?,?,?,?,?,?,?)');
  for (let i = 0; i < 10; i++) ins.run(`cand-${i}`, String(i).repeat(64).slice(0, 64), `rules/x/r${i}.yar`, `r${i}.yar`, 'nextron', t, i % 2 ? 'PENDING' : 'RELEASED', t);
  db.prepare("INSERT INTO decisions (candidate_id, sha256, action, from_state, to_state, candidate_version, actor, role, reason, request_id, at) VALUES ('cand-1', ?, 'hold','PENDING','UNDER_REVIEW',2,'dmuinoo','REVIEWER','Es una prueba','req_x',?)").run('1'.repeat(64), t);
  let prev = '0'.repeat(64); const { chainHash } = await import('../src/core.js');
  for (let i = 0; i < 3; i++) { const e = { at: t, actor: 'a', role: 'ADMIN', action: `x.${i}`, target: 't', detail: '{}' }; const h = await chainHash(prev, e); db.prepare('INSERT INTO audit (at, actor, role, action, target, detail, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?)').run(t, 'a', 'ADMIN', e.action, 't', '{}', prev, h); prev = h; }
  db.prepare("INSERT INTO members (login, role, granted_by, at) VALUES ('old','VIEWER','adm',?)").run(t);
}
test('M-01 migration 0003 only creates objects named policies, policy_lifts or policy_events (static check of every statement)', () => {
  const sql = file('0003_policies.sql').replace(/--[^\n]*/g, ''); const stmts = sql.split(/;\s*(?:\n|$)/).map((s) => s.trim()).filter(Boolean);
  assert.ok(stmts.length > 25);
  for (const s of stmts) {
    assert.match(s, /^CREATE (UNIQUE )?(TABLE|INDEX|TRIGGER) IF NOT EXISTS (policies|policy_lifts|policy_events|policy_events_[a-z_]+|policy_lifts_[a-z_]+|policies_[a-z_]+)\b/, s.slice(0, 80));
    assert.doesNotMatch(s, /\b(INSERT|DELETE|ALTER|DROP)\b\s+(INTO|FROM|TABLE)\b/i, s.slice(0, 80));
    if (/^CREATE (UNIQUE )?INDEX/.test(s)) assert.match(s, /ON (policies|policy_lifts|policy_events) /);
    if (/^CREATE TRIGGER/.test(s)) assert.match(s, /(BEFORE|AFTER) (UPDATE|INSERT|DELETE)( OF [a-z0-9_, ]+)? ON (policies|policy_lifts|policy_events)\b/);
  }
  for (const s of stmts.filter((x) => /^CREATE TRIGGER/.test(x))) assert.equal(s.includes('\n'), false, 'triggers are on one line');
  assert.doesNotMatch(sql, /\b(?:FROM|JOIN|INTO|UPDATE|TABLE|ON)\s+(candidates|decisions|audit|members|blobs|sessions|metrics|pipeline_runs|oauth_states)\b/i, 'no existing table is named by any statement');
  const rb = file('0003_rollback.sql').replace(/--[^\n]*/g, ''); for (const s of rb.split(/;\s*(?:\n|$)/).map((x) => x.trim()).filter(Boolean)) assert.match(s, /^DROP (TRIGGER|INDEX|TABLE) IF EXISTS (policies|policy_lifts|policy_events)/, s);
});
test('M-02 applying 0003 to a production-shaped database (v1 + 0002, 10 candidates, a decision, an audit chain) changes no existing row, column or index; twice is the same', async () => {
  const db = prod(); await seedProd(db); const before = dump(db), shapeBefore = shape(db).filter((r) => !NEW.some((n) => r.name.startsWith(n.slice(0, 6)) && r.name.startsWith('polic')));
  const { verifyChain } = await import('../src/core.js'); const chain = () => verifyChain(db.prepare('SELECT * FROM audit ORDER BY seq').all().map((r) => ({ ...r })));
  assert.equal((await chain()).ok, true); db.exec(file('0003_policies.sql'));
  assert.equal(dump(db), before, 'every row of every existing table is byte-identical'); assert.equal((await chain()).ok, true, 'and the chain still verifies');
  assert.deepEqual(shape(db).filter((r) => !r.name.startsWith('polic')), shapeBefore.filter((r) => !r.name.startsWith('polic')), 'no existing table, index or trigger changed');
  const created = db.prepare("SELECT name FROM sqlite_master WHERE name LIKE 'polic%' ORDER BY name").all().map((r) => r.name); assert.ok(created.length >= 26, String(created.length));
  assert.deepEqual(db.prepare("SELECT COUNT(*) AS n FROM policies").get().n, 0); const once = shape(db); db.exec(file('0003_policies.sql')); assert.deepEqual(shape(db), once, 'idempotent');
  assert.equal(dump(db), before);
});
test('M-03 a fresh install (schema.sql) equals a migrated database, object for object', () => {
  const fresh = new DatabaseSync(':memory:'); fresh.exec(readFileSync(new URL('../schema.sql', import.meta.url), 'utf8')); const mig = prod(); mig.exec(file('0003_policies.sql'));
  const pol = (db) => shape(db).filter((r) => r.name.startsWith('polic')); assert.deepEqual(pol(fresh), pol(mig)); assert.ok(pol(mig).length >= 26);
});
test('M-04 rollback on the migrated database removes only the three tables, their indexes and triggers; every existing row is intact; re-applying works', async () => {
  const db = prod(); await seedProd(db); const before = dump(db), shapeBefore = shape(db); db.exec(file('0003_policies.sql'));
  db.prepare("INSERT INTO policies (id, scope, scope_key, source, path, sha256, candidate_id, criticality, author, author_id, author_role, reason, created_at, request_id, baseline_tag, baseline_published_at, baseline_manifest_sha256, baseline_rules_root, updated_at) VALUES ('p1','path','path:nextron:rules/x/r0.yar','nextron','rules/x/r0.yar',?, 'cand-0','STANDARD','ada',1,'ADMIN','a reason','2026-10-21T00:00:00.000Z','req-1','rules-20261021-1','2026-10-21T00:00:00Z','m','r','2026-10-21T00:00:00.000Z')").run('0'.repeat(64));
  db.exec(file('0003_rollback.sql'));
  assert.deepEqual(db.prepare("SELECT name FROM sqlite_master WHERE name LIKE 'polic%'").all(), [], 'tables, indexes and triggers are gone'); assert.equal(dump(db), before, 'existing data intact'); assert.deepEqual(shape(db), shapeBefore, 'the schema is the one before 0003');
  db.exec(file('0003_policies.sql')); assert.equal(db.prepare('SELECT COUNT(*) AS n FROM policies').get().n, 0);
});
test('M-05 every CHECK and trigger of 0003 refuses what it exists to refuse', () => {
  const db = prod(); db.exec(file('0003_policies.sql')); const t = '2026-10-21T00:00:00.000Z', sha = 'a'.repeat(64);
  const pol = (o = {}) => { const r = { id: 'p1', scope: 'path', scope_key: 'path:nextron:rules/x/a.yar', source: 'nextron', path: 'rules/x/a.yar', sha256: sha, candidate_id: 'c', criticality: 'CRITICAL', author: 'ada', author_id: 1, author_role: 'ADMIN', reason: 'a reason', created_at: t, request_id: 'req-1', baseline_tag: 'rules-20261021-1', baseline_published_at: t, baseline_manifest_sha256: 'm', baseline_rules_root: 'r', updated_at: t, ...o }; db.prepare(`INSERT INTO policies (${Object.keys(r).join(',')}) VALUES (${Object.keys(r).map(() => '?').join(',')})`).run(...Object.values(r)); };
  assert.throws(() => pol({ author_role: 'REVIEWER' }), /constraint/i); assert.throws(() => pol({ reason: '  no ' }), /constraint/i); assert.throws(() => pol({ sha256: 'short' }), /constraint/i); assert.throws(() => pol({ scope_key: 'path:other:x' }), /constraint/i); assert.throws(() => pol({ criticality: 'LOW' }), /constraint/i);
  assert.throws(() => pol({ scope: 'content', scope_key: 'content:wrong' }), /constraint/i); assert.throws(() => pol({ status: 'LIFTED' }), /constraint/i, 'LIFTED needs its facts'); assert.throws(() => pol({ withdrawal: 'CONFIRMED' }), /constraint/i, 'CONFIRMED needs its evidence'); assert.throws(() => pol({ withdrawal: 'CANCELLED' }), /constraint/i);
  pol(); assert.throws(() => pol({ id: 'p2', request_id: 'req-2' }), /UNIQUE/i, 'one ACTIVE policy per scope key'); assert.throws(() => pol({ id: 'p1' }), /UNIQUE|constraint/i);
  assert.throws(() => db.prepare("UPDATE policies SET withdrawal = 'CONFIRMED', version = 2 WHERE id = 'p1'").run(), /constraint/i); assert.throws(() => db.prepare('UPDATE policies SET version = 5 WHERE id = ?').run('p1'), /exactly one/);
  assert.throws(() => db.prepare("UPDATE policies SET source = 'x', version = 2 WHERE id = 'p1'").run(), /immutable/); assert.throws(() => db.prepare("UPDATE policies SET criticality = 'STANDARD', version = 2 WHERE id = 'p1'").run(), /immutable/, 'criticality cannot be downgraded');
  db.prepare("UPDATE policies SET withdrawal = 'CONFIRMED', confirmed_tag='t', confirmed_published_at='x', confirmed_manifest_sha256='m', confirmed_rules_root='r', confirmed_at='x', version = 2 WHERE id = 'p1'").run();
  assert.throws(() => db.prepare("UPDATE policies SET withdrawal = 'REQUESTED', version = 3 WHERE id = 'p1'").run(), /only moves forward/);
  const ev = (o = {}) => { const r = { policy_id: 'p1', policy_version: 1, event: 'LIFTED', actor: 'a', role: 'ADMIN', reason: 'x', request_id: 'r1', at: t, ...o }; db.prepare(`INSERT INTO policy_events (${Object.keys(r).join(',')}) VALUES (${Object.keys(r).map(() => '?').join(',')})`).run(...Object.values(r)); };
  ev(); assert.throws(() => ev({ event: 'OTHER', request_id: 'r2' }), /constraint/i); assert.throws(() => ev(), /UNIQUE/i); assert.throws(() => db.prepare('UPDATE policy_events SET reason = ?').run('y'), /append-only/); assert.throws(() => db.prepare('DELETE FROM policy_events').run(), /append-only/);
  const lf = (o = {}) => { const r = { id: 'l1', policy_id: 'p1', kind: 'DUAL', state: 'REQUESTED', requested_by: 'ada', requested_by_id: 1, requested_role: 'ADMIN', reason: 'a reason', requested_at: t, request_id: 'lr1', not_before: t, expires_at: '2026-10-24T00:00:00.000Z', updated_at: t, ...o }; db.prepare(`INSERT INTO policy_lifts (${Object.keys(r).join(',')}) VALUES (${Object.keys(r).map(() => '?').join(',')})`).run(...Object.values(r)); };
  assert.throws(() => lf({ kind: 'DIRECT', state: 'APPLIED', applied_at: t }), /one administrator/, 'DIRECT on a CRITICAL policy'); assert.throws(() => lf({ state: 'APPLIED', applied_at: t }), /born requested/); assert.throws(() => lf({ requested_role: 'REVIEWER' }), /constraint/i);
  assert.throws(() => lf({ kind: 'BREAKGLASS', reason: 'too short for an emergency', not_before: t }), /constraint/i, 'emergency reason below 20 chars or no delay'); assert.throws(() => lf({ kind: 'BREAKGLASS', reason: 'a sufficiently long emergency reason', not_before: t }), /constraint/i, 'no delay');
  lf(); assert.throws(() => lf({ id: 'l2', request_id: 'lr2' }), /UNIQUE/i, 'one open lift per policy');
  assert.throws(() => db.prepare("UPDATE policy_lifts SET state = 'APPLIED', authorized_by = 'ADA', authorized_by_id = 2, authorized_reason = 'same person, other id', authorized_at = ?, applied_at = ?, version = 2 WHERE id = 'l1'").run(t, t), /constraint/i, 'same login (case-insensitive) cannot authorize');
  assert.throws(() => db.prepare("UPDATE policy_lifts SET state = 'APPLIED', authorized_by = 'bob', authorized_by_id = 1, authorized_reason = 'same account id', authorized_at = ?, applied_at = ?, version = 2 WHERE id = 'l1'").run(t, t), /constraint/i, 'same account id cannot authorize');
  db.prepare("UPDATE policy_lifts SET state = 'APPLIED', authorized_by = 'bob', authorized_by_id = 2, authorized_reason = 'a second person', authorized_at = ?, applied_at = ?, version = 2 WHERE id = 'l1'").run(t, t);
  assert.throws(() => db.prepare("UPDATE policy_lifts SET state = 'CANCELLED', version = 3 WHERE id = 'l1'").run(), /final/); assert.throws(() => db.prepare('DELETE FROM policy_lifts').run(), /never deleted/); assert.throws(() => db.prepare("UPDATE policy_lifts SET reason = 'edit', version = 3 WHERE id = 'l1'").run(), /immutable/);
});
test('M-06 schema.sql and the migration apply statement by statement with the splitter wrangler and the runtime suite use (cut at ";" + newline, full-line comments removed)', () => {
  for (const name of ['../schema.sql', '../migrations/0003_policies.sql']) {
    const db = name.includes('schema') ? new DatabaseSync(':memory:') : prod();
    const stmts = readFileSync(new URL(name, import.meta.url), 'utf8').replace(/^--.*$/gm, '').split(/;[ \t]*\r?\n/).map((s) => s.trim()).filter(Boolean);
    for (const s of stmts) db.exec(s);
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name LIKE 'polic%'").get().n >= 26, true, name);
  }
});
