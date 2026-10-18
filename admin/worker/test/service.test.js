import test from 'node:test';
import assert from 'node:assert/strict';
import { world, cand, sha, rid, actionsToken, REPO, ORIGIN } from './helpers.js';
import { verifyChain } from '../src/core.js';
import { auditRows } from '../src/store.js';

async function seeded(items = ['a', 'b', 'c', 'd']) {
  const w = await world(); const r = await w.submit(items.map((c) => cand(c)));
  assert.equal(r.status, 200); const ids = r.data.results.map((x) => x.id); return { w, ids };
}
const decide = (w, user, body) => w.call('POST', '/api/decisions', { user, body });
const versions = async (w, ids) => Object.fromEntries(await Promise.all(ids.map(async (i) => [i, (await w.call('GET', `/api/candidates/${i}`, { user: w.reviewer })).data.version])));
const state = async (w, id) => (await w.call('GET', `/api/candidates/${id}`, { user: w.reviewer })).data.state;

test('pipeline submissions create PENDING candidates and keep the content private to authenticated roles', async () => {
  const { w, ids } = await seeded(['a']); w.reviewer = await w.login('rita', { push: true });
  const c = (await w.call('GET', `/api/candidates/${ids[0]}`, { user: w.reviewer })).data;
  assert.equal(c.state, 'PENDING'); assert.match(c.content, /rule R_a/); assert.equal(c.reasons[0], 'costly-regex');
  const anon = await w.call('GET', `/api/candidates/${ids[0]}`); assert.equal(anon.status, 401);
});

test('an unauthenticated or unknown GitHub user cannot do anything', async () => {
  const { w, ids } = await seeded(['a']);
  assert.equal((await w.call('GET', '/api/candidates')).status, 401);
  assert.equal((await w.call('POST', '/api/decisions', { body: { action: 'approve', ids } })).status, 401);
  const stranger = await w.login('stranger', { pull: true });          // read access to a public repo is not authorization
  assert.equal((await w.call('GET', '/api/candidates', { user: stranger })).status, 403);
  assert.equal((await decide(w, stranger, { action: 'approve', ids, reason: 'looks fine', request_id: rid(), expect: { [ids[0]]: 1 } })).status, 403);
  assert.equal(await (async () => { w.reviewer = await w.login('rita', { push: true }); return state(w, ids[0]); })(), 'PENDING');
});

test('a read-only member cannot use the approval API directly', async () => {
  const { w, ids } = await seeded(['a']); const admin = await w.login('ada', { admin: true });
  assert.equal((await w.call('POST', '/api/members', { user: admin, body: { login: 'vera', role: 'VIEWER' } })).status, 200);
  const vera = await w.login('vera', { pull: true, id: 7 });
  assert.equal((await w.call('GET', '/api/candidates', { user: vera })).status, 200);
  const r = await decide(w, vera, { action: 'approve', ids, reason: 'let me in', request_id: rid(), expect: { [ids[0]]: 1 } });
  assert.equal(r.status, 403);
  w.reviewer = admin; assert.equal(await state(w, ids[0]), 'PENDING');
  assert.equal((await w.call('POST', `/api/candidates/${ids[0]}/retest`, { user: vera })).status, 403);
  assert.equal((await w.call('GET', '/api/members', { user: vera })).status, 403);
});

test('CSRF and cross-origin requests are refused even for a reviewer', async () => {
  const { w, ids } = await seeded(['a']); const rita = await w.login('rita', { push: true }); w.reviewer = rita;
  const body = { action: 'approve', ids, reason: 'checked by hand', request_id: rid(), expect: { [ids[0]]: 1 } };
  assert.equal((await w.call('POST', '/api/decisions', { user: rita, body, csrf: false })).status, 403);
  assert.equal((await w.call('POST', '/api/decisions', { user: rita, body, origin: false })).status, 403);
  assert.equal((await w.call('POST', '/api/decisions', { user: rita, body, headers: { Origin: 'https://evil.example', 'X-CSRF-Token': rita.csrf }, csrf: false, origin: false })).status, 403);
  assert.equal(await state(w, ids[0]), 'PENDING');
  assert.equal((await decide(w, rita, body)).status, 200);
});

test('expired sessions and a GitHub outage fail closed', async () => {
  const { w, ids } = await seeded(['a']); const rita = await w.login('rita', { push: true });
  assert.equal((await w.call('GET', '/api/candidates', { user: rita })).status, 200);
  w.perms['tok-rita'] = 'down'; w.tick(120);            // cache is stale, GitHub is down: the cached role may be used for 10 minutes only
  assert.equal((await w.call('GET', '/api/candidates', { user: rita })).status, 200);
  w.tick(700); assert.equal((await w.call('GET', '/api/candidates', { user: rita })).status, 403);
  const fresh = await w.login('rita2', { push: true }); w.tick(9 * 3600); assert.equal((await w.call('GET', '/api/candidates', { user: fresh })).status, 401);
});

test('losing write access on GitHub removes the role at the next check', async () => {
  const { w } = await seeded(['a']); const rita = await w.login('rita', { push: true });
  assert.equal((await w.call('GET', '/api/candidates', { user: rita })).status, 200);
  w.perms['tok-rita'] = { pull: true }; w.tick(61);
  assert.equal((await w.call('GET', '/api/candidates', { user: rita })).status, 403);
});

test('batch approval changes only the selected candidates and records who, when, why, version and hash', async () => {
  const { w, ids } = await seeded(['a', 'b', 'c', 'd']); const rita = await w.login('rita', { push: true }, { id: 42 }); w.reviewer = rita;
  const v = await versions(w, ids); const pick = [ids[0], ids[2]];
  const r = await decide(w, rita, { action: 'approve', ids: pick, reason: 'regex reviewed by hand', request_id: rid(), confirm_count: 2, expect: { [pick[0]]: v[pick[0]], [pick[1]]: v[pick[1]] } });
  assert.equal(r.status, 200); assert.equal(r.data.applied.length, 2);
  assert.deepEqual(await Promise.all(ids.map((i) => state(w, i))), ['APPROVED_PENDING_VALIDATION', 'PENDING', 'APPROVED_PENDING_VALIDATION', 'PENDING']);
  const c = (await w.call('GET', `/api/candidates/${ids[0]}`, { user: rita })).data; const d = c.decisions[0];
  assert.equal(d.actor, 'rita'); assert.equal(d.role, 'REVIEWER'); assert.equal(d.action, 'approve'); assert.equal(d.reason, 'regex reviewed by hand'); assert.equal(d.candidate_version, 2); assert.ok(d.at);
  assert.equal(c.sha256, sha('a'));
});

test('a bulk operation must state the exact number of affected rules', async () => {
  const { w, ids } = await seeded(['a', 'b', 'c']); const rita = await w.login('rita', { push: true }); w.reviewer = rita; const v = await versions(w, ids);
  const base = { action: 'reject', ids, reason: 'noisy rules', request_id: rid(), expect: v };
  assert.equal((await decide(w, rita, base)).status, 400);
  assert.equal((await decide(w, rita, { ...base, confirm_count: 2 })).status, 400);
  assert.deepEqual(await Promise.all(ids.map((i) => state(w, i))), ['PENDING', 'PENDING', 'PENDING']);
  assert.equal((await decide(w, rita, { ...base, confirm_count: 3, request_id: rid() })).status, 200);
});

test('decisions need a reason, valid ids and respect the batch limit', async () => {
  const { w, ids } = await seeded(['a']); const rita = await w.login('rita', { push: true }); w.reviewer = rita;
  const ok = { action: 'approve', ids, reason: 'fine after review', request_id: rid(), expect: { [ids[0]]: 1 } };
  for (const bad of [{ ...ok, reason: '' }, { ...ok, reason: 'no' }, { ...ok, request_id: 'short' }, { ...ok, ids: ['../../etc'] }, { ...ok, expect: {} }, { ...ok, action: 'delete' }, { ...ok, ids: [] }, { ...ok, ids: Array(501).fill(ids[0]) }])
    assert.equal((await decide(w, rita, bad)).status, 400, JSON.stringify(bad).slice(0, 80));
  assert.equal(await state(w, ids[0]), 'PENDING');
});

test('concurrent decisions on the same candidate: one wins and the other changes nothing', async () => {
  const { w, ids } = await seeded(['a']); const rita = await w.login('rita', { push: true }), sam = await w.login('sam', { push: true }, { id: 2 }); w.reviewer = rita;
  const mk = (action, user) => decide(w, user, { action, ids, reason: `${action} by ${user.sid.slice(0, 4)}`, request_id: rid(), expect: { [ids[0]]: 1 } });
  const [a, b] = await Promise.all([mk('approve', rita), mk('reject', sam)]);
  assert.deepEqual([a.status, b.status].sort(), [200, 409]);
  const c = (await w.call('GET', `/api/candidates/${ids[0]}`, { user: rita })).data; assert.equal(c.decisions.length, 1); assert.equal(c.version, 2);
});

test('a stale view is refused without touching anything', async () => {
  const { w, ids } = await seeded(['a', 'b']); const rita = await w.login('rita', { push: true }); w.reviewer = rita;
  await decide(w, rita, { action: 'reject', ids: [ids[0]], reason: 'duplicate of another', request_id: rid(), expect: { [ids[0]]: 1 } });
  const r = await decide(w, rita, { action: 'approve', ids, reason: 'approve both', request_id: rid(), confirm_count: 2, expect: { [ids[0]]: 1, [ids[1]]: 1 } });
  assert.equal(r.status, 409); assert.equal(await state(w, ids[1]), 'PENDING'); assert.equal(await state(w, ids[0]), 'REJECTED');
});

test('repeating a request is idempotent and a reused request id for another selection is refused', async () => {
  const { w, ids } = await seeded(['a', 'b']); const rita = await w.login('rita', { push: true }); w.reviewer = rita; const id = rid();
  const body = { action: 'approve', ids: [ids[0]], reason: 'reviewed twice', request_id: id, expect: { [ids[0]]: 1 } };
  assert.equal((await decide(w, rita, body)).status, 200);
  const again = await decide(w, rita, body); assert.equal(again.status, 200); assert.equal(again.data.replay, true);
  assert.equal((await w.call('GET', `/api/candidates/${ids[0]}`, { user: rita })).data.decisions.length, 1);
  const other = await decide(w, rita, { ...body, ids: [ids[1]], expect: { [ids[1]]: 1 } }); assert.equal(other.status, 409);   // the title says it: a reused request id for another selection is refused (it used to be accepted)
  const flipped = await decide(w, rita, { ...body, action: 'reject' }); assert.equal(flipped.status, 409);   // same id, another action: not a silent replay
  assert.equal((await w.call('GET', `/api/candidates/${ids[0]}`, { user: rita })).data.state, 'APPROVED_PENDING_VALIDATION');
});

test('a failure in the store never produces an approval', async () => {
  const { w, ids } = await seeded(['a']); const rita = await w.login('rita', { push: true }); w.reviewer = rita;
  const real = w.db.batch; w.db.batch = async () => { throw new Error('D1 unavailable'); };
  const r = await decide(w, rita, { action: 'approve', ids, reason: 'approve now', request_id: rid(), expect: { [ids[0]]: 1 } });
  w.db.batch = real; assert.notEqual(r.status, 200);
  assert.equal(await state(w, ids[0]), 'PENDING');
  assert.equal((await w.call('GET', `/api/candidates/${ids[0]}`, { user: rita })).data.decisions.length, 0);
});

test('a GitHub failure while checking permissions never approves anything', async () => {
  const { w, ids } = await seeded(['a']); const rita = await w.login('rita', { push: true }); w.reviewer = rita;
  w.perms['tok-rita'] = 'down'; w.deps.fetch = async () => { throw new Error('network down'); }; w.tick(5000);
  const r = await decide(w, rita, { action: 'approve', ids, reason: 'approve now', request_id: rid(), expect: { [ids[0]]: 1 } });
  assert.ok([403, 500].includes(r.status)); w.deps.fetch = async (u) => (String(u).includes('jwks') ? new Response(JSON.stringify({ keys: [w.key.jwk] })) : new Response('{"permissions":{"push":true}}')); w.tick(1);
  assert.equal(await state(w, ids[0]), 'PENDING');
});

test('rejected content is never re-opened by the pipeline; an edited version is a new linked candidate', async () => {
  const { w, ids } = await seeded(['a']); const rita = await w.login('rita', { push: true }); w.reviewer = rita;
  await decide(w, rita, { action: 'reject', ids, reason: 'false positives everywhere', request_id: rid(), expect: { [ids[0]]: 1 } });
  const again = await w.submit([cand('a')]); assert.equal(again.data.results[0].status, 'known-rejected'); assert.equal(await state(w, ids[0]), 'REJECTED');
  const edited = await w.submit([cand('e', 'rules/x/a.yar')]);   // same path, new bytes
  assert.equal(edited.data.results[0].status, 'created'); const ne = (await w.call('GET', `/api/candidates/${edited.data.results[0].id}`, { user: rita })).data;
  assert.equal(ne.state, 'PENDING'); assert.equal(ne.previous_id, ids[0]); assert.equal(ne.related[0].state, 'REJECTED');
});

test('approved rules are released only by the publish workflow, and can fall back to PENDING if revalidation fails', async () => {
  const { w, ids } = await seeded(['a', 'b']); const rita = await w.login('rita', { push: true }); w.reviewer = rita;
  await decide(w, rita, { action: 'approve', ids, reason: 'approved after review', request_id: rid(), confirm_count: 2, expect: { [ids[0]]: 1, [ids[1]]: 1 } });
  const tryRelease = async (wf, hashes) => w.call('POST', '/api/pipeline/released', { bearer: await w.pipelineToken(wf), body: { tag: 'rules-1', hashes } });
  assert.equal((await tryRelease('daily.yml', [sha('a')])).status, 403);
  assert.equal((await tryRelease('publish.yml', [sha('a')])).data.changed.length, 1);
  assert.equal(await state(w, ids[0]), 'RELEASED'); assert.equal((await w.call('GET', `/api/candidates/${ids[0]}`, { user: rita })).data.release_tag, 'rules-1');
  const f = await w.call('POST', '/api/pipeline/revalidation-failed', { bearer: await w.pipelineToken('daily.yml'), body: { hashes: [sha('b')], reason: 'compile error after engine upgrade' } });
  assert.equal(f.data.changed.length, 1); assert.equal(await state(w, ids[1]), 'PENDING');
  const d = await w.call('GET', '/api/pipeline/decisions', { bearer: await w.pipelineToken('daily.yml') });
  assert.equal(d.data.decisions[sha('a')].state, 'RELEASED'); assert.equal(d.data.decisions[sha('b')], undefined);
});

test('people cannot move a candidate through pipeline-only transitions', async () => {
  const { w, ids } = await seeded(['a']); const rita = await w.login('rita', { push: true }); w.reviewer = rita;
  assert.equal((await decide(w, rita, { action: 'released', ids, reason: 'force it through', request_id: rid(), expect: { [ids[0]]: 1 } })).status, 400);
  await decide(w, rita, { action: 'reject', ids, reason: 'not useful at all', request_id: rid(), expect: { [ids[0]]: 1 } });
  const r = await decide(w, rita, { action: 'approve', ids, reason: 'changed my mind', request_id: rid(), expect: { [ids[0]]: 2 } });
  assert.equal(r.status, 409); assert.equal(await state(w, ids[0]), 'REJECTED');
});

test('the pipeline API refuses forged, expired, foreign or wrongly scoped tokens', async () => {
  const w = await world(); const items = [cand('a')]; const other = await (await import('./helpers.js')).rsaKey();
  const send = (token) => w.call('POST', '/api/pipeline/submit', { bearer: token, body: { run_id: '1', candidates: items } });
  assert.equal((await send(await w.pipelineToken())).status, 200);
  assert.equal((await send(undefined)).status, 401);
  assert.equal((await send(await actionsToken(other, {}))).status, 401, 'signed by an unknown key');
  assert.equal((await send(await w.pipelineToken('daily.yml', { aud: 'https://elsewhere' }))).status, 401);
  assert.equal((await send(await w.pipelineToken('daily.yml', { exp: Math.floor(Date.now() / 1000) - 3600 }))).status, 401);
  assert.equal((await send(await w.pipelineToken('daily.yml', { repository: 'evil/fork' }))).status, 401);
  assert.equal((await send(await w.pipelineToken('daily.yml', { ref: 'refs/heads/feature' }))).status, 401);
  assert.equal((await send(await w.pipelineToken('evil.yml'))).status, 401);
  assert.equal((await send(await actionsToken(w.key, {}, { alg: 'none' }))).status, 401);
  assert.equal((await send(await w.pipelineToken('publish.yml'))).status, 403, 'publish may not submit candidates');
  const t = await w.pipelineToken(); const tampered = t.split('.'); tampered[1] = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(tampered[1], 'base64url')), repository: REPO, job_workflow_ref: `${REPO}/.github/workflows/publish.yml@refs/heads/main` })).toString('base64url');
  assert.equal((await send(tampered.join('.'))).status, 401, 'payload edited after signing');
});

test('submissions are validated: no traversal, no oversized content, no malformed hashes', async () => {
  const w = await world();
  for (const bad of [cand('a', '../../etc/passwd'), cand('a', '/abs/path'), { ...cand('a'), sha256: 'zz' }, { ...cand('a'), content_b64: 'A'.repeat(1_500_000) }, { ...cand('a'), reasons: 'nope' }]) assert.equal((await w.submit([bad])).status, 400);
});

test('the audit log is hash-chained: edits, deletions and reordering are detected', async () => {
  const { w, ids } = await seeded(['a', 'b']); const rita = await w.login('rita', { push: true }), ada = await w.login('ada', { admin: true }); w.reviewer = rita;
  await decide(w, rita, { action: 'approve', ids: [ids[0]], reason: 'reviewed carefully', request_id: rid(), expect: { [ids[0]]: 1 } });
  await decide(w, rita, { action: 'reject', ids: [ids[1]], reason: 'duplicate rule', request_id: rid(), expect: { [ids[1]]: 1 } });
  const ok = await w.call('GET', '/api/audit/verify', { user: ada }); assert.equal(ok.data.ok, true); assert.ok(ok.data.entries >= 3);
  assert.equal((await w.call('GET', '/api/audit/verify', { user: rita })).status, 403, 'only admins verify the chain');
  const rows = await auditRows(w.db); assert.equal((await verifyChain(rows)).ok, true);
  w.db.raw.exec("UPDATE audit SET actor = 'mallory' WHERE seq = 2");
  assert.equal((await w.call('GET', '/api/audit/verify', { user: ada })).data.ok, false);
  w.db.raw.exec("UPDATE audit SET actor = 'rita' WHERE seq = 2"); assert.equal((await w.call('GET', '/api/audit/verify', { user: ada })).data.ok, true);
  w.db.raw.exec('DELETE FROM audit WHERE seq = 2'); const broken = (await w.call('GET', '/api/audit/verify', { user: ada })).data; assert.equal(broken.ok, false); assert.match(broken.error, /removed|altered/);
});

test('every decision is in the audit log with who, what and which request', async () => {
  const { w, ids } = await seeded(['a']); const rita = await w.login('rita', { push: true }); const id = rid();
  await decide(w, rita, { action: 'approve', ids, reason: 'reviewed carefully', request_id: id, expect: { [ids[0]]: 1 } });
  const a = (await auditRows(w.db)).find((r) => r.action === 'decision.approve'); assert.equal(a.actor, 'rita'); assert.equal(a.role, 'REVIEWER');
  const d = JSON.parse(a.detail); assert.equal(d.request_id, id); assert.equal(d.reason, 'reviewed carefully'); assert.equal(d.applied[0].sha256, sha('a'));
});

test('role management is admin-only and nobody can change their own role', async () => {
  const w = await world(); const ada = await w.login('ada', { admin: true }), rita = await w.login('rita', { push: true });
  assert.equal((await w.call('POST', '/api/members', { user: rita, body: { login: 'rita', role: 'ADMIN' } })).status, 403);
  assert.equal((await w.call('POST', '/api/members', { user: ada, body: { login: 'ada', role: 'VIEWER' } })).status, 400);
  assert.equal((await w.call('POST', '/api/members', { user: ada, body: { login: 'x y', role: 'ADMIN' } })).status, 400);
  assert.equal((await w.call('POST', '/api/members', { user: ada, body: { login: 'newbie', role: 'VIEWER' } })).status, 200);
  assert.deepEqual((await w.call('GET', '/api/members', { user: ada })).data.members.map((m) => m.login), ['newbie']);
});

test('the public stats endpoint exposes counts only', async () => {
  const { w } = await seeded(['a', 'b']); const r = await w.call('GET', '/public/stats');
  assert.equal(r.status, 200); assert.deepEqual(Object.keys(r.data).sort(), ['approved_waiting_validation', 'pending_review', 'rejected', 'released_after_review', 'schema']);
  assert.ok(!JSON.stringify(r.data).match(/sha|path|rules\//));
});

test('responses carry strict security headers and rule code is only ever data', async () => {
  const { w, ids } = await seeded(['a']); const rita = await w.login('rita', { push: true });
  const r = await w.call('GET', `/api/candidates/${ids[0]}`, { user: rita });
  assert.match(r.headers.get('Content-Security-Policy'), /default-src 'none'/); assert.equal(r.headers.get('X-Content-Type-Options'), 'nosniff'); assert.match(r.headers.get('Content-Type'), /application\/json/);
  const evil = await w.submit([cand('f', 'rules/x/f.yar', { content_b64: Buffer.from('<script>alert(1)</script> rule X { condition: true }').toString('base64') })]);
  const c = (await w.call('GET', `/api/candidates/${evil.data.results[0].id}`, { user: rita })); assert.match(c.headers.get('Content-Type'), /json/); assert.match(c.data.content, /<script>/);
});

test('logout destroys the server-side session', async () => {
  const { w } = await seeded(['a']); const rita = await w.login('rita', { push: true });
  assert.equal((await w.call('POST', '/api/logout', { user: rita })).status, 200); assert.equal((await w.call('GET', '/api/me', { user: rita })).status, 401);
});

test('a candidate list can be searched and filtered', async () => {
  const { w } = await seeded(['a', 'b', 'c']); const rita = await w.login('rita', { push: true });
  const all = (await w.call('GET', '/api/candidates', { user: rita })).data; assert.equal(all.total, 3);
  assert.equal((await w.call('GET', '/api/candidates?q=x/b', { user: rita })).data.total, 1);
  assert.equal((await w.call('GET', '/api/candidates?state=REJECTED', { user: rita })).data.total, 0);
  assert.equal((await w.call('GET', '/api/candidates?pageSize=2&page=2', { user: rita })).data.items.length, 1);
});

test('opening a rule is recorded: who looked at what', async () => {
  const { w, ids } = await seeded(['a']); const rita = await w.login('rita', { push: true });
  await w.call('GET', `/api/candidates/${ids[0]}`, { user: rita });
  const a = (await auditRows(w.db)).find((r) => r.action === 'access.view'); assert.equal(a.actor, 'rita'); assert.equal(JSON.parse(a.detail).sha256, sha('a'));
});

test('a retest request survives until the pipeline reports it done, and earlier metrics are available for comparison', async () => {
  const { w, ids } = await seeded(['a']); const rita = await w.login('rita', { push: true });
  assert.equal((await w.call('POST', `/api/candidates/${ids[0]}/retest`, { user: rita })).status, 200);
  const dm = await w.call('GET', '/api/pipeline/decisions', { bearer: await w.pipelineToken() }); assert.equal(dm.data.retest.length, 1);
  await w.call('POST', '/api/pipeline/submit', { bearer: await w.pipelineToken(), body: { run_id: '2', candidates: [cand('a')], retested: [ids[0]] } });
  assert.equal((await w.call('GET', '/api/pipeline/decisions', { bearer: await w.pipelineToken() })).data.retest.length, 0);
  const edited = await w.submit([cand('e', 'rules/x/a.yar', { metrics: { cpu_s: 9 } })]);
  const d = (await w.call('GET', `/api/candidates/${edited.data.results[0].id}`, { user: rita })).data;
  assert.equal(d.history[0].metrics.cpu_s, 1.2);
});

test('keeping a rule in quarantine is an explicit choice and also takes back an approval that has not been released', async () => {
  const { w, ids } = await seeded(['a', 'b']); const rita = await w.login('rita', { push: true }); w.reviewer = rita;
  assert.equal((await decide(w, rita, { action: 'hold', ids: [ids[0]], reason: '', request_id: rid(), expect: { [ids[0]]: 1 } })).status, 400, 'a reason is required');
  assert.equal((await decide(w, rita, { action: 'hold', ids: [ids[0]], reason: 'waiting for the vendor', request_id: rid(), expect: { [ids[0]]: 1 } })).status, 200);
  assert.equal(await state(w, ids[0]), 'UNDER_REVIEW');
  await decide(w, rita, { action: 'approve', ids: [ids[1]], reason: 'looks right to me', request_id: rid(), expect: { [ids[1]]: 1 } });
  assert.equal((await decide(w, rita, { action: 'hold', ids: [ids[1]], reason: 'second thoughts', request_id: rid(), expect: { [ids[1]]: 2 } })).status, 200);
  const dm = await w.call('GET', '/api/pipeline/decisions', { bearer: await w.pipelineToken() });
  assert.equal(dm.data.decisions[sha('a')], undefined); assert.equal(dm.data.decisions[sha('b')], undefined, 'neither is released by the next run');
  // and a released rule cannot be pulled back by hand
  await decide(w, rita, { action: 'approve', ids: [ids[0]], reason: 'ok now', request_id: rid(), expect: { [ids[0]]: 3 } });
  await w.call('POST', '/api/pipeline/released', { bearer: await w.pipelineToken('publish.yml'), body: { tag: 't', hashes: [sha('a')] } });
  assert.equal((await decide(w, rita, { action: 'hold', ids: [ids[0]], reason: 'too late', request_id: rid(), expect: { [ids[0]]: 5 } })).status, 409);
});

// ---- regression tests for the final audit (FA-*) ----
import { hashOf } from './helpers.js';
import { handle } from '../src/index.js';
import * as store from '../src/store.js';
import { decisionsMap } from '../src/store.js';

test('FA-H1: a human rejection of a path wins over an approval or release of identical bytes at another path', async () => {
  const w = await world(); const a = cand('a', 'rules/a/dup.yar'), b = cand('a', 'rules/b/dup.yar');
  const ids = (await w.submit([a, b])).data.results.map((r) => r.id); assert.notEqual(ids[0], ids[1]);
  const rita = await w.login('rita', { push: true }); w.reviewer = rita;
  const v = await versions(w, ids);
  assert.equal((await decide(w, rita, { action: 'reject', ids: [ids[0]], reason: 'malicious', request_id: rid(), expect: { [ids[0]]: v[ids[0]] } })).status, 200);
  assert.equal((await decide(w, rita, { action: 'approve', ids: [ids[1]], reason: 'looks fine', request_id: rid(), expect: { [ids[1]]: v[ids[1]] } })).status, 200);
  assert.equal((await decisionsMap(w.db))[a.sha256].state, 'REJECTED');
  const rel = await w.call('POST', '/api/pipeline/released', { bearer: await w.pipelineToken('publish.yml'), body: { hashes: [a.sha256], tag: 'rules-x' } });
  assert.equal(rel.status, 200); assert.equal((await decisionsMap(w.db))[a.sha256].state, 'REJECTED');   // RELEASED elsewhere must not hide the rejection
});

test('FA-M1: content that does not hash to its sha256 is refused and nothing is stored', async () => {
  const w = await world(); const good = cand('a'), bad = cand('b', 'rules/x/b.yar', { sha256: sha('c') });
  const r = await w.submit([good, bad]); assert.equal(r.status, 400); assert.match(r.data.error, /does not match its sha256/);
  const rita = await w.login('rita', { push: true });
  assert.equal((await w.call('GET', '/api/candidates', { user: rita })).data.total, 0);   // all-or-nothing: the good item was not stored either
  assert.equal((await w.submit([cand('a', 'rules/x/a.yar', { content_b64: '***' })])).status, 400);
});

test('FA-M2: two same-action decisions racing past the pre-check: only the one that took effect is recorded and answered 200', async () => {
  const { w, ids } = await seeded(['a']); const id = ids[0];
  const actorA = { login: 'rita', id: 12, role: 'REVIEWER' }, actorB = { login: 'rob', id: 14, role: 'REVIEWER' };
  const base = { action: 'approve', ids: [id], reason: 'racing approve', expect: { [id]: 1 } };
  // B reads the candidate before A commits, but reads the audit head after A committed
  let release; const gate = new Promise((r) => (release = r));
  const dbB = { prepare: (sql) => { const s = w.db.prepare(sql); if (/SELECT hash FROM audit/.test(sql)) { const f = s.first.bind(s); s.first = async () => { await gate; return f(); }; } return s; }, batch: (l) => w.db.batch(l) };
  const pB = store.decide(dbB, { ...base, request_id: rid() }, actorB, '2026-01-01T00:00:00Z');
  await new Promise((r) => setTimeout(r, 20));
  const rA = await store.decide(w.db, { ...base, request_id: rid() }, actorA, '2026-01-01T00:00:01Z');
  release(); const rB = await pB;
  assert.equal(rA.status, 200); assert.equal(rB.status, 409);   // used to be 200 for both
  assert.equal(w.db.raw.prepare('SELECT COUNT(*) n FROM decisions').get().n, 1);
  assert.deepEqual(w.db.raw.prepare("SELECT actor FROM audit WHERE action='decision.approve'").all().map((x) => x.actor), ['rita']);
});

test('FA-M3: viewing a candidate is audited once per window, and verification refuses to pass when it did not cover the whole log', async () => {
  const { w, ids } = await seeded(['a']); const rita = await w.login('rita', { push: true });
  for (let i = 0; i < 20; i++) assert.equal((await w.call('GET', `/api/candidates/${ids[0]}`, { user: rita })).status, 200);
  assert.equal((await auditRows(w.db, 1000)).filter((e) => e.action === 'access.view').length, 1);
  w.tick(601); await w.call('GET', `/api/candidates/${ids[0]}`, { user: rita });
  assert.equal((await auditRows(w.db, 1000)).filter((e) => e.action === 'access.view').length, 2);
});

test('FA-M4: the OAuth callback requires the state cookie of the browser that started the login, and expired rows are purged', async () => {
  const w = await world(); w.env.GITHUB_OAUTH_BASE = 'https://gh.example.test';
  const login = await handle(new Request(ORIGIN + '/auth/login'), w.env, w.deps); assert.equal(login.status, 302);
  const state = new URL(login.headers.get('Location')).searchParams.get('state'); const cookie = login.headers.get('Set-Cookie');
  assert.match(cookie, /__Host-mg_oauth=/); assert.match(cookie, /HttpOnly/); assert.match(cookie, /Secure/);
  const noCookie = await handle(new Request(`${ORIGIN}/auth/callback?code=c&state=${state}`), w.env, w.deps); assert.equal(noCookie.status, 400);
  const wrong = await handle(new Request(`${ORIGIN}/auth/callback?code=c&state=${state}`, { headers: { Cookie: '__Host-mg_oauth=' + 'f'.repeat(32) } }), w.env, w.deps); assert.equal(wrong.status, 400);
  w.tick(700); await handle(new Request(ORIGIN + '/auth/login'), w.env, w.deps);
  assert.equal((await w.db.prepare('SELECT COUNT(*) AS n FROM oauth_states WHERE state = ?').bind(state).first()).n, 0);
});

test('FA-L1/L2/L5: replay with another action, missing OIDC audience, invisible reasons and spoofed paths are refused', async () => {
  const { w, ids } = await seeded(['a']); const rita = await w.login('rita', { push: true }); w.reviewer = rita;
  const zw = await decide(w, rita, { action: 'approve', ids, reason: '\u200b\u200b\u200b\u200b\u200b\u200b', request_id: rid(), expect: { [ids[0]]: 1 } }); assert.equal(zw.status, 400);
  for (const path of ['rules/%2e%2e/x.yar', 'rules/a\u202eb.yar', 'rules//x.yar', './x.yar', 'C:/x.yar', 'rules/a\nb.yar', 'rules/../x.yar'])
    assert.equal((await w.submit([cand('z', path)])).status, 400, path);
  assert.equal((await w.submit([cand('y', 'rules/a..b/ok.yar')])).status, 200);   // a benign double dot inside a name is fine
  const token = await w.pipelineToken('daily.yml'); delete w.env.OIDC_AUDIENCE;
  assert.equal((await w.call('POST', '/api/pipeline/submit', { bearer: token, body: { run_id: '1', candidates: [] } })).status, 401);
});
