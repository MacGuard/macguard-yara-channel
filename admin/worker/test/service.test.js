import { readFileSync } from 'node:fs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { world, cand, sha, rid, actionsToken, REPO, ORIGIN } from './helpers.js';
import { verifyChain, dependencyEffect } from '../src/core.js';
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
  w.account('vera', 7); assert.equal((await w.grant(admin, 'vera', 'VIEWER')).status, 200);
  const vera = await w.login('vera', { pull: true }, { id: 7 });
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
  assert.throws(() => w.db.raw.exec("UPDATE audit SET actor = 'mallory' WHERE seq = 2"), /append-only/);   // the service itself cannot rewrite its trail
  assert.throws(() => w.db.raw.exec('DELETE FROM audit WHERE seq = 2'), /append-only/);
  assert.throws(() => w.db.raw.exec("UPDATE decisions SET reason = 'x'"), /append-only/);
  for (const t of ['audit_no_update', 'audit_no_delete']) w.db.raw.exec(`DROP TRIGGER ${t}`);   // someone with direct database access: the chain must still show it
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
  assert.equal((await w.grant(rita, 'rita', 'ADMIN')).status, 403);
  assert.equal((await w.grant(ada, 'ada', 'VIEWER')).status, 400);
  assert.equal((await w.call('GET', '/api/members/lookup?login=x%20y', { user: ada })).status, 400);
  assert.equal((await (w.account('newbie', 900), w.grant(ada, 'newbie', 'VIEWER'))).status, 200);
  assert.deepEqual((await w.call('GET', '/api/members', { user: ada })).data.items.filter((m) => m.manual_role).map((m) => m.login), ['newbie']);
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
  const c = (await w.call('GET', `/api/candidates/${evil.data.results[0].id}`, { user: rita })); assert.match(c.headers.get('Content-Type'), /json/); assert.ok(c.data.content.includes('<script>'));
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
  const noCookie = await handle(new Request(`${ORIGIN}/auth/callback?code=c&state=${state}`), w.env, w.deps); assert.equal(noCookie.status, 302); assert.equal(noCookie.headers.get('Location'), '/?e=state');
  const wrong = await handle(new Request(`${ORIGIN}/auth/callback?code=c&state=${state}`, { headers: { Cookie: '__Host-mg_oauth=' + 'f'.repeat(32) } }), w.env, w.deps); assert.equal(wrong.status, 302); assert.equal(wrong.headers.get('Location'), '/?e=state');
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

test('FA-L3/L5: a change of state asks GitHub again and never uses a stale grant; oversized bodies and malformed members are refused', async () => {
  const { w, ids } = await seeded(['a']); const rita = await w.login('rita', { push: true }); w.reviewer = rita;
  assert.equal((await w.call('GET', '/api/candidates', { user: rita })).status, 200); w.tick(30);
  const token = 'tok-rita'; w.perms[token] = { pull: true };   // write access removed 30 s ago
  assert.equal((await w.call('GET', '/api/candidates', { user: rita })).status, 200);   // reads may use the cached grant for up to 60 s
  const r = await decide(w, rita, { action: 'approve', ids, reason: 'reviewed carefully', request_id: rid(), expect: { [ids[0]]: 1 } });
  assert.equal(r.status, 403); w.perms[token] = { push: true };   // restored
  w.perms[token] = 'down';   // GitHub unreachable: a write must fail closed even though a grant is cached
  assert.equal((await decide(w, rita, { action: 'approve', ids, reason: 'reviewed carefully', request_id: rid(), expect: { [ids[0]]: 1 } })).status, 403);
  w.perms[token] = { push: true };
  const big = await w.call('POST', '/api/decisions', { user: rita, body: { action: 'approve', ids, reason: 'x'.repeat(300000), request_id: rid(), expect: {} } }); assert.equal(big.status, 413);
  const ada = await w.login('ada', { admin: true }, { id: 3 });
  assert.equal((await w.call('POST', '/api/members', { user: ada, body: { user_id: ['a'], role: 'VIEWER', reason: 'reviewed by hand' } })).status, 400);   // used to be a 500
});

test('public/_headers carries exactly the Worker\'s security headers (static assets bypass the Worker on Cloudflare)', async () => {
  const { HEADERS } = await import('../src/index.js');
  const text = readFileSync(new URL('../public/_headers', import.meta.url), 'utf8').split('\n').filter((l) => l && !l.startsWith('#'));
  assert.equal(text[0], '/*');
  const got = Object.fromEntries(text.slice(1).map((l) => { const i = l.indexOf(':'); return [l.slice(0, i).trim(), l.slice(i + 1).trim()]; }));
  assert.deepEqual(got, HEADERS);
});

test('a decision never starts a release: the service has no way to call a GitHub write API or dispatch a workflow', async () => {
  const src = ['index', 'core', 'store', 'auth'].map((f) => readFileSync(new URL(`../src/${f}.js`, import.meta.url), 'utf8')).join('\n');
  assert.doesNotMatch(src, /dispatches|\/actions\/|workflow_dispatch|repository_dispatch/);
  const writes = [...src.matchAll(/deps\.fetch\([^)]*\)?[^;]*?method:\s*'(POST|PUT|PATCH|DELETE)'/g)].map((m) => m[0]);
  assert.ok(writes.every((w) => /login\/oauth\/access_token/.test(w)), `only the OAuth code exchange may POST: ${writes}`);
  const { w, ids } = await seeded(['a', 'b']); w.reviewer = await w.login('rita', { push: true }); const calls = [];
  const orig = w.deps.fetch; w.deps.fetch = async (...a) => { calls.push(String(a[0]) + ' ' + (a[1]?.method || 'GET')); return orig(...a); };
  const v = await versions(w, ids);
  assert.equal((await decide(w, w.reviewer, { action: 'approve', ids, reason: 'reviewed by hand', request_id: rid(), confirm_count: 2, expect: v })).status, 200);
  assert.deepEqual(calls.filter((c) => !/ GET$/.test(c)), [], 'a decision made no outbound write');
});

test('the GitHub token is sealed at rest: D1 holds no usable token, and a row cannot be replayed under another session', async () => {
  const w = await world(); const rita = await w.login('rita', { push: true }); const ada = await w.login('ada', { admin: true }, { id: 3 });
  const rows = (await w.db.prepare('SELECT id, token FROM sessions').all()).results;
  assert.equal(rows.length, 2); assert.ok(rows.every((r) => /^v1\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+$/.test(r.token) && !r.token.includes('tok-')), 'no plaintext token in D1');
  assert.equal((await w.call('GET', '/api/candidates', { user: rita })).status, 200);
  // a seal copied onto another session fails authentication (AAD = session id): the person must sign in again
  const adaRow = rows.find((r) => r.id === ada.sid);
  await w.db.prepare('UPDATE sessions SET token = ?, perm = NULL WHERE id = ?').bind(adaRow.token, rita.sid).run();
  const r = await w.call('GET', '/api/candidates', { user: rita }); assert.equal(r.status, 401);
  assert.equal((await w.db.prepare('SELECT 1 AS x FROM sessions WHERE id = ?').bind(rita.sid).first()), null, 'the session was destroyed');
});

test('a legacy plaintext token or a wrong or missing key never authorizes; sealing needs a valid key', async () => {
  const w = await world(); const rita = await w.login('rita', { push: true });
  await w.db.prepare('UPDATE sessions SET token = ?, perm = NULL WHERE id = ?').bind('tok-rita', rita.sid).run();
  assert.equal((await w.call('GET', '/api/candidates', { user: rita })).status, 401);
  const { createSession } = await import('../src/auth.js');
  await assert.rejects(createSession(w.db, { login: 'x', id: 9, token: 't' }, w.now(), {}), /TOKEN_ENC_KEY/);
  await assert.rejects(createSession(w.db, { login: 'x', id: 9, token: 't' }, w.now(), { TOKEN_ENC_KEY: Buffer.alloc(16).toString('base64') }), /32 random bytes/);
});

test('a revoked or expired GitHub token ends the session at once; it keeps nothing, not even a members grant', async () => {
  const w = await world(); const ada = await w.login('ada', { admin: true }, { id: 3 }); const vera = await w.login('vera', { pull: true }, { id: 5 });
  assert.equal((await w.grant(ada, 'vera', 'VIEWER')).status, 200);
  assert.equal((await w.call('GET', '/api/candidates', { user: vera })).status, 200);
  delete w.perms['tok-vera']; w.tick(61);   // GitHub now answers 401 Bad credentials for her token
  const r = await w.call('GET', '/api/candidates', { user: vera });
  assert.equal(r.status, 401); assert.match(r.data.error, /sign in again/); assert.match(r.headers.get('Set-Cookie'), /Max-Age=0/);
  assert.equal((await w.db.prepare('SELECT 1 AS x FROM sessions WHERE id = ?').bind(vera.sid).first()), null);
  assert.equal((await w.call('GET', '/api/candidates', { user: vera })).status, 401, 'the old cookie stays dead');
  const again = await w.login('vera', { pull: true }, { id: 5 });   // signing in again restores the explicit grant
  assert.equal((await w.call('GET', '/api/candidates', { user: again })).status, 200);
});

test('administrative revocation is different: losing repository permissions keeps only an explicit members grant, and a write is refused at once', async () => {
  const { w, ids } = await seeded(['a']); const rita = await w.login('rita', { push: true }); const ada = await w.login('ada', { admin: true }, { id: 3 });
  assert.equal((await w.call('GET', '/api/candidates', { user: rita })).status, 200);
  w.perms['tok-rita'] = 'denied';   // GitHub 403: the person lost access to the repository, the token itself is still valid
  assert.equal((await decide(w, rita, { action: 'approve', ids, reason: 'reviewed carefully', request_id: rid(), expect: { [ids[0]]: 1 } })).status, 403);
  assert.equal((await w.call('GET', '/api/candidates', { user: rita })).status, 403);
  assert.equal((await w.grant(ada, 'rita', 'VIEWER')).status, 200);
  assert.equal((await w.call('GET', '/api/candidates', { user: rita })).status, 200, 'an explicit VIEWER grant survives');
  assert.equal((await decide(w, rita, { action: 'approve', ids, reason: 'reviewed carefully', request_id: rid(), expect: { [ids[0]]: 1 } })).status, 403, 'VIEWER cannot decide');
});

test('a session never outlives an expiring GitHub token', async () => {
  const w = await world(); const { createSession } = await import('../src/auth.js');
  const s = await createSession(w.db, { login: 'x', id: 9, token: 't', expires_in: 3600 }, w.now(), w.env);
  assert.equal(s.ttl, 3540);
  assert.equal((await createSession(w.db, { login: 'y', id: 10, token: 't' }, w.now(), w.env)).ttl, 8 * 3600);
});

// ---- Decision 1: members bound to the immutable GitHub id ------------------------------------------------------------------------------
import { DatabaseSync } from 'node:sqlite';
const MIG = new URL('../migrations/', import.meta.url), SCHEMA_V1 = new URL('./schema_v1.sql', import.meta.url);
const people = async (w, admin, qs = '') => (await w.call('GET', `/api/members${qs}`, { user: admin })).data;

test('a grant belongs to the GitHub account id: the same login on another account, or a renamed account, never mixes', async () => {
  const w = await world(); const ada = await w.login('ada', { admin: true });
  w.account('vera', 7); assert.equal((await w.grant(ada, 'vera', 'VIEWER')).status, 200);
  const impostor = await w.login('vera', { pull: true }, { id: 8 });   // another person now holds the name "vera"
  assert.equal((await w.call('GET', '/api/candidates', { user: impostor })).status, 403, 'a login match alone grants nothing');
  const renamed = await w.login('vera-new', { pull: true }, { id: 7 }); // the real account was renamed
  assert.equal((await w.call('GET', '/api/candidates', { user: renamed })).status, 200, 'the grant follows the immutable id');
  w.account('vera', 8); const conflict = await w.grant(ada, 'vera', 'VIEWER');
  assert.equal(conflict.status, 409); assert.match(conflict.data.error, /different GitHub account \(id 7\)/);
});

test('a legacy name-only grant authorizes nobody until an administrator re-validates the account and binds it to its immutable id', async () => {
  const w = await world(); const ada = await w.login('ada', { admin: true }); const lou = await w.login('lou', { pull: true }, { id: 55 });
  await w.db.prepare('INSERT INTO members (login, role, granted_by, at) VALUES (?,?,?,?)').bind('lou', 'ADMIN', 'old-admin', '2026-10-01T00:00:00.000Z').run();
  assert.equal((await w.call('POST', '/api/members', { user: lou, body: { user_id: 99, role: 'ADMIN', reason: 'x' } })).status, 403, 'a same-name account does not inherit the legacy ADMIN grant');
  const row = (await people(w, ada)).items.find((p) => p.login === 'lou'); assert.equal(row.state, 'unbound'); assert.equal(row.bound, false); assert.equal(row.effective_role, 'NONE', 'read-only on GitHub and the legacy ADMIN row is ignored');
  assert.equal((await w.grant(ada, 'lou', 'REVIEWER')).status, 200, 'the same role is accepted when it binds a legacy row');
  const after = (await people(w, ada)).items.find((p) => p.login === 'lou'); assert.equal(after.bound, true); assert.equal(after.user_id, 55); assert.equal(after.manual_role, 'REVIEWER');
  const d = JSON.parse((await auditRows(w.db, 100)).find((e) => e.action === 'member.set').detail); assert.equal(d.bound_legacy, true); assert.equal(d.from_role, 'ADMIN'); assert.equal(d.to_role, 'REVIEWER');
});

test('every membership change is audited with actor, account id, previous role, new role, reason and date; the history is readable', async () => {
  const w = await world(); const ada = await w.login('ada', { admin: true }); w.account('vera', 7);
  assert.equal((await w.grant(ada, 'vera', 'VIEWER', 'read access for the weekly review')).status, 200);
  assert.equal((await w.grant(ada, 'vera', 'REVIEWER', 'now reviews rules weekly')).status, 200);
  assert.equal((await w.grant(ada, 'vera', null, 'left the project')).status, 200);
  const entries = (await auditRows(w.db, 100)).filter((e) => e.action === 'member.set'); assert.equal(entries.length, 3);
  const d = entries.map((e) => JSON.parse(e.detail)); assert.deepEqual(d.map((x) => [x.from_role, x.to_role]), [[null, 'VIEWER'], ['VIEWER', 'REVIEWER'], ['REVIEWER', null]]);
  assert.ok(d.every((x) => x.user_id === 7 && x.login === 'vera' && x.reason.length >= 5 && Number.isInteger(x.actor_id) && x.actor_id === d[0].actor_id)); assert.ok(entries.every((e) => e.actor === 'ada' && e.target === 'user:7' && /T/.test(e.at)));
  assert.equal((await verifyChain(await auditRows(w.db, 100))).ok, true);
  const h = (await w.call('GET', '/api/members/7/history?login=vera', { user: ada })).data.history; assert.deepEqual(h.map((x) => x.to_role), [null, 'REVIEWER', 'VIEWER']);
  assert.equal((await people(w, ada)).items.find((p) => p.login === 'vera').state, 'revoked');
  assert.equal((await w.grant(ada, 'vera', 'VIEWER', '')).status, 400, 'a reason is mandatory');
  assert.equal((await w.grant(ada, 'vera', null, 'once more')).status, 409, 'nothing left to revoke');
});

test('privilege escalation is refused by the server: self-change by id, REVIEWER and VIEWER callers, non-user accounts, forged ids', async () => {
  const w = await world(); const ada = await w.login('ada', { admin: true }); const rita = await w.login('rita', { push: true }); w.account('bot-org', 70, 'Organization'); w.account('vera', 7);
  const self = (id) => w.call('POST', '/api/members', { user: ada, body: { user_id: id, role: 'VIEWER', reason: 'trying my luck' } });
  assert.equal((await self((await w.call('GET', '/api/me', { user: ada })).data.user_id)).status, 400);
  for (const call of [() => w.grant(rita, 'vera', 'ADMIN'), () => w.call('GET', '/api/members', { user: rita }), () => w.call('GET', '/api/members/7/history', { user: rita })]) assert.equal((await call()).status, 403);
  assert.equal((await w.call('POST', '/api/members', { body: { user_id: 7, role: 'ADMIN', reason: 'anonymous' } })).status, 401);
  assert.equal((await w.grant(ada, 'bot-org', 'VIEWER')).status, 400, 'only personal accounts');
  assert.equal((await w.call('POST', '/api/members', { user: ada, body: { user_id: 99999, role: 'VIEWER', reason: 'no such account' } })).status, 404, 'the server resolves the id itself');
  assert.equal((await w.call('POST', '/api/members', { user: ada, body: { login: 'vera', role: 'ADMIN', reason: 'legacy name-only request' } })).status, 400, 'the name-only form is gone');
  assert.equal((await w.call('POST', '/api/members', { user: ada, body: { user_id: 7, role: 'OWNER', reason: 'invalid role value' } })).status, 400);
  const noCsrf = await w.call('POST', '/api/members', { user: ada, csrf: false, body: { user_id: 7, role: 'VIEWER', reason: 'no csrf token' } }); assert.equal(noCsrf.status, 403);
  assert.equal(await w.db.prepare('SELECT COUNT(*) AS n FROM members').first().then((r) => r.n), 0);
});

test('the last administrator who cannot be removed from the panel is protected, counting GitHub admins and internal grants', async () => {
  const w = await world(); const ada = await w.login('ada', { admin: true });   // GitHub repository admin: durable
  w.account('dmu', 21); assert.equal((await w.grant(ada, 'dmu', 'ADMIN', 'second administrator')).status, 200);
  assert.equal((await w.grant(ada, 'dmu', 'VIEWER', 'step down')).status, 200, 'a durable GitHub admin remains');
  // only internal grants left: removing the only one must be refused atomically, whatever the caller's source of admin
  await w.db.prepare("DELETE FROM members").run(); await w.db.prepare("INSERT INTO members (login, role, granted_by, at, user_id) VALUES ('solo','ADMIN','x','t',31)").run();
  const before = (await auditRows(w.db, 100)).length;
  const r = await store.changeMember(w.db, { account: { id: 31, login: 'solo' }, role: null, reason: 'cleanup', actor: { login: 'ghost', id: 99, role: 'ADMIN' }, durableAdmin: false }, new Date().toISOString());
  assert.equal(r.status, 409); assert.match(r.error, /last administrator/);
  assert.equal((await w.db.prepare("SELECT role FROM members WHERE user_id = 31").first()).role, 'ADMIN'); assert.equal((await auditRows(w.db, 100)).length, before, 'no audit entry for a change that did not happen');
  await w.db.prepare("INSERT INTO members (login, role, granted_by, at, user_id) VALUES ('duo','ADMIN','x','t',32)").run();
  assert.equal((await store.changeMember(w.db, { account: { id: 31, login: 'solo' }, role: null, reason: 'cleanup', actor: { login: 'ghost', id: 99, role: 'ADMIN' }, durableAdmin: false }, new Date().toISOString())).status, 200);
});

test('the member list separates authorized, unauthorized sign-ins and revoked accounts, with origin and last access, and never exposes tokens', async () => {
  const w = await world(); const ada = await w.login('ada', { admin: true }); const rita = await w.login('rita', { push: true }); const sam = await w.login('sam', { pull: true }, { id: 300 });
  w.account('vera', 7); await w.grant(ada, 'vera', 'VIEWER'); await w.grant(ada, 'vera', null, 'left the project');
  for (const [login, id] of [['ada', 101], ['rita', 102], ['sam', 300]]) await store.appendAudit(w.db, { actor: login, role: 'NONE', action: 'session.login', target: 'session', detail: { user_id: id } }, '2026-10-20T10:00:00.000Z');
  await w.call('GET', '/api/candidates', { user: rita }); await w.call('GET', '/api/candidates', { user: sam });   // their GitHub permission is read and remembered
  w.account('both', 400); await w.grant(ada, 'both', 'ADMIN'); const both = await w.login('both', { push: true }, { id: 400 }); await w.call('GET', '/api/candidates', { user: both });
  const all = await people(w, ada); const by = (l) => all.items.find((p) => p.login === l);
  assert.equal(by('ada').state, 'authorized'); assert.equal(by('ada').origin, 'repo'); assert.equal(by('ada').effective_role, 'ADMIN');
  assert.equal(by('rita').origin, 'repo'); assert.equal(by('rita').effective_role, 'REVIEWER'); assert.equal(by('rita').last_login, '2026-10-20T10:00:00.000Z');
  assert.equal(by('sam').state, 'unauthorized'); assert.equal(by('sam').effective_role, 'NONE');
  assert.equal(by('vera').state, 'revoked'); assert.equal(by('both').origin, 'both'); assert.equal(by('both').effective_role, 'ADMIN');
  assert.deepEqual([all.counts.authorized, all.counts.unauthorized, all.counts.revoked], [3, 1, 1]);
  assert.deepEqual((await people(w, ada, '?status=revoked')).items.map((p) => p.login), ['vera']);
  assert.deepEqual((await people(w, ada, '?q=@RIT')).items.map((p) => p.login), ['rita']); assert.equal((await people(w, ada, '?q=300')).items[0].login, 'sam');
  assert.equal((await people(w, ada, '?pageSize=2&page=2')).items.length, 2);
  assert.doesNotMatch(JSON.stringify(all), /tok-|v1\.|csrf|"token"/i); assert.ok(both && sam && rita);
});

test('migration 0002 upgrades a v1 database in place, keeps every decision and audit row, archives only the synthetic candidates and can be rolled back', async () => {
  const db = new DatabaseSync(':memory:'); db.exec(readFileSync(SCHEMA_V1, 'utf8'));
  const t = '2026-10-20T00:00:00.000Z'; const ins = db.prepare('INSERT INTO candidates (id, sha256, path, name, source, detected_at, state, updated_at) VALUES (?,?,?,?,?,?,?,?)');
  const S1 = ['680aae67-48ce-4bd1-bbd3-627f4bee53da', '4fa1288eb21c0c29772c5da12cde20a357536ad16f491d1206f8ec35b9e87ad7'];
  ins.run(S1[0], S1[1], 'synthetic-quarantine-test/s1.yar', 's1.yar', 'synthetic-test', t, 'UNDER_REVIEW', t); ins.run('r1', 'b'.repeat(64), 'rules/x/real.yar', 'real.yar', 'nextron', t, 'PENDING', t);
  ins.run('look-alike', 'c'.repeat(64), 'synthetic-quarantine-test/s9.yar', 's9.yar', 'synthetic-test', t, 'PENDING', t);   // same source and path pattern, not one of the four ids
  db.prepare("INSERT INTO decisions (candidate_id, sha256, action, from_state, to_state, candidate_version, actor, role, reason, request_id, at) VALUES (?, ?, 'hold','PENDING','UNDER_REVIEW',2,'dmuinoo','REVIEWER','Es una prueba','req_x',?)").run(S1[0], S1[1], t);
  db.prepare("INSERT INTO members (login, role, granted_by, at) VALUES ('old','VIEWER','adm',?)").run(t);
  const snap = () => JSON.stringify([db.prepare('SELECT * FROM decisions').all(), db.prepare('SELECT * FROM audit').all(), db.prepare('SELECT id, sha256, state, version FROM candidates ORDER BY id').all()]);
  const before = snap(); db.exec(readFileSync(new URL('0002_member_identity.sql', MIG), 'utf8'));
  const cols = (d, tb) => d.prepare(`SELECT name, type FROM pragma_table_info('${tb}')`).all().map((c) => `${c.name}:${c.type}`).sort();
  const fresh = new DatabaseSync(':memory:'); fresh.exec(readFileSync(new URL('../schema.sql', import.meta.url), 'utf8'));
  for (const tb of ['members', 'candidates', 'sessions', 'decisions', 'audit']) assert.deepEqual(cols(db, tb), cols(fresh, tb), `${tb} matches a fresh install`);
  assert.deepEqual(db.prepare('SELECT id FROM candidates WHERE archived_at IS NOT NULL').all().map((r) => r.id), [S1[0]], 'only the exact synthetic candidate; a look-alike and a real rule stay visible');
  assert.equal(snap().replace(/"archived_at":"[^"]*"/g, ''), before.replace(/"archived_at":"[^"]*"/g, ''), 'decisions, audit and candidate state/version untouched');
  assert.deepEqual(db.prepare("SELECT login, role, user_id FROM members").all().map((r) => ({ ...r })), [{ login: 'old', role: 'VIEWER', user_id: null }]);
  db.exec(readFileSync(new URL('0002_rollback.sql', MIG), 'utf8')); for (const tb of ['members', 'candidates']) assert.deepEqual(cols(db, tb), cols(new (class { prepare(q) { const d = new DatabaseSync(':memory:'); d.exec(readFileSync(SCHEMA_V1, 'utf8')); return d.prepare(q); } })(), tb));
  assert.equal(snap(), before, 'rollback restores the v1 shape without touching append-only data');
});

test('archived candidates leave every operational view (list, counts, public stats, pipeline decisions) while their decisions stay', async () => {
  const { w, ids } = await seeded(['a', 'b']); const rita = await w.login('rita', { push: true }); w.reviewer = rita; const v = await versions(w, ids);
  assert.equal((await decide(w, rita, { action: 'reject', ids: [ids[0]], reason: 'synthetic check', request_id: rid(), expect: { [ids[0]]: v[ids[0]] } })).status, 200);
  const dm = async () => (await w.call('GET', '/api/pipeline/decisions', { bearer: await w.pipelineToken('daily.yml') })).data.decisions;
  assert.equal(Object.keys(await dm()).length, 1);
  await w.db.prepare('UPDATE candidates SET archived_at = ? WHERE id = ?').bind('2026-10-20T00:00:00.000Z', ids[0]).run();
  assert.equal((await w.call('GET', '/api/candidates', { user: rita })).data.total, 1);
  assert.equal((await w.call('GET', '/api/stats', { user: rita })).data.counts.REJECTED, undefined);
  assert.equal((await w.call('GET', '/public/stats')).data.rejected, 0); assert.deepEqual(await dm(), {});
  assert.equal((await w.call('GET', `/api/candidates/${ids[0]}`, { user: rita })).data.decisions.length, 1, 'the decision is still readable by id');
  assert.equal((await w.db.prepare('SELECT COUNT(*) AS n FROM decisions').first()).n, 1);
});

// ---- sign-in screen states are real server states --------------------------------------------------------------------------------------
test('a person without a role can only learn that and sign out; a declined or failed GitHub login returns to the sign-in screen with a reason', async () => {
  const w = await world(); const nobody = await w.login('nobody', { pull: true });
  const me = await w.call('GET', '/api/me', { user: nobody }); assert.equal(me.status, 403); assert.equal(me.data.code, 'no_access'); assert.equal(me.data.login, 'nobody'); assert.ok(me.data.csrf);
  assert.doesNotMatch(JSON.stringify(me.data), /counts|candidates|members/);
  for (const [m, p] of [['GET', '/api/candidates'], ['GET', '/api/stats'], ['GET', '/api/audit'], ['GET', '/api/members']]) { const r = await w.call(m, p, { user: nobody }); assert.equal(r.status, 403); assert.equal(r.data.code, 'no_access'); }
  const out = await w.call('POST', '/api/logout', { user: { ...nobody, csrf: me.data.csrf } }); assert.equal(out.status, 200);
  assert.equal((await w.call('GET', '/api/me', { user: nobody })).data.code, 'signin');
  const start = await handle(new Request(ORIGIN + '/auth/login'), w.env, w.deps); const state = new URL(start.headers.get('Location')).searchParams.get('state');
  const jar = { headers: { Cookie: `__Host-mg_oauth=${state}` } };
  const declined = await handle(new Request(`${ORIGIN}/auth/callback?error=access_denied&state=${state}`, jar), w.env, w.deps); assert.equal(declined.headers.get('Location'), '/?e=cancelled');
  const start2 = await handle(new Request(ORIGIN + '/auth/login'), w.env, w.deps); const s2 = new URL(start2.headers.get('Location')).searchParams.get('state');
  const refused = await handle(new Request(`${ORIGIN}/auth/callback?code=bad&state=${s2}`, { headers: { Cookie: `__Host-mg_oauth=${s2}` } }), w.env, w.deps); assert.equal(refused.headers.get('Location'), '/?e=oauth');
  const old = await w.login('old', { push: true }); w.tick(9 * 3600); assert.equal((await w.call('GET', '/api/me', { user: old })).data.code, 'signin');
  const rev = await w.login('rev', { push: true }); delete w.perms['tok-rev']; w.tick(61); const r = await w.call('GET', '/api/candidates', { user: rev }); assert.equal(r.data.code, 'reauth');
  delete w.env.TOKEN_ENC_KEY; const down = await handle(new Request(`${ORIGIN}/auth/callback?code=c&state=${s2}`), w.env, w.deps); assert.match(down.headers.get('Location'), /^\/\?e=/);
});

test('the audit API pages newest first, filters by action family and actor, and returns the parsed detail', async () => {
  const { w, ids } = await seeded(['a', 'b', 'c']); const rita = await w.login('rita', { push: true }); w.reviewer = rita; const v = await versions(w, ids);
  await decide(w, rita, { action: 'hold', ids: [ids[0]], reason: 'looking closer', request_id: rid(), expect: { [ids[0]]: v[ids[0]] } });
  await decide(w, rita, { action: 'reject', ids: [ids[1]], reason: 'broken regex', request_id: rid(), expect: { [ids[1]]: v[ids[1]] } });
  const all = (await w.call('GET', '/api/audit?limit=2', { user: rita })).data; assert.equal(all.entries.length, 2); assert.equal(all.has_more, true); assert.ok(all.entries[0].seq > all.entries[1].seq);
  assert.equal(all.entries[0].action, 'decision.reject'); assert.equal(all.entries[0].detail.reason, 'broken regex');
  const next = (await w.call('GET', `/api/audit?limit=50&before=${all.next_before}`, { user: rita })).data; assert.ok(next.entries.every((e) => e.seq < all.next_before));
  const dec = (await w.call('GET', '/api/audit?family=decision', { user: rita })).data.entries; assert.deepEqual(dec.map((e) => e.action), ['decision.reject', 'decision.hold']);
  assert.equal((await w.call('GET', '/api/audit?actor=nobody', { user: rita })).data.entries.length, 0);
  assert.equal((await w.call('GET', '/api/audit?family=%25', { user: rita })).status, 200);
  const stats = (await w.call('GET', '/api/stats', { user: rita })).data; assert.deepEqual(stats.sources, { nextron: 3 });
});

test('a candidate with a technical finding is not approvable: the server refuses the approval, all-or-nothing, and says why; reject and hold stay possible', async () => {
  const w = await world(); const rita = await w.login('rita', { push: true }); w.reviewer = rita;
  const r = await w.submit([cand('ok', 'rules/x/ok.yar', { reasons: ['costly-regex', 'matches-benign-corpus'] }), cand('trunc', 'rules/x/trunc.yar', { reasons: ['ends-mid-file'] }), cand('dyn', 'rules/x/dyn.yar', { reasons: ['costly-regex', 'dynamic-failure'] }), cand('none', 'rules/x/none.yar', { reasons: [] })]);
  const [ok, trunc, dyn, none] = r.data.results.map((x) => x.id); const v = await versions(w, [ok, trunc, dyn, none]);
  const list = (await w.call('GET', '/api/candidates?pageSize=50', { user: rita })).data.items; const by = (id) => list.find((c) => c.id === id);
  assert.deepEqual([ok, trunc, dyn, none].map((i) => by(i).approvable), [true, false, false, true]); assert.deepEqual(by(trunc).blocking, ['ends-mid-file']); assert.deepEqual(by(dyn).blocking, ['dynamic-failure']);
  const auditBefore = (await auditRows(w.db, 500)).length;
  const refused = await decide(w, rita, { action: 'approve', ids: [ok, trunc], reason: 'approve both', request_id: rid(), expect: { [ok]: v[ok], [trunc]: v[trunc] }, confirm_count: 2 });
  assert.equal(refused.status, 409); assert.deepEqual(refused.data.conflicts.map((c) => [c.id, c.code]), [[trunc, 'not_approvable']]); assert.match(refused.data.conflicts[0].error, /ends-mid-file/);
  assert.equal(await state(w, ok), 'PENDING', 'the approvable one in the same batch was not applied either'); assert.equal(await state(w, trunc), 'PENDING');
  assert.equal((await auditRows(w.db, 500)).length, auditBefore, 'a refused approval writes neither a decision nor an audit entry');
  assert.equal((await decide(w, rita, { action: 'approve', ids: [dyn], reason: 'dynamic failure', request_id: rid(), expect: { [dyn]: v[dyn] } })).status, 409);
  assert.equal((await decide(w, rita, { action: 'approve', ids: [ok, none], reason: 'both are judgement-only', request_id: rid(), expect: { [ok]: v[ok], [none]: v[none] }, confirm_count: 2 })).status, 200);
  assert.equal((await decide(w, rita, { action: 'reject', ids: [trunc], reason: 'truncated upstream', request_id: rid(), expect: { [trunc]: v[trunc] } })).status, 200);
  assert.equal((await decide(w, rita, { action: 'hold', ids: [dyn], reason: 'wait for upstream fix', request_id: rid(), expect: { [dyn]: v[dyn] } })).status, 200);
  const approved = (await w.call('GET', '/api/pipeline/decisions', { bearer: await w.pipelineToken('daily.yml') })).data.decisions;
  assert.deepEqual(Object.keys(approved).sort(), [ok, none, trunc].map((i) => by(i).sha256).sort(), 'the pipeline hears only about the two approvals and the rejection');
  assert.equal(approved[by(trunc).sha256].state, 'REJECTED'); assert.equal(approved[by(dyn).sha256], undefined);
});

test('the panel waivable list is exactly the one scripts/decide.py enforces when the pipeline applies decisions', async () => {
  const { WAIVABLE } = await import('../src/core.js');
  const py = readFileSync(new URL('../../../scripts/decide.py', import.meta.url), 'utf8').match(/^WAIVABLE = \{([^}]*)\}/m);
  assert.ok(py, 'WAIVABLE found in decide.py'); const codes = [...py[1].matchAll(/'([a-z-]+)'/g)].map((m) => m[1]).sort();
  assert.deepEqual([...WAIVABLE].sort(), codes);
});

test('the sheet says whether an approval will take effect; the server refuses one that never can and counts a joint approval', async () => {
  const w = await world(); const rita = await w.login('rita', { push: true }); w.reviewer = rita;
  const r = await w.submit([cand('cap', 'rules/x/cap.yar', { reasons: ['matches-benign-corpus'] }),
    cand('d1', 'rules/x/d1.yar', { reasons: ['dependency-not-validated'], depends_on: ['rules/x/cap.yar'] }), cand('d2', 'rules/x/d2.yar', { reasons: ['dependency-not-validated'], depends_on: ['rules/x/cap.yar'] }),
    cand('bad', 'rules/x/bad.yar', { reasons: ['blocked-module'] }), cand('x', 'rules/x/x.yar', { reasons: ['dependency-not-validated'], depends_on: ['rules/x/bad.yar'] })]);
  const [cap, d1, d2, bad, x] = r.data.results.map((i) => i.id); const v = await versions(w, [cap, d1, d2, bad, x]);
  const dep = async (id) => (await w.call('GET', `/api/candidates/${id}`, { user: rita })).data.dependencies;
  const c = await dep(cap); assert.equal(c.effect, 'effective'); assert.deepEqual(c.would_return.map((q) => q.path).sort(), ['rules/x/d1.yar', 'rules/x/d2.yar']); assert.ok(c.dependents.every((q) => q.returns && q.own_blockers.length === 0));
  const a = await dep(d1); assert.equal(a.effect, 'conditional'); assert.deepEqual(a.needs_approval_of, ['rules/x/cap.yar']); assert.equal(a.required[0].status, 'needs_approval'); assert.deepEqual(a.required[0].reasons, ['matches-benign-corpus']);
  const b = await dep(x); assert.equal(b.effect, 'ineffective'); assert.equal(b.blocked_by, 'rules/x/bad.yar'); assert.equal(b.required[0].status, 'blocked'); assert.deepEqual(b.required[0].blocking, ['blocked-module']);
  assert.equal((await dep(bad)).effect, 'not_approvable'); assert.equal((await dep(bad)).dependents[0].returns, false, 'approving what cannot be approved brings nothing back');
  const audit0 = (await auditRows(w.db, 500)).length;
  const refused = await decide(w, rita, { action: 'approve', ids: [x, cap], reason: 'try both', request_id: rid(), expect: { [x]: v[x], [cap]: v[cap] }, confirm_count: 2 });
  assert.equal(refused.status, 409); assert.deepEqual(refused.data.conflicts.map((q) => [q.id, q.code, q.blocked_by]), [[x, 'dependency_blocked', 'rules/x/bad.yar']]);
  assert.equal(await state(w, cap), 'PENDING', 'all or nothing'); assert.equal((await auditRows(w.db, 500)).length, audit0, 'a refused approval leaves no audit entry');
  assert.equal((await decide(w, rita, { action: 'approve', ids: [d1], reason: 'dependent first', request_id: rid(), expect: { [d1]: v[d1] } })).status, 200, 'a conditional approval is allowed: it just does nothing yet');
  assert.equal((await dep(d1)).effect, 'conditional', 'still waiting for the file it needs');
  assert.equal((await decide(w, rita, { action: 'approve', ids: [cap, d2], reason: 'the file and a dependent together', request_id: rid(), expect: { [cap]: v[cap], [d2]: v[d2] }, confirm_count: 2 })).status, 200);
  const after = await dep(d1); assert.equal(after.effect, 'effective'); assert.equal(after.required[0].status, 'approved');
  assert.equal((await dep(d2)).effect, 'effective');
});

test('the panel never calls an approval effective when decide.py leaves the file out: the same scenarios as the pipeline suite', async () => {
  const sc = JSON.parse(readFileSync(new URL('../../../tests/fixtures/dependency_scenarios.json', import.meta.url), 'utf8')).scenarios; let checked = 0;
  const rowsFor = (s, approved) => s.panel.map((p) => ({ id: p.path, path: p.path, state: approved.includes(p.path) ? 'APPROVED_PENDING_VALIDATION' : 'PENDING', reasons: p.reasons, depends_on: p.deps, detected_at: '2026-10-20' }));
  for (const s of sc) for (const k of s.cases) {
    const panelPaths = s.panel.map((p) => p.path), inPanel = k.included.filter((q) => panelPaths.includes(q)).sort();
    // everything the reviewer approved is already approved: the effect of each approval must match what decide.py publishes
    for (const x of k.approve.filter((q) => panelPaths.includes(q))) {
      const d = dependencyEffect(rowsFor(s, k.approve), x), published = k.included.includes(x);
      assert.equal(d.effect === 'effective', published, `${s.name} / approved ${k.approve}: effect of ${x} is ${d.effect} but decide.py ${published ? 'publishes' : 'leaves out'} it`); checked++;
    }
    // one approval about to be made: what the sheet promises it brings back is exactly what the pipeline then publishes among the panel files
    if (k.approve.length === 1 && panelPaths.includes(k.approve[0])) {
      const d = dependencyEffect(rowsFor(s, []), k.approve[0]);
      if (d.effect === 'effective') assert.deepEqual([k.approve[0], ...d.would_return.map((q) => q.path)].sort(), inPanel, `${s.name} / approve ${k.approve}: what would return`);
      else assert.deepEqual(inPanel, [], `${s.name} / approve ${k.approve}: the sheet says it will not take effect, so nothing from the panel is published`);
      checked++;
    }
  }
  assert.ok(checked >= 15, `checked ${checked}`);
});

test('every pipeline receipt records the run and attempt from the verified token; a retry is told apart and creates nothing', async () => {
  const w = await world(); const rita = await w.login('rita', { push: true }); w.reviewer = rita;
  const items = [cand('p', 'rules/x/p.yar'), cand('q', 'rules/x/q.yar')];
  const send = async (attempt, runIdInBody = '777') => w.call('POST', '/api/pipeline/submit', { bearer: await w.pipelineToken('daily.yml', { run_id: '777', run_attempt: String(attempt) }), body: { run_id: runIdInBody, run_url: `${ORIGIN}/runs/777`, candidates: items } });
  const first = await send(1), retry = await send(2), third = await send(3, '999');
  assert.deepEqual([first.status, retry.status, third.status], [200, 200, 200]);
  assert.deepEqual(first.data.results.map((q) => q.status), ['created', 'created']); assert.deepEqual(retry.data.results.map((q) => q.status), ['known', 'known']);
  const rows = (await auditRows(w.db, 100)).filter((e) => e.action === 'pipeline.submit').map((e) => ({ target: e.target, ...JSON.parse(e.detail) }));
  assert.deepEqual(rows.map((q) => [q.receipt, q.run_attempt, q.token_run_id, q.created, q.count]), [['first', 1, '777', 2, 2], ['idempotent_retry', 2, '777', 0, 2], ['idempotent_retry', 3, '777', 0, 2]]);
  assert.equal(rows[2].target, '999', 'what the body claims is kept as it was, and the verified token run is recorded next to it');
  const list = (await w.call('GET', '/api/candidates?pageSize=50', { user: rita })).data; assert.equal(list.total, 2, 'no duplicates after three receipts'); assert.ok(list.items.every((q) => q.version === 1));
  assert.equal((await verifyChain(await auditRows(w.db, 100))).ok, true, 'the chain still verifies');
});
