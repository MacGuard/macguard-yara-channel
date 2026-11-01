// Adversarial regressions for the six HIGH findings of the review of #53 (Codex, batch pr53-expedited-publication, round 1):
// F1 a transition committed without its event/audit; F2 a daily request APPLIED with no publication evidence; F3 an expedited request APPLIED by an
// unrelated release; F4 a completed emergency that can no longer be reviewed; F5 publication operations without a recent sign-in;
// F6 a workflow run reporting on (and overwriting) another run's request. Each test fails on 3b900b9.
import test from 'node:test';
import assert from 'node:assert/strict';
import { world, cand, rid } from './helpers.js';
import { verifyChain } from '../src/core.js';
import { auditRows } from '../src/store.js';
import * as P from '../src/publication_requests.js';

const chainOk = async (w) => assert.equal((await verifyChain(await auditRows(w.db, 5000))).ok, true, 'the audit chain verifies');
async function fx() {
  const w = await world(); const sub = await w.submit([cand('a'), cand('b'), cand('c')]); assert.equal(sub.status, 200); const ids = sub.data.results.map((x) => x.id);
  w.ada = await w.login('ada', { admin: true }, { id: 9001 }); w.bob = await w.login('bob', { admin: true }, { id: 9002 }); w.rita = await w.login('rita', { push: true }, { id: 9003 });
  for (const [l, id] of [['sam', 9004], ['pat', 9005]]) w.account(l, id);
  for (const [l, role] of [['sam', 'SECURITY_ADMIN'], ['pat', 'PUBLISHER']]) assert.equal((await w.grant(w.ada, l, role)).status, 200, l);
  w.sam = await w.login('sam', { pull: true }, { id: 9004 }); w.pat = await w.login('pat', { pull: true }, { id: 9005 });
  for (const u of [w.ada, w.bob, w.rita, w.sam, w.pat]) await w.call('GET', '/api/me', { user: u });
  for (const id of ids.slice(0, 2)) { const c = (await w.call('GET', `/api/candidates/${id}`, { user: w.rita })).data; const r = await w.call('POST', '/api/decisions', { user: w.rita, body: { action: 'approve', ids: [id], expect: { [id]: c.version }, reason: 'reviewed by a person', request_id: rid() } }); assert.equal(r.status, 200, JSON.stringify(r.data)); }
  w.dispatches = []; w.env.GITHUB_DISPATCH_TOKEN = 'dispatch-token-for-tests'; w.route(/\/actions\/workflows\/publish-expedited\.yml\/dispatches$/, (url, init) => { w.dispatches.push({ url, init }); return new Response(null, { status: 204 }); });
  w.ids = ids; w.v = async (id) => (await w.call('GET', `/api/candidates/${id}`, { user: w.ada })).data.version;
  w.entry = (id) => { const r = w.db.raw.prepare('SELECT path, sha256, bytes FROM candidates WHERE id = ?').get(id); return { path: r.path, sha256: r.sha256, bytes: r.bytes }; };
  return w;
}
const body = async (w, id, over = {}) => ({ mode: 'SCHEDULED', action: 'PUBLISH', resource_kind: 'yara_rule', resource_id: id, resource_version: await w.v(id), request_id: rid(), reason: 'publish this approved rule', ...over });
const expedite = async (w, user, id) => w.call('POST', '/api/publication-requests', { user, body: await body(w, id, { mode: 'EXPEDITED', reason: 'a customer reports the rule is needed today', confirm: id }) });
const rows = (w, sql, ...a) => w.db.raw.prepare(sql).all(...a).map((r) => ({ ...r }));
/** a report signed by the OIDC token of run `run` (attempt 1 unless given) */
const report = async (w, id, b, run = '555', attempt = 1) => w.call('POST', `/api/pipeline/expedite/${id}/report`, { bearer: await w.pipelineToken('publish-expedited.yml', { run_id: run, run_attempt: String(attempt) }), body: { run_id: run, ...b } });   // the body states the same run as the token unless a test says otherwise
const toVerifying = async (w, id, run = '555') => { for (const st of ['RUNNING', 'VALIDATING', 'SIGNING', 'PUBLISHING', 'VERIFYING']) { const r = await report(w, id, { state: st }, run); assert.equal(r.status, 200, `${st} ${JSON.stringify(r.data)}`); } };
/** the database, except that the first write matching `re` fails (alone or inside a batch: a batch is one transaction, so it fails as a whole) */
function faulty(db, re) {
  let armed = true;
  return { ...db, prepare: (sql) => { const s = db.prepare(sql); if (re.test(sql)) { const run = s.run.bind(s); s.run = async () => { if (armed) { armed = false; throw new Error('D1_ERROR: injected failure'); } return run(); }; s._poison = true; } return s; },
    batch: async (list) => { if (armed && list.some((s) => s._poison)) { armed = false; throw new Error('D1_ERROR: injected failure'); } return db.batch(list); } };
}

// ---- F1 ----
for (const [what, re] of [['its event', /INSERT INTO publication_request_events/], ['its audit entry', /INSERT INTO audit/]]) {
  test(`F1: if ${what} cannot be written, the transition is not committed either (QUEUED stays QUEUED, nothing half-written)`, async () => {
    const w = await fx(); const ex = (await expedite(w, w.pat, w.ids[0])).data.request; assert.equal(ex.state, 'QUEUED');
    const ev0 = rows(w, 'SELECT COUNT(*) AS n FROM publication_request_events WHERE request_id = ?', ex.id)[0].n, au0 = rows(w, 'SELECT COUNT(*) AS n FROM audit')[0].n;
    const db = faulty(w.db, re); let threw = false, r = null;
    try { r = await P.cancel(db, ex.id, { reason: 'no longer needed' }, { login: 'pat', id: 9005, role: 'PUBLISHER', roles: ['PUBLISHER'] }, new Date().toISOString()); } catch { threw = true; }
    assert.ok(threw || r.status !== 200, 'the failure is reported'); const cur = await P.get(w.db, ex.id);
    assert.equal(cur.state, 'QUEUED', 'the state did not move without its evidence'); assert.equal(cur.version, ex.version);
    assert.equal(rows(w, 'SELECT COUNT(*) AS n FROM publication_request_events WHERE request_id = ?', ex.id)[0].n, ev0); assert.equal(rows(w, 'SELECT COUNT(*) AS n FROM audit')[0].n, au0);
    const again = await P.cancel(w.db, ex.id, { reason: 'no longer needed' }, { login: 'pat', id: 9005, role: 'PUBLISHER', roles: ['PUBLISHER'] }, new Date().toISOString()); assert.equal(again.status, 200, 'a retry works');
    assert.equal(rows(w, "SELECT COUNT(*) AS n FROM publication_request_events WHERE request_id = ? AND to_state = 'CANCELLED'", ex.id)[0].n, 1); await chainOk(w);
  });
}
test('F1: a request whose creation event cannot be written is not created', async () => {
  const w = await fx(); const db = faulty(w.db, /INSERT INTO publication_request_events/); const b = await body(w, w.ids[0]); let threw = false, r = null;
  try { r = await P.create(db, b, { login: 'pat', id: 9005, role: 'PUBLISHER', roles: ['PUBLISHER'] }, new Date().toISOString(), { uuid: () => '00000000-0000-4000-8000-0000000000f1', env: {} }); } catch { threw = true; }
  assert.ok(threw || r.status !== 200); assert.equal(rows(w, 'SELECT COUNT(*) AS n FROM publication_requests')[0].n, 0, 'no request without its evidence');
});

// ---- F2 ----
test('F2: the daily run cannot close a scheduled request without publication evidence: no tag, an unknown tag, or a release without the exact rule', async () => {
  const w = await fx(); const sch = (await w.call('POST', '/api/publication-requests', { user: w.pat, body: await body(w, w.ids[0]) })).data.request; assert.equal(sch.state, 'PENDING');
  const daily = await w.pipelineToken('daily.yml', { run_id: '777', run_attempt: '1' }); const applied = (b) => w.call('POST', '/api/pipeline/publication-requests/applied', { bearer: daily, body: b });
  for (const b of [{ ids: [sch.id] }, { ids: [sch.id], run_id: '777' }, { ids: [sch.id], run_id: '777', release_tag: 'rules-20261101-1' }]) {
    const r = await applied(b); assert.ok(r.status !== 200 || !(r.data.applied || []).includes(sch.id), `not applied: ${JSON.stringify(b)} -> ${JSON.stringify(r.data)}`);
  }
  await w.release('rules-20261101-2', [w.entry(w.ids[1])]);   // a real public release, but without the requested rule
  const other = await applied({ ids: [sch.id], run_id: '777', release_tag: 'rules-20261101-2' }); assert.ok(!(other.data.applied || []).includes(sch.id), JSON.stringify(other.data));
  assert.equal((await P.get(w.db, sch.id)).state, 'PENDING', 'still pending: the next run can apply it');
  await w.release('rules-20261101-3', [w.entry(w.ids[0])]);
  const ok = await applied({ ids: [sch.id], release_tag: 'rules-20261101-3' }); assert.deepEqual(ok.data.applied, [sch.id], JSON.stringify(ok.data));
  const row = await P.get(w.db, sch.id); assert.equal(row.state, 'APPLIED'); assert.equal(row.release_tag, 'rules-20261101-3'); assert.equal(row.run_id, '777', 'the run id comes from the signed token');
  assert.equal(rows(w, 'SELECT state FROM candidates WHERE id = ?', w.ids[0])[0].state, 'RELEASED', 'the effective state was synced from the verified release'); await chainOk(w);
});

// ---- F3 ----
test('F3: an expedited request is not APPLIED by a valid public release that does not contain the requested rule', async () => {
  const w = await fx(); const ex = (await expedite(w, w.pat, w.ids[0])).data.request; await toVerifying(w, ex.id);
  await w.release('rules-20261020-1', [w.entry(w.ids[1])]);   // older, valid, unrelated
  const r = await report(w, ex.id, { state: 'APPLIED', release_tag: 'rules-20261020-1', commit_sha: 'a'.repeat(40) }); assert.notEqual(r.data.request && r.data.request.state, 'APPLIED', JSON.stringify(r.data));
  assert.equal(rows(w, 'SELECT state FROM candidates WHERE id = ?', w.ids[0])[0].state, 'APPROVED_PENDING_VALIDATION');
  const w2 = await fx(); const e2 = (await expedite(w2, w2.pat, w2.ids[0])).data.request; await toVerifying(w2, e2.id);
  await w2.release('rules-20261101-5', [w2.entry(w2.ids[0])]);
  const ok = await report(w2, e2.id, { state: 'APPLIED', release_tag: 'rules-20261101-5', commit_sha: 'a'.repeat(40) }); assert.equal(ok.data.request.state, 'APPLIED', JSON.stringify(ok.data));
  assert.equal(rows(w2, 'SELECT state FROM candidates WHERE id = ?', w2.ids[0])[0].state, 'RELEASED', 'synced before APPLIED'); await chainOk(w2);
});

// ---- F4 ----
async function emergencyRun(w) {
  const id = w.ids[0], pid = '33333333-3333-4333-8333-333333333333';
  w.db.raw.prepare("INSERT INTO policies (id, scope, scope_key, source, path, sha256, candidate_id, criticality, kind, author, author_id, author_role, reason, created_at, request_id, baseline_tag, baseline_published_at, baseline_manifest_sha256, baseline_rules_root, status, withdrawal, version, updated_at) VALUES (?,'path','path:s:r','s','r',?,?,'CRITICAL','WITHDRAWAL','ada',9001,'ADMIN','reported as unsafe','2026-10-26T10:00:00Z','req-policy-0000000003','t','2026-10-25T00:00:00Z',?,?,'ACTIVE','REQUESTED',1,'2026-10-26T10:00:00Z')").run(pid, 'a'.repeat(64), id, 'b'.repeat(64), 'c'.repeat(64));
  const r = await w.call('POST', '/api/publication-requests', { user: w.ada, body: { mode: 'EXPEDITED', action: 'WITHDRAW', resource_kind: 'policy', resource_id: pid, resource_version: 1, request_id: rid(), reason: 'incident: the only other administrator is unreachable', confirm: pid } });
  const rq = r.data.request.id, ada = { login: 'ada', id: 9001, role: 'ADMIN', roles: ['ADMIN'] }, now = new Date().toISOString(), later = new Date(Date.now() + 31 * 60 * 1000).toISOString();
  assert.equal((await P.emergency(w.db, rq, { reason: 'the only other administrator is unreachable and a dangerous detection is live now', no_second_approver: true }, ada, now)).status, 200);
  assert.equal((await P.executeEmergency(w.db, rq, ada, later, { dispatch: async () => ({ ok: true }) })).status, 200); return { rq, later };
}
const sam = { login: 'sam', id: 9004, role: 'SECURITY_ADMIN', roles: ['SECURITY_ADMIN'] };
test('F4: a FAILED emergency still receives its mandatory review (append-only), exactly once, by a third identity', async () => {
  const w = await fx(); const { rq, later } = await emergencyRun(w);
  assert.equal((await report(w, rq, { state: 'RUNNING' }, '901')).status, 200); assert.equal((await report(w, rq, { state: 'FAILED', failure_reason: 'signature verification failed' }, '901')).data.request.state, 'FAILED');
  const rv = await P.review(w.db, rq, { outcome: 'APPROPRIATE', reason: 'justified by the incident' }, sam, later); assert.equal(rv.status, 200, JSON.stringify(rv.body));
  assert.equal(rv.body.review.outcome, 'APPROPRIATE'); assert.equal(rv.body.request.state, 'FAILED', 'the closed request itself is not reopened');
  assert.equal((await P.review(w.db, rq, { outcome: 'INAPPROPRIATE', reason: 'second opinion' }, sam, later)).status, 409, 'one review');
  assert.throws(() => w.db.raw.prepare("UPDATE publication_request_reviews SET outcome = 'INAPPROPRIATE'").run(), /append-only/); await chainOk(w);
});
test('F4: an APPLIED emergency keeps its emergency evidence and can still be reviewed', async () => {
  const w = await fx(); const { rq, later } = await emergencyRun(w); await toVerifying(w, rq, '902');
  // the release that confirms the withdrawal: published after the baseline, without the withdrawn path
  await w.release('rules-20261101-7', [w.entry(w.ids[1])], { publishedAt: '2026-11-01T03:40:00Z' });
  const ap = await report(w, rq, { state: 'APPLIED', release_tag: 'rules-20261101-7', commit_sha: 'c'.repeat(40) }, '902'); assert.equal(ap.data.request.state, 'APPLIED', JSON.stringify(ap.data));
  assert.ok(ap.data.request.evidence.emergency && ap.data.request.evidence.emergency.executed_at, 'the emergency metadata survives completion');
  const rv = await P.review(w.db, rq, { outcome: 'APPROPRIATE', reason: 'justified by the incident' }, sam, later); assert.equal(rv.status, 200, JSON.stringify(rv.body));
});

// ---- F5 ----
test('F5: approving, executing an emergency and asking for an expedited run need a recent sign-in, like every critical operation', async () => {
  const w = await fx(); const ex = (await w.call('POST', '/api/publication-requests', { user: w.pat, body: await body(w, w.ids[0], { mode: 'EXPEDITED', action: 'PUBLISH', reason: 'a customer reports the rule is needed today', confirm: w.ids[0] }) }));
  assert.equal(ex.status, 200); w.tick(Number(w.env.CRITICAL_REAUTH_S || 1800) + 60);
  const late = await expedite(w, w.pat, w.ids[1]); assert.equal(late.status, 401, JSON.stringify(late.data)); assert.equal(late.data.code, 'reauth_required');
  const ap = await w.call('POST', `/api/publication-requests/${ex.data.request.id}/approve`, { user: w.bob, body: { reason: 'authorised', expect_version: 1 } }); assert.equal(ap.status, 401); assert.equal(ap.data.code, 'reauth_required');
  for (const step of ['emergency', 'execute-emergency', 'review', 'dispatch']) assert.equal((await w.call('POST', `/api/publication-requests/${ex.data.request.id}/${step}`, { user: w.ada, body: {} })).data.code, 'reauth_required', step);
});

// ---- F6 ----
test('F6: a run reports only on the request it claimed: another run cannot advance, fail or re-label it, and the run id comes from the token', async () => {
  const w = await fx(); const a = (await expedite(w, w.pat, w.ids[0])).data.request, b = (await expedite(w, w.pat, w.ids[1])).data.request;
  assert.equal((await report(w, a.id, { state: 'RUNNING' }, '1001')).status, 200); assert.equal((await report(w, b.id, { state: 'RUNNING' }, '2002')).status, 200);
  for (const st of [{ state: 'VALIDATING' }, { state: 'FAILED', failure_reason: 'sabotage' }, { state: 'BLOCKED', blocked_reason: 'sabotage' }]) {
    const r = await report(w, b.id, st, '1001'); assert.equal(r.status, 403, `${JSON.stringify(st)} ${JSON.stringify(r.data)}`);
  }
  assert.equal((await report(w, b.id, { state: 'VALIDATING' }, '2002', 2)).status, 403, 'another attempt of the same run is another execution');
  assert.equal((await report(w, b.id, { state: 'VALIDATING', run_id: '1001' }, '2002')).status, 400, 'a body run id different from the token is refused');
  const cur = await P.get(w.db, b.id); assert.equal(cur.state, 'RUNNING'); assert.equal(cur.run_id, '2002');
  assert.equal((await report(w, b.id, { state: 'VALIDATING' }, '2002')).status, 200, 'its own run continues');
});
test('F6: a report without a run identity in the token is refused', async () => {
  const w = await fx(); const a = (await expedite(w, w.pat, w.ids[0])).data.request;
  const r = await w.call('POST', `/api/pipeline/expedite/${a.id}/report`, { bearer: await w.pipelineToken('publish-expedited.yml'), body: { state: 'RUNNING', run_id: '42' } }); assert.equal(r.status, 403, JSON.stringify(r.data));
  assert.equal((await P.get(w.db, a.id)).state, 'QUEUED');
});
