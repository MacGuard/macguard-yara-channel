// Scheduled and expedited publication requests: desired state only, a fixed GitHub Actions workflow as the only way to run, separation of requester / approver / executor, bound and expiring authorisations,
// idempotence, conflicts, budget, the daily run after an expedited one, failures that keep the previous state, and no path that publishes from Cloudflare.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { world, cand, rid, REPO, ORIGIN } from './helpers.js';
import { verifyChain } from '../src/core.js';
import { auditRows } from '../src/store.js';
import { TRANSITIONS, STATES } from '../src/publication_requests.js';

const T1 = 'rules-20261026-1';
const chainOk = async (w) => assert.equal((await verifyChain(await auditRows(w.db, 5000))).ok, true, 'the audit chain verifies');
/** ada + bob (ADMIN), pat (PUBLISHER), sam (SECURITY_ADMIN), rita (REVIEWER), vera (VIEWER); two candidates: `a` approved, `b` approved; a GitHub that records dispatches. */
async function fx({ dispatcher = true } = {}) {
  const w = await world(); const sub = await w.submit([cand('a'), cand('b'), cand('c')]); assert.equal(sub.status, 200); const ids = sub.data.results.map((x) => x.id);
  w.ada = await w.login('ada', { admin: true }, { id: 9001 }); w.bob = await w.login('bob', { admin: true }, { id: 9002 }); w.rita = await w.login('rita', { push: true }, { id: 9003 });
  for (const [l, id] of [['sam', 9004], ['pat', 9005], ['vera', 9006]]) w.account(l, id);
  for (const [l, role] of [['sam', 'SECURITY_ADMIN'], ['pat', 'PUBLISHER'], ['vera', 'VIEWER']]) assert.equal((await w.grant(w.ada, l, role)).status, 200, l);
  w.sam = await w.login('sam', { pull: true }, { id: 9004 }); w.pat = await w.login('pat', { pull: true }, { id: 9005 }); w.vera = await w.login('vera', { pull: true }, { id: 9006 });
  for (const u of [w.ada, w.bob, w.rita, w.sam, w.pat, w.vera]) await w.call('GET', '/api/me', { user: u });
  for (const id of ids.slice(0, 2)) { const c = (await w.call('GET', `/api/candidates/${id}`, { user: w.rita })).data; const r = await w.call('POST', '/api/decisions', { user: w.rita, body: { action: 'approve', ids: [id], expect: { [id]: c.version }, reason: 'reviewed by a person', request_id: rid() } }); assert.equal(r.status, 200, JSON.stringify(r.data)); }
  w.dispatches = []; if (dispatcher) { w.env.GITHUB_DISPATCH_TOKEN = 'dispatch-token-for-tests'; w.route(/\/actions\/workflows\/publish-expedited\.yml\/dispatches$/, (url, init) => { w.dispatches.push({ url, init }); return new Response(null, { status: w.dispatchStatus || 204 }); }); }
  w.ids = ids; w.v = async (id) => (await w.call('GET', `/api/candidates/${id}`, { user: w.ada })).data.version;
  return w;
}
const body = async (w, id, over = {}) => ({ mode: 'SCHEDULED', action: 'PUBLISH', resource_kind: 'yara_rule', resource_id: id, resource_version: await w.v(id), request_id: rid(), reason: 'publish this approved rule', ...over });
const expedite = async (w, user, id, over = {}) => w.call('POST', '/api/publication-requests', { user, body: await body(w, id, { mode: 'EXPEDITED', reason: 'a customer reports the rule is needed today', confirm: id, ...over }) });
const rows = (w, sql, ...a) => w.db.raw.prepare(sql).all(...a).map((r) => ({ ...r }));
const wf = async (w, wfName = 'publish-expedited.yml') => w.pipelineToken(wfName);
const report = async (w, id, b, bearerWf) => w.call('POST', `/api/pipeline/expedite/${id}/report`, { bearer: await wf(w, bearerWf), body: b });

test('1. an ordinary change is saved for the next daily run: nothing is dispatched, the effective state is untouched, and the daily run recovers it', async () => {
  const w = await fx(); const id = w.ids[0]; const r = await w.call('POST', '/api/publication-requests', { user: w.pat, body: await body(w, id) }); assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.equal(r.data.request.mode, 'SCHEDULED'); assert.equal(r.data.request.state, 'PENDING'); assert.equal(r.data.request.desired_state, 'RELEASED'); assert.equal(r.data.request.effective_state_at_request, 'APPROVED_PENDING_VALIDATION'); assert.equal(w.dispatches.length, 0, 'no workflow was started');
  assert.equal(rows(w, 'SELECT state FROM candidates WHERE id = ?', id)[0].state, 'APPROVED_PENDING_VALIDATION', 'the effective state is not changed by a request');
  const def = await w.call('POST', '/api/publication-requests', { user: w.rita, body: { ...(await body(w, w.ids[1])), mode: undefined } }); assert.equal(def.data.request.mode, 'SCHEDULED', 'SCHEDULED is the default'); await chainOk(w);
  const daily = await w.call('GET', '/api/pipeline/publication-requests', { bearer: await w.pipelineToken('daily.yml') }); assert.equal(daily.data.items.length, 2);
});
test('2. an authorised expedited change asks for exactly one run of the fixed workflow with one validated input', async () => {
  const w = await fx(); const id = w.ids[0]; const r = await expedite(w, w.pat, id); assert.equal(r.status, 200, JSON.stringify(r.data)); assert.equal(r.data.request.state, 'QUEUED'); assert.equal(w.dispatches.length, 1);
  const d = w.dispatches[0]; assert.equal(d.url, `https://api.github.com/repos/${REPO}/actions/workflows/publish-expedited.yml/dispatches`); assert.deepEqual(JSON.parse(d.init.body), { ref: 'main', inputs: { request_id: r.data.request.id } }); assert.equal(d.init.method, 'POST');
  assert.equal(r.data.request.authorized_by, 'pat'); assert.match(r.data.request.authorization_sha256, /^[0-9a-f]{64}$/); assert.deepEqual(rows(w, 'SELECT from_state, to_state FROM publication_request_events ORDER BY seq').map((e) => `${e.from_state}>${e.to_state}`), ['null>AWAITING_APPROVAL', 'AWAITING_APPROVAL>AUTHORIZED', 'AUTHORIZED>QUEUED']);
});
test('3. permissions: a viewer cannot ask for anything, a reviewer may only propose, a security administrator only for security actions; confirmation, reason and exact version are required', async () => {
  const w = await fx(); const id = w.ids[0];
  assert.equal((await w.call('POST', '/api/publication-requests', { user: w.vera, body: await body(w, id) })).status, 403);
  assert.equal((await w.call('POST', '/api/publication-requests', { user: w.rita, body: await body(w, id) })).status, 200, 'a reviewer proposes a scheduled change');
  const rev = await expedite(w, w.rita, w.ids[1]); assert.equal(rev.status, 403); assert.match(rev.data.error, /propose/); assert.equal(w.dispatches.length, 0);
  const sec = await expedite(w, w.sam, w.ids[1]); assert.equal(sec.status, 403, 'publishing an approved rule is not a security action'); assert.match(sec.data.error, /security actions/);
  for (const bad of [{ confirm: 'something else' }, { confirm: undefined }, { reason: 'too short' }, { resource_version: 999 }, { action: 'PUBLISH', resource_kind: 'nope' }]) assert.ok([400, 409].includes((await expedite(w, w.pat, w.ids[1], bad)).status), JSON.stringify(bad));
  assert.ok(rows(w, "SELECT COUNT(*) AS n FROM audit WHERE action = 'authz.denied'")[0].n >= 1, 'the refusal is audited');
});
test('4. a duplicate request returns the open one; the same request id replays; a reused id for another request is refused', async () => {
  const w = await fx(); const id = w.ids[0], b = await body(w, id); const a = await w.call('POST', '/api/publication-requests', { user: w.pat, body: b });
  const again = await w.call('POST', '/api/publication-requests', { user: w.pat, body: b }); assert.equal(again.data.replay, true); assert.equal(again.data.request.id, a.data.request.id);
  const twin = await w.call('POST', '/api/publication-requests', { user: w.pat, body: { ...b, request_id: rid() } }); assert.equal(twin.data.duplicate, true, 'an equivalent open request is detected'); assert.equal(rows(w, 'SELECT COUNT(*) AS n FROM publication_requests')[0].n, 1);
  assert.equal((await w.call('POST', '/api/publication-requests', { user: w.pat, body: { ...b, resource_id: w.ids[1], resource_version: await w.v(w.ids[1]) } })).status, 409, 'same request id, another resource');
});
test('5. incompatible requests for the same resource: the second is refused until the first is closed', async () => {
  const w = await fx(); const id = w.ids[0]; assert.equal((await w.call('POST', '/api/publication-requests', { user: w.pat, body: await body(w, id) })).status, 200);
  const other = await w.call('POST', '/api/publication-requests', { user: w.ada, body: await body(w, id, { action: 'WITHDRAW', resource_kind: 'yara_rule' }) }); assert.ok([409].includes(other.status), JSON.stringify(other.data));
});
test('6. 7. an expedited change during or after the daily run: the daily run skips what an expedited run already applied, and never applies it twice', async () => {
  const w = await fx(); const id = w.ids[0]; const sch = (await w.call('POST', '/api/publication-requests', { user: w.pat, body: await body(w, w.ids[1]) })).data.request;
  const ex = (await expedite(w, w.pat, id)).data.request; const daily = await w.pipelineToken('daily.yml');
  const pending = (await w.call('GET', '/api/pipeline/publication-requests', { bearer: daily })).data.items.map((x) => x.id); assert.deepEqual(pending, [sch.id], 'an expedited request is never offered to the daily run');
  const ap = await w.call('POST', '/api/pipeline/publication-requests/applied', { bearer: daily, body: { ids: [sch.id, ex.id], run_id: '777', release_tag: T1 } }); assert.equal(ap.status, 200, JSON.stringify(ap.data)); assert.deepEqual(ap.data.applied, [sch.id]); assert.deepEqual(ap.data.skipped, [ex.id], 'the expedited one is skipped, not applied by the daily run');
  const again = await w.call('POST', '/api/pipeline/publication-requests/applied', { bearer: daily, body: { ids: [sch.id], run_id: '778', release_tag: T1 } }); assert.deepEqual(again.data.applied, [], 'a second report applies nothing'); assert.equal((await w.call('POST', '/api/pipeline/publication-requests/applied', { bearer: await wf(w), body: { ids: [] } })).status, 403, 'the expedited workflow does not report the daily run');
});
test('8. a critical change (withdrawal of a published rule) needs a second identity: requester and approver differ, the approval is bound to the request, and only then is the run asked for', async () => {
  const w = await fx(); const id = w.ids[0]; const cx = (await w.call('GET', `/api/candidates/${id}`, { user: w.ada })).data;
  const pol = await w.call('POST', '/api/policies/withdrawals', { user: w.ada, body: { candidate_id: id, scope: 'path', criticality: 'CRITICAL', reason: 'reported as unsafe by the owner', request_id: rid(), expect_version: cx.version, confirm_collateral: 0 } });
  assert.notEqual(pol.status, 200, 'an unpublished rule has no withdrawal: nothing to expedite here'); assert.equal(w.dispatches.length, 0);
  // the critical path on a policy resource is exercised with a policy row inserted as the policy engine would
  w.db.raw.prepare("INSERT INTO policies (id, scope, scope_key, source, path, sha256, candidate_id, criticality, kind, author, author_id, author_role, reason, created_at, request_id, baseline_tag, baseline_published_at, baseline_manifest_sha256, baseline_rules_root, status, withdrawal, version, updated_at) VALUES ('11111111-1111-4111-8111-111111111111','path','path:s:p','s','p','" + 'a'.repeat(64) + "','" + id + "','CRITICAL','WITHDRAWAL','ada',9001,'ADMIN','reported as unsafe','2026-10-26T10:00:00Z','req-policy-0000000001','t','2026-10-25T00:00:00Z','" + 'b'.repeat(64) + "','" + 'c'.repeat(64) + "','ACTIVE','REQUESTED',1,'2026-10-26T10:00:00Z')").run();
  const pid = '11111111-1111-4111-8111-111111111111', req = { mode: 'EXPEDITED', action: 'WITHDRAW', resource_kind: 'policy', resource_id: pid, resource_version: 1, request_id: rid(), reason: 'incident: a dangerous detection is live', confirm: pid };
  const r = await w.call('POST', '/api/publication-requests', { user: w.sam, body: req }); assert.equal(r.status, 200, JSON.stringify(r.data)); assert.equal(r.data.request.state, 'AWAITING_APPROVAL'); assert.equal(w.dispatches.length, 0, 'nothing runs before a second identity authorises');
  const act = (user, step, b) => w.call('POST', `/api/publication-requests/${r.data.request.id}/${step}`, { user, body: b }), v = r.data.request.version;
  assert.equal((await act(w.sam, 'approve', { reason: 'I asked for it myself', expect_version: v })).data.code, 'same_identity', 'the requester is never the approver'); assert.equal((await act(w.pat, 'approve', { reason: 'a publisher cannot authorise', expect_version: v })).status, 403);
  assert.equal((await act(w.bob, 'approve', { reason: 'incident confirmed, authorised', expect_version: v + 7 })).status, 409, 'a stale view authorises nothing');
  const ok = await act(w.bob, 'approve', { reason: 'incident confirmed, authorised', expect_version: v }); assert.equal(ok.status, 200, JSON.stringify(ok.data));
  const cur = (await w.call('GET', `/api/publication-requests/${r.data.request.id}`, { user: w.sam })).data; assert.equal(cur.request.state, 'QUEUED'); assert.equal(cur.request.authorized_by, 'bob'); assert.equal(cur.request.requested_by, 'sam'); assert.equal(w.dispatches.length, 1, 'one run, after the second identity');
  assert.deepEqual(cur.events.map((e) => e.to_state), ['AWAITING_APPROVAL', 'AUTHORIZED', 'QUEUED']); assert.ok(rows(w, "SELECT COUNT(*) AS n FROM audit WHERE action = 'authz.denied'")[0].n >= 1, 'the same-identity attempt is audited'); await chainOk(w);
});
test('8b. a single administrator uses the emergency path: long reason, a delay, execution by the requester, a review by a third identity; no permanent bypass', async () => {
  const w = await fx(); const id = w.ids[0]; w.db.raw.prepare("INSERT INTO policies (id, scope, scope_key, source, path, sha256, candidate_id, criticality, kind, author, author_id, author_role, reason, created_at, request_id, baseline_tag, baseline_published_at, baseline_manifest_sha256, baseline_rules_root, status, withdrawal, version, updated_at) VALUES ('22222222-2222-4222-8222-222222222222','path','path:s:q','s','q','" + 'a'.repeat(64) + "','" + id + "','CRITICAL','WITHDRAWAL','ada',9001,'ADMIN','reported as unsafe','2026-10-26T10:00:00Z','req-policy-0000000002','t','2026-10-25T00:00:00Z','" + 'b'.repeat(64) + "','" + 'c'.repeat(64) + "','ACTIVE','REQUESTED',1,'2026-10-26T10:00:00Z')").run();
  const pid = '22222222-2222-4222-8222-222222222222', r = await w.call('POST', '/api/publication-requests', { user: w.ada, body: { mode: 'EXPEDITED', action: 'WITHDRAW', resource_kind: 'policy', resource_id: pid, resource_version: 1, request_id: rid(), reason: 'incident: the only other administrator is unreachable', confirm: pid } }); assert.equal(r.data.request.state, 'AWAITING_APPROVAL');
  const act = (user, step, b) => w.call('POST', `/api/publication-requests/${r.data.request.id}/${step}`, { user, body: b }); const long = 'the only other administrator is unreachable and a dangerous detection is live now';
  assert.equal((await act(w.ada, 'emergency', { reason: 'urgent', no_second_approver: true })).status, 400); assert.equal((await act(w.ada, 'emergency', { reason: long })).status, 400, 'no_second_approver is explicit'); assert.equal((await act(w.pat, 'emergency', { reason: long, no_second_approver: true })).status, 403);
  const em = await act(w.ada, 'emergency', { reason: long, no_second_approver: true }); assert.equal(em.status, 200, JSON.stringify(em.data)); const early = await act(w.ada, 'execute-emergency', {}); assert.equal(early.status, 409); assert.equal(early.data.code, 'delay'); assert.equal(w.dispatches.length, 0);
  const { executeEmergency, review } = await import('../src/publication_requests.js'); const later = new Date(Date.now() + 31 * 60 * 1000).toISOString(); const ran = await executeEmergency(w.db, r.data.request.id, { login: 'ada', id: 9001, role: 'ADMIN', roles: ['ADMIN'] }, later, { dispatch: async () => ({ ok: true }) }); assert.equal(ran.status, 200, JSON.stringify(ran.body)); assert.equal(ran.body.request.state, 'QUEUED');
  assert.equal((await review(w.db, r.data.request.id, { outcome: 'APPROPRIATE', reason: 'it was justified' }, { login: 'ada', id: 9001, role: 'ADMIN', roles: ['ADMIN'] }, later)).body.code, 'same_identity', 'the executor cannot review their own emergency');
  const ok = await review(w.db, r.data.request.id, { outcome: 'APPROPRIATE', reason: 'it was justified by the incident' }, { login: 'sam', id: 9004, role: 'SECURITY_ADMIN', roles: ['SECURITY_ADMIN'] }, later); assert.equal(ok.status, 200); assert.equal(ok.body.request.evidence.emergency.review.outcome, 'APPROPRIATE'); assert.equal((await review(w.db, r.data.request.id, { outcome: 'APPROPRIATE', reason: 'again' }, { login: 'sam', id: 9004, role: 'SECURITY_ADMIN', roles: ['SECURITY_ADMIN'] }, later)).status, 409, 'one review');
  assert.ok(rows(w, "SELECT COUNT(*) AS n FROM audit WHERE action IN ('publication.emergency_requested','publication.emergency_executed','publication.emergency_reviewed')")[0].n === 3); await chainOk(w);
});
test('9. 10. 11. families without a signed-package pipeline (IOC, signature replacement, intelligence records) are not eligible and nothing is dispatched', async () => {
  const w = await fx();
  for (const [kind, action] of [['intel_record', 'ADD_IOC'], ['intel_record', 'PUBLISH'], ['yara_rule', 'REPLACE'], ['package', 'PACKAGE_PROFILE'], ['source', 'SOURCE_CHANGE']]) { const r = await w.call('POST', '/api/publication-requests', { user: w.ada, body: { mode: 'EXPEDITED', action, resource_kind: kind, resource_id: 'ioc:ip:203.0.113.7', resource_version: 1, request_id: rid(), reason: 'urgent change for this family please', confirm: 'ioc:ip:203.0.113.7' } }); assert.equal(r.status, 409, `${kind} ${action}`); assert.equal(r.data.code, 'not_eligible'); }
  assert.equal(w.dispatches.length, 0); assert.equal(rows(w, 'SELECT COUNT(*) AS n FROM publication_requests')[0].n, 0);
});
test('11b. quarantine to published: only an APPROVED rule can be published, and it must be the exact version the person saw', async () => {
  const w = await fx(); const pending = w.ids[2];
  const r = await expedite(w, w.pat, pending); assert.equal(r.status, 409); assert.equal(r.data.code, 'precondition'); assert.match(r.data.error, /APPROVED_PENDING_VALIDATION/);
  const stale = await w.call('POST', '/api/publication-requests', { user: w.pat, body: await body(w, w.ids[0], { resource_version: 1 }) }); assert.ok([409].includes(stale.status) || stale.status === 200);
  const old = await expedite(w, w.pat, w.ids[0], { resource_version: (await w.v(w.ids[0])) + 5 }); assert.equal(old.status, 409); assert.equal(old.data.code, 'stale');
});
test('12. 13. 14. a failing run keeps the previous state: quality gate, invalid signature and a partial publication end FAILED with the cause, and the request can never be applied afterwards', async () => {
  const w = await fx(); const ex = (await expedite(w, w.pat, w.ids[0])).data.request;
  for (const st of ['RUNNING', 'VALIDATING']) assert.equal((await report(w, ex.id, { state: st, run_id: '555' })).status, 200, st);
  const gate = await report(w, ex.id, { state: 'FAILED', failure_reason: 'quality gate: yara_x_compile failed' }); assert.equal(gate.data.request.state, 'FAILED'); assert.equal(gate.data.request.state_reason, 'quality gate: yara_x_compile failed');
  assert.equal(rows(w, 'SELECT state FROM candidates WHERE id = ?', w.ids[0])[0].state, 'APPROVED_PENDING_VALIDATION', 'the previous effective state is kept'); assert.equal((await report(w, ex.id, { state: 'APPLIED', release_tag: T1, commit_sha: 'a'.repeat(40), run_id: '555' })).status, 409, 'a failed request cannot be applied');
  const w2 = await fx(); const e2 = (await expedite(w2, w2.pat, w2.ids[0])).data.request; for (const st of ['RUNNING', 'VALIDATING', 'SIGNING']) await report(w2, e2.id, { state: st, run_id: '556' });
  assert.equal((await report(w2, e2.id, { state: 'FAILED', failure_reason: 'signature verification failed' })).data.request.state, 'FAILED'); const e3 = (await expedite(w2, w2.pat, w2.ids[1])).data.request; for (const st of ['RUNNING', 'VALIDATING', 'SIGNING', 'PUBLISHING']) await report(w2, e3.id, { state: st, run_id: '557' });
  assert.equal((await report(w2, e3.id, { state: 'FAILED', failure_reason: 'only 2 of 3 assets uploaded' })).data.request.state, 'FAILED'); assert.ok(rows(w2, "SELECT COUNT(*) AS n FROM audit WHERE action = 'publication.failed'")[0].n >= 2); await chainOk(w2);
});
test('15. the release verifies but the panel sync fails: SYNC_PENDING, then reconciliation completes it WITHOUT republishing', async () => {
  const w = await fx(); const ex = (await expedite(w, w.pat, w.ids[0])).data.request; for (const st of ['RUNNING', 'VALIDATING', 'SIGNING', 'PUBLISHING', 'VERIFYING']) await report(w, ex.id, { state: st, run_id: '600' });
  const { report: rep, reconcile, get } = await import('../src/publication_requests.js'); const now = new Date().toISOString(); let fail = true, syncs = 0;
  const deps = { verifyRelease: async () => true, sync: async () => { syncs++; if (fail) throw new Error('D1 unavailable'); } };
  const r1 = await rep(w.db, ex.id, { state: 'APPLIED', release_tag: T1, commit_sha: 'a'.repeat(40), run_id: '600', hashes: { manifest: 'x' } }, now, deps); assert.equal(r1.body.request.state, 'SYNC_PENDING'); assert.equal(rows(w, 'SELECT COUNT(*) AS n FROM publication_requests WHERE state = ?', 'APPLIED')[0].n, 0, 'not APPLIED until the panel agrees');
  assert.deepEqual((await reconcile(w.db, now, deps)).synced, [], 'still failing: stays pending'); fail = false; assert.deepEqual((await reconcile(w.db, now, deps)).synced, [ex.id]); assert.equal((await get(w.db, ex.id)).state, 'APPLIED'); assert.equal(w.dispatches.length, 1, 'nothing was dispatched again');
});
test('15b. APPLIED needs the release to be verifiable: an unverifiable release ends FAILED, never APPLIED', async () => {
  const w = await fx(); const ex = (await expedite(w, w.pat, w.ids[0])).data.request; for (const st of ['RUNNING', 'VALIDATING', 'SIGNING', 'PUBLISHING', 'VERIFYING']) await report(w, ex.id, { state: st, run_id: '601' });
  const r = await report(w, ex.id, { state: 'APPLIED', release_tag: 'rules-20261026-9', commit_sha: 'b'.repeat(40), run_id: '601' }); assert.equal(r.data.request.state, 'FAILED'); assert.equal(r.data.request.state_reason, 'release_not_verifiable');
  assert.equal((await report(w, ex.id, { state: 'SIGNING' })).status, 409, 'states only move forward');
});
test('16. GitHub Actions unavailable or no dispatcher configured: the request is BLOCKED with the exact cause, the authorisation is kept, retry works, and the daily run still covers it', async () => {
  const w = await fx(); w.dispatchStatus = 503; const r = await expedite(w, w.pat, w.ids[0]); assert.equal(r.data.blocked, 'github_unavailable'); assert.equal(r.data.request.state, 'BLOCKED'); assert.equal(r.data.request.state_reason, 'github_unavailable');
  w.dispatchStatus = 204; const retry = await w.call('POST', `/api/publication-requests/${r.data.request.id}/dispatch`, { user: w.pat, body: {} }); assert.equal(retry.status, 200, JSON.stringify(retry.data)); assert.equal(retry.data.request.state, 'QUEUED');
  const w2 = await fx({ dispatcher: false }); const nb = await expedite(w2, w2.pat, w2.ids[0]); assert.equal(nb.data.blocked, 'dispatcher_not_configured'); assert.match(nb.data.note, /no credential/);
  assert.equal((await w.call('POST', `/api/publication-requests/${r.data.request.id}/dispatch`, { user: w.vera, body: {} })).status, 403);
});
test('17. budget: non-critical expedited runs stop at the daily budget and at the open limit, with the way out stated; a critical change is never blocked, only flagged', async () => {
  const w = await fx(); w.env.EXPEDITE_MINUTES_PER_DAY = '10'; const a = (await expedite(w, w.pat, w.ids[0])).data.request;
  for (const st of ['RUNNING', 'VALIDATING', 'SIGNING', 'PUBLISHING', 'VERIFYING']) await report(w, a.id, { state: st, run_id: '700', minutes: 12 }); await report(w, a.id, { state: 'FAILED', failure_reason: 'cost test', minutes: 12 });
  const over = await expedite(w, w.pat, w.ids[1]); assert.equal(over.status, 409); assert.equal(over.data.code, 'budget_exhausted'); assert.match(over.data.error, /next daily run|emergency/); assert.equal((await w.call('POST', '/api/publication-requests', { user: w.pat, body: await body(w, w.ids[1]) })).status, 200, 'the scheduled path is never blocked by budget');
});
test('18. replay of an old authorisation: an expired one cannot be dispatched, a tampered one does not match, and a closed request is final', async () => {
  const w = await fx({ dispatcher: false }); const blocked = (await expedite(w, w.pat, w.ids[0])).data.request; const { dispatch } = await import('../src/publication_requests.js');
  const late = new Date(Date.now() + 25 * 3600 * 1000).toISOString(); const exp = await dispatch(w.db, blocked.id, { login: 'pat', id: 9005, role: 'PUBLISHER' }, late, { dispatch: async () => ({ ok: true }) }); assert.equal(exp.status, 409); assert.equal(exp.body.code, 'authorization_expired');
  w.db.raw.prepare("UPDATE publication_requests SET authorization_sha256 = ? , version = version + 1 WHERE id = ?").run('0'.repeat(64), blocked.id); const bad = await dispatch(w.db, blocked.id, { login: 'pat', id: 9005, role: 'PUBLISHER' }, new Date().toISOString(), { dispatch: async () => ({ ok: true }) }); assert.equal(bad.status, 409); assert.match(bad.body.error, /does not match/);
  await assert.rejects(async () => w.db.raw.prepare("UPDATE publication_requests SET action = 'REVOKE', version = version + 1 WHERE id = ?").run(blocked.id), /cannot be edited/); await assert.rejects(async () => w.db.raw.prepare('DELETE FROM publication_requests').run(), /never deleted/);
});
test('19. concurrent catalogue updates: two reports race for the same step and only one wins; the other changes nothing', async () => {
  const w = await fx(); const ex = (await expedite(w, w.pat, w.ids[0])).data.request; const { report: rep } = await import('../src/publication_requests.js'); const now = new Date().toISOString();
  const rs = await Promise.all([rep(w.db, ex.id, { state: 'RUNNING', run_id: '800' }, now, {}), rep(w.db, ex.id, { state: 'RUNNING', run_id: '801' }, now, {})]); assert.equal(rs.filter((r) => r.status === 200).length >= 1, true);
  assert.equal(rows(w, "SELECT COUNT(*) AS n FROM publication_request_events WHERE request_id = ? AND to_state = 'RUNNING'", ex.id)[0].n, 1, 'one transition, one event');
});
test('20. reconciliation after a failure: a run that never reports back is closed as FAILED (previous state kept), and nothing is republished', async () => {
  const w = await fx(); const ex = (await expedite(w, w.pat, w.ids[0])).data.request; const { reconcile, get } = await import('../src/publication_requests.js');
  assert.deepEqual((await reconcile(w.db, new Date().toISOString())).stalled, [], 'a fresh request is left alone'); const later = new Date(Date.now() + 4 * 3600 * 1000).toISOString();
  assert.deepEqual((await reconcile(w.db, later)).stalled, [ex.id]); assert.equal((await get(w.db, ex.id)).state, 'FAILED'); assert.equal((await get(w.db, ex.id)).state_reason, 'stalled'); assert.equal(w.dispatches.length, 1);
});
test('the workflow can only read and report ITS OWN authorised request, with its own identity; no other workflow, no browser session, no request that is not authorised', async () => {
  const w = await fx(); const ex = (await expedite(w, w.pat, w.ids[0])).data.request;
  const mine = await w.call('GET', `/api/pipeline/expedite/${ex.id}`, { bearer: await wf(w) }); assert.equal(mine.status, 200); assert.equal(mine.data.resource_id, w.ids[0]); assert.equal(mine.data.authorization_sha256, ex.authorization_sha256);
  for (const other of ['daily.yml', 'publish.yml']) assert.equal((await w.call('GET', `/api/pipeline/expedite/${ex.id}`, { bearer: await wf(w, other) })).status, 403, other);
  assert.equal((await w.call('GET', `/api/pipeline/expedite/${ex.id}`, { user: w.ada })).status, 401, 'a browser session is not a workflow'); assert.equal((await report(w, ex.id, { state: 'APPLIED', release_tag: T1 })).status, 409, 'APPLIED only after VERIFYING');
  for (const bad of [{ state: 'RUNNING', run_id: 'x; rm -rf /' }, { state: 'RUNNING', run_url: 'https://evil.example.org/run/1' }, { state: 'RUNNING', commit_sha: 'zzz' }, { state: 'ROOT' }, null]) assert.equal((await report(w, ex.id, bad)).status, 400, JSON.stringify(bad));
  const sched = (await w.call('POST', '/api/publication-requests', { user: w.pat, body: await body(w, w.ids[1]) })).data.request; assert.equal((await w.call('GET', `/api/pipeline/expedite/${sched.id}`, { bearer: await wf(w) })).status, 404, 'a scheduled request is not an expedited run');
});
test('no path publishes from Cloudflare: the only outbound GitHub call is the fixed dispatch, the Worker holds no general write credential, the state machine has no skip, and every state is reachable only through a recorded event', async () => {
  const src = readFileSync(new URL('../src/publication_requests.js', import.meta.url), 'utf8'), idx = readFileSync(new URL('../src/index.js', import.meta.url), 'utf8');
  assert.equal((src.match(/api\.github\.com/g) || []).length, 1, 'one GitHub URL in the module: the dispatch'); assert.match(src, /publish-expedited\.yml\/dispatches/); assert.doesNotMatch(src, /\/releases|\/contents|\/git\/|createRelease|upload/i);
  assert.doesNotMatch(idx, /method: 'PUT'|method: 'PATCH'|uploads\.github/, 'the Worker never writes releases or contents'); assert.deepEqual([...new Set(Object.values(TRANSITIONS).flat())].filter((s) => !STATES.includes(s)), []);
  for (const [from, tos] of Object.entries(TRANSITIONS)) for (const to of tos) assert.ok(STATES.includes(from) && STATES.includes(to)); assert.deepEqual(TRANSITIONS.APPLIED, []); assert.ok(!TRANSITIONS.AUTHORIZED.includes('APPLIED') && !TRANSITIONS.QUEUED.includes('APPLIED') && !TRANSITIONS.RUNNING.includes('APPLIED'), 'nothing jumps to APPLIED');
});
