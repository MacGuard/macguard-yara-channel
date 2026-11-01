// F6 and F3 of the #53 review, closed for good. F6: a run executes ONLY the request the panel dispatched it for (request id + dispatch id in its run-name,
// dispatched by the panel's own identity, attempt 1, created after the dispatch, read back from GitHub), the claim is atomic and recorded once, and it fails closed.
// F3: only the ACTIVE authorised release (latest public, or one an authorised operation PINNED: an audited rollback) closes a request; an older release that lists
// the same path and SHA-256 does not. Synthetic data only; GitHub is faked (helpers.js world + publication_requests_runs.js).
import test from 'node:test';
import assert from 'node:assert/strict';
import { world, cand, rid } from './helpers.js';
import { verifyChain, rulesRoot } from '../src/core.js';
import { auditRows } from '../src/store.js';
import * as P from '../src/publication_requests.js';
import { DISPATCHER, bindRuns, ghRun, runToken, currentDispatchOf } from './publication_requests_runs.js';

const chainOk = async (w) => assert.equal((await verifyChain(await auditRows(w.db, 5000))).ok, true, 'the audit chain verifies');
const rows = (w, sql, ...a) => w.db.raw.prepare(sql).all(...a).map((r) => ({ ...r }));
async function fx() {
  const w = await world(); const sub = await w.submit([cand('a'), cand('b'), cand('c')]); assert.equal(sub.status, 200); const ids = sub.data.results.map((x) => x.id);
  w.ada = await w.login('ada', { admin: true }, { id: 9001 }); w.bob = await w.login('bob', { admin: true }, { id: 9002 }); w.rita = await w.login('rita', { push: true }, { id: 9003 });
  for (const [l, id] of [['sam', 9004], ['pat', 9005]]) w.account(l, id);
  for (const [l, role] of [['sam', 'SECURITY_ADMIN'], ['pat', 'PUBLISHER']]) assert.equal((await w.grant(w.ada, l, role)).status, 200, l);
  w.sam = await w.login('sam', { pull: true }, { id: 9004 }); w.pat = await w.login('pat', { pull: true }, { id: 9005 });
  for (const u of [w.ada, w.bob, w.rita, w.sam, w.pat]) await w.call('GET', '/api/me', { user: u });
  for (const id of ids.slice(0, 2)) { const c = (await w.call('GET', `/api/candidates/${id}`, { user: w.rita })).data; const r = await w.call('POST', '/api/decisions', { user: w.rita, body: { action: 'approve', ids: [id], expect: { [id]: c.version }, reason: 'reviewed by a person', request_id: rid() } }); assert.equal(r.status, 200); }
  w.dispatches = []; w.env.GITHUB_DISPATCH_TOKEN = 'dispatch-token-for-tests'; w.route(/\/actions\/workflows\/publish-expedited\.yml\/dispatches$/, (url, init) => { w.dispatches.push({ url, init }); return new Response(null, { status: w.dispatchStatus || 204 }); });
  bindRuns(w); w.ids = ids; w.v = async (id) => (await w.call('GET', `/api/candidates/${id}`, { user: w.ada })).data.version;
  w.entry = (id) => { const r = w.db.raw.prepare('SELECT path, sha256, bytes FROM candidates WHERE id = ?').get(id); return { path: r.path, sha256: r.sha256, bytes: r.bytes }; };
  return w;
}
const body = async (w, id, over = {}) => ({ mode: 'SCHEDULED', action: 'PUBLISH', resource_kind: 'yara_rule', resource_id: id, resource_version: await w.v(id), request_id: rid(), reason: 'publish this approved rule', ...over });
const expedite = async (w, id) => (await w.call('POST', '/api/publication-requests', { user: w.pat, body: await body(w, id, { mode: 'EXPEDITED', reason: 'a customer reports the rule is needed today', confirm: id }) })).data.request;
/** POST a report signed by the token of `run` (attempt, extra token claims); GitHub's view of the run is whatever the test registered with ghRun */
const send = async (w, id, b, run, attempt = 1, claims = {}) => w.call('POST', `/api/pipeline/expedite/${id}/report`, { bearer: await runToken(w, run, attempt, claims), body: { run_id: String(run), ...b } });
const claims = (w, id) => rows(w, 'SELECT run_id, run_attempt FROM publication_request_claims WHERE request_id = ?', id);
const toVerifying = async (w, id, run) => { if (!w.ghRuns.has(String(run))) ghRun(w, run, id); for (const st of ['RUNNING', 'VALIDATING', 'SIGNING', 'PUBLISHING', 'VERIFYING']) { const r = await send(w, id, { state: st }, run); assert.equal(r.status, 200, `${st} ${JSON.stringify(r.data)}`); } };

// ---------------------------------------------------------------- F6 ----------------------------------------------------------------
test('F6: a run dispatched for request A cannot claim request B (both queued); it claims A, and B stays free for its own run', async () => {
  const w = await fx(); const a = await expedite(w, w.ids[0]), b = await expedite(w, w.ids[1]); assert.equal(a.state, 'QUEUED'); assert.equal(b.state, 'QUEUED');
  ghRun(w, 3001, a.id); const r = await send(w, b.id, { state: 'RUNNING' }, 3001);
  assert.equal(r.status, 403, JSON.stringify(r.data)); assert.equal(r.data.code, 'run_not_bound'); assert.deepEqual(r.data.failed, ['run_name']);
  assert.equal((await P.get(w.db, b.id)).state, 'QUEUED'); assert.deepEqual(claims(w, b.id), [], 'no claim recorded');
  assert.equal((await send(w, a.id, { state: 'RUNNING' }, 3001)).status, 200, 'its own request'); ghRun(w, 3002, b.id); assert.equal((await send(w, b.id, { state: 'RUNNING' }, 3002)).status, 200);
  assert.deepEqual(claims(w, a.id), [{ run_id: '3001', run_attempt: 1 }]); await chainOk(w);
});
test('F6: two bound runs racing for the same dispatch: exactly one claim, one transition, one event (the other changes nothing)', async () => {
  const w = await fx(); const a = await expedite(w, w.ids[0]); ghRun(w, 3101, a.id); ghRun(w, 3102, a.id);
  const rs = await Promise.all([send(w, a.id, { state: 'RUNNING' }, 3101), send(w, a.id, { state: 'RUNNING' }, 3102)]);
  assert.equal(rs.filter((r) => r.status === 200).length, 1, JSON.stringify(rs.map((r) => r.data))); assert.equal(claims(w, a.id).length, 1);
  assert.equal(rows(w, "SELECT COUNT(*) AS n FROM publication_request_events WHERE request_id = ? AND to_state = 'RUNNING'", a.id)[0].n, 1);
  const loser = rs.find((r) => r.status !== 200), winner = claims(w, a.id)[0].run_id, other = winner === '3101' ? 3102 : 3101;
  assert.ok([403, 409].includes(loser.status)); assert.equal((await send(w, a.id, { state: 'VALIDATING' }, other)).status, 403, 'the loser cannot report afterwards either'); await chainOk(w);
});
test('F6: replay: the same claim again changes nothing, and a run that claimed one request cannot claim another, even with a matching run-name', async () => {
  const w = await fx(); const a = await expedite(w, w.ids[0]), b = await expedite(w, w.ids[1]); ghRun(w, 3201, a.id);
  assert.equal((await send(w, a.id, { state: 'RUNNING' }, 3201)).status, 200); const v1 = (await P.get(w.db, a.id)).version;
  assert.equal((await send(w, a.id, { state: 'RUNNING' }, 3201)).status, 409, 'a replayed RUNNING is refused'); assert.equal((await P.get(w.db, a.id)).version, v1);
  ghRun(w, 3201, b.id);   // even if GitHub showed B's run-name for that run id, one run executes one request
  const r = await send(w, b.id, { state: 'RUNNING' }, 3201); assert.equal(r.status, 403); assert.equal(r.data.code, 'run_already_claimed'); assert.deepEqual(claims(w, b.id), []);
  assert.throws(() => w.db.raw.prepare("UPDATE publication_request_claims SET run_id = '1'").run(), /append-only/); assert.throws(() => w.db.raw.prepare('DELETE FROM publication_request_claims').run(), /append-only/);
});
test('F6: re-runs: attempt 2 cannot claim; after attempt 1 claimed, attempt 2 is another execution; a re-dispatch binds a NEW run and the old one is refused', async () => {
  const w = await fx(); const a = await expedite(w, w.ids[0]); ghRun(w, 3301, a.id, { run_attempt: 2 });
  const r2 = await send(w, a.id, { state: 'RUNNING' }, 3301, 2); assert.equal(r2.status, 403); assert.equal(r2.data.code, 'rerun_cannot_claim');
  ghRun(w, 3301, a.id); assert.equal((await send(w, a.id, { state: 'RUNNING' }, 3301, 1)).status, 200);
  const later = await send(w, a.id, { state: 'VALIDATING' }, 3301, 2); assert.equal(later.status, 403); assert.equal(later.data.code, 'other_execution');
  assert.equal((await send(w, a.id, { state: 'BLOCKED', blocked_reason: 'runner lost' }, 3301)).status, 200); const old = currentDispatchOf(w, a.id).dispatch_id;
  w.tick(5); const re = await w.call('POST', `/api/publication-requests/${a.id}/dispatch`, { user: w.pat, body: {} }); assert.equal(re.status, 200, JSON.stringify(re.data)); assert.equal(re.data.request.state, 'QUEUED');
  const fresh = currentDispatchOf(w, a.id).dispatch_id; assert.notEqual(fresh, old, 'a new dispatch id');
  assert.equal(JSON.parse(w.dispatches.at(-1).init.body).inputs.dispatch_id, fresh);
  ghRun(w, 3302, a.id, { display_title: `publish-expedited ${a.id} ${old}` });   // a re-run of the OLD execution, or a run carrying the old dispatch id
  const stale = await send(w, a.id, { state: 'RUNNING' }, 3302); assert.equal(stale.status, 403); assert.deepEqual(stale.data.failed, ['run_name']);
  ghRun(w, 3303, a.id); assert.equal((await send(w, a.id, { state: 'RUNNING' }, 3303)).status, 200, 'the run of the new dispatch claims it');
});
test('F6: the token must be of a workflow_dispatch run started by the panel, of the expedited workflow on main; missing claims are refused', async () => {
  const w = await fx(); const a = await expedite(w, w.ids[0]); ghRun(w, 3401, a.id);
  const ev = await send(w, a.id, { state: 'RUNNING' }, 3401, 1, { event_name: 'push' }); assert.equal(ev.status, 403); assert.equal(ev.data.code, 'not_dispatched');
  const fa = await send(w, a.id, { state: 'RUNNING' }, 3401, 1, { actor_id: '12345' }); assert.equal(fa.status, 403); assert.equal(fa.data.code, 'foreign_dispatcher');
  const none = await send(w, a.id, { state: 'RUNNING' }, 3401, 1, { event_name: undefined, actor_id: undefined }); assert.equal(none.status, 403, 'no event/actor claims');
  const wf = await w.call('POST', `/api/pipeline/expedite/${a.id}/report`, { bearer: await w.pipelineToken('publish.yml', { run_id: '3401', run_attempt: '1', event_name: 'workflow_dispatch', actor_id: DISPATCHER }), body: { state: 'RUNNING' } }); assert.equal(wf.status, 403, 'another workflow');
  const ref = await w.call('POST', `/api/pipeline/expedite/${a.id}/report`, { bearer: await runToken(w, 3401, 1, { ref: 'refs/heads/feature', job_workflow_ref: 'MacGuard/macguard-yara-channel/.github/workflows/publish-expedited.yml@refs/heads/feature' }), body: { state: 'RUNNING' } }); assert.equal(ref.status, 401, 'another ref');
  assert.equal((await P.get(w.db, a.id)).state, 'QUEUED'); assert.deepEqual(claims(w, a.id), []);
});
test('F6: what GitHub says about the run must match: run-name, who triggered it, the workflow, the branch, the attempt, and it was created after the dispatch', async () => {
  const w = await fx(); const a = await expedite(w, w.ids[0]); const d = currentDispatchOf(w, a.id);
  const cases = [['run_name', { display_title: `publish-expedited ${a.id}` }], ['triggering_actor', { triggering_actor: { id: 777 } }], ['actor', { actor: { id: 777 } }], ['workflow', { path: '.github/workflows/publish.yml' }],
    ['branch', { head_branch: 'feature' }], ['event', { event: 'push' }], ['run_attempt', { run_attempt: 3 }], ['created_after_dispatch', { created_at: new Date(Date.parse(d.at) - 60_000).toISOString() }]];
  let n = 3500; for (const [k, over] of cases) { ghRun(w, ++n, a.id, over); const r = await send(w, a.id, { state: 'RUNNING' }, n); assert.equal(r.status, 403, k); assert.deepEqual(r.data.failed, [k], k); }
  assert.deepEqual(claims(w, a.id), []); assert.equal((await P.get(w.db, a.id)).state, 'QUEUED');
  const unknown = await send(w, a.id, { state: 'RUNNING' }, 3599); assert.equal(unknown.status, 503, 'a run GitHub does not know (404) is not claimed');
});
test('F6: fail closed: GitHub unreachable, or no dispatcher identity configured, means no claim; it works once GitHub answers', async () => {
  const w = await fx(); const a = await expedite(w, w.ids[0]); ghRun(w, 3601, a.id); w.runsDown = true;
  const down = await send(w, a.id, { state: 'RUNNING' }, 3601); assert.equal(down.status, 503); assert.equal(down.data.code, 'run_lookup_failed'); assert.deepEqual(claims(w, a.id), []);
  w.runsDown = false; const id0 = w.env.EXPEDITE_DISPATCHER_ID; delete w.env.EXPEDITE_DISPATCHER_ID;
  const nocfg = await send(w, a.id, { state: 'RUNNING' }, 3601); assert.equal(nocfg.status, 503); assert.equal(nocfg.data.code, 'dispatcher_identity_not_configured');
  w.env.EXPEDITE_DISPATCHER_ID = id0; assert.equal((await send(w, a.id, { state: 'RUNNING' }, 3601)).status, 200); assert.equal(claims(w, a.id).length, 1);
  assert.ok(!JSON.stringify(rows(w, 'SELECT detail FROM audit')).includes('dispatch-token-for-tests'), 'the GitHub credential never reaches the audit');
});

// ---------------------------------------------------------------- F3 ----------------------------------------------------------------
/** Several public releases at once: helpers.js serves one manifest download for all tags, so each tag gets its own manifest route (the last one is the latest). */
async function releases(w, list) {
  for (const [tag, entries, opts] of list) await w.release(tag, entries, opts || {});
  for (const [tag, entries] of list) { const files = entries.map((e) => ({ path: e.path, sha256: e.sha256, bytes: e.bytes ?? null })); const bytes = new TextEncoder().encode(JSON.stringify({ schema: 1, files, rules_root: await rulesRoot(files) }));
    w.route(new RegExp(`/releases/download/${tag}/manifest\\.json$`), () => new Response(bytes)); }
}
const OLD = 'rules-20261020-1', NEW = 'rules-20261101-2';
test('F3: an older public release that lists the exact path and SHA-256 does NOT close the request; the active (latest) one does', async () => {
  const w = await fx(); const a = await expedite(w, w.ids[0]); await toVerifying(w, a.id, 3701);
  await releases(w, [[OLD, [w.entry(w.ids[0])], { publishedAt: '2026-10-20T03:40:00Z' }], [NEW, [w.entry(w.ids[1])], { publishedAt: '2026-11-01T03:40:00Z' }]]);   // OLD is public and verifiable
  const r = await send(w, a.id, { state: 'APPLIED', release_tag: OLD, commit_sha: 'a'.repeat(40) }, 3701); assert.equal(r.data.request.state, 'FAILED', JSON.stringify(r.data)); assert.equal(r.data.request.state_reason, 'release_not_active');
  assert.equal(rows(w, 'SELECT state FROM candidates WHERE id = ?', w.ids[0])[0].state, 'APPROVED_PENDING_VALIDATION', 'not synced from a historical release');
  const w2 = await fx(); const b = await expedite(w2, w2.ids[0]); await toVerifying(w2, b.id, 3702);
  await w2.release(OLD, [w2.entry(w2.ids[1])]); await w2.release(NEW, [w2.entry(w2.ids[0]), w2.entry(w2.ids[1])], { publishedAt: '2026-11-01T03:40:00Z' });
  const ok = await send(w2, b.id, { state: 'APPLIED', release_tag: NEW, commit_sha: 'a'.repeat(40) }, 3702); assert.equal(ok.data.request.state, 'APPLIED', JSON.stringify(ok.data)); await chainOk(w2);
});
test('F3: the active release cannot be determined (GitHub down): nothing changes, the request stays VERIFYING', async () => {
  const w = await fx(); const a = await expedite(w, w.ids[0]); await toVerifying(w, a.id, 3801);
  await w.release(NEW, [w.entry(w.ids[0])], { apiStatus: 502, manifestStatus: 502 });
  const r = await send(w, a.id, { state: 'APPLIED', release_tag: NEW, commit_sha: 'a'.repeat(40) }, 3801); assert.equal(r.status, 503); assert.equal(r.data.code, 'active_release_unknown'); assert.equal((await P.get(w.db, a.id)).state, 'VERIFYING');
});
const pinReq = (w, user, b) => w.call('POST', '/api/publication-releases/pins', { user, body: b });
test('F3: rollback = an authorised, audited PIN of a verified release: while pinned, only that release closes requests; UNPIN returns to the latest', async () => {
  const w = await fx(); await releases(w, [[OLD, [w.entry(w.ids[0])], { publishedAt: '2026-10-20T03:40:00Z' }], [NEW, [w.entry(w.ids[1])], { publishedAt: '2026-11-01T03:40:00Z' }]]);
  assert.equal((await w.call('GET', '/api/publication-releases/pins', { user: w.rita })).data.active.tag, NEW, 'latest by default');
  const p = await pinReq(w, w.ada, { kind: 'PIN', tag: OLD, reason: 'roll back: the newest release broke a customer deployment', expect_seq: 0 }); assert.equal(p.status, 200, JSON.stringify(p.data));
  assert.deepEqual([p.data.active.tag, p.data.active.basis, p.data.rollback], [OLD, 'pinned', true]);
  const au = rows(w, "SELECT actor, detail FROM audit WHERE action = 'publication.release_pinned'"); assert.equal(au.length, 1); assert.equal(au[0].actor, 'ada');
  assert.deepEqual((({ tag, previous_tag, rollback }) => ({ tag, previous_tag, rollback }))(JSON.parse(au[0].detail)), { tag: OLD, previous_tag: NEW, rollback: true });
  const a = await expedite(w, w.ids[0]); await toVerifying(w, a.id, 3901); const b = await expedite(w, w.ids[1]); await toVerifying(w, b.id, 3902);
  assert.equal((await send(w, b.id, { state: 'APPLIED', release_tag: NEW, commit_sha: 'b'.repeat(40) }, 3902)).data.request.state_reason, 'release_not_active', 'the latest is not active while pinned');
  assert.equal((await send(w, a.id, { state: 'APPLIED', release_tag: OLD, commit_sha: 'a'.repeat(40) }, 3901)).data.request.state, 'APPLIED', 'the pinned release is');
  const stale = await pinReq(w, w.bob, { kind: 'UNPIN', reason: 'the fix is out, follow the latest again', expect_seq: 0 }); assert.equal(stale.status, 409, 'a stale view cannot overwrite the pin');
  const un = await pinReq(w, w.bob, { kind: 'UNPIN', reason: 'the fix is out, follow the latest again', expect_seq: 1 }); assert.equal(un.status, 200, JSON.stringify(un.data)); assert.deepEqual([un.data.active.tag, un.data.active.basis], [NEW, 'latest']);
  assert.equal(rows(w, "SELECT COUNT(*) AS n FROM audit WHERE action = 'publication.release_unpinned'")[0].n, 1);
  assert.throws(() => w.db.raw.prepare("UPDATE publication_release_pins SET tag = 'x'").run(), /append-only/); assert.throws(() => w.db.raw.prepare('DELETE FROM publication_release_pins').run(), /append-only/); await chainOk(w);
});
test('F3: pinning is refused to a PUBLISHER or REVIEWER, for an unverifiable release, without a reason, and UNPIN with nothing pinned', async () => {
  const w = await fx(); await releases(w, [[OLD, [w.entry(w.ids[0])]], [NEW, [w.entry(w.ids[1])]]]);
  for (const u of [w.pat, w.rita]) { const r = await pinReq(w, u, { kind: 'PIN', tag: OLD, reason: 'roll back to the previous release', expect_seq: 0 }); assert.equal(r.status, 403, JSON.stringify(r.data)); }
  assert.equal((await pinReq(w, w.ada, { kind: 'PIN', tag: 'rules-20990101-1', reason: 'roll back to the previous release', expect_seq: 0 })).status, 409, 'no such public release');
  assert.equal((await pinReq(w, w.ada, { kind: 'PIN', tag: OLD, reason: 'short', expect_seq: 0 })).status, 400);
  assert.equal((await pinReq(w, w.ada, { kind: 'UNPIN', reason: 'nothing to undo here really', expect_seq: 0 })).status, 409);
  assert.equal(rows(w, 'SELECT COUNT(*) AS n FROM publication_release_pins')[0].n, 0); assert.ok(rows(w, "SELECT COUNT(*) AS n FROM audit WHERE action = 'authz.denied'")[0].n >= 2, 'the refusals are audited');
});
test('F3: the daily run closes a scheduled request only with the ACTIVE release, not with an older one that lists the rule', async () => {
  const w = await fx(); const sch = (await w.call('POST', '/api/publication-requests', { user: w.pat, body: await body(w, w.ids[0]) })).data.request; assert.equal(sch.state, 'PENDING');
  await releases(w, [[OLD, [w.entry(w.ids[0])], { publishedAt: '2026-10-20T03:40:00Z' }], [NEW, [w.entry(w.ids[1])], { publishedAt: '2026-11-01T03:40:00Z' }]]);
  const daily = await w.pipelineToken('daily.yml', { run_id: '4001', run_attempt: '1' });
  const r = await w.call('POST', '/api/pipeline/publication-requests/applied', { bearer: daily, body: { ids: [sch.id], release_tag: OLD } }); assert.deepEqual(r.data.applied, []); assert.equal(r.data.not_active.active_tag, NEW);
  assert.equal((await P.get(w.db, sch.id)).state, 'PENDING');
  assert.equal((await pinReq(w, w.ada, { kind: 'PIN', tag: OLD, reason: 'roll back: the newest release broke a customer deployment', expect_seq: 0 })).status, 200);
  const ok = await w.call('POST', '/api/pipeline/publication-requests/applied', { bearer: daily, body: { ids: [sch.id], release_tag: OLD } }); assert.deepEqual(ok.data.applied, [sch.id], JSON.stringify(ok.data));
});

// ---------------------------------------------------------------- migration 0010 ----------------------------------------------------------------
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { newDb } from './d1shim.js';
const read = (f) => readFileSync(new URL(f, import.meta.url), 'utf8');
const M10 = read('../migrations/0010_publication_execution_binding.sql'), R10 = read('../migrations/0010_rollback.sql');
const objs = (db) => db.raw.prepare("SELECT type || ':' || name AS n FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY n").all().map((r) => r.n);
test('migration 0010: applies on a database at 0009, is idempotent, mirrored in schema.sql, and its rollback removes only what it added', () => {
  const full = newDb(), all = objs(full); const db = newDb(); db.raw.exec(R10); const before = objs(db);
  assert.ok(!before.some((n) => /publication_request_(dispatches|claims)|publication_release_pins/.test(n)), 'the state of a database migrated up to 0009');
  db.raw.exec(M10); db.raw.exec(M10); assert.deepEqual(objs(db), all, 'upgraded = fresh install');
  const schema = read('../schema.sql').replace(/\s+/g, ' ');
  for (const st of M10.split('\n').filter((l) => !l.startsWith('--')).join('\n').split(/;\s*\n/).map((x) => x.replace(/\s+/g, ' ').trim()).filter(Boolean)) assert.ok(schema.includes(st.replace(/;$/, '')), st.slice(0, 80));
  db.raw.exec(R10); assert.deepEqual(objs(db), before);
});
test('migrations 0008 and 0009 are byte-identical to the reviewed head 5703ca4 (released migrations are never edited)', (t) => {
  for (const f of ['0008_publication_requests.sql', '0008_rollback.sql', '0009_publication_request_reviews.sql', '0009_rollback.sql']) {
    let orig; try { orig = execFileSync('git', ['show', `5703ca478ec4bd390a1e208b34ab1b6c65e83318:admin/worker/migrations/${f}`], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }); } catch { t.skip('git history not available'); return; }
    assert.equal(read(`../migrations/${f}`), orig, f);
  }
});
test('F3 (Codex pr53-highs-fix round 2, HIGH): a PIN authorises one exact manifest; replacing the assets under the pinned tag closes nothing (fails closed) until re-pinned', async () => {
  const w = await fx(); await releases(w, [[OLD, [w.entry(w.ids[0])], { publishedAt: '2026-10-20T03:40:00Z' }], [NEW, [w.entry(w.ids[0])], { publishedAt: '2026-11-01T03:40:00Z' }]]);
  assert.equal((await pinReq(w, w.ada, { kind: 'PIN', tag: OLD, reason: 'roll back: the newest release broke a customer deployment', expect_seq: 0 })).status, 200);
  // the OLD tag's assets are replaced with a manifest that now lists the requested rule (ids[1]): not what was authorised
  await releases(w, [[OLD, [w.entry(w.ids[0]), w.entry(w.ids[1])], { publishedAt: '2026-10-20T03:40:00Z' }], [NEW, [w.entry(w.ids[0])], { publishedAt: '2026-11-01T03:40:00Z' }]]);
  const b = await expedite(w, w.ids[1]); await toVerifying(w, b.id, 3903);
  const r = await send(w, b.id, { state: 'APPLIED', release_tag: OLD, commit_sha: 'c'.repeat(40) }, 3903);
  assert.notEqual(r.data?.request?.state, 'APPLIED', JSON.stringify(r.data)); assert.equal(r.status, 503, 'the pinned release no longer matches its authorised manifest');
  assert.equal(rows(w, 'SELECT state FROM publication_requests WHERE id = ?', b.id)[0].state, 'VERIFYING', 'nothing changed');
  assert.equal((await pinReq(w, w.ada, { kind: 'PIN', tag: OLD, reason: 'reviewed the replaced assets and re-authorised them', expect_seq: 1 })).status, 200);
  assert.equal((await send(w, b.id, { state: 'APPLIED', release_tag: OLD, commit_sha: 'c'.repeat(40) }, 3903)).data.request.state, 'APPLIED', 'after an authorised re-pin it works');
});
