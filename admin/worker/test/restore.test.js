// Recovery status and audited progress: states come only from records, absence is never a pass, roles are enforced, events are typed, idempotent and secret-free. Synthetic GitHub data only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { world } from './helpers.js';
import { buildRecoveryStatus, classifyRun, parseEvidence, validateEvent, procedureBundle, STALE_HOURS, PROVIDERS } from '../src/restore.js';
import { PARAMS, STEPS, PROCEDURES, serializeParams } from '../src/restore_procedures.js';
import { reviveParams } from '../public/restore/engine.js';

const NOW = Date.parse('2026-10-26T12:00:00Z'), H = 3600000, at = (h) => new Date(NOW - h * H).toISOString();
const job = (name, conclusion, completed_at = at(1), steps = []) => ({ name, status: conclusion ? 'completed' : 'in_progress', conclusion, completed_at, steps });
const SIGN = { name: 'Sign ANCHOR.json and CHECKPOINT.json with Sigstore keyless (nothing is kept unless it verifies for the pinned identity)', conclusion: 'success' };
const fullJobs = (over = {}) => [job('export', 'success', at(2), [SIGN]), ...PROVIDERS.flatMap((p) => [job(`fetch (${p})`, 'success'), job(`write (${p})`, over[`write_${p}`] ?? 'success'), job(`read (${p})`, over[`read_${p}`] ?? 'success', over.readAt ?? at(1))]), job('redundancy', 'success'), job('selftest', 'skipped')];
const run = (id, hours, conclusion = 'success') => ({ id, html_url: `https://github.com/x/actions/runs/${id}`, event: 'workflow_dispatch', created_at: at(hours + 0.1), updated_at: at(hours), status: 'completed', conclusion });
const by = (st, id) => st.indicators.find((i) => i.id === id);
const TRUST = { age_recipient: 'age1abc', ed25519: { fingerprint: 'SHA256:x', max_sequence: 1, namespaces: ['macguard-backup/1'] }, sigstore: { identity: 'https://github.com/o/r/.github/workflows/backup.yml@refs/heads/main', repository: 'o/r' } };

test('no backup has ever run: everything is NOT_RUN or UNKNOWN, never VERIFIED, never FAILED', () => {
  const st = buildRecoveryStatus({ runs: [], jobs: {}, evidence: null, trust: TRUST, tools: [{ path: 'a', present: true }] }, NOW);
  for (const id of ['last_backup', 'last_signed', 'checkpoint_produced', 'last_restore', 'rto_observed', 'provider_b2', 'provider_scaleway', 'provider_r2']) assert.equal(by(st, id).state, 'NOT_RUN', id);
  for (const id of ['checkpoint_external', 'rpo_observed', 'secrets', 'next_drill']) assert.equal(by(st, id).state, 'UNKNOWN', id);
  assert.notEqual(by(st, 'copies_verified').state, 'VERIFIED'); assert.equal(st.inventory.length, 0); assert.equal(by(st, 'verifiers').state, 'VERIFIED');
  assert.ok(st.indicators.every((i) => ['VERIFIED', 'FAILED', 'STALE', 'UNKNOWN', 'NOT_RUN'].includes(i.state) && 'source' in i && 'observed_at' in i));
});

test('a complete good run: dates, sources and the three copies VERIFIED; the external checkpoint, the restores and the secrets stay UNKNOWN/NOT_RUN because the panel cannot see them', () => {
  const st = buildRecoveryStatus({ runs: [run(7, 2)], jobs: { 7: fullJobs() }, evidence: [], trust: TRUST, tools: [] }, NOW);
  assert.equal(by(st, 'last_backup').state, 'VERIFIED'); assert.equal(by(st, 'last_signed').state, 'VERIFIED'); assert.equal(by(st, 'copies_verified').state, 'VERIFIED'); assert.equal(by(st, 'copies_verified').value, 3);
  assert.equal(by(st, 'rpo_observed').value, 7200); assert.match(by(st, 'last_backup').source, /run 7/); assert.equal(by(st, 'checkpoint_external').state, 'UNKNOWN'); assert.equal(by(st, 'last_restore').state, 'NOT_RUN'); assert.equal(by(st, 'secrets').state, 'UNKNOWN');
  assert.equal(st.inventory.length, 3); for (const row of st.inventory) { assert.equal(row.recoverable, 'AUTHENTICATED', 'read back and verified, but never restored: not PROVEN'); assert.equal(row.signature_type, 'sigstore'); assert.equal(row.signer_identity, TRUST.sigstore.identity); assert.equal(row.sequence, null); assert.equal(row.sha256, null); assert.equal(row.transparency_log.state, 'UNKNOWN'); assert.equal(row.last_restore, null); }
});

test('three copies are claimed only when all three verified: one failing provider is FAILED, the count is 2, and a copy that exists is not recoverable by itself', () => {
  const st = buildRecoveryStatus({ runs: [run(8, 3)], jobs: { 8: fullJobs({ write_scaleway: 'failure', read_scaleway: 'skipped' }) }, evidence: [], trust: TRUST }, NOW);
  assert.equal(st.providers.scaleway.state, 'FAILED'); assert.equal(st.providers.b2.state, 'VERIFIED'); assert.equal(by(st, 'copies_verified').value, 2); assert.equal(by(st, 'copies_verified').state, 'FAILED');
  const row = st.inventory.find((r) => r.provider === 'scaleway'); assert.equal(row.recoverable, 'FAILED'); assert.equal(row.provider_state, 'FAILED');
  const readOnlyFail = buildRecoveryStatus({ runs: [run(9, 3)], jobs: { 9: fullJobs({ read_r2: 'failure' }) }, evidence: [], trust: TRUST }, NOW); assert.equal(readOnlyFail.providers.r2.state, 'FAILED'); assert.equal(readOnlyFail.inventory.find((r) => r.provider === 'r2').provider_state, 'FAILED');
});

test('an export that failed is FAILED with the run; an old good run is STALE; a selftest or an unread run never counts as a backup', () => {
  const failedExport = [job('export', 'failure', at(2), []), ...PROVIDERS.flatMap((p) => [job(`fetch (${p})`, 'success'), job(`write (${p})`, 'skipped'), job(`read (${p})`, 'skipped')])];
  let st = buildRecoveryStatus({ runs: [run(1, 2, 'failure')], jobs: { 1: failedExport }, evidence: [], trust: TRUST }, NOW);
  assert.equal(by(st, 'last_backup').state, 'FAILED'); assert.equal(by(st, 'last_signed').state, 'NOT_RUN'); assert.equal(st.providers.b2.state, 'NOT_RUN'); assert.equal(by(st, 'copies_verified').state, 'FAILED');
  st = buildRecoveryStatus({ runs: [run(2, STALE_HOURS + 10)], jobs: { 2: fullJobs({ readAt: at(STALE_HOURS + 10) }) }, evidence: [], trust: TRUST }, NOW); assert.equal(by(st, 'last_backup').state, 'STALE'); assert.equal(st.providers.b2.state, 'STALE'); assert.equal(by(st, 'rpo_observed').state, 'STALE');
  const selftest = [job('selftest', 'success'), job('export', 'skipped')]; st = buildRecoveryStatus({ runs: [run(3, 1)], jobs: { 3: selftest }, evidence: [], trust: TRUST }, NOW); assert.equal(by(st, 'last_backup').state, 'NOT_RUN'); assert.equal(classifyRun(run(3, 1), selftest).kind, 'selftest');
  st = buildRecoveryStatus({ runs: [run(4, 1)], jobs: {}, evidence: [], trust: TRUST }, NOW); assert.equal(by(st, 'last_backup').state, 'NOT_RUN', 'a run whose jobs could not be read is not counted as a backup');
});

test('GitHub unreadable: run-derived indicators are UNKNOWN (not NOT_RUN, not FAILED); evidence records bring restore, checkpoint and RTO, and a failed-only history is FAILED', () => {
  let st = buildRecoveryStatus({ runs: null, jobs: {}, evidence: null, trust: null, tools: null }, NOW);
  for (const id of ['last_backup', 'last_signed', 'rpo_observed', 'copies_verified', 'provider_b2', 'signature_chain']) assert.equal(by(st, id).state, 'UNKNOWN', id); assert.equal(by(st, 'verifiers').state, 'UNKNOWN'); assert.equal(st.policy, null);
  const ev = parseEvidence([JSON.stringify({ kind: 'restore', at: at(30), ok: true, mode: 'drill', provider: 'b2', stamp: '20261025T032300Z', duration_s: 412 }), JSON.stringify({ kind: 'checkpoint_confirmed', at: at(5), sequence: 2, where: 'bitwarden' }), '{broken', JSON.stringify({ kind: 'unknown', x: 1 }), JSON.stringify({ kind: 'backup', run_id: 7, stamp: '20261025T032300Z', sequence: 2, files: { 'd1-export.sql.age': { sha256: 'ab'.repeat(32), bytes: 40638 } }, signer: { identity: TRUST.sigstore.identity, tlog_index: 3465351221 }, schema_version: 'macguard.gateway-backup/2' })].join('\n'));
  assert.equal(ev.length, 3, 'malformed lines and unknown kinds are not evidence');
  st = buildRecoveryStatus({ runs: [run(7, 2)], jobs: { 7: fullJobs() }, evidence: ev, trust: TRUST }, NOW);
  assert.equal(by(st, 'last_restore').state, 'VERIFIED'); assert.equal(by(st, 'rto_observed').value, 412); assert.equal(by(st, 'checkpoint_external').state, 'VERIFIED'); const b2 = st.inventory.find((r) => r.provider === 'b2');
  assert.deepEqual([b2.stamp, b2.sequence, b2.bytes, b2.transparency_log.index, b2.recoverable], ['20261025T032300Z', 2, 40638, 3465351221, 'PROVEN'], 'PROVEN only for the provider that has a matching restore record'); assert.equal(st.inventory.find((r) => r.provider === 'r2').recoverable, 'AUTHENTICATED');
  st = buildRecoveryStatus({ runs: [], jobs: {}, evidence: parseEvidence(JSON.stringify({ kind: 'restore', at: at(1), ok: false })), trust: TRUST }, NOW); assert.equal(by(st, 'last_restore').state, 'FAILED');
});

// ---- HTTP ----
const memCache = () => { const m = new Map(); return { async match(r) { const v = m.get(r.url); return v ? v.clone() : undefined; }, async put(r, res) { m.set(r.url, res.clone()); } }; };
function feed(w, { runs = [], jobs = {}, noRuns = false } = {}) {
  const calls = []; const body = (o) => new Response(JSON.stringify(o), { headers: { 'x-ratelimit-remaining': '4990', 'x-ratelimit-limit': '5000' } });
  w.route(/actions\/workflows\/backup\.yml\/runs/, (u, i) => { calls.push(['runs', i.headers.Authorization]); return noRuns ? new Response('{}', { status: 403 }) : body({ workflow_runs: runs }); });
  w.route(/actions\/runs\/(\d+)\/jobs/, (u) => { calls.push(['jobs']); return body({ jobs: jobs[u.match(/runs\/(\d+)\//)[1]] || [] }); });
  w.route(/backup-trust\.json$/, () => new Response(JSON.stringify(TRUST))); w.route(/evidence\/backups\.jsonl$/, () => new Response('not found', { status: 404 }));
  w.route(/\/gateway\/tools\/[a-z_.]+$/, () => new Response('#!/bin/sh')); return calls;
}

test('GET /api/restore/status: REVIEWER and ADMIN only (VIEWER 403, anonymous 401), the person\'s own token is used, cached, and no secret is in the answer', async () => {
  const w = await world(); const calls = feed(w, { runs: [{ ...run(7, 1), created_at: new Date().toISOString(), updated_at: new Date().toISOString() }], jobs: { 7: fullJobs() } }); w.deps.cache = memCache();
  const ada = await w.login('ada', { admin: true }), vera = await w.login('vera', { pull: true }, { id: 7 }), rita = await w.login('rita', { push: true }, { id: 8 }); await w.grant(ada, 'vera', 'VIEWER'); await w.grant(ada, 'rita', 'REVIEWER');
  assert.equal((await w.call('GET', '/api/restore/status')).status, 401); assert.equal((await w.call('GET', '/api/restore/status', { user: vera })).status, 403);
  const r = await w.call('GET', '/api/restore/status', { user: rita }); assert.equal(r.status, 200, JSON.stringify(r.data)); assert.equal(r.data.cache.hit, false); assert.equal(r.data.indicators.length > 10, true); assert.equal(calls.find((c) => c[0] === 'runs')[1], 'Bearer tok-rita');
  assert.doesNotMatch(JSON.stringify(r.data), /tok-|csrf|secret_value|AGE-SECRET|PRIVATE KEY/i); const n = calls.length; assert.equal((await w.call('GET', '/api/restore/status', { user: ada })).data.cache.hit, true); assert.equal(calls.length, n, 'cached');
  assert.equal(r.data.policy.sigstore.identity, TRUST.sigstore.identity);
});

test('an unreadable GitHub gives UNKNOWN, a short cache, and a clear list of unavailable sources', async () => {
  const w = await world(); feed(w, { noRuns: true }); w.deps.cache = memCache(); const ada = await w.login('ada', { admin: true });
  const r = await w.call('GET', '/api/restore/status', { user: ada }); assert.equal(r.status, 200); assert.ok(r.data.unavailable.some((u) => u.source === 'backup_runs' && u.reason === 'rate_limited')); assert.equal(r.data.indicators.find((i) => i.id === 'last_backup').state, 'UNKNOWN');
  const c = await w.deps.cache.match(new Request(`${w.env.PUBLIC_URL}/__cache/restore-status-v1`)); assert.equal(c.headers.get('Cache-Control'), 'max-age=30');
});

test('GET /api/restore/procedures: signed-in REVIEWER+ only, never cached, regexes travel as source/flags and revive to the same behaviour, and the runbook is not a public asset', async () => {
  const w = await world(); const ada = await w.login('ada', { admin: true }), vera = await w.login('vera', { pull: true }, { id: 7 }); await w.grant(ada, 'vera', 'VIEWER');
  assert.equal((await w.call('GET', '/api/restore/procedures')).status, 401); assert.equal((await w.call('GET', '/api/restore/procedures', { user: vera })).status, 403);
  const r = await w.call('GET', '/api/restore/procedures', { user: ada }); assert.equal(r.status, 200); assert.deepEqual(Object.keys(r.data.procedures).sort(), ['compromise', 'd1_only', 'drill', 'full_service']);
  const back = reviveParams(JSON.parse(JSON.stringify(r.data.params))); for (const k of Object.keys(PARAMS)) { assert.equal(back[k].re.test(PARAMS[k].example), true); assert.equal(back[k].re.test('x; rm -rf /'), false); }
  assert.deepEqual(Object.keys(serializeParams(PARAMS)), Object.keys(PARAMS)); assert.equal(Object.keys(r.data.steps).length, Object.keys(STEPS).length);
});

test('POST /api/restore/event: typed and audited; a protected procedure needs ADMIN, the drill needs REVIEWER; unknown fields, steps and methods are refused; retries are idempotent; nothing but identifiers is stored; the audit chain stays valid', async () => {
  const w = await world(); const ada = await w.login('ada', { admin: true }), rita = await w.login('rita', { push: true }, { id: 8 }), vera = await w.login('vera', { pull: true }, { id: 7 }); await w.grant(ada, 'rita', 'REVIEWER'); await w.grant(ada, 'vera', 'VIEWER');
  const run = '9f2b6a40-1c3d-4e5f-8a7b-0c1d2e3f4a5b', post = (user, body) => w.call('POST', '/api/restore/event', { user, body });
  assert.equal((await post(vera, { event: 'procedure_started', procedure: 'drill', run })).status, 403);
  assert.equal((await post(rita, { event: 'procedure_started', procedure: 'd1_only', run })).status, 403, 'protected procedure: ADMIN only'); assert.equal((await post(rita, { event: 'procedure_started', procedure: 'drill', run })).status, 200);
  assert.equal((await post(ada, { event: 'procedure_started', procedure: 'd1_only', run })).status, 403, 'a protected procedure is not recorded without an authorisation by two identities');
  const sec = await w.login('sera', { push: true }, { id: 9 }); await w.grant(ada, 'sera', 'SECURITY_ADMIN');
  const ask = await w.call('POST', '/api/approvals', { user: ada, body: { op: 'restore.real', request_id: 'req-restore-0000001', reason: 'drill of the real procedure', params: { procedure: 'd1_only', run, target: 'staging-d1-copy', backup: { stamp: '20261025T224553Z', provider: 'b2' }, rollback_plan: 'keep the current database untouched and swap back' } } }); assert.equal(ask.status, 200, JSON.stringify(ask.data));
  assert.equal((await w.call('POST', `/api/approvals/${ask.data.approval.id}/approve`, { user: ada, body: { request_id: 'req-restore-0000002', expect_version: ask.data.approval.version, reason: 'I asked for it myself' } })).status, 403, 'nobody authorises their own request');
  const okd = await w.call('POST', `/api/approvals/${ask.data.approval.id}/approve`, { user: sec, body: { request_id: 'req-restore-0000003', expect_version: ask.data.approval.version, reason: 'plan and target checked' } }); assert.equal(okd.status, 200, JSON.stringify(okd.data));
  assert.equal((await post(ada, { event: 'procedure_started', procedure: 'd1_only', run, authorization_id: ask.data.approval.id })).data.duplicate, false);
  const ok = { event: 'step_done', procedure: 'drill', step: 'machine_os', run, via: 'output' }; assert.equal((await post(rita, ok)).data.duplicate, false); assert.equal((await post(rita, ok)).data.duplicate, true, 'the same event twice is recorded once');
  for (const bad of [{ ...ok, step: 'cutover' }, { ...ok, step: 'nope' }, { ...ok, via: 'attest' }, { ...ok, via: 'none' }, { ...ok, command: 'rm -rf /' }, { ...ok, output: 'x'.repeat(10) }, { event: 'step_done', procedure: 'drill', run }, { ...ok, run: 'x' }, { ...ok, event: 'execute' }, { ...ok, procedure: 'nope' }, { event: 'procedure_started', procedure: 'drill', run, step: 'machine_os' }, null, []])
    assert.equal((await post(rita, bad)).status, 400, JSON.stringify(bad));
  assert.equal((await post(rita, { event: 'step_done', procedure: 'drill', step: 'pick_backup', run, via: 'attest' })).status, 200, 'an attestation step is confirmed by attestation'); assert.equal((await post(rita, { event: 'step_done', procedure: 'drill', step: 'record_evidence', run, via: 'none' })).status, 200);
  const rows = (await w.call('GET', '/api/audit?family=restore', { user: ada })).data; const text = JSON.stringify(rows); assert.match(text, /restore\.step_done/); assert.doesNotMatch(text, /rm -rf|"command":|"output":|tok-/); assert.equal((await w.call('GET', '/api/audit/verify', { user: ada })).data.ok, true);
  assert.equal((await w.call('POST', '/api/restore/event', { user: rita, body: { event: 'step_done', procedure: 'drill', step: 'machine_os', run, via: 'output' }, csrf: false })).status, 403, 'CSRF is enforced like every write');
});

test('validateEvent is pure and strict', () => {
  const run = 'abcdefgh-1234'; assert.equal(validateEvent({ event: 'procedure_completed', procedure: 'drill', run }, 'REVIEWER').ok, true); assert.equal(validateEvent({ event: 'procedure_completed', procedure: 'compromise', run }, 'REVIEWER').status, 403);
  assert.equal(validateEvent({ event: 'step_failed', procedure: 'drill', step: 'machine_os', run }, 'REVIEWER').ok, true); assert.equal(validateEvent({ event: 'step_failed', procedure: 'drill', step: 'machine_os', run, via: 'output' }, 'REVIEWER').ok, false);
  assert.deepEqual(validateEvent({ event: 'step_done', procedure: 'drill', step: 'machine_os', run, via: 'output' }, 'ADMIN').detail, { run, step: 'machine_os', via: 'output', procedure_version: 1 });
  assert.equal(procedureBundle().version, 1);
});

test('the panel database is protected by the same pipeline but reported on its own: gateway indicators ignore panel runs and the other way round; inventory rows carry their service', () => {
  const titled = (r, title) => ({ ...r, display_title: title }), panelJobs = fullJobs();
  const st = buildRecoveryStatus({ runs: [titled(run(21, 1), 'backup panel'), titled(run(20, 2), 'backup gateway'), run(19, 50, 'success')], jobs: { 21: panelJobs, 20: fullJobs({ write_r2: 'failure' }), 19: fullJobs() }, evidence: [], trust: TRUST }, NOW);
  assert.equal(by(st, 'panel_last_backup').state, 'VERIFIED'); assert.equal(by(st, 'panel_copies_verified').value, 3); assert.equal(by(st, 'copies_verified').value, 2, 'the gateway run with a failed R2 write is not hidden by a good panel run'); assert.equal(by(st, 'last_backup').value, 20);
  assert.deepEqual([...new Set(st.inventory.map((r) => r.service))].sort(), ['gateway', 'panel']); assert.equal(st.inventory.filter((r) => r.service === 'panel').length, 3);
  const none = buildRecoveryStatus({ runs: [run(1, 1)], jobs: { 1: fullJobs() }, evidence: [], trust: TRUST }, NOW); assert.equal(by(none, 'panel_last_backup').state, 'NOT_RUN'); assert.equal(by(none, 'panel_copies_verified').state, 'NOT_RUN');
  const down = buildRecoveryStatus({ runs: null, jobs: {}, evidence: null, trust: null }, NOW); assert.equal(by(down, 'panel_last_backup').state, 'UNKNOWN');
});

test('a failed export is ONE failure with its cause; the jobs that did not run are NOT_RUN, never three corrupt copies; an annotation of the wrong shape is ignored', async () => {
  const { parseDiagnosis, failureOf } = await import('../src/restore.js'); const { parseAnnotation } = await import('../../../gateway/tools/backup_diagnose.mjs');
  const msg = 'macguard-backup: resource=gateway phase=export kind=cloudflare_auth code=10000';
  const failed = [{ id: 901, ...job('export', 'failure', at(3), [{ name: 'Export D1', conclusion: 'failure' }]) }, ...PROVIDERS.flatMap((p) => [job(`fetch (${p})`, 'success'), job(`write (${p})`, 'skipped'), job(`read (${p})`, 'skipped')])];
  const st = buildRecoveryStatus({ runs: [run(8, 3, 'failure')], jobs: { 8: failed }, evidence: [], trust: TRUST, tools: [], diagnoses: { 8: parseDiagnosis(msg) } }, NOW);
  assert.equal(st.failures.length, 1); const f = st.failures[0];
  assert.deepEqual([f.run_id, f.failed_jobs.map((j) => j.name), f.failed_jobs[0].failed_step, f.cause_known, f.diagnosis.kind, f.diagnosis.code], [8, ['export'], 'Export D1', true, 'cloudflare_auth', '10000']);
  assert.equal(f.not_run_jobs.length, 6, 'write and read of every provider did not run'); assert.equal(st.inventory.filter((r) => r.recoverable === 'FAILED').length, 0, 'no copy is reported corrupt');
  assert.equal(failureOf(run(9, 1, 'success'), [], null), null, 'a good run has no failure'); assert.equal(failureOf(run(8, 3, 'failure'), failed, null).cause_known, false, 'without an annotation the cause is unknown, not guessed');
  for (const bad of ['', 'macguard-backup: kind=evil phase=export', msg + ' <script>', 'x']) assert.equal(parseDiagnosis(bad), null, bad);
  for (const m of [msg, `${msg} http=401`, 'macguard-backup: phase=write kind=timeout', 'macguard-backup: resource=panel phase=verify kind=verify_failed']) assert.deepEqual(parseDiagnosis(m), parseAnnotation(m), 'the Worker and the workflow parse the same way');
});

test('the intelligence database is a third resource: never-backed-up is NOT_RUN, a weekly copy is fresh for eight days, its failures and inventory are its own and never hide the gateway or the panel', () => {
  const titled = (r, title) => ({ ...r, display_title: title });
  const none = buildRecoveryStatus({ runs: [titled(run(21, 1), 'backup panel'), titled(run(20, 2), 'backup gateway'), run(19, 50, 'success')], jobs: { 21: fullJobs(), 20: fullJobs(), 19: fullJobs() }, evidence: [], trust: TRUST }, NOW);
  assert.equal(by(none, 'intel_last_backup').state, 'NOT_RUN'); assert.equal(by(none, 'intel_copies_verified').state, 'NOT_RUN'); assert.equal(by(none, 'panel_last_backup').state, 'VERIFIED');
  const week = buildRecoveryStatus({ runs: [titled(run(21, 1), 'backup panel'), titled(run(20, 2), 'backup gateway'), titled(run(22, 6 * 24), 'backup intel')], jobs: { 21: fullJobs(), 20: fullJobs(), 22: fullJobs() }, evidence: [], trust: TRUST }, NOW);
  assert.equal(by(week, 'intel_last_backup').state, 'VERIFIED'); assert.equal(by(week, 'intel_copies_verified').value, 3); assert.equal(by(week, 'intel_copies_verified').state, 'VERIFIED', 'six days old is fresh for a weekly resource'); assert.equal(by(week, 'panel_copies_verified').value, 3);
  assert.deepEqual([...new Set(week.inventory.map((r) => r.service))].sort(), ['gateway', 'intel', 'panel']);
  const failed = buildRecoveryStatus({ runs: [titled(run(21, 1), 'backup panel'), titled(run(20, 2), 'backup gateway'), titled(run(22, 3, 'failure'), 'backup intel')], jobs: { 21: fullJobs(), 20: fullJobs(), 22: [job('export', 'failure', at(3))] }, evidence: [], trust: TRUST }, NOW);
  assert.equal(by(failed, 'intel_last_backup').state, 'FAILED'); assert.equal(by(failed, 'last_backup').state, 'VERIFIED', 'an intelligence failure does not touch the gateway'); assert.deepEqual(failed.failures.map((f) => f.resource), ['intel']);
});
