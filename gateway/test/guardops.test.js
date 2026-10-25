// Contract tests for the GuardOps adapter, against a LOCAL fake ingestion server (real HTTP, real fetch). GuardOps itself is not deployed: this proves what MacGuard sends, never that GuardOps accepts it.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import worker from '../src/index.js';
import { endpoint, toEnvelope, envelopeFromAlert, forward, flush, enqueueMetrics, FORWARDED_TYPES } from '../src/guardops.js';
import { emit, EVENT_TYPES } from '../src/events.js';
import { validate } from '../src/schema.js';
import { apiWorld } from './apiworld.js';
import { world } from './helpers.js';

const SCHEMA = JSON.parse(readFileSync(new URL('../../contracts/v1/event.schema.json', import.meta.url), 'utf8')), TOKEN = 'gi_' + 'Zx9'.repeat(14);
async function ingest(handler) { const seen = []; const srv = http.createServer((req, res) => { let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => { seen.push({ headers: req.headers, body: b ? JSON.parse(b) : null }); handler(req, res, seen.length); }); }); await new Promise((r) => srv.listen(0, '127.0.0.1', r)); srv.unref();
  return { seen, url: `http://127.0.0.1:${srv.address().port}/v1/events`, close: () => new Promise((r) => { srv.closeAllConnections?.(); srv.close(r); }) }; }
const REAL_FETCH = globalThis.fetch;
const cfg = (url, extra = {}) => ({ guardopsFetch: (u, o) => REAL_FETCH(u, o), GUARDOPS_INGEST_URL: url, GUARDOPS_INGEST_TOKEN: TOKEN, GUARDOPS_ALLOW_INSECURE_LOCAL: '1', ...extra });
const rows = async (w) => (await w.db.prepare('SELECT * FROM guardops_outbox ORDER BY created_at, event_id').all()).results;
const sample = { 'gateway.incident': { component: 'github-collector', code: 'github_rate_limited' }, 'stripe.failure': { stage: 'meter', status: 500 }, 'api.saturated': { tenant_id: 't1', scope: 'minute' }, 'abuse.detected': { tenant_id: 't1', signal: 'shared_link' },
  'signature.invalid': { release_id: 'r1', stage: 'verify' }, 'replication.failed': { release_id: 'r1', provider: 'b2' }, 'billing.error': { tenant_id: 't1', stage: 'x', code: 'y' } };

test('every forwarded event becomes a valid macguard.event/1 envelope; business events are not forwarded; ids are deterministic and no tenant or key id leaks', async () => {
  const clock = () => new Date('2026-10-24T06:00:00Z'), env = { GUARDOPS_TENANT: 'macguard' };
  for (const t of FORWARDED_TYPES) { assert.ok(EVENT_TYPES[t], t); const ev = { type: t, at: '2026-10-24T06:00:00Z', data: sample[t] }, e = await toEnvelope(ev, env, clock); assert.deepEqual(validate(SCHEMA, e), [], t + ' ' + JSON.stringify(validate(SCHEMA, e))); assert.equal((await toEnvelope(ev, env, clock)).event_id, e.event_id, 'deterministic'); assert.ok(!JSON.stringify(e).includes('"t1"') || e.tenant_id === 'macguard', 'the customer tenant id is not forwarded'); }
  for (const t of ['download.authorized', 'download.rejected', 'usage.near_limit', 'tenant.suspended', 'release.premium_published']) assert.equal(await toEnvelope({ type: t, data: {} }, env, clock), null, t);
  assert.equal((await toEnvelope({ type: 'gateway.incident', data: { component: 'github-collector', code: 'x' } }, env, clock)).type, 'cron.run.failed'); assert.equal((await toEnvelope({ type: 'gateway.incident', data: { component: 'origin', code: 'r2_error' } }, env, clock)).type, 'download.failed'); assert.equal((await toEnvelope({ type: 'gateway.incident', data: { component: 'router', code: 'x' } }, env, clock)).type, 'gateway.error');
  assert.equal((await toEnvelope({ type: 'signature.invalid', data: sample['signature.invalid'] }, env, clock)).data.severity, 'critical');
  for (const a of [{ rule_id: 'backup.stale', severity: 'high', state: 'FIRING', message: 'x', evaluated_at: '2026-10-24T06:00:00Z', source: { kind: 'agent', id: 'backup-check' } }, { rule_id: 'github.collector_failing', severity: 'high', state: 'FIRING', message: 'y' }]) assert.deepEqual(validate(SCHEMA, await envelopeFromAlert(a, env, clock)), []);
});
test('nothing is sent unless GuardOps is configured, and only to an allow-listed https host (the credential never goes elsewhere)', async () => {
  assert.equal(endpoint({}), null); assert.equal(endpoint({ GUARDOPS_INGEST_URL: 'https://ingest.mac-guard.com/v1/events' }).hostname, 'ingest.mac-guard.com');
  for (const bad of ['http://ingest.mac-guard.com/x', 'https://evil.example/x', 'https://ingest.mac-guard.com.evil.example/x', 'not a url', 'https://panel.mac-guard.com/x', 'http://127.0.0.1:1/x']) assert.equal(endpoint({ GUARDOPS_INGEST_URL: bad }), null, bad);
  assert.equal(endpoint({ GUARDOPS_INGEST_URL: 'http://127.0.0.1:9/x', GUARDOPS_ALLOW_INSECURE_LOCAL: '1' }).hostname, '127.0.0.1');
  const w = await world(); assert.equal(await forward({}, w.db, w.clock, { type: 'gateway.incident', data: sample['gateway.incident'] }), false); assert.equal((await rows(w)).length, 0);
  assert.deepEqual(await flush({ GUARDOPS_INGEST_URL: 'https://ingest.mac-guard.com/v1/events' }, w.db, w.clock), { skipped: true, sent: 0, retry: 0, dead: 0 }, 'no token: no call');
});
test('delivery: a batch is POSTed with the limited credential and an idempotency key, marked sent, and a second flush sends nothing', async () => {
  const srv = await ingest((req, res) => { res.writeHead(202); res.end(); }); const w = await world(); const env = cfg(srv.url);
  try {
    for (const t of ['gateway.incident', 'signature.invalid']) await forward(env, w.db, w.clock, { type: t, at: '2026-10-24T06:00:00Z', data: sample[t] });
    assert.equal((await rows(w)).length, 2); const r = await flush(env, w.db, w.clock); assert.deepEqual([r.sent, r.retry, r.dead], [2, 0, 0]);
    const call = srv.seen[0]; assert.equal(call.headers.authorization, `Bearer ${TOKEN}`); assert.match(call.headers['idempotency-key'], /^mgb-[0-9a-f]{32}$/); assert.equal(call.body.schema, 'macguard.event-batch/1'); assert.equal(call.body.events.length, 2); for (const e of call.body.events) assert.deepEqual(validate(SCHEMA, e), []);
    assert.deepEqual((await rows(w)).map((x) => x.state), ['sent', 'sent']); assert.equal((await flush(env, w.db, w.clock)).sent, 0); assert.equal(srv.seen.length, 1);
    assert.ok(!JSON.stringify(await rows(w)).includes(TOKEN), 'the credential is not stored');
  } finally { await srv.close(); }
});
test('failures: 5xx and 429 retry with growing backoff (Retry-After honoured), 4xx and exhaustion dead-letter, and the same fact is queued once', async () => {
  const mode = { n: 429 }; const srv = await ingest((req, res) => { res.writeHead(mode.n, mode.n === 429 ? { 'retry-after': '900' } : {}); res.end(); }); const w = await world({ now: '2026-10-24T06:00:00Z' }); const env = cfg(srv.url);
  try {
    const ev = { type: 'gateway.incident', at: '2026-10-24T06:00:00Z', data: sample['gateway.incident'] }; await forward(env, w.db, w.clock, ev); await forward(env, w.db, w.clock, ev); assert.equal((await rows(w)).length, 1, 'idempotent by event id');
    let r = await flush(env, w.db, w.clock); assert.deepEqual([r.sent, r.retry], [0, 1]); let row = (await rows(w))[0]; assert.equal(row.state, 'pending'); assert.equal(row.attempts, 1); assert.equal(row.next_attempt_at, '2026-10-24T06:15:00Z', 'Retry-After 900 s honoured');
    assert.equal((await flush(env, w.db, w.clock)).retry, 0, 'not due yet: nothing is sent'); w.clock.advance(16 * 60000); mode.n = 503; r = await flush(env, w.db, w.clock); row = (await rows(w))[0]; assert.equal(row.attempts, 2); assert.equal(row.next_attempt_at, new Date(w.clock().getTime() + 120000).toISOString().replace(/\.\d{3}Z$/, 'Z'), '60 s x 2^attempts');
    w.clock.advance(3 * 3600000); mode.n = 400; r = await flush(env, w.db, w.clock); assert.equal(r.dead, 1); assert.equal((await rows(w))[0].state, 'dead'); assert.match((await rows(w))[0].last_error, /400/);
    await w.db.prepare("UPDATE guardops_outbox SET state='pending', attempts=19, next_attempt_at='2000-01-01T00:00:00Z'").run(); mode.n = 500; assert.equal((await flush(env, w.db, w.clock)).dead, 1); assert.match((await rows(w))[0].last_error, /gave up/);
  } finally { await srv.close(); }
  const down = cfg('http://127.0.0.1:1/x'); const w2 = await world(); await forward(down, w2.db, w2.clock, { type: 'gateway.incident', data: sample['gateway.incident'] }); const r2 = await flush(down, w2.db, w2.clock); assert.equal(r2.retry, 1, 'ingestion down: kept for later, nothing thrown'); assert.equal((await rows(w2))[0].last_error, 'network error');
});
test('a request is never delayed or failed by GuardOps: an incident during a request is queued and delivered after the response; a down receiver changes nothing', async () => {
  const srv = await ingest((req, res) => { res.writeHead(202); res.end(); }); const w = await apiWorld({ envExtra: { KEY_PEPPER: 'k'.repeat(40), ...cfg(srv.url) } }); await w.tenant('t1'); const key = (await w.key('t1')).key;
  try {
    w.r2.fail = true; const a = await w.call('/v1/premium/releases/prem-1/download', { key }); const r = await w.call(a.json.url.replace('https://gw.test', ''), { key });
    assert.equal(r.status, 503, 'the request answers exactly as before'); assert.ok(srv.seen.some((c) => c.body.events.some((e) => e.type === 'download.failed')), 'the R2 failure reached the fake GuardOps');
    await srv.close(); w.r2.fail = true; const a2 = await w.call('/v1/premium/releases/prem-1/download', { key }); const r2 = await w.call(a2.json.url.replace('https://gw.test', ''), { key }); assert.equal(r2.status, 503, 'receiver down: same answer');
  } finally { await srv.close().catch(() => {}); }
});
test('the cron reports a collector STREAK (third consecutive failure), flushes the outbox, and sends one metrics snapshot a day', async () => {
  const srv = await ingest((req, res) => { res.writeHead(202); res.end(); }); const w = await apiWorld({ envExtra: { KEY_PEPPER: 'k'.repeat(40), ...cfg(srv.url) } });
  const real = globalThis.fetch; const fire = async (at, f) => { const waits = []; globalThis.fetch = (u, o) => (String(u).startsWith('http://127.0.0.1') ? real(u, o) : f(u, o)); try { await worker.scheduled({ scheduledTime: Date.parse(at) }, w.env, { waitUntil: (p) => waits.push(p) }); await Promise.all(waits); } finally { globalThis.fetch = real; } };
  try {
    const limited = async () => new Response('{"message":"API rate limit exceeded"}', { status: 403, headers: { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '1790000000' } });
    await fire('2026-10-24T01:17:00Z', limited); await fire('2026-10-24T02:17:00Z', limited); assert.equal(srv.seen.length, 0, 'two failures are a blip, not an incident'); await fire('2026-10-24T03:17:00Z', limited);
    const inc = srv.seen.flatMap((c) => c.body.events).filter((e) => e.type === 'cron.run.failed'); assert.equal(inc.length, 1); assert.equal(inc[0].data.code, 'github_rate_limited'); assert.equal(inc[0].data.severity, 'high');
    await fire('2026-10-24T06:17:00Z', limited); const snaps = srv.seen.flatMap((c) => c.body.events).filter((e) => e.type === 'metrics.snapshot'); assert.equal(snaps.length, 1); assert.deepEqual(validate(SCHEMA, snaps[0]), []); assert.deepEqual(Object.keys(snaps[0].data).sort(), ['collector_ok_24h', 'collector_runs_24h', 'day', 'error_rate', 'requests', 'server_errors']);
    await fire('2026-10-24T07:17:00Z', limited); assert.equal(srv.seen.flatMap((c) => c.body.events).filter((e) => e.type === 'metrics.snapshot').length, 1, 'once a day');
  } finally { await srv.close(); }
});

test('local tools report FIRING alerts through the same contract; an unreachable receiver spools them and the next run delivers them once', async () => {
  const { emitAlerts } = await import('../tools/guardops_emit.mjs'); const { mkdtempSync, rmSync, existsSync, readFileSync } = await import('node:fs'); const { join } = await import('node:path'); const { homedir } = await import('node:os');
  const dir = mkdtempSync(join(homedir(), '.mg-spool-')), spool = join(dir, 'spool.jsonl'); const alerts = [{ schema: 'macguard.alert/1', rule_id: 'backup.stale', category: 'integrity', severity: 'high', state: 'FIRING', message: 'Last successful backup 40 h ago.', evaluated_at: '2026-10-24T06:00:00Z', source: { kind: 'agent', id: 'backup-check' } }, { rule_id: 'backup.integrity', state: 'OK', severity: 'critical', message: 'fine' }];
  try {
    assert.deepEqual(await emitAlerts(alerts, {}, { spool }), { sent: 0, spooled: 0, skipped: true });
    const env = { GUARDOPS_INGEST_URL: 'http://127.0.0.1:1/x', GUARDOPS_INGEST_TOKEN: TOKEN, GUARDOPS_ALLOW_INSECURE_LOCAL: '1' }; assert.deepEqual(await emitAlerts(alerts, env, { spool }), { sent: 0, spooled: 1, skipped: false }); assert.equal(readFileSync(spool, 'utf8').trim().split('\n').length, 1); assert.ok(!readFileSync(spool, 'utf8').includes(TOKEN));
    const srv = await ingest((req, res) => { res.writeHead(202); res.end(); }); try { const r = await emitAlerts([], cfg(srv.url), { spool }); assert.equal(r.sent, 1, 'the spooled event is delivered'); assert.equal(srv.seen[0].body.events[0].type, 'backup.failed'); assert.deepEqual(validate(SCHEMA, srv.seen[0].body.events[0]), []); assert.equal(readFileSync(spool, 'utf8'), '');
      assert.equal((await emitAlerts(alerts, cfg(srv.url), { spool })).sent, 1); assert.equal(srv.seen.at(-1).body.events[0].event_id, srv.seen[0].body.events[0].event_id, 'the same fact keeps the same id, so the receiver can dedupe'); } finally { await srv.close(); }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('self-hosted GuardOps: any https host the installation lists is accepted, anything else is not; the SaaS default admits only ingest.mac-guard.com; the credential stays tied to the listed host', async () => {
  const own = { GUARDOPS_INGEST_URL: 'https://guardops.corp.example/ingest/v1', GUARDOPS_ALLOWED_HOSTS: 'guardops.corp.example' };
  assert.equal(endpoint(own).hostname, 'guardops.corp.example'); assert.equal(endpoint({ ...own, GUARDOPS_ALLOWED_HOSTS: 'other.corp.example' }), null, 'a URL whose host is not listed is refused'); assert.equal(endpoint({ GUARDOPS_INGEST_URL: own.GUARDOPS_INGEST_URL }), null, 'the SaaS default does not admit a custom host');
  assert.equal(endpoint({ ...own, GUARDOPS_INGEST_URL: 'http://guardops.corp.example/x' }), null, 'plain http is never accepted for a real host'); assert.equal(endpoint({ GUARDOPS_INGEST_URL: 'https://ingest.mac-guard.com/v1/events' }).pathname, '/v1/events');
  const calls = []; const w = await world(); await forward({ ...own, GUARDOPS_INGEST_TOKEN: TOKEN }, w.db, w.clock, { type: 'gateway.incident', at: '2026-10-24T06:00:00Z', data: sample['gateway.incident'] });
  const r = await flush({ ...own, GUARDOPS_INGEST_TOKEN: TOKEN, guardopsFetch: async (u, o) => { calls.push({ u: String(u), auth: o.headers.authorization, redirect: o.redirect }); return new Response(null, { status: 202 }); } }, w.db, w.clock);
  assert.equal(r.sent, 1); assert.equal(calls[0].u, 'https://guardops.corp.example/ingest/v1'); assert.equal(calls[0].auth, `Bearer ${TOKEN}`); assert.equal(calls[0].redirect, 'manual', 'redirects are never followed with the credential');
});

test('the published contract examples are valid, current, cover every operational event type the adapter can emit, and carry no customer id or secret', async () => {
  const { execFileSync } = await import('node:child_process'); const { readdirSync } = await import('node:fs');
  execFileSync('node', [new URL('../tools/gen_contract_examples.mjs', import.meta.url).pathname, '--check']);
  const dir = new URL('../../contracts/v1/examples/', import.meta.url), files = readdirSync(dir).filter((f) => f.startsWith('event-')), types = files.map((f) => JSON.parse(readFileSync(new URL(f, dir), 'utf8')));
  for (const e of types) assert.deepEqual(validate(SCHEMA, e), [], e.type);
  assert.deepEqual(types.map((e) => e.type).sort(), ['backup.failed', 'cron.run.failed', 'download.failed', 'gateway.error', 'integrity.error', 'metrics.snapshot', 'saturation.detected', 'security.incident']);
  const all = JSON.stringify(types); assert.ok(!/tenant-ref|t1|mgk_|mga_|whsec|sk_(live|test)/.test(all), 'no customer tenant id, key or secret in any example');
  const batch = JSON.parse(readFileSync(new URL('batch.json', dir), 'utf8')); assert.equal(batch.schema, 'macguard.event-batch/1'); assert.equal(batch.events.length, types.length);
});
