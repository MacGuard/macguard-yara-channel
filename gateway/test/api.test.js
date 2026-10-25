import test from 'node:test';
import assert from 'node:assert/strict';
import { apiWorld, FILE, FILE_SHA, SEED, clone, paid } from './apiworld.js';

const KEY = async (w, tenant = 't1', scopes, o = {}) => { await w.tenant(tenant, o); return (await w.key(tenant, scopes)).key; };

test('Community is free and independent: no credentials, no database, and the origin failing only fails the index', async () => {
  const w = await apiWorld(); w.env.DB = undefined;                                                         // not even a database: Community must not touch it
  const a = await w.call('/v1/community/releases'); assert.equal(a.status, 200); assert.equal(a.text, w.origin.releases);
  assert.equal((await w.call('/v1/community/releases/latest')).text, w.origin.latest); assert.match(a.res.headers.get('cache-control'), /public/);
  w.origin.fail = true; const b = await w.call('/v1/community/releases'); assert.equal(b.status, 502); assert.equal(b.json.error.code, 'origin_unavailable');
});
test('Premium and the API are protected: no key, a bad key, a revoked key', async () => {
  const w = await apiWorld(); const key = await KEY(w);
  for (const p of ['/v1/premium/releases', '/v1/premium/releases/latest', '/v1/account/usage', '/v1/account/entitlements', '/v1/account/commercial', '/v1/intelligence/hash/' + w.H]) {
    const r = await w.call(p); assert.equal(r.status, 401, p); assert.equal(r.res.headers.get('www-authenticate'), 'Bearer realm="macguard"');
    assert.equal((await w.call(p, { key: key.slice(0, -2) + 'zz' })).status, 401);
  }
  assert.equal((await w.call('/v1/premium/releases', { key })).status, 200);
  const { revokeKey } = await import('../src/auth.js'); await revokeKey(w.db, w.clock, 't1', key.split('_')[1]); assert.equal((await w.call('/v1/premium/releases', { key })).status, 401);
});
test('FREE_LAUNCH serves the authorised catalogue and every use is recorded with its theoretical value', async () => {
  const w = await apiWorld(); const key = await KEY(w);
  const l = await w.call('/v1/premium/releases', { key }); assert.deepEqual(l.json.releases.map((r) => r.id), ['prem-1'], 'a release with unlicensed content is not even listed'); assert.equal(l.res.headers.get('x-commercial-mode'), 'FREE_LAUNCH');
  assert.equal((await w.call('/v1/premium/releases/latest', { key })).status, 200);
  const h = await w.call('/v1/intelligence/hash/' + w.H, { key }); assert.equal(h.status, 200); assert.equal(h.json.found, true); assert.deepEqual(h.json.records.map((r) => r.source_id), ['syn-ok']);
  assert.ok(!h.text.includes('MUST-NOT-APPEAR'), 'content from a source that is not licensed for the API is never returned, even in the free launch');
  assert.equal((await w.call('/v1/intelligence/hash/' + 'b'.repeat(64), { key })).json.found, false, 'a source without owner confirmation does not count as licensed');
  assert.equal((await w.call('/v1/intelligence/hash/xyz', { key })).status, 400);
  const c = await w.call('/v1/intelligence/cve/cve-2026-0001', { key }); assert.equal(c.json.value, 'CVE-2026-0001'); assert.equal(c.json.priority.score, 95);
  assert.deepEqual(c.json.priority.factors.map((f) => [f.factor, f.points]), [['listed_as_exploited', 50], ['epss', 30], ['cvss', 15]]); assert.ok(!JSON.stringify(c.json).includes('0.99'));
  const s = await w.call('/v1/intelligence/ioc/search', { key, method: 'POST', json: { values: ['203.0.113.7', '203.0.113.8'] } }); assert.deepEqual(s.json.results.map((r) => r.found), [true, false], 'an expired indicator is not served');
  assert.equal((await w.call('/v1/intelligence/ioc/search', { key, method: 'POST', json: { values: ['not an indicator'] } })).status, 400);
  const e1 = await w.call('/v1/intelligence/enrich', { key, method: 'POST', json: { indicators: ['203.0.113.7', 'CVE-2026-0001'] } }); assert.equal(e1.status, 400); assert.equal(e1.json.error.code, 'idempotency_key_required');
  const e = await w.call('/v1/intelligence/enrich', { key, method: 'POST', headers: { 'idempotency-key': 'enrich-0001' }, json: { indicators: ['203.0.113.7', 'CVE-2026-0001'] } });
  assert.deepEqual(e.json.results[0].relations, { malware: ['SynMalware'], cves: ['CVE-2026-0001'], attack: ['T1071'] }); assert.equal(e.json.results[1].priority.score, 95);
  const ev = (await w.db.prepare("SELECT operation, billable_micros b, theoretical_micros t, commercial_mode m FROM usage_events WHERE operation = 'intel.enrich'").all()).results; assert.deepEqual(JSON.parse(JSON.stringify(ev)), [{ operation: 'intel.enrich', b: 0, t: 10000, m: 'FREE_LAUNCH' }]);
  const u = await w.call('/v1/account/usage', { key }); assert.equal(u.json.billed_micros, 0); assert.ok(u.json.theoretical_micros >= 10000);
});
test('errors never expose internals: unknown routes, bad JSON, huge bodies, wrong types and an internal failure', async () => {
  const w = await apiWorld(); const key = await KEY(w);
  assert.equal((await w.call('/v1/nope', { key })).status, 404); assert.equal((await w.call('/v1/intelligence/enrich', { key, method: 'POST', body: '{bad', headers: { 'content-type': 'application/json', 'idempotency-key': 'abcdefgh' } })).status, 400);
  assert.equal((await w.call('/v1/intelligence/enrich', { key, method: 'POST', body: 'x'.repeat(70000), headers: { 'content-type': 'application/json', 'content-length': '70000' } })).status, 413);
  assert.equal((await w.call('/v1/intelligence/enrich', { key, method: 'POST', body: '{}', headers: { 'content-type': 'text/plain' } })).status, 415);
  const boom = await w.call('/v1/premium/releases', { key, headers: {} }); assert.equal(boom.status, 200);
  const realPrepare = w.db.prepare; w.db.prepare = (sql) => { if (/FROM releases/.test(sql)) throw new Error('SQLITE_ERROR near "FROM": /srv/secret/path password=hunter2'); return realPrepare(sql); };
  const r = await w.call('/v1/premium/releases', { key }); w.db.prepare = realPrepare;
  assert.equal(r.status, 500); assert.equal(r.json.error.code, 'internal_error'); for (const leak of ['SQLITE', 'hunter2', '/srv', 'password', 'stack', ' at ']) assert.ok(!r.text.includes(leak), leak); assert.match(r.json.error.request_id, /^req_/);
});
test('suspended tenants, missing scopes and plans are refused with the right status', async () => {
  const w = await apiWorld({ policy: paid() }); const k = await KEY(w, 'c1'); assert.equal((await w.call('/v1/premium/releases', { key: k })).json.error.code, 'not_entitled');
  const w2 = await apiWorld(); const narrow = await KEY(w2, 't1', ['account.read']); assert.equal((await w2.call('/v1/premium/releases', { key: narrow })).json.error.code, 'insufficient_scope');
  assert.equal((await w2.call('/v1/account/entitlements', { key: narrow })).status, 200);
  await w2.tenant('s1', { status: 'suspended' }); const sk = (await w2.key('s1')).key; assert.equal((await w2.call('/v1/premium/releases', { key: sk })).json.error.code, 'tenant_suspended');
});
test('rate limits answer 429 with Retry-After, and a tenant can never read another tenant\'s usage or downloads', async () => {
  const d = clone(SEED); d.launch.quotas.minute = 3; const w = await apiWorld({ policy: d }); const a = await KEY(w, 'ta'), b = await KEY(w, 'tb');
  for (let i = 0; i < 3; i++) assert.equal((await w.call('/v1/intelligence/hash/' + w.H, { key: a })).status, 200);
  const r = await w.call('/v1/intelligence/hash/' + w.H, { key: a }); assert.equal(r.status, 429); assert.ok(Number(r.res.headers.get('retry-after')) > 0);
  assert.equal((await w.call('/v1/intelligence/hash/' + w.H, { key: b })).status, 200, 'another tenant has its own counters');
  const ub = await w.call('/v1/account/usage', { key: b }); assert.equal(ub.json.operations.reduce((n, o) => n + o.n, 0), 1);
});

// ---- downloads ----
const auth = (w, key, id = 'prem-1', headers = {}) => w.call(`/v1/premium/releases/${id}/download`, { key, headers });
test('download: request -> authorisation -> transfer, bytes and SHA-256 verified, resumable by Range', async () => {
  const w = await apiWorld(); const key = await KEY(w);
  const a = await auth(w, key); assert.equal(a.status, 200); assert.equal(a.json.sha256, FILE_SHA); assert.equal(a.json.size, FILE.length); assert.match(a.json.url, /^https:\/\/gw\.test\/v1\/dl\/dlt_/);
  const path = a.json.url.replace('https://gw.test', '');
  assert.equal((await w.call(path)).status, 401, 'the link alone is useless without the key');
  const part = await w.call(path, { key, headers: { range: 'bytes=0-1999' } }); assert.equal(part.status, 206); assert.equal(part.res.headers.get('content-range'), `bytes 0-1999/${FILE.length}`); assert.equal(part.bytes.length, 2000);
  assert.equal((await w.db.prepare('SELECT state FROM downloads').first()).state, 'in_progress');
  const rest = await w.call(path, { key, headers: { range: 'bytes=2000-' } }); assert.equal(rest.status, 206);
  const whole = new Uint8Array([...part.bytes, ...rest.bytes]); assert.deepEqual(whole, FILE);
  const { createHash } = await import('node:crypto'); assert.equal(createHash('sha256').update(whole).digest('hex'), a.json.sha256);
  const row = await w.db.prepare('SELECT state, bytes, uses FROM downloads').first(); assert.deepEqual([row.state, row.bytes, row.uses], ['completed', FILE.length, 2]);
  assert.equal((await w.call(path, { key })).status, 410, 'a completed authorisation does not serve again');
  assert.equal((await w.call(path, { key, headers: { range: 'bytes=9999-' } })).status, 410);
});
test('download: shared links, other tenants, expiry, unknown tokens and bad ranges', async () => {
  const w = await apiWorld(); const k1 = await KEY(w, 'ta'); const k1b = (await w.key('ta')).key; const k2 = await KEY(w, 'tb');
  const a = await auth(w, k1); const path = a.json.url.replace('https://gw.test', '');
  const shared = await w.call(path, { key: k1b }); assert.equal(shared.status, 403); assert.equal(shared.json.error.code, 'forbidden');                  // same tenant, different key: a shared link
  assert.equal((await w.call(path, { key: k2 })).status, 404, 'another tenant learns nothing');
  assert.equal((await w.call('/v1/dl/dlt_' + 'A'.repeat(43), { key: k1 })).status, 404); assert.equal((await w.call('/v1/dl/nonsense', { key: k1 })).status, 404);
  assert.equal((await w.call(path, { key: k1, headers: { range: 'bytes=5-1' } })).status, 416); assert.equal((await w.call(path, { key: k1, headers: { range: 'bytes=0-1,5-9' } })).status, 416);
  assert.ok((await w.db.prepare("SELECT 1 x FROM audit WHERE action = 'download.shared_link_rejected'").first()));
  w.clock.advance(121000); const late = await w.call(path, { key: k1 }); assert.equal(late.status, 410); assert.equal(late.json.error.code, 'expired');
  assert.equal((await w.db.prepare('SELECT state FROM downloads').first()).state, 'expired');
});
test('download: attempts per authorisation are limited, a retry is one logical operation, and the monthly transfer allowance holds', async () => {
  const d = clone(SEED); d.launch.quotas.bytes_month = FILE.length + 100; const w = await apiWorld({ policy: d }); const key = await KEY(w);
  const a1 = await auth(w, key), a2 = await auth(w, key); assert.equal(a1.status, 200); assert.equal(a2.status, 200); assert.notEqual(a1.json.download_id, a2.json.download_id);
  assert.equal((await w.db.prepare("SELECT COUNT(*) n FROM usage_events WHERE operation = 'premium.download'").first()).n, 1, 'asking twice the same day for the same release is one logical operation');
  assert.equal((await w.db.prepare("SELECT n FROM counters WHERE scope = 'downloads'").first()).n, 1);
  assert.equal((await w.call(a1.json.url.replace('https://gw.test', ''), { key })).status, 200);
  const over = await w.call(a2.json.url.replace('https://gw.test', ''), { key }); assert.equal(over.status, 429); assert.equal(over.json.error.code, 'bandwidth_exceeded');
});
test('download: unlicensed content is refused even for free; a withdrawn or unknown release does not exist', async () => {
  const w = await apiWorld(); const key = await KEY(w);
  const bad = await auth(w, key, 'prem-bad'); assert.equal(bad.status, 409); assert.equal(bad.json.error.code, 'release_not_licensed'); assert.equal((await w.db.prepare('SELECT COUNT(*) n FROM downloads').first()).n, 0);
  assert.ok(await w.db.prepare("SELECT 1 x FROM audit WHERE action = 'download.blocked_license'").first());
  assert.equal((await auth(w, key, 'nope')).status, 404); await w.db.prepare("UPDATE releases SET status = 'withdrawn' WHERE id = 'prem-1'").run(); assert.equal((await auth(w, key)).status, 404);
  await w.db.prepare("UPDATE releases SET status = 'published' WHERE id = 'prem-1'").run(); await w.db.prepare("UPDATE intel_sources SET status = 'BLOCKED' WHERE source_id = 'syn-ok'").run();
  assert.equal((await auth(w, key)).json.error.code, 'release_not_licensed', 'a later licence change closes the door immediately');
});
test('download: the private origin failing gives a generic error, an event, and leaks nothing', async () => {
  const w = await apiWorld(); const key = await KEY(w); const a = await auth(w, key); const path = a.json.url.replace('https://gw.test', '');
  w.r2.fail = true; const r = await w.call(path, { key }); assert.equal(r.status, 503); assert.equal(r.json.error.code, 'origin_unavailable'); for (const leak of ['bucket', 'private-bucket', 'hunter2', 'account']) assert.ok(!r.text.includes(leak), leak);
  w.r2.fail = false; w.r2.missing = true; assert.equal((await w.call(path, { key })).status, 503); assert.ok(w.env.EVENTS.events.some((e) => e.type === 'gateway.incident'));
  w.r2.missing = false; assert.equal((await w.call(path, { key })).status, 200, 'recovers when the origin returns');
});
