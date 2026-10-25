import test from 'node:test';
import assert from 'node:assert/strict';
import { mergeRange, covers } from '../src/downloads.js';
import { quantile, bucketIndex } from '../src/analytics.js';
import { apiWorld } from './apiworld.js';

const rows = (w, sql, ...a) => w.env.DB.prepare(sql).bind(...a).all().then((r) => r.results);
const SECRET = { KEY_PEPPER: 'k'.repeat(40), ANALYTICS_PEPPER: 'a'.repeat(40), COMMUNITY_DOWNLOAD_BASE: 'https://dl.example.test/base', COMMUNITY_DEFAULT_ASSET: 'bundle.tar.gz' };

test('mergeRange agrees with a brute-force byte model for every sequence of fragments', () => {
  let seed = 7; const rnd = (n) => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) % n;
  for (let round = 0; round < 300; round++) {
    const size = 1 + rnd(40), bytes = new Array(size).fill(false); let list = [];
    for (let i = 0; i < 1 + rnd(8); i++) {
      const s = rnd(size), e = s + 1 + rnd(size - s); list = mergeRange(list, s, e); for (let b = s; b < e; b++) bytes[b] = true;
      const model = []; for (let b = 0; b < size; b++) if (bytes[b]) { if (model.length && model.at(-1)[1] === b) model.at(-1)[1] = b + 1; else model.push([b, b + 1]); }
      assert.deepEqual(list, model, `round ${round}`); assert.equal(covers(list, size), bytes.every(Boolean));
    }
  }
});

test('the latency histogram yields upper-bound estimates and never invents a value for no data', () => {
  assert.equal(bucketIndex(5), 0); assert.equal(bucketIndex(5.1), 1); assert.equal(bucketIndex(99999), 9);
  assert.equal(quantile([0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0.5), null); assert.equal(quantile([9, 1, 0, 0, 0, 0, 0, 0, 0, 0], 0.95), 10); assert.equal(quantile([0, 0, 0, 0, 0, 0, 0, 0, 0, 3], 0.5), Infinity);
});

test('a REST call writes ONE aggregate row, and counts the actor once per day without storing the raw key id', async () => {
  const w = await apiWorld({ envExtra: SECRET }); await w.tenant('t1'); const key = (await w.key('t1')).key;
  const hash = '/v1/intelligence/hash/' + 'a'.repeat(64);
  for (let i = 0; i < 3; i++) assert.equal((await w.call(hash, { key })).status, 200);
  const agg = await rows(w, "SELECT * FROM analytics_daily WHERE tenant_id='t1' AND operation='intel.hash'");
  assert.equal(agg.length, 1); assert.equal(agg[0].requests, 3); assert.equal(agg[0].status_class, '2xx');
  assert.equal((await rows(w, "SELECT * FROM activity_daily WHERE tenant_id='t1'")).length, 1, 'three calls, one actor-day');
  assert.ok(!JSON.stringify(await rows(w, 'SELECT * FROM activity_daily')).includes(key.slice(0, 12)), 'no raw key id is stored');
});

test('refusals are counted by status class and an unauthenticated request creates no actor', async () => {
  const w = await apiWorld({ envExtra: SECRET }); await w.tenant('t1');
  assert.equal((await w.call('/v1/intelligence/hash/' + 'a'.repeat(64))).status, 401);
  assert.equal((await rows(w, 'SELECT * FROM activity_daily')).length, 0);
});

test('telemetry failure never changes the answer: with analytics tables gone the request still succeeds', async () => {
  const w = await apiWorld({ envExtra: SECRET }); await w.tenant('t1'); const key = (await w.key('t1')).key;
  await w.env.DB.prepare('DROP TABLE analytics_daily').run();
  assert.equal((await w.call('/v1/intelligence/hash/' + 'a'.repeat(64), { key })).status, 200);
});

test('Community download/manifest are validated redirects to GitHub; a redirect is counted as a redirect, never a completed download', async () => {
  const w = await apiWorld({ envExtra: SECRET });
  const r = await w.call('/v1/community/releases/rules-20261021-1/download');
  assert.equal(r.status, 302); assert.equal(r.res.headers.get('location'), 'https://dl.example.test/base/rules-20261021-1/bundle.tar.gz');
  const m = await w.call('/v1/community/releases/rules-20261021-1/manifest'); assert.ok(m.res.headers.get('location').endsWith('/manifest.json'));
  for (const bad of ['/v1/community/releases/..%2Fx/download', '/v1/community/releases/rules-1/download', '/v1/community/releases/rules-20261021-1/download?asset=../x']) assert.equal((await w.call(bad)).status, 400, bad);
  const c = await rows(w, 'SELECT * FROM community_requests_daily'); assert.equal(c.length, 2); assert.ok(c.every((x) => x.actor_kind === 'anonymous_request' && x.redirected === 1));
  assert.equal((await rows(w, 'SELECT * FROM downloads')).length, 0, 'no download row is ever created for a redirect');
});

test('Community redirects keep working when the telemetry store is down', async () => {
  const w = await apiWorld({ envExtra: SECRET }); await w.env.DB.prepare('DROP TABLE community_requests_daily').run();
  assert.equal((await w.call('/v1/community/releases/rules-20261021-1/download')).status, 302);
});

test('MCP calls are counted on their own channel, tool errors are separated, and an idempotent replay adds a request but no units or money', async () => {
  const w = await apiWorld({ envExtra: SECRET }); await w.tenant('t1'); const key = (await w.key('t1')).key;
  const meta = { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {}, 'io.modelcontextprotocol/clientInfo': { name: 't', version: '1' } };
  let n = 0; const mcp = (name, args, idem) => w.call('/mcp', { method: 'POST', key, headers: { 'mcp-protocol-version': '2026-07-28', 'mcp-method': 'tools/call', 'mcp-name': name, accept: 'application/json, text/event-stream' },
    json: { jsonrpc: '2.0', id: ++n, method: 'tools/call', params: { name, arguments: args, _meta: { ...meta, ...(idem ? { 'io.github.macguard/idempotencyKey': idem } : {}) } } } });
  const args = { hash: 'a'.repeat(64) };
  const a = await mcp('macguard_lookup_hash', args, 'idem-0001-test'); const b = await mcp('macguard_lookup_hash', args, 'idem-0001-test'); assert.equal(a.status, 200); assert.equal(b.json.result._meta['io.github.macguard/replayed'], true);
  const bad = await mcp('macguard_lookup_hash', { hash: 'zz' }); assert.equal(bad.json.result.isError, true);
  const agg = await rows(w, "SELECT status_class, requests, units, billable_micros FROM analytics_daily WHERE channel='mcp' ORDER BY status_class");
  const ok = agg.find((x) => x.status_class === '2xx'), err = agg.find((x) => x.status_class === 'tool_error');
  assert.equal(ok.requests, 2); assert.equal(err.requests, 1); assert.equal(ok.billable_micros, 0, 'FREE_LAUNCH bills nothing');
  const single = await rows(w, "SELECT COALESCE(SUM(units),0) u FROM usage_events WHERE tenant_id='t1'"); assert.equal(ok.units, single[0].u, 'units equal the ledger: the replay was not counted twice');
});

test('first-seen statements are written once per actor-day, but only AFTER a batch committed (a failed write is retried)', async () => {
  const w = await apiWorld({ envExtra: SECRET }); await w.tenant('t1'); const key = (await w.key('t1')).key; const url = '/v1/intelligence/hash/' + 'a'.repeat(64);
  const real = w.env.DB; let batches = 0, failNext = true;
  w.env.DB = { raw: real.raw, prepare: (s) => real.prepare(s), batch: async (l) => { if (l.some((x) => /analytics_daily/.test(x._sql))) { batches++; const first = l.some((x) => /INSERT OR IGNORE INTO activity_daily/.test(x._sql)); if (failNext) { failNext = false; throw new Error('d1 down'); } if (!first && batches > 2) l.forEach((x) => assert.ok(!/INSERT OR IGNORE/.test(x._sql), 'no redundant first-seen statements')); } return real.batch(l); } };
  assert.equal((await w.call(url, { key })).status, 200, 'telemetry failure does not fail the request');
  assert.equal((await rows(w, 'SELECT * FROM activity_daily')).length, 0, 'the failed batch wrote nothing');
  await w.call(url, { key }); assert.equal((await rows(w, 'SELECT * FROM activity_daily')).length, 1, 'the next request retried the first-seen rows');
  await w.call(url, { key }); await w.call(url, { key }); assert.equal((await rows(w, 'SELECT SUM(requests) r FROM analytics_daily'))[0].r, 3, 'the failed request is the one lost count'); assert.equal((await rows(w, 'SELECT * FROM activity_daily')).length, 1);
});
test('the telemetry kill switch turns every write off without touching the answer', async () => {
  const w = await apiWorld({ envExtra: { ...SECRET, ANALYTICS_ENABLED: '0' } }); await w.tenant('t1'); const key = (await w.key('t1')).key;
  assert.equal((await w.call('/v1/intelligence/hash/' + 'a'.repeat(64), { key })).status, 200); assert.equal((await w.call('/v1/community/releases/rules-20261021-1/download')).status, 302);
  for (const t of ['analytics_daily', 'activity_daily', 'community_requests_daily']) assert.equal((await rows(w, `SELECT * FROM ${t}`)).length, 0, t);
});
test('last_used_at is refreshed at most every five minutes, but authentication is unaffected', async () => {
  const w = await apiWorld({ envExtra: SECRET }); await w.tenant('t1'); const k = await w.key('t1'); const url = '/v1/intelligence/hash/' + 'a'.repeat(64); const lu = async () => (await rows(w, 'SELECT last_used_at l FROM api_keys'))[0].l;
  await w.call(url, { key: k.key }); const t0 = await lu(); assert.ok(t0); w.clock.advance(60000); await w.call(url, { key: k.key }); assert.equal(await lu(), t0, 'within 5 minutes: no write');
  w.clock.advance(300000); await w.call(url, { key: k.key }); assert.notEqual(await lu(), t0, 'after 5 minutes: refreshed');
});

test('the Community redirect target is configuration: unconfigured or non-https bases are refused, never guessed', async () => {
  for (const env of [{}, { COMMUNITY_DOWNLOAD_BASE: 'http://insecure.test/x', COMMUNITY_DEFAULT_ASSET: 'a' }, { COMMUNITY_DOWNLOAD_BASE: 'https://dl.test/x' }]) {
    const w = await apiWorld({ envExtra: { ...SECRET, COMMUNITY_DOWNLOAD_BASE: undefined, COMMUNITY_DEFAULT_ASSET: undefined, ...env } });
    assert.equal((await w.call('/v1/community/releases/rules-20261021-1/download')).status, 503, JSON.stringify(env));
  }
  const w = await apiWorld({ envExtra: SECRET }); assert.equal((await w.call('/v1/community/releases/rules-20261021-1/download?asset=other.sig')).res.headers.get('location'), 'https://dl.example.test/base/rules-20261021-1/other.sig');
});
