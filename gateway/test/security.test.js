import test from 'node:test';
import assert from 'node:assert/strict';
import { apiWorld } from './apiworld.js';
import { fromBase32, totp, stepOf } from '../src/totp.js';
import { createAdmin } from '../src/admin.js';
import { readBounded } from '../src/util.js';

const SECRET = { KEY_PEPPER: 'k'.repeat(40), ANALYTICS_PEPPER: 'a'.repeat(40) };
const stream = (n, chunk = 1000) => new ReadableStream({ start(c) { for (let i = 0; i < n; i += chunk) c.enqueue(new Uint8Array(Math.min(chunk, n - i)).fill(97)); c.close(); } });
const post = (w, path, body, headers = {}) => w.call(path, { method: 'POST', body, headers: { 'content-type': 'application/json', ...headers } });
const count = async (w, sql) => (await w.env.DB.prepare(sql).first()).n;

test('readBounded refuses a declared length over the limit without reading, and cuts a streamed body that lies or declares nothing', async () => {
  assert.equal(await readBounded(new Request('https://x.test', { method: 'POST', body: 'hello' }), 10), 'hello');
  await assert.rejects(readBounded(new Request('https://x.test', { method: 'POST', body: 'x'.repeat(50) }), 10), (e) => e.status === 413);
  const big = new Request('https://x.test', { method: 'POST', body: stream(100000), duplex: 'half' });          // no content-length: chunked
  await assert.rejects(readBounded(big, 5000), (e) => e.status === 413);
  assert.equal(await readBounded(new Request('https://x.test'), 10), '');
});
test('every body-reading route answers 413 for an oversized body and never parses it', async () => {
  const w = await apiWorld({ envExtra: { ...SECRET } }); await w.tenant('t1'); const key = (await w.key('t1')).key;
  const huge = '{"a":"' + 'x'.repeat(300 * 1024) + '"}';
  assert.equal((await post(w, '/stripe/webhook', huge)).status, 413, 'the size limit applies before the signature is even looked at');
  assert.equal((await post(w, '/stripe/webhook', '{}')).status, 400, 'a small unsigned body reaches the signature check and is refused');
  assert.equal((await w.call('/mcp', { method: 'POST', key, body: huge, headers: { 'content-type': 'application/json', 'mcp-protocol-version': '2025-11-25' } })).status, 413);
  assert.equal((await post(w, '/v1/intelligence/ioc/search', 'x'.repeat(70 * 1024), { authorization: `Bearer ${key}` })).status, 413);
});
test('unknown administrator ids cost no D1 write; attempts naming a real administrator are audited', async () => {
  const w = await apiWorld({ envExtra: { ...SECRET } }); const adm = await createAdmin(w.env.DB, w.env, w.clock, { name: 'root' });
  const before = await count(w, "SELECT COUNT(*) n FROM audit WHERE action = 'admin.rejected'");
  for (let i = 0; i < 5; i++) assert.equal((await w.call('/admin/v1/analytics/kpis', { headers: { authorization: `Bearer mga_${'0'.repeat(16)}_${'A'.repeat(43)}`, 'x-mfa-code': '000000' } })).status, 401);
  assert.equal(await count(w, "SELECT COUNT(*) n FROM audit WHERE action = 'admin.rejected'"), before, 'no row for unknown ids');
  assert.equal((await w.call('/admin/v1/analytics/kpis', { headers: { authorization: `Bearer ${adm.key}`, 'x-mfa-code': '000000' } })).status, 401);
  assert.equal(await count(w, "SELECT COUNT(*) n FROM audit WHERE action = 'admin.rejected'"), before + 1, 'a wrong code for a real administrator is audited');
});
test('administrator responses are identical for every failure mode (no oracle on key, id or code) and carry no internals', async () => {
  const w = await apiWorld({ envExtra: { ...SECRET } }); const adm = await createAdmin(w.env.DB, w.env, w.clock, { name: 'root' });
  const bodies = new Set(); const bad = [{}, { authorization: 'Bearer nope' }, { authorization: `Bearer mga_${'0'.repeat(16)}_${'A'.repeat(43)}`, 'x-mfa-code': '123456' }, { authorization: `Bearer ${adm.key.slice(0, -1)}A`, 'x-mfa-code': '123456' }, { authorization: `Bearer ${adm.key}`, 'x-mfa-code': '123456' }];
  for (const h of bad) { const r = await w.call('/admin/v1/analytics/kpis', { headers: h }); assert.equal(r.status, 401); bodies.add(JSON.stringify({ ...r.json, error: { ...r.json.error, request_id: '-' } })); }
  assert.equal(bodies.size, 1, 'one indistinguishable answer');
});
test('a replayed TOTP code is refused, and a tenant key is never accepted on administrator routes', async () => {
  const w = await apiWorld({ envExtra: { ...SECRET } }); await w.tenant('t1'); const key = (await w.key('t1')).key;
  const adm = await createAdmin(w.env.DB, w.env, w.clock, { name: 'root' }), seed = fromBase32(adm.totp_seed_base32); w.clock.advance(60000);
  const h = { authorization: `Bearer ${adm.key}`, 'x-mfa-code': await totp(seed, stepOf(w.clock().getTime())) };
  assert.equal((await w.call('/admin/v1/analytics/kpis', { headers: h })).status, 200); assert.equal((await w.call('/admin/v1/analytics/kpis', { headers: h })).status, 401, 'same code twice');
  assert.equal((await w.call('/admin/v1/analytics/kpis', { key })).status, 401);
});
test('administrator filters cannot be used to probe other tenants through the tenant API, and tenant keys are bound to their tenant', async () => {
  const w = await apiWorld({ envExtra: { ...SECRET } }); await w.tenant('t1'); await w.tenant('t2'); const k1 = (await w.key('t1')).key;
  for (const q of ['?tenant=t2', '?tenant_id=t2', '?tenant=ghost']) { const r = await w.call('/v1/account/analytics' + q, { key: k1 }); assert.equal(r.status, 200); assert.equal(r.json.tenant_id, 't1'); }
  const ent = await w.call('/v1/account/entitlements', { key: k1 }); assert.ok(!JSON.stringify(ent.json).includes('t2'));
});

test('the hostname gate: only allowed hosts answer, /admin can be confined to its own hostnames, and unset means unrestricted', async () => {
  const w = await apiWorld({ envExtra: { ...SECRET } }); const on = async (host, path, env = {}) => { Object.assign(w.env, { ALLOWED_HOSTS: undefined, ADMIN_HOSTS: undefined }, env); return w.handle(new Request('https://' + host + path), w.env, { waitUntil() {} }); };
  assert.equal((await on('gw.test', '/v1/health')).status, 200, 'unset: unrestricted');
  assert.equal((await on('api.mac-guard.com', '/v1/health', { ALLOWED_HOSTS: 'api.mac-guard.com, quarantine-api.mac-guard.com' })).status, 200); assert.equal((await on('API.MAC-GUARD.COM', '/v1/health', { ALLOWED_HOSTS: 'api.mac-guard.com' })).status, 200, 'case-insensitive');
  for (const h of ['panel.mac-guard.com', 'ingest.mac-guard.com', 'rules.mac-guard.com', 'evil.example', 'api.mac-guard.com.evil.example']) { const r = await on(h, '/v1/health', { ALLOWED_HOSTS: 'api.mac-guard.com' }); assert.equal(r.status, 404, h); assert.ok(!(await r.text()).includes('api.mac-guard.com'), 'no hint about the allowed list'); }
  assert.equal((await on('api.mac-guard.com', '/admin/v1/analytics/kpis', { ALLOWED_HOSTS: 'api.mac-guard.com', ADMIN_HOSTS: 'admin.mac-guard.com' })).status, 404, '/admin only on its own hostname');
  assert.equal((await on('admin.mac-guard.com', '/admin/v1/analytics/kpis', { ALLOWED_HOSTS: 'api.mac-guard.com,admin.mac-guard.com', ADMIN_HOSTS: 'admin.mac-guard.com' })).status, 401, 'on the admin hostname the normal authentication applies');
  assert.equal((await on('api.mac-guard.com', '/v1/health', { ALLOWED_HOSTS: 'api.mac-guard.com', ADMIN_HOSTS: 'admin.mac-guard.com' })).status, 200, 'public routes unaffected by ADMIN_HOSTS');
});
