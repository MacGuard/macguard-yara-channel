// Tenant isolation matrix: two tenants use every tenant-scoped capability and neither can see, replay, consume or influence the other's data. Local (NODE_LOCAL); no remote tenant exists yet.
import test from 'node:test';
import assert from 'node:assert/strict';
import { apiWorld } from './apiworld.js';
import { fromBase32, totp, stepOf } from '../src/totp.js';
import { createAdmin } from '../src/admin.js';
import { routes } from '../tools/route_inventory.mjs';

const SECRET = { KEY_PEPPER: 'k'.repeat(40), ANALYTICS_PEPPER: 'a'.repeat(40), COMMUNITY_DOWNLOAD_BASE: 'https://dl.example.test/base', COMMUNITY_DEFAULT_ASSET: 'bundle.tar.gz' };
async function two() { const w = await apiWorld({ envExtra: SECRET }); await w.tenant('t1'); await w.tenant('t2'); return { w, k1: (await w.key('t1')).key, k2: (await w.key('t2')).key }; }
const HASH = '/v1/intelligence/hash/' + 'a'.repeat(64);

test('the same Idempotency-Key used by two tenants is two independent operations: no replay across tenants, separate ledger rows, separate usage', async () => {
  const { w, k1, k2 } = await two(); const body = { indicators: ['203.0.113.7'] }, hdr = { 'idempotency-key': 'shared-key-0001' };
  const a = await w.call('/v1/intelligence/enrich', { method: 'POST', key: k1, headers: hdr, json: body }), b = await w.call('/v1/intelligence/enrich', { method: 'POST', key: k2, headers: hdr, json: body });
  assert.equal(a.status, 200); assert.equal(b.status, 200); assert.notEqual(a.res.headers.get('x-usage-event-id'), b.res.headers.get('x-usage-event-id')); assert.equal(b.res.headers.get('x-idempotent-replayed'), null, 'tenant 2 did not receive tenant 1\'s stored result');
  const rows = (await w.env.DB.prepare("SELECT tenant_id, COUNT(*) n FROM usage_events WHERE operation = 'intel.enrich' GROUP BY tenant_id").all()).results.map((r) => ({ ...r })); assert.deepEqual(rows, [{ tenant_id: 't1', n: 1 }, { tenant_id: 't2', n: 1 }]);
  const again = await w.call('/v1/intelligence/enrich', { method: 'POST', key: k1, headers: hdr, json: body }); assert.equal(again.res.headers.get('x-idempotent-replayed'), 'true', 'within the same tenant the replay still works');
});
test('every tenant-scoped read shows only the caller\'s own numbers, whatever the query string says', async () => {
  const { w, k1, k2 } = await two(); for (let i = 0; i < 4; i++) await w.call(HASH, { key: k1 }); await w.call(HASH, { key: k2 });
  const u1 = await w.call('/v1/account/usage', { key: k1 }), u2 = await w.call('/v1/account/usage?tenant=t1&tenant_id=t1', { key: k2 });
  assert.notDeepEqual(u1.json, u2.json); assert.ok(!JSON.stringify(u2.json).includes('"t1"')); assert.ok(!JSON.stringify(u1.json).includes('"t2"'));
  const e2 = await w.call('/v1/account/entitlements', { key: k2, headers: { 'x-tenant-id': 't1' } }); assert.equal(e2.json.tenant.id, 't2', 'a tenant header is ignored on purpose');
  const a1 = await w.call('/v1/account/analytics', { key: k1 }), a2 = await w.call('/v1/account/analytics?tenant=t1', { key: k2 }); assert.equal(a1.json.tenant_id, 't1'); assert.equal(a2.json.tenant_id, 't2'); assert.ok(a1.json.kpis.requests_by_channel.value.rest.requests > a2.json.kpis.requests_by_channel.value.rest.requests);
});
test('MCP calls are isolated too: a tool reading usage under tenant 2 never sees tenant 1', async () => {
  const { w, k1, k2 } = await two(); for (let i = 0; i < 3; i++) await w.call(HASH, { key: k1 });
  const meta = { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {}, 'io.modelcontextprotocol/clientInfo': { name: 't', version: '1' } }; let n = 0;
  const call = (key) => w.call('/mcp', { method: 'POST', key, headers: { 'mcp-protocol-version': '2026-07-28', 'mcp-method': 'tools/call', 'mcp-name': 'macguard_account_usage', accept: 'application/json, text/event-stream' }, json: { jsonrpc: '2.0', id: ++n, method: 'tools/call', params: { name: 'macguard_account_usage', arguments: {}, _meta: meta } } });
  const r1 = await call(k1), r2 = await call(k2); assert.equal(r1.status, 200); assert.notDeepEqual(r1.json.result.structuredContent, r2.json.result.structuredContent); assert.ok(!JSON.stringify(r2.json).includes('t1'));
});
test('the administrator tenant view lists only that tenant\'s keys (never another tenant\'s), and one tenant\'s key id cannot be revoked through another tenant\'s path', async () => {
  const { w, k1, k2 } = await two(); const adm = await createAdmin(w.env.DB, w.env, w.clock, { name: 'root' }), seed = fromBase32(adm.totp_seed_base32);
  const A = async (path, o = {}) => { w.clock.advance(60000); return w.call(path, { ...o, headers: { authorization: `Bearer ${adm.key}`, 'x-mfa-code': await totp(seed, stepOf(w.clock().getTime())) } }); };
  const id1 = k1.split('_')[1]; const d1 = await A('/admin/v1/tenants/t1'), d2 = await A('/admin/v1/tenants/t2'); assert.deepEqual(d1.json.keys.map((k) => k.id), [id1]); assert.deepEqual(d2.json.keys.map((k) => k.id), [k2.split('_')[1]], 'tenant 2 sees its own key and not tenant 1\'s'); assert.ok(!JSON.stringify(d2.json).includes(id1));
  assert.equal((await A(`/admin/v1/tenants/t2/keys/${id1}/revoke`, { method: 'POST' })).status, 404, 'a key is revocable only through its own tenant'); assert.equal((await w.call(HASH, { key: k1 })).status, 200, 'and it still works');
  assert.equal((await A(`/admin/v1/tenants/t2/keys/${id1}/rotate`, { method: 'POST', json: {} })).status, 404);
});
test('no response of any documented public route sets a cookie or opens CORS to the world (host-only, header-authenticated service: safe next to the other subdomains)', async () => {
  const { w, k1 } = await two();
  for (const r of routes().filter((x) => !x.area.startsWith('admin') && x.area !== 'x402')) { const res = await w.call(r.path.replace('{token}', 'dlt_' + 'A'.repeat(43)).replace('{id}', 'rules-20261021-1').replace('{sha256}', 'a'.repeat(64)), { method: r.method, key: k1, json: ['POST', 'PUT'].includes(r.method) ? {} : undefined });
    assert.equal(res.res.headers.get('set-cookie'), null, `${r.method} ${r.path}`); const acao = res.res.headers.get('access-control-allow-origin'); assert.ok(acao === null, `${r.method} ${r.path} must not send CORS headers (${acao})`); }
});
