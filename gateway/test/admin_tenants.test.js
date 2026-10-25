import test from 'node:test';
import assert from 'node:assert/strict';
import { apiWorld } from './apiworld.js';
import { fromBase32, totp, stepOf } from '../src/totp.js';
import { createAdmin } from '../src/admin.js';

const SECRET = { KEY_PEPPER: 'k'.repeat(40), ANALYTICS_PEPPER: 'a'.repeat(40) };
async function setup() {
  const w = await apiWorld({ envExtra: SECRET }), adm = await createAdmin(w.env.DB, w.env, w.clock, { name: 'root' }), seed = fromBase32(adm.totp_seed_base32);
  const A = async (path, o = {}) => { w.clock.advance(60000); return w.call(path, { ...o, headers: { authorization: `Bearer ${adm.key}`, 'x-mfa-code': await totp(seed, stepOf(w.clock().getTime())) } }); };
  return { w, A };
}
test('onboarding end to end: create tenant, issue a scoped key once, the key works, tenant analytics are its own, revoke stops it', async () => {
  const { w, A } = await setup();
  assert.equal((await w.call('/admin/v1/tenants')).status, 401);
  const t = await A('/admin/v1/tenants', { method: 'POST', json: { id: 'acme', name: 'Acme Corp', plan: 'community' } }); assert.equal(t.status, 201);
  assert.equal((await A('/admin/v1/tenants', { method: 'POST', json: { id: 'acme', name: 'Again' } })).status, 409);
  for (const bad of [{ id: 'A B', name: 'x x' }, { id: 'ok-id', name: 'x', plan: 'gold' }, { id: '../x', name: 'xx' }]) assert.equal((await A('/admin/v1/tenants', { method: 'POST', json: bad })).status, 400, JSON.stringify(bad));
  const k = await A('/admin/v1/tenants/acme/keys', { method: 'POST', json: { scopes: ['intel.query', 'account.read'], label: 'ci', ttl_days: 30 } }); assert.equal(k.status, 201); assert.equal(k.res.headers.get('cache-control'), 'no-store'); assert.match(k.json.key, /^mgk_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$/);
  assert.equal((await w.call('/v1/intelligence/hash/' + 'a'.repeat(64), { key: k.json.key })).status, 200); assert.equal((await w.call('/v1/account/analytics', { key: k.json.key })).json.tenant_id, 'acme');
  const detail = await A('/admin/v1/tenants/acme'); assert.ok(!JSON.stringify(detail.json).includes(k.json.key) && !JSON.stringify(detail.json).includes('secret_hash'), 'the secret is never shown again');
  assert.equal((await A('/admin/v1/tenants/acme/keys', { method: 'POST', json: { scopes: ['nope'] } })).status, 400); assert.equal((await A('/admin/v1/tenants/acme/keys', { method: 'POST', json: { scopes: [] } })).status, 400);
  assert.equal((await A(`/admin/v1/tenants/acme/keys/${k.json.key_id}/revoke`, { method: 'POST' })).status, 200); assert.equal((await w.call('/v1/intelligence/hash/' + 'a'.repeat(64), { key: k.json.key })).status, 401);
  assert.equal((await A(`/admin/v1/tenants/acme/keys/${k.json.key_id}/revoke`, { method: 'POST' })).status, 404, 'already revoked');
});
test('rotation keeps scopes and actor kind, the old key works only for the overlap, and suspension blocks both issuing and use', async () => {
  const { w, A } = await setup(); await A('/admin/v1/tenants', { method: 'POST', json: { id: 'beta', name: 'Beta Ltd' } });
  const k = await A('/admin/v1/tenants/beta/keys', { method: 'POST', json: { scopes: ['intel.query'], actor_kind: 'authenticated_service' } });
  const n = await A(`/admin/v1/tenants/beta/keys/${k.json.key_id}/rotate`, { method: 'POST', json: { overlap_hours: 1 } }); assert.equal(n.status, 201);
  const keys = (await A('/admin/v1/tenants/beta')).json.keys; assert.deepEqual(keys.map((x) => x.actor_kind), ['authenticated_service', 'authenticated_service']); assert.deepEqual(keys[1].scopes, ['intel.query']);
  const hash = '/v1/intelligence/hash/' + 'a'.repeat(64); assert.equal((await w.call(hash, { key: k.json.key })).status, 200); w.clock.advance(2 * 3600000); assert.equal((await w.call(hash, { key: k.json.key })).status, 401, 'overlap over'); assert.equal((await w.call(hash, { key: n.json.key })).status, 200);
  assert.equal((await A('/admin/v1/tenants/beta/status', { method: 'POST', json: { status: 'suspended' } })).status, 200); assert.equal((await w.call(hash, { key: n.json.key })).status, 403);
  assert.equal((await A('/admin/v1/tenants/beta/keys', { method: 'POST', json: { scopes: ['intel.query'] } })).status, 409);
});
test('listing is paginated and cursor-validated; tenant keys cannot reach any of these routes; every change is audited without secrets', async () => {
  const { w, A } = await setup(); for (const id of ['t-a', 't-b', 't-c']) await A('/admin/v1/tenants', { method: 'POST', json: { id, name: 'Tenant ' + id } });
  const p1 = (await A('/admin/v1/tenants?limit=2')).json; assert.equal(p1.tenants.length, 2); assert.equal(p1.next, 't-b'); assert.deepEqual((await A('/admin/v1/tenants?limit=2&after=t-b')).json.tenants.map((x) => x.id), ['t-c']); assert.equal((await A('/admin/v1/tenants?after=%3Bdrop')).status, 400);
  const k = await A('/admin/v1/tenants/t-a/keys', { method: 'POST', json: { scopes: ['account.read'] } });
  for (const [path, method] of [['/admin/v1/tenants', 'GET'], ['/admin/v1/tenants', 'POST'], ['/admin/v1/tenants/t-a', 'GET']]) assert.equal((await w.call(path, { method, key: k.json.key, json: method === 'POST' ? { id: 'x1', name: 'xx' } : undefined })).status, 401);
  const rows = (await w.env.DB.prepare("SELECT action, detail FROM audit WHERE action LIKE 'tenant.%' OR action LIKE 'key.%'").all()).results; assert.ok(rows.some((r) => r.action === 'tenant.created') && rows.some((r) => r.action === 'key.issued_by_admin'));
  assert.ok(!JSON.stringify(rows).includes('mgk_'), 'no key material in the audit chain');
});
