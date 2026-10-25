import { ALL_SCOPES } from './plans.js';
import { audit } from './audit.js';
import { HttpError, hmacHex, iso, randomHex, randomToken, safeEqual } from './util.js';

export const KEY_RE = /^mgk_([0-9a-f]{16})_([A-Za-z0-9_-]{43})$/;
const unauthorized = () => Object.assign(new HttpError(401, 'unauthorized', 'A valid API key is required.'), { headers: { 'www-authenticate': 'Bearer realm="macguard"' } });
export const LAST_USED_GRANULARITY_MS = 300000;
const pepper = (env) => { if (!env.KEY_PEPPER || env.KEY_PEPPER.length < 32) throw new Error('KEY_PEPPER is not configured'); return env.KEY_PEPPER; };

export async function createTenant(db, clock, { id, name, plan = 'community', status = 'active', budgetMicros = 0 }) {
  await db.prepare('INSERT INTO tenants(id,name,status,plan,monthly_budget_micros,created_at) VALUES (?,?,?,?,?,?)').bind(id, name, status, plan, budgetMicros, iso(clock())).run();
}
// The secret is returned ONCE. Only HMAC(pepper, secret) is stored: a database leak does not yield usable keys.
export async function issueKey(db, env, clock, tenantId, { scopes = [], ttlDays = null, label = null, actorKind = 'api_key_client' } = {}) {
  if (!['authenticated_service', 'api_key_client', 'device_identity'].includes(actorKind)) throw new HttpError(400, 'invalid_actor_kind', 'A key is never a person: choose service, client or device.');
  const bad = scopes.filter((s) => !ALL_SCOPES.includes(s));
  if (bad.length) throw new HttpError(400, 'invalid_scope', `Unknown scopes: ${bad.join(', ')}`);
  const id = randomHex(8), secret = randomToken(32), now = clock();
  await db.prepare('INSERT INTO api_keys(id,tenant_id,secret_hash,scopes,label,created_at,expires_at,actor_kind) VALUES (?,?,?,?,?,?,?,?)')
    .bind(id, tenantId, await hmacHex(pepper(env), secret), JSON.stringify(scopes), label, iso(now), ttlDays ? iso(new Date(now.getTime() + ttlDays * 86400000)) : null, actorKind).run();
  await audit(db, clock, tenantId, 'key.issued', { key_id: id, scopes, label });
  return { id, key: `mgk_${id}_${secret}` };
}
export async function revokeKey(db, clock, tenantId, keyId) {
  const r = await db.prepare('UPDATE api_keys SET revoked_at = ? WHERE id = ? AND tenant_id = ? AND revoked_at IS NULL').bind(iso(clock()), keyId, tenantId).run();
  await audit(db, clock, tenantId, 'key.revoked', { key_id: keyId, changed: r.meta.changes });
  return r.meta.changes === 1;
}
// Rotation: a new key with the same scopes; the old one keeps working only for `overlapHours` so deployments can switch without an outage.
export async function rotateKey(db, env, clock, tenantId, keyId, { overlapHours = 24 } = {}) {
  const old = await db.prepare('SELECT * FROM api_keys WHERE id = ? AND tenant_id = ? AND revoked_at IS NULL').bind(keyId, tenantId).first();
  if (!old) throw new HttpError(404, 'not_found', 'No such key.');
  const fresh = await issueKey(db, env, clock, tenantId, { scopes: JSON.parse(old.scopes), label: old.label, actorKind: old.actor_kind });
  const until = iso(new Date(Math.min(clock().getTime() + overlapHours * 3600000, old.expires_at ? Date.parse(old.expires_at) : Infinity)));
  await db.prepare('UPDATE api_keys SET expires_at = ? WHERE id = ?').bind(until, keyId).run();
  await audit(db, clock, tenantId, 'key.rotated', { old_key_id: keyId, new_key_id: fresh.id, old_valid_until: until });
  return fresh;
}

// Identity comes ONLY from the verified key. Any x-tenant-id (or similar) header is ignored on purpose.
export async function authenticate(request, env, db, clock) {
  const m = /^Bearer\s+(\S+)$/i.exec(request.headers.get('authorization') || '');
  const parsed = m && KEY_RE.exec(m[1]);
  const p = pepper(env);
  if (!parsed) { await hmacHex(p, 'dummy'); throw unauthorized(); }                       // same work as a real check: no timing signal for malformed input
  const row = await db.prepare('SELECT k.*, t.status AS t_status, t.plan, t.name AS t_name, t.monthly_budget_micros, t.stripe_customer_id FROM api_keys k JOIN tenants t ON t.id = k.tenant_id WHERE k.id = ?').bind(parsed[1]).first();
  const ok = safeEqual(await hmacHex(p, parsed[2]), row ? row.secret_hash : '0'.repeat(64));
  if (!row || !ok) throw unauthorized();                                                  // unknown id and wrong secret are indistinguishable
  const now = clock();
  if (row.revoked_at || (row.expires_at && Date.parse(row.expires_at) <= now.getTime())) { await audit(db, clock, row.tenant_id, 'auth.rejected', { key_id: row.id, reason: row.revoked_at ? 'revoked' : 'expired' }); throw unauthorized(); }
  if (row.t_status !== 'active') { await audit(db, clock, row.tenant_id, 'auth.rejected', { key_id: row.id, reason: 'tenant_' + row.t_status }); throw new HttpError(403, 'tenant_suspended', 'This account is not active.'); }
  // last_used_at is informational (nothing reads it for a decision): refreshing it at most every 5 minutes saves one D1 write on almost every request.
  if (!row.last_used_at || now.getTime() - Date.parse(row.last_used_at) >= LAST_USED_GRANULARITY_MS) await db.prepare('UPDATE api_keys SET last_used_at = ? WHERE id = ?').bind(iso(now), row.id).run();
  return { tenant: { id: row.tenant_id, name: row.t_name, plan: row.plan, status: row.t_status, budgetMicros: row.monthly_budget_micros, stripeCustomerId: row.stripe_customer_id }, key: { id: row.id, actorKind: row.actor_kind }, scopes: new Set(JSON.parse(row.scopes)) };
}
