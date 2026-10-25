// Tenant and API-key lifecycle for the administrator (key + TOTP already verified by the caller). A key's secret is returned ONCE, with no-store caching, and is never stored or logged.
// Every change is written to the audit chain by the underlying functions (or here). Tenant ids are chosen by the administrator and validated; nothing here is reachable with a tenant key.
import { createTenant, issueKey, revokeKey, rotateKey } from './auth.js';
import { audit } from './audit.js';
import { HttpError, jsonResponse, readBounded } from './util.js';

const ID = /^[a-z0-9][a-z0-9._-]{1,62}$/, KEY_ID = /^[0-9a-f]{16}$/, PLANS = ['community', 'intelligence', 'business'], STATUSES = ['active', 'suspended', 'closed'];
const bad = (m) => new HttpError(400, 'invalid_input', m);
async function body(request) { try { const v = JSON.parse((await readBounded(request, 20_000)) || '{}'); if (v === null || typeof v !== 'object' || Array.isArray(v)) throw 0; return v; } catch (e) { if (e instanceof HttpError) throw e; throw bad('Send a JSON object.'); } }
const secretResponse = (status, obj) => { const r = jsonResponse(status, obj); r.headers.set('cache-control', 'no-store'); return r; };
const tenantOr404 = async (db, id) => { const t = await db.prepare('SELECT id, name, status, plan, created_at FROM tenants WHERE id = ?').bind(id).first(); if (!t) throw new HttpError(404, 'not_found', 'Unknown tenant.'); return t; };

export async function adminTenants(request, env, db, clock, path, url, admin) {
  const m = request.method, p = path.slice('/admin/v1/tenants'.length) || '/';
  if (p === '/' && m === 'GET') {
    const limit = Math.min(Math.max(Number(url.searchParams.get('limit') ?? 50) || 50, 1), 200), after = url.searchParams.get('after');
    if (after !== null && !ID.test(after)) throw bad('Invalid after.');
    const rows = (await db.prepare('SELECT id, name, status, plan, created_at FROM tenants WHERE (? IS NULL OR id > ?) ORDER BY id LIMIT ?').bind(after, after, limit + 1).all()).results;
    return jsonResponse(200, { tenants: rows.slice(0, limit), next: rows.length > limit ? rows[limit - 1].id : null });
  }
  if (p === '/' && m === 'POST') {
    const b = await body(request); if (!ID.test(b.id ?? '')) throw bad('id must be 2-63 characters of a-z, 0-9, dot, dash, underscore.'); if (typeof b.name !== 'string' || b.name.trim().length < 2 || b.name.length > 120) throw bad('name is required (2-120 characters).');
    const plan = b.plan ?? 'community'; if (!PLANS.includes(plan)) throw bad('Unknown plan.');
    if (await db.prepare('SELECT 1 x FROM tenants WHERE id = ?').bind(b.id).first()) throw new HttpError(409, 'conflict', 'That tenant id exists.');
    await createTenant(db, clock, { id: b.id, name: b.name.trim(), plan }); await audit(db, clock, b.id, 'tenant.created', { admin_id: admin.id, plan }); return jsonResponse(201, await tenantOr404(db, b.id));
  }
  let r;
  if ((r = /^\/([a-z0-9][a-z0-9._-]{1,62})$/.exec(p)) && m === 'GET') { const t = await tenantOr404(db, r[1]); const keys = (await db.prepare('SELECT id, label, scopes, actor_kind, created_at, expires_at, revoked_at, last_used_at FROM api_keys WHERE tenant_id = ? ORDER BY created_at').bind(t.id).all()).results; return jsonResponse(200, { ...t, keys: keys.map((k) => ({ ...k, scopes: JSON.parse(k.scopes) })) }); }
  if ((r = /^\/([a-z0-9][a-z0-9._-]{1,62})\/status$/.exec(p)) && m === 'POST') {
    const b = await body(request); if (!STATUSES.includes(b.status)) throw bad('status must be active, suspended or closed.'); const t = await tenantOr404(db, r[1]);
    await db.prepare('UPDATE tenants SET status = ? WHERE id = ?').bind(b.status, t.id).run(); await audit(db, clock, t.id, 'tenant.status_changed', { admin_id: admin.id, from: t.status, to: b.status }); return jsonResponse(200, { id: t.id, status: b.status });
  }
  if ((r = /^\/([a-z0-9][a-z0-9._-]{1,62})\/keys$/.exec(p)) && m === 'POST') {
    const t = await tenantOr404(db, r[1]); if (t.status !== 'active') throw new HttpError(409, 'tenant_not_active', 'Keys are issued for active tenants only.'); const b = await body(request);
    if (!Array.isArray(b.scopes) || b.scopes.length === 0 || b.scopes.length > 20 || b.scopes.some((s) => typeof s !== 'string')) throw bad('scopes must be a non-empty list.');
    const ttl = b.ttl_days ?? null; if (ttl !== null && (!Number.isInteger(ttl) || ttl < 1 || ttl > 730)) throw bad('ttl_days must be 1-730.'); const label = b.label == null ? null : String(b.label).slice(0, 80);
    const k = await issueKey(db, env, clock, t.id, { scopes: b.scopes, ttlDays: ttl, label, actorKind: b.actor_kind ?? 'api_key_client' }); await audit(db, clock, t.id, 'key.issued_by_admin', { admin_id: admin.id, key_id: k.id });
    return secretResponse(201, { tenant_id: t.id, key_id: k.id, key: k.key, note: 'Shown once. Store it in a secret manager; it cannot be shown again.' });
  }
  if ((r = /^\/([a-z0-9][a-z0-9._-]{1,62})\/keys\/([0-9a-f]{16})\/(revoke|rotate)$/.exec(p)) && m === 'POST') {
    const t = await tenantOr404(db, r[1]);
    if (r[3] === 'revoke') { const ok = await revokeKey(db, clock, t.id, r[2]); if (!ok) throw new HttpError(404, 'not_found', 'No active key with that id for this tenant.'); await audit(db, clock, t.id, 'key.revoked_by_admin', { admin_id: admin.id, key_id: r[2] }); return jsonResponse(200, { revoked: true, key_id: r[2] }); }
    const b = await body(request), hours = b.overlap_hours ?? 24; if (!Number.isInteger(hours) || hours < 0 || hours > 168) throw bad('overlap_hours must be 0-168.');
    const k = await rotateKey(db, env, clock, t.id, r[2], { overlapHours: hours }); await audit(db, clock, t.id, 'key.rotated_by_admin', { admin_id: admin.id, old_key_id: r[2], new_key_id: k.id });
    return secretResponse(201, { tenant_id: t.id, key_id: k.id, key: k.key, old_key_valid_hours: hours, note: 'Shown once.' });
  }
  throw new HttpError(404, 'not_found', 'Not found.');
}
