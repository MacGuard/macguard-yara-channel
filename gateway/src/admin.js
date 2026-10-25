// Administrator identity: a long random key AND a TOTP code on every call, single use per time step. The same checks guard every policy change.
import { audit } from './audit.js';
import { HttpError, hmacHex, iso, randomHex, randomToken, safeEqual } from './util.js';
import { fromBase32, matchStep, seal, toBase32, unseal } from './totp.js';

export const ADMIN_KEY_RE = /^mga_([0-9a-f]{16})_([A-Za-z0-9_-]{43})$/;
const need = (env) => { if (!env.ADMIN_PEPPER || env.ADMIN_PEPPER.length < 32 || !env.TOTP_SEAL_KEY || env.TOTP_SEAL_KEY.length < 32) throw new Error('admin secrets are not configured'); };
const denied = () => new HttpError(401, 'unauthorized', 'Administrator authentication failed.');

export async function createAdmin(db, env, clock, { id = randomHex(8), name }) {
  need(env); const secret = randomToken(32), seed = crypto.getRandomValues(new Uint8Array(20));
  await db.prepare('INSERT INTO admins(id,name,secret_hash,totp_sealed,created_at) VALUES (?,?,?,?,?)').bind(id, name, await hmacHex(env.ADMIN_PEPPER, secret), await seal(env.TOTP_SEAL_KEY, seed), iso(clock())).run();
  await audit(db, clock, null, 'admin.created', { admin_id: id });
  return { id, key: `mga_${id}_${secret}`, totp_seed_base32: toBase32(seed) };      // shown once
}
export async function authenticateAdmin(request, env, db, clock) {
  need(env);
  const m = ADMIN_KEY_RE.exec((/^Bearer\s+(\S+)$/i.exec(request.headers.get('authorization') || '') || [])[1] || '');
  const code = request.headers.get('x-mfa-code') || '';
  const row = m ? await db.prepare('SELECT * FROM admins WHERE id = ? AND disabled_at IS NULL').bind(m[1]).first() : null;
  const keyOk = safeEqual(await hmacHex(env.ADMIN_PEPPER, m ? m[2] : 'dummy'), row ? row.secret_hash : '0'.repeat(64));
  const step = row ? await matchStep(await unseal(env.TOTP_SEAL_KEY, row.totp_sealed), code, clock().getTime()) : null;
  // Only attempts that name a REAL administrator are written to the audit chain: anyone on the internet can send unknown ids, and one D1 write per anonymous attempt would be a free write-amplification lever.
  // Unknown-id attempts are rate limited at the edge (config/cloudflare/gateway-hardening.json), not recorded here.
  if (!row || !keyOk || step === null) { if (row) await audit(db, clock, null, 'admin.rejected', { admin_id: row.id, reason: !keyOk ? 'key' : 'mfa' }); throw denied(); }
  const r = await db.prepare('UPDATE admins SET last_totp_step = ? WHERE id = ? AND last_totp_step < ?').bind(step, row.id, step).run();
  if (r.meta.changes !== 1) { await audit(db, clock, null, 'admin.rejected', { admin_id: row.id, reason: 'mfa_replay' }); throw denied(); }       // the same code twice is a replay
  return { id: row.id, name: row.name };
}
export { fromBase32 };
