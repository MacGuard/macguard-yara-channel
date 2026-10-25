import { readFileSync } from 'node:fs';
import { newDb, fixedClock } from './d1shim.js';
import { createTenant, issueKey } from '../src/auth.js';
import { createAdmin } from '../src/admin.js';
import { seedPolicy, propose, approve, applyProposal } from '../src/policy.js';
import { buildContext } from '../src/context.js';
import { fromBase32, } from '../src/totp.js';
import { totp, stepOf } from '../src/totp.js';
import { memorySink } from '../src/events.js';

export const SEED = JSON.parse(readFileSync(new URL('../../config/commercial/policy.seed.json', import.meta.url), 'utf8'));
export const clone = (o) => JSON.parse(JSON.stringify(o));
export const ENV = () => ({ KEY_PEPPER: 'k'.repeat(40), ADMIN_PEPPER: 'a'.repeat(40), TOTP_SEAL_KEY: 's'.repeat(40), EVENTS: memorySink() });

export async function world({ now = '2026-10-23T10:00:00Z', policy = SEED } = {}) {
  const db = newDb(), clock = fixedClock(now), env = ENV();
  await seedPolicy(db, clock, policy);
  const w = { db, clock, env };
  w.tenant = async (id, o = {}) => { await createTenant(db, clock, { id, name: id, ...o }); return id; };
  w.key = async (tenantId, scopes = ['premium.read', 'premium.download', 'intel.query', 'intel.enrich', 'usage.estimate', 'account.read', 'account.billing', 'mcp'], o = {}) => issueKey(db, env, clock, tenantId, { scopes, ...o });
  w.req = (key, init = {}) => new Request('https://gw.test/x', { ...init, headers: { authorization: `Bearer ${key}`, ...(init.headers || {}) } });
  w.ctx = (key) => buildContext(w.req(key), env, db, clock);
  w.admin = async (name) => {
    const a = await createAdmin(db, env, clock, { name }); const seed = fromBase32(a.totp_seed_base32); let last = 0;
    return { ...a, headers: async () => { clock.advance(30000 * 2); const code = await totp(seed, stepOf(clock().getTime())); return { authorization: `Bearer ${a.key}`, 'x-mfa-code': code }; } };
  };
  w.apply = async (a, b, doc, reason = 'test') => {                        // propose -> approve -> apply with real admin authentication
    const { authenticateAdmin } = await import('../src/admin.js');
    const as = async (adm) => authenticateAdmin(new Request('https://gw.test/a', { headers: await adm.headers() }), env, db, clock);
    const p = await propose(db, clock, await as(a), doc, reason);
    if (p.approvals_required > 1) await approve(db, clock, await as(b), p.id);
    return applyProposal(db, clock, await as(a), p.id);
  };
  return w;
}
export const paid = (doc = SEED, over = {}) => { const d = clone(doc); d.mode = 'PAID'; d.billing.live = true; d.billing.pricing.approved = true; Object.assign(d.billing, over); return d; };
