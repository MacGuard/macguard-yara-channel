// The one path every entitled operation takes, whatever the entry point (REST, MCP). Order: identity (done by the caller) -> effective commercial policy -> scope and plan ->
// idempotency -> quotas -> budget (only when real money is involved) -> usage event -> handler -> completion. Each step is one atomic SQL statement or is compensated, because
// D1 has no interactive transactions. EVERY real use is recorded, even when nothing is charged; `theoretical_micros` is what the example prices would charge and is never billed.
import { OPS } from './plans.js';
import { audit } from './audit.js';
import { emit } from './events.js';
import { effective, productOf } from './policy.js';
import { HttpError, iso, sha256Hex, windows } from './util.js';

const END = { minute: (d) => 60 - d.getUTCSeconds(), day: (d) => 86400 - (d.getUTCHours() * 3600 + d.getUTCMinutes() * 60 + d.getUTCSeconds()), month: (d) => Math.ceil((Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 1) - d.getTime()) / 1000) };
const RESULT_CAP = 64 * 1024;

export async function consume(db, tenantId, scope, win, limit, n = 1) {
  if (n > limit) return null;
  const r = await db.prepare('INSERT INTO counters(tenant_id,scope,window,n) VALUES (?,?,?,?) ON CONFLICT(tenant_id,scope,window) DO UPDATE SET n = n + excluded.n WHERE n + excluded.n <= ? RETURNING n').bind(tenantId, scope, win, n, limit).first();
  return r ? r.n : null;
}
export const unconsume = (db, tenantId, scope, win, n = 1) => db.prepare('UPDATE counters SET n = MAX(n - ?, 0) WHERE tenant_id = ? AND scope = ? AND window = ?').bind(n, tenantId, scope, win).run();
export async function reserveBudget(db, tenantId, month, micros, limit) {
  await db.prepare('INSERT OR IGNORE INTO budget(tenant_id, month, spent_micros) VALUES (?,?,0)').bind(tenantId, month).run();
  const r = await db.prepare('UPDATE budget SET spent_micros = spent_micros + ? WHERE tenant_id = ? AND month = ? AND spent_micros + ? <= ?').bind(micros, tenantId, month, micros, limit).run();
  return r.meta.changes === 1;
}
export const releaseBudget = (db, tenantId, month, micros) => db.prepare('UPDATE budget SET spent_micros = MAX(spent_micros - ?, 0) WHERE tenant_id = ? AND month = ?').bind(micros, tenantId, month).run();

// ctx: { tenant, key, scopes, policy: {version, doc}, acceptance }. The effective policy is computed ONCE per call from the version the request pinned.
export const effectiveFor = (ctx, opName, nowMs) => effective(ctx.policy.doc, ctx.tenant, productOf(opName), nowMs, ctx.acceptance);

export function authorize(ctx, opName, eff) {
  const op = OPS[opName]; if (!op) throw new HttpError(404, 'unknown_operation', 'No such operation.');
  if (op.auth === false) return op;
  if (op.scope && !ctx.scopes.has(op.scope)) throw new HttpError(403, 'insufficient_scope', `This key lacks the scope ${op.scope}.`, { required_scope: op.scope });
  if (op.feature && !eff.features.has(op.feature)) throw new HttpError(403, 'not_entitled', 'Your current access does not include this operation.', { required_feature: op.feature, commercial_mode: eff.mode });
  return op;
}
const prices = (ctx, eff, opName, units) => {
  const unit = eff.pricing.unit_micros[opName] ?? 0, theo = ctx.policy.doc.theoretical_prices_micros?.[opName] ?? unit;
  return { charge: unit * units, theoretical: theo * units };
};
const gone = (scope, n) => new HttpError(429, 'quota_exceeded', `The ${scope} limit of your current access was reached.`, { scope, retry_after_seconds: n });

async function takeQuota(db, ctx, now, eff, extra = []) {
  const w = windows(now), taken = [];
  const steps = [['minute', w.minute, eff.quotas.minute, 1], ['day', w.day, eff.quotas.day, 1], ['month', w.month, eff.quotas.month, 1], ...extra.map(([s, l, n]) => [s, w.month, l, n])];
  for (const [scope, win, limit, n] of steps) {
    if ((await consume(db, ctx.tenant.id, scope, win, limit, n)) === null) {
      for (const t of taken) await unconsume(db, ctx.tenant.id, t[0], t[1], t[3]);
      throw gone(scope, END[['minute', 'day'].includes(scope) ? scope : 'month'](now));
    }
    taken.push([scope, win, limit, n]);
  }
  return taken;
}

export const usageEventId = async (tenantId, key) => 'ue_' + (await sha256Hex(`${tenantId}|${key}`)).slice(0, 24);

export async function run(env, db, clock, ctx, opName, args, handler, { idemKey = null, requestId = 'req', extraQuota = () => [], cacheResult = true } = {}) {
  const now = clock(), eff = effectiveFor(ctx, opName, now.getTime()), op = authorize(ctx, opName, eff), w = windows(now);
  if (op.class === 'free') {                                     // free operations still count against the per-minute rate limit
    if ((await consume(db, ctx.tenant.id, 'minute', w.minute, eff.quotas.minute, 1)) === null) throw gone('minute', END.minute(now));
    return { result: await handler(args, eff), replayed: false, units: 0, billable: 0, theoretical: 0 };
  }
  if (op.class === 'metered' && !idemKey) throw new HttpError(400, 'idempotency_key_required', 'Metered operations need an Idempotency-Key so that a retry is never counted twice.');
  const units = op.class === 'metered' ? Math.max(1, args?.indicators?.length ?? 1) : 1, { charge, theoretical } = prices(ctx, eff, opName, units);
  if (idemKey) {
    if (!/^[A-Za-z0-9._:-]{8,128}$/.test(idemKey)) throw new HttpError(400, 'invalid_idempotency_key', 'Idempotency-Key must be 8-128 characters of [A-Za-z0-9._:-].');
    const prev = await db.prepare('SELECT * FROM usage_events WHERE tenant_id = ? AND idem_key = ?').bind(ctx.tenant.id, idemKey).first();
    if (prev) {
      if (prev.operation !== opName) throw new HttpError(409, 'idempotency_key_reuse', 'This Idempotency-Key was used for a different operation.');
      return { result: prev.result ? JSON.parse(prev.result) : { replayed: true, usage_event_id: prev.usage_event_id }, replayed: true, usage_event_id: prev.usage_event_id };
    }
  }
  const taken = await takeQuota(db, ctx, now, eff, extraQuota(eff));
  const undoQuota = async () => { for (const t of taken) await unconsume(db, ctx.tenant.id, t[0], t[1], t[3]); };
  let reserved = 0, freeUnits = 0;
  if (op.class === 'metered' && !eff.charging && eff.mode !== 'FREE_LAUNCH') {          // FREEMIUM / PAID without accepted terms: only the free allowance, never money
    if (Number.isFinite(eff.meteredFreeUnits) && (await consume(db, ctx.tenant.id, 'metered_free', w.month, eff.meteredFreeUnits, units)) === null) {
      await undoQuota(); throw new HttpError(402, 'upgrade_required', 'The free allowance for this operation is used up. A paid plan with accepted terms is needed.', { commercial_mode: eff.mode, terms_accepted: eff.accepted });
    }
    freeUnits = units;
  }
  if (op.class === 'metered' && eff.charging && charge > 0) {
    const limit = ctx.tenant.budgetMicros;
    if (limit <= 0) { await undoQuota(); throw new HttpError(402, 'budget_required', 'This operation is billed per use: set a monthly spending limit first.', { estimated_micros: charge, currency: eff.currency }); }
    if (!(await reserveBudget(db, ctx.tenant.id, w.month, charge, limit))) {
      await undoQuota(); await emit(env, clock, 'usage.near_limit', { tenant_id: ctx.tenant.id, kind: 'budget', used: limit, limit });
      throw new HttpError(402, 'budget_exceeded', 'The monthly spending limit would be exceeded.', { estimated_micros: charge, currency: eff.currency });
    }
    reserved = charge;
    const spent = (await db.prepare('SELECT spent_micros AS s FROM budget WHERE tenant_id = ? AND month = ?').bind(ctx.tenant.id, w.month).first()).s;
    if (spent * 5 >= limit * 4 && (spent - charge) * 5 < limit * 4) await emit(env, clock, 'usage.near_limit', { tenant_id: ctx.tenant.id, kind: 'budget', used: spent, limit });
  }
  const id = await usageEventId(ctx.tenant.id, idemKey ?? requestId);
  const unit = eff.pricing.unit_micros[opName] ?? 0;
  try {
    await db.prepare(`INSERT INTO usage_events(usage_event_id,tenant_id,customer_id,api_key_id,request_id,operation,pricing_version,units,unit_price_micros,billable_micros,theoretical_micros,commercial_mode,policy_version,currency,request_status,billing_status,idem_key,created_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,'authorized',?,?,?)`).bind(id, ctx.tenant.id, ctx.tenant.stripeCustomerId, ctx.key.id, requestId, opName, eff.pricing.version, units, unit, reserved, theoretical, eff.mode, ctx.policy.version, eff.currency,
      reserved > 0 ? 'pending' : (op.class === 'metered' ? 'none' : 'included'), idemKey ?? requestId, iso(now)).run();
  } catch (e) {                                                   // a concurrent request with the same key won the insert: give everything back and replay its outcome
    if (reserved) await releaseBudget(db, ctx.tenant.id, w.month, reserved);
    if (freeUnits) await unconsume(db, ctx.tenant.id, 'metered_free', w.month, freeUnits);
    await undoQuota();
    const prev = await db.prepare('SELECT * FROM usage_events WHERE tenant_id = ? AND idem_key = ?').bind(ctx.tenant.id, idemKey ?? requestId).first();
    if (prev) return { result: prev.result ? JSON.parse(prev.result) : { replayed: true, usage_event_id: prev.usage_event_id }, replayed: true, usage_event_id: prev.usage_event_id };
    throw e;
  }
  let result;
  try { result = await handler(args, eff); }
  catch (e) {                                                     // the work failed: nothing is charged, the reservation returns, the usage event keeps the failure
    if (reserved) await releaseBudget(db, ctx.tenant.id, w.month, reserved);
    await db.prepare("UPDATE usage_events SET request_status = 'failed', billing_status = 'not_billable', billable_micros = 0, completed_at = ? WHERE usage_event_id = ?").bind(iso(clock()), id).run();
    throw e;
  }
  await db.prepare("UPDATE usage_events SET request_status = 'processed' WHERE usage_event_id = ? AND request_status = 'authorized'").bind(id).run();
  const text = JSON.stringify(result);
  await db.prepare("UPDATE usage_events SET request_status = 'completed', billing_status = ?, result = ?, completed_at = ? WHERE usage_event_id = ?").bind(reserved > 0 ? 'billed' : (op.class === 'metered' ? 'none' : 'included'), cacheResult && text.length <= RESULT_CAP ? text : null, iso(clock()), id).run();
  return { result, replayed: false, usage_event_id: id, units, billable: reserved, theoretical };
}

// A refund returns the money to the budget and marks the event; it is the only way a billed event changes after completion.
export async function refund(db, clock, tenantId, usageEventId, reason) {
  const ev = await db.prepare('SELECT * FROM usage_events WHERE usage_event_id = ? AND tenant_id = ?').bind(usageEventId, tenantId).first();
  if (!ev || ev.billing_status !== 'billed') throw new HttpError(409, 'not_refundable', 'Only a billed event can be refunded.');
  const r = await db.prepare("UPDATE usage_events SET billing_status = 'refunded' WHERE usage_event_id = ? AND billing_status = 'billed'").bind(usageEventId).run();
  if (r.meta.changes !== 1) throw new HttpError(409, 'not_refundable', 'Already refunded.');
  await releaseBudget(db, tenantId, ev.created_at.slice(0, 7), ev.billable_micros);
  await audit(db, clock, tenantId, 'usage.refunded', { usage_event_id: usageEventId, reason, micros: ev.billable_micros });
  return { refunded_micros: ev.billable_micros, stripe_reported: !!ev.stripe_reported };
}

export async function monthUsage(db, ctx, clock) {
  const now = clock(), w = windows(now), eff = effective(ctx.policy.doc, ctx.tenant, 'api', now.getTime(), ctx.acceptance);
  const spent = (await db.prepare('SELECT spent_micros AS s FROM budget WHERE tenant_id = ? AND month = ?').bind(ctx.tenant.id, w.month).first())?.s ?? 0;
  const by = (await db.prepare("SELECT operation, COUNT(*) AS n, SUM(units) AS units, SUM(CASE WHEN billing_status = 'billed' THEN billable_micros ELSE 0 END) AS billed_micros, SUM(theoretical_micros) AS theoretical_micros FROM usage_events WHERE tenant_id = ? AND created_at >= ? AND request_status = 'completed' GROUP BY operation").bind(ctx.tenant.id, w.month).all()).results;
  const c = async (scope, win) => (await db.prepare('SELECT n FROM counters WHERE tenant_id = ? AND scope = ? AND window = ?').bind(ctx.tenant.id, scope, win).first())?.n ?? 0;
  const limit = ctx.tenant.budgetMicros;
  return { month: w.month, commercial_mode: eff.mode, currency: eff.currency, pricing_version: eff.pricing.version, prices_approved: eff.pricing.approved,
    quotas: { minute: { used: await c('minute', w.minute), limit: eff.quotas.minute }, day: { used: await c('day', w.day), limit: eff.quotas.day }, month: { used: await c('month', w.month), limit: eff.quotas.month } },
    budget: { limit_micros: limit, spent_micros: spent, remaining_micros: Math.max(limit - spent, 0), near_limit: limit > 0 && spent * 5 >= limit * 4 },
    operations: by, billed_micros: by.reduce((a, r) => a + r.billed_micros, 0), theoretical_micros: by.reduce((a, r) => a + r.theoretical_micros, 0),
    note: 'theoretical_micros is what the example prices would charge; it is NOT billed' };
}
