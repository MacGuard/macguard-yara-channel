// Stripe: webhook verification, idempotent event handling, subscription state, checkout and usage reporting. Written against the documented scheme (Stripe-Signature t=,v1=;
// HMAC-SHA256 over "t.payload"; ignore other schemes; 5 minutes tolerance; deduplicate by EVENT ID, never by `created`). NOT run against Stripe: tests use a local fake server.
import { audit } from './audit.js';
import { emit } from './events.js';
import { loadActive } from './policy.js';
import { HttpError, bytes, hex, hmac, iso, safeEqual } from './util.js';

export async function verifyWebhook(rawBody, header, secrets, nowMs, toleranceSeconds = 300) {
  const bad = (m) => new HttpError(400, 'invalid_signature', m);
  if (!header || typeof rawBody !== 'string') throw bad('Missing signature.');
  let t = null; const sigs = [];
  for (const part of header.split(',')) { const i = part.indexOf('='); if (i < 0) continue; const k = part.slice(0, i).trim(), v = part.slice(i + 1).trim(); if (k === 't') t = v; else if (k === 'v1') sigs.push(v); }
  if (!/^\d{1,12}$/.test(t || '') || !sigs.length) throw bad('Malformed signature header.');
  if (!(toleranceSeconds > 0)) throw new Error('a tolerance of 0 disables the replay check');
  if (Math.abs(nowMs / 1000 - Number(t)) > toleranceSeconds) throw bad('The signature timestamp is outside the tolerance.');
  let ok = false;
  for (const secret of secrets) { const want = hex(await hmac(bytes(secret), `${t}.${rawBody}`)); for (const s of sigs) if (safeEqual(want, s)) ok = true; }     // rolled secrets: any active secret may match
  if (!ok) throw bad('The signature does not match.');
  let ev; try { ev = JSON.parse(rawBody); } catch { throw bad('The payload is not JSON.'); }
  if (!ev || typeof ev.id !== 'string' || typeof ev.type !== 'string') throw bad('Not an event.');
  return ev;
}
export const signPayload = async (secret, rawBody, tSeconds) => `t=${tSeconds},v1=${hex(await hmac(bytes(secret), `${tSeconds}.${rawBody}`))}`;      // for tests and for the fake server

const form = (o, prefix = '') => Object.entries(o).flatMap(([k, v]) => (v !== null && typeof v === 'object' ? form(v, prefix ? `${prefix}[${k}]` : k) : [[prefix ? `${prefix}[${k}]` : k, String(v)]]));
export class StripeApi {
  // `fetch` must be called as a plain function: storing it on the object and calling this.f() makes `this` the StripeApi, which workerd rejects ("Illegal invocation").
  constructor({ baseUrl = 'https://api.stripe.com', apiKey, fetchImpl = null, timeoutMs = 10000 }) { this.base = baseUrl; this.key = apiKey; this.f = (...a) => (fetchImpl ?? fetch)(...a); this.t = timeoutMs; }
  async call(method, path, params, idem) {
    if (!this.key) throw new HttpError(503, 'billing_unavailable', 'Billing is not configured.');
    const body = params ? new URLSearchParams(form(params)).toString() : undefined;
    let r; try { r = await this.f(this.base + path, { method, headers: { authorization: `Bearer ${this.key}`, ...(body ? { 'content-type': 'application/x-www-form-urlencoded' } : {}), ...(idem ? { 'idempotency-key': idem } : {}) }, body, signal: AbortSignal.timeout(this.t) }); }
    catch { throw new HttpError(502, 'stripe_unreachable', 'The payment provider could not be reached.'); }
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new HttpError(r.status >= 500 ? 502 : 400, 'stripe_error', 'The payment provider rejected the request.', { stripe_status: r.status });
    return j;
  }
  retrieveSubscription(id) { return this.call('GET', `/v1/subscriptions/${encodeURIComponent(id)}`); }
  createCheckoutSession({ tenantId, priceId, successUrl, cancelUrl }, idem) {
    return this.call('POST', '/v1/checkout/sessions', { mode: 'subscription', client_reference_id: tenantId, 'line_items': { 0: { price: priceId, quantity: 1 } }, success_url: successUrl, cancel_url: cancelUrl }, idem);
  }
  createMeterEvent({ eventName, customerId, value, identifier, timestamp }) {
    return this.call('POST', '/v1/billing/meter_events', { event_name: eventName, payload: { stripe_customer_id: customerId, value }, identifier, timestamp });
  }
}

const OK_STATUS = new Set(['active', 'trialing']);
const planFor = (env, sub) => { const price = sub.items?.data?.[0]?.price?.id; const map = JSON.parse(env.PRICE_MAP || '{}'); return map[price] ?? null; };

// Brings the tenant in line with the subscription AS STRIPE REPORTS IT NOW (fetched, not trusted from the event): out-of-order or repeated events converge on the same state.
export async function syncSubscription(env, db, clock, api, subscriptionId) {
  const sub = await api.retrieveSubscription(subscriptionId); const customer = typeof sub.customer === 'string' ? sub.customer : sub.customer?.id;
  const tenant = await db.prepare('SELECT id, plan FROM tenants WHERE stripe_customer_id = ?').bind(customer).first();
  if (!tenant) { await audit(db, clock, null, 'stripe.unknown_customer', { subscription: sub.id }); return { applied: false, reason: 'unknown_customer' }; }
  const plan = planFor(env, sub);
  if (!plan) { await audit(db, clock, tenant.id, 'stripe.unknown_price', { subscription: sub.id }); return { applied: false, reason: 'unknown_price' }; }       // an unmapped price grants nothing
  const now = clock(), nowS = Math.floor(now.getTime() / 1000), cur = await db.prepare('SELECT past_due_since FROM subscriptions WHERE stripe_subscription_id = ?').bind(sub.id).first();
  let newPlan = 'community', pastDue = null;
  if (OK_STATUS.has(sub.status)) newPlan = plan;
  else if (sub.status === 'past_due') { newPlan = plan; pastDue = cur?.past_due_since ?? nowS; }                                    // grace period: access stays while Stripe retries
  await db.batch([
    db.prepare('INSERT INTO subscriptions(stripe_subscription_id,tenant_id,plan,status,current_period_end,past_due_since,updated_at) VALUES (?,?,?,?,?,?,?) ON CONFLICT(stripe_subscription_id) DO UPDATE SET plan=excluded.plan, status=excluded.status, current_period_end=excluded.current_period_end, past_due_since=excluded.past_due_since, updated_at=excluded.updated_at')
      .bind(sub.id, tenant.id, plan, sub.status, sub.current_period_end ?? null, pastDue, iso(now)),
    db.prepare('UPDATE tenants SET plan = ? WHERE id = ?').bind(newPlan, tenant.id)]);
  await audit(db, clock, tenant.id, 'subscription.synced', { subscription: sub.id, status: sub.status, plan: newPlan });
  return { applied: true, plan: newPlan, status: sub.status };
}
// Run from a cron trigger: past-due subscriptions lose access after the grace period (a payment recovered in the meantime has already reset the state through its event).
export async function sweepPastDue(db, clock, graceDays = 3) {
  const cutoff = Math.floor(clock().getTime() / 1000) - graceDays * 86400, rows = (await db.prepare("SELECT stripe_subscription_id AS id, tenant_id FROM subscriptions WHERE status = 'past_due' AND past_due_since IS NOT NULL AND past_due_since <= ?").bind(cutoff).all()).results;
  for (const r of rows) { await db.prepare("UPDATE tenants SET plan = 'community' WHERE id = ?").bind(r.tenant_id).run(); await audit(db, clock, r.tenant_id, 'subscription.grace_expired', { subscription: r.id }); }
  return rows.length;
}

export async function handleEvent(env, db, clock, api, ev) {
  const at = iso(clock());
  const ins = await db.prepare("INSERT OR IGNORE INTO stripe_events(event_id,type,received_at,outcome) VALUES (?,?,?,'processing')").bind(ev.id, ev.type, at).run();
  if (ins.meta.changes === 0) {
    const stale = iso(new Date(clock().getTime() - 300000));
    const take = await db.prepare("UPDATE stripe_events SET outcome = 'processing', received_at = ? WHERE event_id = ? AND (outcome = 'error' OR (outcome = 'processing' AND received_at < ?))").bind(at, ev.id, stale).run();
    if (take.meta.changes === 0) return { duplicate: true };                         // already handled (or being handled): processing twice would double its effects
  }
  try {
    const o = ev.data?.object ?? {}; let outcome = 'done';
    switch (ev.type) {
      case 'checkout.session.completed': {
        const t = o.client_reference_id && await db.prepare('SELECT id, stripe_customer_id FROM tenants WHERE id = ?').bind(o.client_reference_id).first();
        if (!t || !o.customer) { outcome = 'ignored'; break; }
        if (t.stripe_customer_id && t.stripe_customer_id !== o.customer) { await audit(db, clock, t.id, 'stripe.customer_conflict', {}); outcome = 'ignored'; break; }
        try { await db.prepare('UPDATE tenants SET stripe_customer_id = ? WHERE id = ?').bind(o.customer, t.id).run(); } catch { await audit(db, clock, t.id, 'stripe.customer_conflict', {}); outcome = 'ignored'; break; }
        await audit(db, clock, t.id, 'checkout.completed', { session: o.id }); if (o.subscription) await syncSubscription(env, db, clock, api, o.subscription); break;
      }
      case 'customer.subscription.created': case 'customer.subscription.updated': case 'customer.subscription.deleted': await syncSubscription(env, db, clock, api, o.id); break;
      case 'invoice.paid': if (o.subscription) await syncSubscription(env, db, clock, api, o.subscription); await audit(db, clock, null, 'invoice.paid', { invoice: o.id }); break;
      case 'invoice.payment_failed': {
        const s = o.subscription && await db.prepare('SELECT tenant_id FROM subscriptions WHERE stripe_subscription_id = ?').bind(o.subscription).first();
        if (s) await db.prepare('UPDATE subscriptions SET past_due_since = COALESCE(past_due_since, ?) WHERE stripe_subscription_id = ?').bind(Math.floor(clock().getTime() / 1000), o.subscription).run();
        await audit(db, clock, s?.tenant_id ?? null, 'invoice.payment_failed', { invoice: o.id }); await emit(env, clock, 'billing.error', { tenant_id: s?.tenant_id ?? 'unknown', stage: 'invoice', code: 'payment_failed' }); break;
      }
      case 'charge.refunded': case 'charge.dispute.created': await audit(db, clock, null, ev.type, { charge: o.id ?? o.charge }); await emit(env, clock, 'billing.error', { tenant_id: 'unknown', stage: ev.type, code: 'review' }); break;
      default: outcome = 'ignored';
    }
    await db.prepare('UPDATE stripe_events SET outcome = ? WHERE event_id = ?').bind(outcome, ev.id).run();
    return { duplicate: false, outcome };
  } catch (e) {
    await db.prepare("UPDATE stripe_events SET outcome = 'error' WHERE event_id = ?").bind(ev.id).run();                // Stripe will retry; the next delivery may take the event over
    await emit(env, clock, 'stripe.failure', { stage: ev.type, status: e.status ?? 0 });
    throw e;
  }
}

// Usage reporting: only events actually CHARGED, only while the active policy says billing is live with approved prices. The meter event identifier is the usage event id.
export async function reportUsage(env, db, clock, api, limit = 100) {
  const { doc } = await loadActive(db); if (!doc.billing.live || !doc.billing.pricing.approved) return { reported: 0, skipped: 'billing_not_live' };
  const rows = (await db.prepare("SELECT * FROM usage_events WHERE billing_status = 'billed' AND stripe_reported = 0 AND customer_id IS NOT NULL AND billable_micros > 0 ORDER BY created_at LIMIT ?").bind(limit).all()).results;
  let reported = 0, failed = 0;
  for (const r of rows) {
    try {
      await api.createMeterEvent({ eventName: 'macguard_' + r.operation.replace(/\./g, '_'), customerId: r.customer_id, value: r.units, identifier: r.usage_event_id, timestamp: Math.floor(Date.parse(r.created_at) / 1000) });
      await db.prepare('UPDATE usage_events SET stripe_reported = 1 WHERE usage_event_id = ?').bind(r.usage_event_id).run(); reported++;
    } catch (e) { failed++; await emit(env, clock, 'billing.error', { tenant_id: r.tenant_id, stage: 'meter_event', code: e.code ?? 'error' }); }
  }
  return { reported, failed };
}
