import test from 'node:test';
import assert from 'node:assert/strict';
import { apiWorld, fakeStripe, SEED, clone, paid, signPayload, WH } from './apiworld.js';
import { StripeApi, handleEvent, reportUsage, sweepPastDue, verifyWebhook } from '../src/stripe.js';
import { acceptTerms } from '../src/policy.js';
import { run } from '../src/pipeline.js';

let evn = 0;
const ev = (type, object) => ({ id: 'evt_' + ++evn, type, created: 1, data: { object } });
const hook = async (w, event, { secret = WH, t = Math.floor(w.clock().getTime() / 1000), body } = {}) => {
  const raw = body ?? JSON.stringify(event); return w.call('/stripe/webhook', { method: 'POST', body: raw, headers: { 'stripe-signature': await signPayload(secret, raw, t), 'content-type': 'application/json' } });
};
const setup = async (opts = {}) => { const stripe = await fakeStripe(); const w = await apiWorld({ stripe, ...opts }); await w.tenant('t1'); await w.db.prepare("UPDATE tenants SET stripe_customer_id = 'cus_1' WHERE id = 't1'").run(); return { w, stripe }; };
const plan = async (w) => (await w.db.prepare("SELECT plan FROM tenants WHERE id = 't1'").first()).plan;

test('webhook signature: only a correct, fresh, v1 signature is accepted; tampering and replay of old deliveries are not', async () => {
  const { w, stripe } = await setup(); const e = ev('ping.test', {});
  assert.equal((await hook(w, e)).status, 200);
  const t = Math.floor(w.clock().getTime() / 1000);
  assert.equal((await hook(w, ev('x.y', {}), { secret: 'whsec_other' })).status, 400); assert.equal((await hook(w, ev('x.y', {}), { t: t - 301 })).status, 400); assert.equal((await hook(w, ev('x.y', {}), { t: t + 301 })).status, 400);
  const raw = JSON.stringify(ev('x.y', {})); const sig = await signPayload(WH, raw, t);
  assert.equal((await w.call('/stripe/webhook', { method: 'POST', body: raw.replace('x.y', 'z.z'), headers: { 'stripe-signature': sig } })).status, 400, 'a modified body fails');
  assert.equal((await w.call('/stripe/webhook', { method: 'POST', body: raw })).status, 400); assert.equal((await w.call('/stripe/webhook', { method: 'POST', body: raw, headers: { 'stripe-signature': sig.replace('v1=', 'v0=') } })).status, 400, 'only v1 counts');
  assert.equal((await w.call('/stripe/webhook', { method: 'POST', body: raw, headers: { 'stripe-signature': `${sig},v1=${'0'.repeat(64)}` } })).status, 200, 'several signatures while a secret is rolled');
  w.env.STRIPE_WEBHOOK_SECRETS = 'whsec_new_secret,' + WH; assert.equal((await hook(w, ev('ping.test', {}))).status, 200, 'the previous secret still works during the rollover'); w.env.STRIPE_WEBHOOK_SECRETS = '';
  assert.equal((await hook(w, ev('ping.test', {}))).status, 503);
  await assert.rejects(verifyWebhook(raw, sig, [WH], Date.now(), 0), /tolerance of 0/); await stripe.close();
});
test('subscription state is read from Stripe, not from the event: a lying or stale event cannot grant access, and delivery order does not matter', async () => {
  const { w, stripe } = await setup(); stripe.sub('sub_1', 'cus_1', 'active');
  assert.equal(await plan(w), 'community');
  const created = ev('customer.subscription.created', { id: 'sub_1', status: 'active' }); assert.equal((await hook(w, created)).status, 200); assert.equal(await plan(w), 'intelligence');
  const dup = await hook(w, created); assert.equal(dup.json.duplicate, true); assert.equal((await w.db.prepare('SELECT COUNT(*) n FROM stripe_events').first()).n, 1);
  stripe.sub('sub_1', 'cus_1', 'canceled'); const deleted = ev('customer.subscription.deleted', { id: 'sub_1', status: 'active' });          // the payload lies ("active"); Stripe says canceled
  await hook(w, deleted); assert.equal(await plan(w), 'community');
  await hook(w, ev('customer.subscription.updated', { id: 'sub_1', status: 'active' })); assert.equal(await plan(w), 'community', 'a late, stale event converges on the current truth');
  stripe.sub('sub_1', 'cus_1', 'active', 'price_biz'); await hook(w, ev('customer.subscription.updated', { id: 'sub_1' })); assert.equal(await plan(w), 'business', 'plan change');
  assert.ok(stripe.reqs.every((r) => r.auth === 'Bearer sk_test_fake_for_local_server_only'));
  stripe.sub('sub_2', 'cus_1', 'active', 'price_unmapped'); await hook(w, ev('customer.subscription.created', { id: 'sub_2' })); assert.equal(await plan(w), 'business', 'an unmapped price grants nothing');
  stripe.sub('sub_3', 'cus_unknown', 'active'); assert.equal((await hook(w, ev('customer.subscription.created', { id: 'sub_3' }))).status, 200);
  await stripe.close();
});
test('payment failure keeps access during the grace period, then removes it; a recovered payment restores the state', async () => {
  const { w, stripe } = await setup(); stripe.sub('sub_1', 'cus_1', 'active'); await hook(w, ev('customer.subscription.created', { id: 'sub_1' }));
  stripe.sub('sub_1', 'cus_1', 'past_due'); await hook(w, ev('invoice.payment_failed', { id: 'in_1', subscription: 'sub_1' })); await hook(w, ev('customer.subscription.updated', { id: 'sub_1' }));
  assert.equal(await plan(w), 'intelligence', 'still inside the grace period'); assert.ok(w.env.EVENTS.events.some((e) => e.type === 'billing.error'));
  w.clock.advance(2 * 86400000); assert.equal(await sweepPastDue(w.db, w.clock, 3), 0); w.clock.advance(2 * 86400000); assert.equal(await sweepPastDue(w.db, w.clock, 3), 1); assert.equal(await plan(w), 'community');
  stripe.sub('sub_1', 'cus_1', 'active'); await hook(w, ev('invoice.paid', { id: 'in_2', subscription: 'sub_1' })); assert.equal(await plan(w), 'intelligence');
  await hook(w, ev('charge.refunded', { id: 'ch_1' })); assert.ok(await w.db.prepare("SELECT 1 x FROM audit WHERE action = 'charge.refunded'").first());
  await stripe.close();
});
test('checkout.session.completed links the customer to OUR tenant only, and a customer cannot be linked twice', async () => {
  const stripe = await fakeStripe(); const w = await apiWorld({ stripe }); await w.tenant('t1'); await w.tenant('t2');
  await hook(w, ev('checkout.session.completed', { id: 'cs_1', client_reference_id: 't1', customer: 'cus_A' })); assert.equal((await w.db.prepare("SELECT stripe_customer_id c FROM tenants WHERE id = 't1'").first()).c, 'cus_A');
  await hook(w, ev('checkout.session.completed', { id: 'cs_2', client_reference_id: 't2', customer: 'cus_A' })); assert.equal((await w.db.prepare("SELECT stripe_customer_id c FROM tenants WHERE id = 't2'").first()).c, null);
  await hook(w, ev('checkout.session.completed', { id: 'cs_3', client_reference_id: 't1', customer: 'cus_B' })); assert.equal((await w.db.prepare("SELECT stripe_customer_id c FROM tenants WHERE id = 't1'").first()).c, 'cus_A');
  await hook(w, ev('checkout.session.completed', { id: 'cs_4', client_reference_id: 'ghost', customer: 'cus_C' })); assert.ok(await w.db.prepare("SELECT 1 x FROM audit WHERE action = 'stripe.customer_conflict'").first());
  await stripe.close();
});
test('an event whose processing failed is retried by Stripe and then processed, not skipped as a duplicate', async () => {
  const { w, stripe } = await setup(); const e = ev('customer.subscription.created', { id: 'sub_1' });
  const first = await hook(w, e); assert.equal(first.status, 400); assert.equal(first.json.error.code, 'stripe_error'); assert.ok(!first.text.includes('secret detail'), 'the provider\'s message is not forwarded');
  assert.equal((await w.db.prepare('SELECT outcome FROM stripe_events').first()).outcome, 'error'); stripe.sub('sub_1', 'cus_1', 'active');
  const second = await hook(w, e); assert.equal(second.status, 200); assert.equal(second.json.duplicate, false); assert.equal(await plan(w), 'intelligence');
  assert.equal((await hook(w, e)).json.duplicate, true);
  await w.db.prepare("UPDATE stripe_events SET outcome = 'processing', received_at = '2026-10-23T09:00:00Z' WHERE event_id = ?").bind(e.id).run(); assert.equal((await hook(w, e)).json.duplicate, false, 'a processing claim abandoned long ago is taken over');
  await stripe.close();
});
test('usage reporting: only charged usage, only while billing is live with approved prices, each event once, retries safe', async () => {
  const stripe = await fakeStripe(); const w = await apiWorld({ stripe, policy: paid() }); await w.tenant('t1', { plan: 'intelligence', budgetMicros: 100000 }); await w.db.prepare("UPDATE tenants SET stripe_customer_id = 'cus_1' WHERE id = 't1'").run();
  const key = (await w.key('t1')).key; let ctx = await w.ctx(key); await acceptTerms(w.db, w.clock, ctx, ctx.policy.doc, { pricing_version: SEED.billing.pricing.version, terms_version: SEED.billing.terms_version }); w.clock.advance(1000);
  const r = await w.call('/v1/intelligence/enrich', { key, method: 'POST', headers: { 'idempotency-key': 'report-0001' }, json: { indicators: ['203.0.113.7', 'CVE-2026-0001', 'a'.repeat(64)] } }); assert.equal(r.status, 200);
  await w.call('/v1/intelligence/hash/' + w.H, { key });
  const api = new StripeApi({ baseUrl: stripe.url, apiKey: w.env.STRIPE_API_KEY });
  assert.deepEqual(await reportUsage(w.env, w.db, w.clock, api), { reported: 1, failed: 0 }); const m = [...stripe.meter.values()][0];
  assert.deepEqual([m.event_name, m['payload[stripe_customer_id]'], m['payload[value]']], ['macguard_intel_enrich', 'cus_1', '3']); assert.equal(m.identifier, (await w.db.prepare("SELECT usage_event_id u FROM usage_events WHERE idem_key = 'report-0001'").first()).u);
  assert.deepEqual(await reportUsage(w.env, w.db, w.clock, api), { reported: 0, failed: 0 }, 'nothing is reported twice');
  await w.call('/v1/intelligence/enrich', { key, method: 'POST', headers: { 'idempotency-key': 'report-0002' }, json: { indicators: ['203.0.113.7'] } }); stripe.meterFail = true;
  assert.deepEqual(await reportUsage(w.env, w.db, w.clock, api), { reported: 0, failed: 1 }); assert.ok(w.env.EVENTS.events.some((e) => e.type === 'billing.error' && e.data.stage === 'meter_event'));
  stripe.meterFail = false; assert.deepEqual(await reportUsage(w.env, w.db, w.clock, api), { reported: 1, failed: 0 }); assert.equal(stripe.meter.size, 2);
  const { rollback } = await import('../src/policy.js'); const a = await w.admin('ana'); const { authenticateAdmin } = await import('../src/admin.js');
  await rollback(w.db, w.clock, await authenticateAdmin(new Request('https://x', { headers: await a.headers() }), w.env, w.db, w.clock), 'stop billing');
  await w.call('/v1/intelligence/enrich', { key, method: 'POST', headers: { 'idempotency-key': 'report-0003' }, json: { indicators: ['203.0.113.7'] } });
  assert.deepEqual(await reportUsage(w.env, w.db, w.clock, api), { reported: 0, skipped: 'billing_not_live' }); await stripe.close();
});
test('checkout is closed during the launch, opens only by policy, and is idempotent per day', async () => {
  const stripe = await fakeStripe(); let w = await apiWorld({ stripe }); await w.tenant('t1'); let key = (await w.key('t1')).key;
  const closed = await w.call('/v1/account/checkout', { key, method: 'POST', json: { plan: 'intelligence' } }); assert.equal(closed.status, 409); assert.equal(closed.json.error.code, 'checkout_disabled'); assert.equal(stripe.checkouts, 0);
  const d = paid(); d.billing.allow_checkout = true; w = await apiWorld({ stripe, policy: d }); await w.tenant('t1'); key = (await w.key('t1')).key;
  const ok = await w.call('/v1/account/checkout', { key, method: 'POST', json: { plan: 'intelligence' } }); assert.equal(ok.status, 200); assert.match(ok.json.checkout_url, /^https:\/\/checkout\.stripe\.test/);
  const rq = stripe.reqs.find((r) => r.url === '/v1/checkout/sessions'); assert.ok(rq.idem.startsWith('checkout:t1:intelligence:')); assert.match(rq.body, /client_reference_id=t1/); assert.match(rq.body, /price_intel/);
  assert.equal((await w.call('/v1/account/checkout', { key, method: 'POST', json: { plan: 'enterprise' } })).json.error.code, 'invalid_plan');
  const narrow = (await w.key('t1', ['account.read'])).key; assert.equal((await w.call('/v1/account/checkout', { key: narrow, method: 'POST', json: { plan: 'intelligence' } })).status, 403);
  await stripe.close();
});
test('terms: the view explains the change, acceptance is explicit and versioned, and it only governs what happens afterwards', async () => {
  const d = clone(SEED); d.scheduled = { mode: 'PAID', effective_from: '2026-12-01T00:00:00Z' }; const w = await apiWorld({ policy: d }); await w.tenant('t1', { plan: 'intelligence' }); const key = (await w.key('t1')).key;
  const v = await w.call('/v1/account/commercial', { key }); assert.equal(v.json.community, 'FREE_FOREVER'); assert.deepEqual(v.json.upcoming_change, { mode: 'PAID', effective_from: '2026-12-01T00:00:00Z', notice_days: 30 }); assert.equal(v.json.terms_accepted, false); assert.equal(v.json.pricing.approved, false);
  assert.equal((await w.call('/v1/account/commercial/accept', { key, method: 'POST', json: { pricing_version: 'wrong', terms_version: 'x' } })).status, 409);
  const ok = await w.call('/v1/account/commercial/accept', { key, method: 'POST', json: { pricing_version: SEED.billing.pricing.version, terms_version: SEED.billing.terms_version } }); assert.equal(ok.status, 200); assert.match(ok.json.effect, /never charged/);
  assert.equal((await w.call('/v1/account/commercial', { key })).json.terms_accepted, true);
  const narrow = (await w.key('t1', ['account.read'])).key; assert.equal((await w.call('/v1/account/commercial/accept', { key: narrow, method: 'POST', json: {} })).status, 403, 'accepting needs the billing scope');
});

test('regression (found on workerd): the Stripe client calls fetch as a plain function, never as a method of itself', async () => {
  const strict = function (...a) { if (this !== undefined && this !== globalThis) throw new TypeError('Illegal invocation'); return new Response(JSON.stringify({ id: 'sub_x', customer: 'cus_1', status: 'active', items: { data: [] } })); };
  const api = new StripeApi({ baseUrl: 'https://api.stripe.test', apiKey: 'sk_test_x', fetchImpl: strict }); assert.equal((await api.retrieveSubscription('sub_x')).id, 'sub_x');
});
