import test from 'node:test';
import assert from 'node:assert/strict';
import { world, SEED, clone, paid } from './helpers.js';
import { run, refund, monthUsage } from '../src/pipeline.js';
import { revokeKey, rotateKey } from '../src/auth.js';
import { effective, validatePolicy, seedPolicy } from '../src/policy.js';
import { HttpError } from '../src/util.js';
import { totp, fromBase32 } from '../src/totp.js';
import { verifyAudit } from '../src/audit.js';

const rejects = (p, status, code) => assert.rejects(p, (e) => e instanceof HttpError && e.status === status && (!code || e.code === code), `expected ${status} ${code}`);
const enrich = (n = 2) => ({ indicators: Array.from({ length: n }, (_, i) => `i${i}`) });
const callEnrich = (w, ctx, key = 'idem-0001', n = 2) => run(w.env, w.db, w.clock, ctx, 'intel.enrich', enrich(n), async () => ({ ok: true }), { idemKey: key, requestId: key });
const callHash = (w, ctx, id) => run(w.env, w.db, w.clock, ctx, 'intel.hash', {}, async () => ({ found: false }), { requestId: id });
const events = async (w) => (await w.db.prepare('SELECT * FROM usage_events ORDER BY created_at, usage_event_id').all()).results;

test('authentication: only a verified key gives identity; every failure looks the same', async () => {
  const w = await world(); await w.tenant('t1'); await w.tenant('t2'); const { key, id } = await w.key('t1');
  const ok = await w.ctx(key); assert.equal(ok.tenant.id, 't1');
  const h = { 'x-tenant-id': 't2', 'x-tenant': 't2' };
  assert.equal((await (await import('../src/context.js')).buildContext(w.req(key, { headers: h }), w.env, w.db, w.clock)).tenant.id, 't1', 'a client-supplied tenant header must change nothing');
  const bodies = [];
  for (const bad of ['', 'mgk_0000000000000000_' + 'A'.repeat(43), key.slice(0, -1) + (key.endsWith('A') ? 'B' : 'A'), 'nonsense', key.replace(id, '0'.repeat(16))]) {
    try { await w.ctx(bad); assert.fail('accepted'); } catch (e) { assert.equal(e.status, 401); bodies.push(JSON.stringify({ c: e.code, m: e.message })); }
  }
  assert.equal(new Set(bodies).size, 1, 'unknown id, wrong secret and malformed input are indistinguishable');
  assert.ok(!JSON.stringify((await w.db.prepare('SELECT * FROM api_keys').all()).results).includes(key.split('_').slice(2).join('_')), 'the secret is never stored');   // the WHOLE secret: it is base64url and can itself contain '_', so split('_')[2] alone was a short fragment that appeared in the stored JSON by chance
});
test('revocation, expiry, suspension and rotation with overlap', async () => {
  const w = await world(); await w.tenant('t1'); const k1 = await w.key('t1');
  const k2 = await w.key('t1', undefined, { ttlDays: 1 }); await w.ctx(k2.key); w.clock.advance(2 * 86400000); await rejects(w.ctx(k2.key), 401);
  await revokeKey(w.db, w.clock, 't1', k1.id); await rejects(w.ctx(k1.key), 401);
  const k3 = await w.key('t1'); const fresh = await rotateKey(w.db, w.env, w.clock, 't1', k3.id, { overlapHours: 1 });
  await w.ctx(k3.key); await w.ctx(fresh.key); w.clock.advance(2 * 3600000); await rejects(w.ctx(k3.key), 401); await w.ctx(fresh.key);
  await w.tenant('t9', { status: 'suspended' }); const k9 = await w.key('t9'); await rejects(w.ctx(k9.key), 403, 'tenant_suspended');
  assert.ok((await verifyAudit(w.db)).ok);
});
test('FREE_LAUNCH: everything authorised is reachable, every use is recorded, nothing is charged, the theoretical amount is kept apart', async () => {
  const w = await world(); await w.tenant('t1'); const { key } = await w.key('t1'); const ctx = await w.ctx(key);
  assert.equal(effective(ctx.policy.doc, ctx.tenant, 'api', w.clock().getTime()).mode, 'FREE_LAUNCH');
  await callEnrich(w, ctx, 'launch-0001', 3); await callHash(w, ctx, 'r1');
  const [h, e] = (await events(w)).sort((a, b) => a.operation.localeCompare(b.operation)).reverse();
  assert.equal(e.operation, 'intel.enrich'); assert.equal(e.billable_micros, 0); assert.equal(e.billing_status, 'none'); assert.equal(e.theoretical_micros, 15000); assert.equal(e.commercial_mode, 'FREE_LAUNCH'); assert.equal(e.policy_version, 1);
  assert.equal(h.billing_status, 'included'); assert.equal(h.billable_micros, 0);
  const u = await monthUsage(w.db, ctx, w.clock); assert.equal(u.billed_micros, 0); assert.ok(u.theoretical_micros >= 15000); assert.match(u.note, /NOT billed/);
});
test('scopes and plans: a key limited to one scope cannot use another, and PAID without a plan opens nothing', async () => {
  const w = await world(); await w.tenant('t1'); const narrow = await w.key('t1', ['intel.query']);
  const ctx = await w.ctx(narrow.key); await callHash(w, ctx, 'r1'); await rejects(callEnrich(w, ctx), 403, 'insufficient_scope');
  const w2 = await world({ policy: paid() }); await w2.tenant('c'); const c = await w2.ctx((await w2.key('c')).key);
  await rejects(callHash(w2, c, 'r1'), 403, 'not_entitled');
});
test('quotas are atomic: 20 concurrent requests against a limit of 5 let exactly 5 through and the refused ones consume nothing', async () => {
  const d = clone(SEED); d.launch.quotas.minute = 5; const w = await world({ policy: d }); await w.tenant('t1'); const ctx = await w.ctx((await w.key('t1')).key);
  const out = await Promise.allSettled(Array.from({ length: 20 }, (_, i) => callHash(w, ctx, 'c' + i)));
  assert.equal(out.filter((o) => o.status === 'fulfilled').length, 5); assert.ok(out.filter((o) => o.status === 'rejected').every((o) => o.reason.code === 'quota_exceeded' && o.reason.extra.retry_after_seconds > 0));
  assert.equal((await w.db.prepare("SELECT n FROM counters WHERE scope = 'minute'").first()).n, 5);
  w.clock.advance(60000); await callHash(w, ctx, 'next');                                    // a new minute, a new window
});
test('daily and monthly limits, and a refused request does not burn the other windows', async () => {
  const d = clone(SEED); d.launch.quotas.day = 2; const w = await world({ policy: d }); await w.tenant('t1'); const ctx = await w.ctx((await w.key('t1')).key);
  await callHash(w, ctx, 'a'); await callHash(w, ctx, 'b'); await rejects(callHash(w, ctx, 'c'), 429, 'quota_exceeded');
  assert.equal((await w.db.prepare("SELECT n FROM counters WHERE scope = 'minute'").first()).n, 2, 'the minute counter was given back');
});
test('retries never count twice: same Idempotency-Key replays the stored result; a metered call without a key is refused; reuse across operations is a conflict', async () => {
  const w = await world(); await w.tenant('t1'); const ctx = await w.ctx((await w.key('t1')).key);
  await rejects(run(w.env, w.db, w.clock, ctx, 'intel.enrich', enrich(), async () => ({}), { requestId: 'x' }), 400, 'idempotency_key_required');
  let calls = 0; const h = async () => ({ n: ++calls });
  const a = await run(w.env, w.db, w.clock, ctx, 'intel.enrich', enrich(), h, { idemKey: 'retry-0001', requestId: 'a' }); const b = await run(w.env, w.db, w.clock, ctx, 'intel.enrich', enrich(), h, { idemKey: 'retry-0001', requestId: 'b' });
  assert.deepEqual(a.result, b.result); assert.equal(calls, 1); assert.equal(b.replayed, true); assert.equal((await events(w)).length, 1);
  await rejects(run(w.env, w.db, w.clock, ctx, 'intel.hash', {}, h, { idemKey: 'retry-0001' }), 409, 'idempotency_key_reuse');
  await rejects(run(w.env, w.db, w.clock, ctx, 'intel.enrich', enrich(), h, { idemKey: 'bad key!' }), 400, 'invalid_idempotency_key');
  const par = await Promise.all(Array.from({ length: 8 }, () => run(w.env, w.db, w.clock, ctx, 'intel.enrich', enrich(), h, { idemKey: 'parallel-0001', requestId: 'p' })));
  assert.equal(new Set(par.map((p) => p.usage_event_id)).size, 1); assert.equal((await events(w)).filter((e) => e.idem_key === 'parallel-0001').length, 1);
});
test('a failed operation is not billed, returns its reservation and keeps the failure on record', async () => {
  const w = await world({ policy: paid() }); await w.tenant('t1', { plan: 'intelligence', budgetMicros: 100000 }); const ctx0 = await w.ctx((await w.key('t1')).key);
  await (await import('../src/policy.js')).acceptTerms(w.db, w.clock, ctx0, ctx0.policy.doc, { pricing_version: SEED.billing.pricing.version, terms_version: SEED.billing.terms_version }); const ctx = await w.ctx((await w.key('t1')).key);
  await rejects(run(w.env, w.db, w.clock, ctx, 'intel.enrich', enrich(), async () => { throw new HttpError(503, 'upstream', 'x'); }, { idemKey: 'fail-0001' }), 503);
  const e = (await events(w))[0]; assert.equal([e.request_status, e.billing_status, e.billable_micros].join(), 'failed,not_billable,0');
  assert.equal((await w.db.prepare('SELECT spent_micros AS s FROM budget').first()).s, 0);
});

test('PAID needs an accepted pricing version: before acceptance nothing is charged, after it only later uses are, and the budget is a hard limit', async () => {
  const w = await world({ policy: paid() }); await w.tenant('t1', { plan: 'intelligence', budgetMicros: 20000 }); const { key } = await w.key('t1');
  let ctx = await w.ctx(key); const eff = effective(ctx.policy.doc, ctx.tenant, 'api', w.clock().getTime(), ctx.acceptance);
  assert.deepEqual([eff.mode, eff.charging, eff.accepted], ['PAID', false, false]);
  await rejects(callEnrich(w, ctx, 'before-0001'), 402, 'upgrade_required');                                    // freemium allowance is 0 metered units: asked to accept and subscribe
  await callHash(w, ctx, 'inc1');                                                                                 // included operations work on the free allowance
  const { acceptTerms } = await import('../src/policy.js'); w.clock.advance(60000);
  await rejects(acceptTerms(w.db, w.clock, ctx, ctx.policy.doc, { pricing_version: 'old', terms_version: 'x' }), 409, 'terms_mismatch');
  await acceptTerms(w.db, w.clock, ctx, ctx.policy.doc, { pricing_version: SEED.billing.pricing.version, terms_version: SEED.billing.terms_version }); ctx = await w.ctx(key);
  assert.equal(effective(ctx.policy.doc, ctx.tenant, 'api', w.clock().getTime(), ctx.acceptance).charging, true);
  w.clock.advance(1000); await callEnrich(w, ctx, 'after-0001', 2);                                               // 2 x 5000 = 10000
  const billed = (await events(w)).filter((e) => e.billing_status === 'billed'); assert.equal(billed.length, 1); assert.equal(billed[0].billable_micros, 10000);
  assert.ok((await events(w)).filter((e) => e.operation === 'intel.hash').every((e) => e.billable_micros === 0), 'earlier uses are never charged retroactively');
  await callEnrich(w, ctx, 'after-0002', 2); await rejects(callEnrich(w, ctx, 'after-0003', 1), 402, 'budget_exceeded');
  assert.ok(w.env.EVENTS.events.some((e) => e.type === 'usage.near_limit'));
  const r = await refund(w.db, w.clock, 't1', billed[0].usage_event_id, 'customer request'); assert.equal(r.refunded_micros, 10000);
  await callEnrich(w, ctx, 'after-0004', 2);                                                                      // the refund freed budget
  await rejects(refund(w.db, w.clock, 't1', billed[0].usage_event_id, 'again'), 409, 'not_refundable');
  const u = await monthUsage(w.db, ctx, w.clock); assert.ok(u.theoretical_micros > 0 && u.billed_micros === 20000);
});
test('metered operations need a spending limit; a tenant with budget 0 cannot run up charges', async () => {
  const w = await world({ policy: paid() }); await w.tenant('t1', { plan: 'intelligence', budgetMicros: 0 }); const { key } = await w.key('t1'); let ctx = await w.ctx(key);
  const { acceptTerms } = await import('../src/policy.js'); await acceptTerms(w.db, w.clock, ctx, ctx.policy.doc, { pricing_version: SEED.billing.pricing.version, terms_version: SEED.billing.terms_version }); w.clock.advance(1000); ctx = await w.ctx(key);
  await rejects(callEnrich(w, ctx, 'nobudget-1'), 402, 'budget_required');
});
test('prices not approved or billing not live: PAID mode still charges nothing', async () => {
  for (const [live, approved] of [[true, false], [false, true]]) {
    const d = paid(); d.billing.live = live; d.billing.pricing.approved = approved; const w = await world({ policy: d }); await w.tenant('t1', { plan: 'intelligence', budgetMicros: 100000 }); const { key } = await w.key('t1'); let ctx = await w.ctx(key);
    const { acceptTerms } = await import('../src/policy.js'); await acceptTerms(w.db, w.clock, ctx, ctx.policy.doc, { pricing_version: SEED.billing.pricing.version, terms_version: SEED.billing.terms_version }); w.clock.advance(1000); ctx = await w.ctx(key);
    assert.equal(effective(ctx.policy.doc, ctx.tenant, 'api', w.clock().getTime(), ctx.acceptance).charging, false);
  }
});

test('effective policy precedence: scheduled mode, product mode, offers, tenant overrides, and their expiry', () => {
  const t = { id: 'a', plan: 'community' }, now = Date.parse('2026-10-23T10:00:00Z');
  const d = clone(SEED); d.mode = 'FREE_LAUNCH'; d.scheduled = { mode: 'PAID', effective_from: '2026-12-01T00:00:00Z' };
  assert.equal(effective(d, t, 'api', now).mode, 'FREE_LAUNCH'); assert.equal(effective(d, t, 'api', Date.parse('2026-12-01T00:00:00Z')).mode, 'PAID');
  d.products.premium.mode = 'FREEMIUM'; assert.equal(effective(d, t, 'premium', now).mode, 'FREEMIUM'); assert.equal(effective(d, t, 'api', now).mode, 'FREE_LAUNCH');
  d.mode = 'PAID'; d.scheduled = null; d.products.premium.mode = null; d.offers = [{ id: 'early', tenant_id: null, products: ['api'], free_until: '2026-11-01T00:00:00Z' }];
  assert.equal(effective(d, t, 'api', now).mode, 'FREE_LAUNCH'); assert.equal(effective(d, t, 'api', Date.parse('2026-11-01T00:00:01Z')).mode, 'PAID'); assert.equal(effective(d, t, 'premium', now).mode, 'PAID', 'the offer is per product');
  d.overrides = [{ tenant_id: 'a', mode: 'FREEMIUM', product: null, until: '2026-11-15T00:00:00Z', reason: 'pilot' }]; assert.equal(effective(d, t, 'premium', now).mode, 'FREEMIUM'); assert.equal(effective(d, { id: 'b', plan: 'community' }, 'premium', now).mode, 'PAID');
  assert.equal(effective(d, t, 'premium', Date.parse('2026-11-16T00:00:00Z')).mode, 'PAID');
});
test('policy validation rejects secrets, floats, bad modes and malformed exceptions', () => {
  const bad = (f, re) => { const d = clone(SEED); f(d); const e = validatePolicy(d); assert.ok(e.some((x) => re.test(x)), `${re}: ${e}`); };
  bad((d) => { d.mode = 'FREE'; }, /mode must be/); bad((d) => { d.billing.stripe_secret = 'x'; }, /named like a secret/); bad((d) => { d._comment = 'key ' + ['sk', 'live', 'abcdefghijklmnopqrstuvwx'].join('_'); }, /looks like a secret/);
  bad((d) => { d.billing.pricing.unit_micros['intel.enrich'] = 0.005; }, /floats/); bad((d) => { d.launch.quotas.day = -1; }, /non-negative/); bad((d) => { d.launch.features = ['everything']; }, /subset/);
  bad((d) => { d.overrides = [{ tenant_id: 'x', mode: 'PAID' }]; }, /malformed/); bad((d) => { d.offers = [{ id: 'o', products: ['nope'], free_until: '2026-12-01T00:00:00Z' }]; }, /malformed/); bad((d) => { d.scheduled = { mode: 'PAID' }; }, /scheduled/);
  assert.deepEqual(validatePolicy(SEED), []);
});

test('TOTP matches the RFC 6238 test vector', async () => {
  const k = new TextEncoder().encode('12345678901234567890'); assert.equal(await totp(k, 1, 8), '94287082'); assert.equal(await totp(k, 37037036, 8), '07081804'); assert.equal(await totp(k, 1, 6), '287082');
  assert.equal(new TextDecoder().decode(fromBase32('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')), '12345678901234567890');
});
test('audit is a hash chain that cannot be edited or deleted', async () => {
  const w = await world(); await w.tenant('t1'); await w.key('t1'); assert.ok((await verifyAudit(w.db)).ok);
  assert.throws(() => w.db.raw.exec("UPDATE audit SET action = 'x'"), /append-only/); assert.throws(() => w.db.raw.exec('DELETE FROM audit'), /append-only/);
});
