import test from 'node:test';
import assert from 'node:assert/strict';
import { world, SEED, clone } from './helpers.js';
import { authenticateAdmin } from '../src/admin.js';
import { acceptTerms, applyProposal, approve, effective, loadActive, policyHistory, propose, rollback } from '../src/policy.js';
import { run } from '../src/pipeline.js';
import { HttpError } from '../src/util.js';
import { verifyAudit } from '../src/audit.js';

const rejects = (p, status, code) => assert.rejects(p, (e) => e instanceof HttpError && e.status === status && (!code || e.code === code), `expected ${status} ${code}`);
const asAdmin = async (w, a) => authenticateAdmin(new Request('https://gw.test/a', { headers: await a.headers() }), w.env, w.db, w.clock);
const day = 86400000;
const scheduledPaid = (w, days) => { const d = clone(SEED); d.scheduled = { mode: 'PAID', effective_from: new Date(w.clock().getTime() + days * day).toISOString().replace(/\.\d+Z/, 'Z') }; d.billing.live = true; d.billing.pricing.approved = true; return d; };

test('administrator authentication needs the key AND a fresh TOTP code; a code works once; failures look alike and are audited', async () => {
  const w = await world(); const a = await w.admin('ana');
  const ok = await asAdmin(w, a); assert.equal(ok.id, a.id);
  const h = await a.headers(); delete h['x-mfa-code']; await rejects(authenticateAdmin(new Request('https://gw.test/a', { headers: h }), w.env, w.db, w.clock), 401);
  const h2 = await a.headers(); h2['x-mfa-code'] = '000000'; await rejects(authenticateAdmin(new Request('https://gw.test/a', { headers: h2 }), w.env, w.db, w.clock), 401);
  const h3 = await a.headers(); await authenticateAdmin(new Request('https://gw.test/a', { headers: h3 }), w.env, w.db, w.clock);
  await rejects(authenticateAdmin(new Request('https://gw.test/a', { headers: h3 }), w.env, w.db, w.clock), 401);                    // the same code, replayed
  const h4 = await a.headers(); h4.authorization = h4.authorization.slice(0, -2) + 'xx'; await rejects(authenticateAdmin(new Request('https://gw.test/a', { headers: h4 }), w.env, w.db, w.clock), 401);
  assert.ok(!JSON.stringify((await w.db.prepare('SELECT * FROM admins').all()).results).includes(a.totp_seed_base32), 'the TOTP seed is sealed, never stored in clear');
  const rows = (await w.db.prepare("SELECT detail FROM audit WHERE action = 'admin.rejected'").all()).results; assert.ok(rows.length >= 3); assert.ok(rows.every((r) => !/mga_|[0-9]{6}/.test(r.detail.replace(/"admin_id":"[0-9a-f]+"/, ''))));
  await w.db.prepare("UPDATE admins SET disabled_at = '2026-10-23T00:00:00Z'").run(); await rejects(asAdmin(w, a), 401);
});
test('an increase in charging can never be immediate, needs notice, needs two different administrators, and is recorded', async () => {
  const w = await world(); const [a, b] = [await w.admin('ana'), await w.admin('ben')];
  const direct = clone(SEED); direct.mode = 'PAID';
  await rejects(propose(w.db, w.clock, await asAdmin(w, a), direct, 'go live'), 422, 'policy_rejected');
  await rejects(propose(w.db, w.clock, await asAdmin(w, a), scheduledPaid(w, 10), 'too soon'), 422);                                 // 10 days < the 30 days of notice
  const sched = scheduledPaid(w, 31); const p = await propose(w.db, w.clock, await asAdmin(w, a), sched, 'announce paid plans'); assert.equal(p.approvals_required, 2);
  await rejects(applyProposal(w.db, w.clock, await asAdmin(w, a), p.id), 403, 'approvals_missing');
  await approve(w.db, w.clock, await asAdmin(w, a), p.id); await rejects(applyProposal(w.db, w.clock, await asAdmin(w, a), p.id), 403, 'approvals_missing');      // the same person twice is still one
  await approve(w.db, w.clock, await asAdmin(w, b), p.id); const r = await applyProposal(w.db, w.clock, await asAdmin(w, b), p.id); assert.equal(r.version, 2);
  const act = await loadActive(w.db); assert.equal(act.doc.mode, 'FREE_LAUNCH', 'still free until the announced date'); assert.equal(act.doc.scheduled.mode, 'PAID');
  const h = await policyHistory(w.db); assert.deepEqual([h.chain_ok, h.versions.map((v) => v.kind), h.versions.map((v) => v.created_by)], [true, ['seed', 'change'], ['seed', b.id]]);
  assert.throws(() => w.db.raw.exec("UPDATE policy_versions SET doc = '{}'"), /immutable/); assert.throws(() => w.db.raw.exec('DELETE FROM policy_versions'), /immutable/);
  assert.ok((await verifyAudit(w.db)).ok);
});
test('the full transition FREE_LAUNCH -> scheduled PAID -> charging, with acceptance first and no retroactive charge, then a safe rollback', async () => {
  const w = await world(); const [a, b] = [await w.admin('ana'), await w.admin('ben')];
  await w.tenant('t1', { plan: 'intelligence', budgetMicros: 100000 }); const { key } = await w.key('t1');
  const enrich = (ctx, id) => run(w.env, w.db, w.clock, ctx, 'intel.enrich', { indicators: ['a', 'b'] }, async () => ({ ok: 1 }), { idemKey: id, requestId: id });
  let ctx = await w.ctx(key); await enrich(ctx, 'launch-use-1');                                                                    // FREE_LAUNCH: recorded, not charged
  await w.apply(a, b, scheduledPaid(w, 31), 'announce'); w.clock.advance(5 * day); ctx = await w.ctx(key); await enrich(ctx, 'notice-use-1');       // during the notice period it is still free
  w.clock.advance(27 * day); ctx = await w.ctx(key);                                                                                   // the date has passed: PAID applies, but this tenant has not accepted
  assert.equal(effective(ctx.policy.doc, ctx.tenant, 'api', w.clock().getTime(), ctx.acceptance).mode, 'PAID');
  await rejects(enrich(ctx, 'paid-noaccept-1'), 402, 'upgrade_required');                                                              // no acceptance: no charge, asked to accept
  await acceptTerms(w.db, w.clock, ctx, ctx.policy.doc, { pricing_version: SEED.billing.pricing.version, terms_version: SEED.billing.terms_version }); w.clock.advance(1000); ctx = await w.ctx(key);
  await enrich(ctx, 'paid-use-1');
  const ev = Object.fromEntries((await w.db.prepare('SELECT idem_key k, billable_micros b, theoretical_micros t, commercial_mode m, policy_version v, billing_status s FROM usage_events').all()).results.map((r) => [r.k, r]));
  assert.deepEqual([ev['launch-use-1'].b, ev['launch-use-1'].m, ev['launch-use-1'].t], [0, 'FREE_LAUNCH', 10000]); assert.equal(ev['notice-use-1'].b, 0);
  assert.deepEqual([ev['paid-use-1'].b, ev['paid-use-1'].m, ev['paid-use-1'].s, ev['paid-use-1'].v], [10000, 'PAID', 'billed', 2]);
  // incident: one administrator with MFA reverts immediately; charging stops, history stays
  const r = await rollback(w.db, w.clock, await asAdmin(w, b), 'billing incident'); assert.equal(r.version, 3); ctx = await w.ctx(key);
  const eff = effective(ctx.policy.doc, ctx.tenant, 'api', w.clock().getTime(), ctx.acceptance); assert.deepEqual([eff.mode, eff.charging], ['FREE_LAUNCH', false]);
  await enrich(ctx, 'after-rollback-1'); assert.equal((await w.db.prepare("SELECT billable_micros b FROM usage_events WHERE idem_key = 'after-rollback-1'").first()).b, 0);
  assert.equal((await w.db.prepare("SELECT COUNT(*) n FROM usage_events WHERE billing_status = 'billed'").first()).n, 1, 'what was billed before stays recorded');
  const h = await policyHistory(w.db); assert.deepEqual(h.versions.map((v) => v.kind), ['seed', 'change', 'rollback']); assert.ok(h.chain_ok);
});
test('every request pins ONE policy version: a change in the middle cannot split it, and the version used is recorded', async () => {
  const w = await world(); const [a, b] = [await w.admin('ana'), await w.admin('ben')]; await w.tenant('t1'); const { key } = await w.key('t1');
  const old = await w.ctx(key); const d = clone(SEED); d.launch.quotas.minute = 2; await w.apply(a, b, d, "tighten launch limits"); const fresh = await w.ctx(key);
  const call = (ctx, id) => run(w.env, w.db, w.clock, ctx, 'intel.hash', {}, async () => ({}), { requestId: id });
  await call(old, 'old-1'); await call(fresh, 'new-1'); await rejects(call(fresh, 'new-2'), 429, 'quota_exceeded');
  const v = Object.fromEntries((await w.db.prepare('SELECT request_id r, policy_version v FROM usage_events').all()).results.map((x) => [x.r, x.v])); assert.deepEqual([v['old-1'], v['new-1']], [1, 2]);
});
test('two proposals from the same base: exactly one wins, the other goes stale', async () => {
  const w = await world(); const [a, b] = [await w.admin('ana'), await w.admin('ben')];
  const d1 = clone(SEED); d1.launch.quotas.day = 900; const d2 = clone(SEED); d2.launch.quotas.day = 800;
  const p1 = await propose(w.db, w.clock, await asAdmin(w, a), d1, 'one'); const p2 = await propose(w.db, w.clock, await asAdmin(w, b), d2, 'two');
  await applyProposal(w.db, w.clock, await asAdmin(w, a), p1.id); await rejects(applyProposal(w.db, w.clock, await asAdmin(w, b), p2.id), 409, 'policy_conflict');
  assert.equal((await loadActive(w.db)).doc.launch.quotas.day, 900); assert.equal((await w.db.prepare('SELECT status FROM policy_proposals WHERE id = ?').bind(p2.id).first()).status, 'stale');
});
test('exceptions: offers and tenant overrides need one approval when they only lower charging, and an override that raises it needs an end date', async () => {
  const w = await world(); const [a, b] = [await w.admin('ana'), await w.admin('ben')];
  const d = clone(SEED); d.offers = [{ id: 'partner-q4', tenant_id: null, products: ['premium', 'api'], free_until: '2027-01-31T00:00:00Z' }]; d.overrides = [{ tenant_id: 'vip', mode: 'FREE_LAUNCH', product: null, until: null, reason: 'design partner' }];
  const p = await propose(w.db, w.clock, await asAdmin(w, a), d, 'free access offers'); assert.equal(p.approvals_required, 1); await applyProposal(w.db, w.clock, await asAdmin(w, a), p.id);
  const up = clone((await loadActive(w.db)).doc); up.overrides.push({ tenant_id: 'x', mode: 'PAID', product: null, until: null, reason: 'raise' });
  await rejects(propose(w.db, w.clock, await asAdmin(w, a), up, 'raise without end'), 422);
  const secret = clone((await loadActive(w.db)).doc); secret.billing.note = 'whsec_abcdefghijklmnop'; await rejects(propose(w.db, w.clock, await asAdmin(w, a), secret, 'oops'), 422);
  const pricing = clone((await loadActive(w.db)).doc); pricing.billing.pricing.approved = true; assert.equal((await propose(w.db, w.clock, await asAdmin(w, a), pricing, 'approve prices')).approvals_required, 2);
  const live = clone((await loadActive(w.db)).doc); live.billing.live = true; assert.equal((await propose(w.db, w.clock, await asAdmin(w, b), live, 'go live')).approvals_required, 2);
});
test('a rollback is immediate, needs one administrator with MFA, and clears checkout and charging', async () => {
  const w = await world(); const [a, b] = [await w.admin('ana'), await w.admin('ben')];
  const d = clone(SEED); d.mode = 'FREEMIUM'; d.billing.allow_checkout = true;                                                       // an increase: needs the notice path, so build it the long way
  const s = scheduledPaid(w, 31); s.billing.allow_checkout = true; await w.apply(a, b, s, 'announce');
  const h = await b.headers(); h['x-mfa-code'] = '123456'; await rejects(authenticateAdmin(new Request('https://gw.test/a', { headers: h }), w.env, w.db, w.clock), 401);
  await rollback(w.db, w.clock, await asAdmin(w, b), 'revert'); const act = (await loadActive(w.db)).doc;
  assert.deepEqual([act.mode, act.scheduled, act.billing.live, act.billing.allow_checkout], ['FREE_LAUNCH', null, false, false]);
});
