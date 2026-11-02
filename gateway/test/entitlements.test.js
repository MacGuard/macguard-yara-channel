// Entitlements (macguard.entitlements/1): capabilities resolved on the server from plan, commercial policy, explicit grants and access mode. Synthetic tenants and data only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { apiWorld, SEED, clone, paid } from './apiworld.js';
import { ACCESS_MODES, CAPABILITIES, PREMIUM, PUBLIC, accessMode, can, grant, resolve, revoke } from '../src/entitlements.js';
import { applyEvent, emptyState, planOf } from '../src/subscriptions.js';
import { requiredApprovals, validatePolicy } from '../src/policy.js';
import { validate } from '../src/schema.js';
import { MODERN } from '../src/mcp.js';

const NOW = Date.parse('2026-11-01T10:00:00Z');
const SCHEMA = JSON.parse(readFileSync(new URL('../../contracts/v1/entitlements.schema.json', import.meta.url), 'utf8'));
const P = (o = {}) => ({ anonymous: false, organizations: [{ id: 'org1' }], plan: 'community', subscribed: false, features: [], accessMode: 'ENFORCED', grants: [], ...o });
const G = (capability, o = {}) => ({ subject: { kind: 'organization', id: 'org1' }, capability, granted_at: '2026-10-01T00:00:00Z', expires_at: null, revoked_at: null, source: 'manual', ...o });
const enforced = () => { const d = clone(SEED); d.mode = 'FREEMIUM'; d.freemium.features = []; d.entitlements = { access_mode: 'ENFORCED' }; return d; };
const K = async (w, t = 't1', o = {}, scopes) => { await w.tenant(t, o); return (await w.key(t, scopes)).key; };
let rid = 0;
const mcp = (w, key, method, params = {}) => w.call('/mcp', { method: 'POST', key, json: { jsonrpc: '2.0', id: ++rid, method, params: { ...params, _meta: { 'io.modelcontextprotocol/protocolVersion': MODERN, 'io.modelcontextprotocol/clientCapabilities': {}, 'io.modelcontextprotocol/clientInfo': { name: 't', version: '1' } } } },
  headers: { 'mcp-protocol-version': MODERN, 'mcp-method': method, ...(params.name ? { 'mcp-name': params.name } : {}), accept: 'application/json, text/event-stream' } });

// ---- the model ----
test('the capability set is exactly the approved one; public, premium and explicit-only are disjoint and cover it', () => {
  assert.deepEqual(CAPABILITIES, ['catalog.public.read', 'vulnerability.public.read', 'yara.community.download', 'rules.premium.read', 'rules.premium.download', 'ioc.premium.read', 'intel.correlation.read', 'intel.advanced.export', 'research.poc.metadata.read']);
  assert.deepEqual([...PUBLIC, ...PREMIUM, 'research.poc.metadata.read'].sort(), [...CAPABILITIES].sort());
  assert.deepEqual(ACCESS_MODES, ['OPEN_PREMIUM_PREVIEW', 'ENFORCED']);
});
test('anonymous and FREE: the public capabilities (positive control: FREE can download YARA Community), nothing premium when ENFORCED', () => {
  for (const p of [P({ anonymous: true, organizations: [] }), P()]) {
    for (const c of PUBLIC) assert.equal(can(p, c, NOW), true, c);
    for (const c of [...PREMIUM, 'research.poc.metadata.read']) assert.equal(can(p, c, NOW), false, c);
  }
  assert.equal(can(P(), 'yara.community.download', NOW), true);
  assert.equal(can(P(), 'not.a.capability', NOW), false, 'unknown capability names are never granted');
});
test('PREMIUM: features of a paid plan give the premium capabilities; only business adds the advanced export; no plan gives PoC metadata', () => {
  const intel = P({ plan: 'intelligence', subscribed: true, features: ['premium', 'intel', 'intel.enrich', 'mcp'] }), biz = P({ plan: 'business', subscribed: true, features: ['premium', 'intel', 'intel.enrich', 'mcp'] });
  for (const c of ['rules.premium.read', 'rules.premium.download', 'ioc.premium.read', 'intel.correlation.read']) { assert.equal(can(intel, c, NOW), true, c); assert.equal(can(biz, c, NOW), true, c); }
  assert.equal(can(intel, 'intel.advanced.export', NOW), false); assert.equal(can(biz, 'intel.advanced.export', NOW), true);
  assert.equal(can(P({ plan: 'business', subscribed: false, features: [] }), 'intel.advanced.export', NOW), false, 'the plan name alone, without a subscription, gives nothing');
  for (const p of [intel, biz]) assert.equal(can(p, 'research.poc.metadata.read', NOW), false);
});
test('OPEN_PREMIUM_PREVIEW gives every premium capability to everyone, marked as preview, but NEVER the PoC metadata', () => {
  for (const p of [P({ accessMode: 'OPEN_PREMIUM_PREVIEW' }), P({ anonymous: true, organizations: [], accessMode: 'OPEN_PREMIUM_PREVIEW' })]) {
    const r = resolve(p, NOW); for (const c of PREMIUM) assert.ok(r.caps.has(c) && r.preview.has(c), c);
    assert.equal(r.caps.has('research.poc.metadata.read'), false);
  }
  const paidUser = resolve(P({ accessMode: 'OPEN_PREMIUM_PREVIEW', plan: 'intelligence', subscribed: true, features: ['premium'] }), NOW);
  assert.equal(paidUser.preview.has('rules.premium.read'), false, 'what the plan gives is not counted as preview');
});
test('an unknown or malformed access mode fails CLOSED for premium and OPEN for public, even for a paying business tenant', () => {
  const d = clone(SEED);
  for (const bad of [{ access_mode: 'OPEN' }, { access_mode: 'enforced' }, 'ENFORCED', [], { access_mode: 'ENFORCED', extra: 1 }]) {
    d.entitlements = bad; const m = accessMode(d, 'FREE_LAUNCH'); assert.ok(m === 'INVALID' || (typeof bad === 'object' && bad.access_mode === 'ENFORCED'), JSON.stringify(bad));
  }
  d.entitlements = { access_mode: 'OPEN' }; assert.equal(accessMode(d, 'FREE_LAUNCH'), 'INVALID'); assert.ok(validatePolicy(d).some((e) => /access_mode/.test(e)), 'and the policy store refuses to install it');
  const r = resolve(P({ accessMode: 'INVALID', plan: 'business', subscribed: true, features: ['premium', 'intel', 'intel.enrich'], grants: [G('research.poc.metadata.read')] }), NOW);
  assert.deepEqual([...r.caps].sort(), [...PUBLIC].sort());
});
test('access mode follows the commercial mode when not set: FREE_LAUNCH keeps today\'s free access (preview), a charging mode is ENFORCED', () => {
  assert.equal(accessMode(SEED, 'FREE_LAUNCH'), 'OPEN_PREMIUM_PREVIEW'); assert.equal(accessMode(SEED, 'FREEMIUM'), 'ENFORCED'); assert.equal(accessMode(paid(), 'PAID'), 'ENFORCED');
});
test('the preview cannot coexist with charging; enforcing needs two administrators; a rollback reopens the preview', () => {
  const p = paid(); p.entitlements = { access_mode: 'OPEN_PREMIUM_PREVIEW' }; assert.ok(validatePolicy(p).some((e) => /cannot be combined/.test(e)));
  const s = clone(SEED); s.scheduled = { mode: 'PAID', effective_from: '2027-01-01T00:00:00Z' }; s.entitlements = { access_mode: 'OPEN_PREMIUM_PREVIEW' }; assert.ok(validatePolicy(s).some((e) => /cannot be combined/.test(e)), 'a scheduled charging mode too');
  const open = clone(SEED); open.entitlements = { access_mode: 'OPEN_PREMIUM_PREVIEW' }; assert.deepEqual(validatePolicy(open), []);
  const enf = clone(SEED); enf.entitlements = { access_mode: 'ENFORCED' }; assert.equal(requiredApprovals(open, enf), 2); assert.equal(requiredApprovals(SEED, enf), 2); assert.equal(requiredApprovals(enf, open), 1);
});
test('explicit grants: expiry, revocation and future start are honoured; grants of other subjects never apply', () => {
  const at = (o) => P({ grants: [G('research.poc.metadata.read', o)] });
  assert.equal(can(at({}), 'research.poc.metadata.read', NOW), true);
  assert.equal(can(at({ expires_at: '2026-10-31T00:00:00Z' }), 'research.poc.metadata.read', NOW), false, 'expired');
  assert.equal(can(at({ revoked_at: '2026-10-31T00:00:00Z' }), 'research.poc.metadata.read', NOW), false, 'revoked');
  assert.equal(can(at({ granted_at: '2026-12-01T00:00:00Z' }), 'research.poc.metadata.read', NOW), false, 'not yet valid');
  assert.equal(can(at({ subject: { kind: 'organization', id: 'org2' } }), 'research.poc.metadata.read', NOW), false, 'another organization');
  assert.equal(can(P({ anonymous: true, organizations: [], grants: [G('rules.premium.read')] }), 'rules.premium.read', NOW), false, 'anonymous never takes a grant');
});
test('organizations: a user inherits its organizations\' grants, a user grant applies to that user only', () => {
  const user = (orgs, grants) => P({ user: { id: 'u1' }, organizations: orgs.map((id) => ({ id })), grants });
  assert.equal(can(user(['org1'], [G('ioc.premium.read')]), 'ioc.premium.read', NOW), true, 'inherited from org1');
  assert.equal(can(user(['org9'], [G('ioc.premium.read')]), 'ioc.premium.read', NOW), false, 'not a member');
  const ug = G('intel.correlation.read', { subject: { kind: 'user', id: 'u1' } });
  assert.equal(can(user([], [ug]), 'intel.correlation.read', NOW), true); assert.equal(can(P({ user: { id: 'u2' }, grants: [ug] }), 'intel.correlation.read', NOW), false);
});

// ---- subscription events (provider-agnostic) ----
test('subscription events: a repeated webhook is a no-op, an out-of-order (older) event never overwrites a newer state, malformed events change nothing', () => {
  let s = emptyState(); const ev = (id, status, version, o = {}) => ({ id, provider: 'stripe', subscription_id: 'sub1', tenant_id: 't1', plan: 'intelligence', status, version, ...o });
  let r = applyEvent(s, ev('e1', 'active', 10)); assert.equal(r.outcome, 'applied'); s = r.state; assert.equal(planOf(s, 't1'), 'intelligence');
  r = applyEvent(s, ev('e1', 'active', 10)); assert.equal(r.outcome, 'duplicate'); assert.equal(r.state, s);
  r = applyEvent(s, ev('e2', 'canceled', 20)); s = r.state; assert.equal(planOf(s, 't1'), 'community');
  r = applyEvent(s, ev('e3', 'active', 15)); assert.equal(r.outcome, 'stale'); s = r.state; assert.equal(planOf(s, 't1'), 'community', 'the late "active" does not resurrect access');
  for (const st of ['expired', 'refunded', 'revoked']) { const x = applyEvent(emptyState(), ev('x' + st, st, 1)); assert.equal(planOf(x.state, 't1'), 'community', st); }
  assert.equal(planOf(applyEvent(emptyState(), ev('p', 'past_due', 1)).state, 't1'), 'intelligence', 'past_due keeps access during the grace period (closed by sweepPastDue)');
  assert.equal(planOf(applyEvent(emptyState(), ev('u', 'active', 1, { plan: 'platinum' })).state, 't1'), 'community', 'an unknown plan grants nothing');
  const bad = applyEvent(s, { id: 'b', provider: 'stripe', subscription_id: 'sub1', status: 'active', version: 1.5 }); assert.equal(bad.outcome, 'rejected'); assert.equal(bad.state, s);
  assert.equal(applyEvent(s, ev('t', 'active', 99, { tenant_id: 't2' })).outcome, 'tenant_conflict');
});
test('provider failure never grants access: the Stripe webhook for a subscription the provider cannot return leaves the tenant on community', async () => {
  const { fakeStripe, WH, signPayload } = await import('./apiworld.js'); const st = await fakeStripe();
  try {
    const d = enforced(); const w = await apiWorld({ policy: d, stripe: st }); const key = await K(w, 'c1');
    await w.db.prepare("UPDATE tenants SET stripe_customer_id = 'cus_1' WHERE id = 'c1'").run();
    const raw = JSON.stringify({ id: 'evt_1', type: 'customer.subscription.updated', data: { object: { id: 'sub_missing', customer: 'cus_1' } } });
    const r = await w.call('/stripe/webhook', { method: 'POST', body: raw, headers: { 'stripe-signature': await signPayload(WH, raw, Math.floor(w.clock().getTime() / 1000)), 'content-type': 'application/json' } });
    assert.notEqual(r.status, 200); assert.equal((await w.db.prepare("SELECT plan FROM tenants WHERE id = 'c1'").first()).plan, 'community');
    assert.equal((await w.call('/v1/premium/releases', { key })).json.error.code, 'not_entitled');
  } finally { await st.close(); }
});

// ---- the gateway: server-side checks on every route ----
test('today (seed policy, FREE_LAUNCH): unchanged access for a community key, marked as preview; the PoC capability is not part of it', async () => {
  const w = await apiWorld(); const key = await K(w);
  const l = await w.call('/v1/premium/releases', { key }); assert.equal(l.status, 200); assert.equal(l.res.headers.get('x-access-mode'), 'OPEN_PREMIUM_PREVIEW');
  const e = await w.call('/v1/account/entitlements', { key }); assert.equal(e.status, 200); assert.equal(e.json.access_mode, 'OPEN_PREMIUM_PREVIEW'); assert.equal(e.json.preview, true);
  assert.ok(!e.json.capabilities.includes('research.poc.metadata.read')); assert.deepEqual(validate(SCHEMA, e.json.entitlements, 'entitlements'), []);
  assert.equal(e.json.tenant.id, 't1', 'the existing fields are still there');
  const h = await w.call('/v1/intelligence/hash/' + w.H, { key }); assert.deepEqual(h.json.records[0].data.malware, ['SynMalware'], 'no field is removed while access is open');
});
test('ENFORCED: a FREE key gets 403 on every premium route (REST and MCP), whatever the client claims about itself', async () => {
  const w = await apiWorld({ policy: enforced() }); const key = await K(w);
  const claims = { 'x-plan': 'business', 'x-is-premium': 'true', 'x-entitlements-mode': 'OPEN_PREMIUM_PREVIEW', 'x-access-mode': 'OPEN_PREMIUM_PREVIEW', 'x-tenant-id': 'biz', cookie: 'isPremium=true' };
  for (const p of ['/v1/premium/releases', '/v1/premium/releases/latest?isPremium=true', '/v1/premium/releases/prem-1/download', '/v1/intelligence/hash/' + w.H]) {
    const r = await w.call(p, { key, headers: claims }); assert.equal(r.status, 403, p); assert.equal(r.json.error.code, 'not_entitled'); assert.ok(r.json.error.required_capability, p);
  }
  const s = await w.call('/v1/intelligence/ioc/search', { key, method: 'POST', json: { values: ['203.0.113.7'], isPremium: true } }); assert.ok([400, 403].includes(s.status), 'an extra body field never authorises');
  const s2 = await w.call('/v1/intelligence/ioc/search', { key, method: 'POST', json: { values: ['203.0.113.7'] } }); assert.equal(s2.status, 403);
  const en = await w.call('/v1/intelligence/enrich', { key, method: 'POST', headers: { 'idempotency-key': 'enrich-free-1' }, json: { indicators: ['203.0.113.7'] } }); assert.equal(en.status, 403);
  const list = await mcp(w, key, 'tools/list'); const names = list.json.result.tools.map((t) => t.name);
  for (const t of ['macguard_list_premium_releases', 'macguard_authorize_download', 'macguard_lookup_hash', 'macguard_search_iocs', 'macguard_enrich_indicators']) assert.ok(!names.includes(t), `${t} not listed`);
  const c = await mcp(w, key, 'tools/call', { name: 'macguard_list_premium_releases', arguments: {} }); assert.equal(c.json.result.isError, true); assert.equal(c.json.result.structuredContent.error.code, 'not_entitled');
  const ent = await w.call('/v1/account/entitlements', { key }); assert.equal(ent.json.access_mode, 'ENFORCED'); assert.deepEqual(ent.json.capabilities, [...PUBLIC].sort()); assert.deepEqual(validate(SCHEMA, ent.json.entitlements, 'e'), []);
  assert.equal((await w.call('/v1/community/releases')).status, 200, 'Community stays free and needs nothing');
});
test('ENFORCED: a PREMIUM (intelligence) key gets the premium routes and the correlation fields', async () => {
  const w = await apiWorld({ policy: enforced() }); const key = await K(w, 'p1', { plan: 'intelligence' });
  assert.equal((await w.call('/v1/premium/releases', { key })).status, 200);
  const h = await w.call('/v1/intelligence/hash/' + w.H, { key }); assert.equal(h.status, 200); assert.deepEqual(h.json.records[0].data.malware, ['SynMalware']); assert.equal(h.json.redacted, undefined);
  assert.equal(h.res.headers.get('x-access-mode'), 'ENFORCED');
});
test('a grant of IOC access without correlation: indicators are served, correlation fields are removed ON THE SERVER, and an idempotent replay cannot bring them back', async () => {
  const w = await apiWorld({ policy: enforced() }); const key = await K(w, 'g1');
  assert.equal((await w.call('/v1/intelligence/hash/' + w.H, { key })).status, 403);
  await grant(w.db, w.clock, { subjectId: 'g1', capability: 'ioc.premium.read', reason: 'partner pilot', grantedBy: 'admin:test' });
  const h = await w.call('/v1/intelligence/hash/' + w.H, { key }); assert.equal(h.status, 200); assert.deepEqual(h.json.redacted, ['correlation']);
  assert.equal(h.json.records[0].data.family, 'SynMalware'); for (const k of ['malware', 'attack']) assert.ok(!(k in h.json.records[0].data), k); assert.ok(!h.text.includes('T1059'), 'not in the body at all');
  const s = await w.call('/v1/intelligence/ioc/search', { key, method: 'POST', headers: { 'idempotency-key': 'ioc-search-0001' }, json: { values: ['203.0.113.7'] } }); assert.equal(s.status, 200); assert.ok(!s.text.includes('CVE-2026-0001') && !s.text.includes('T1071'));
  const s2 = await w.call('/v1/intelligence/ioc/search', { key, method: 'POST', headers: { 'idempotency-key': 'ioc-search-0001' }, json: { values: ['203.0.113.7'] } }); assert.ok(!s2.text.includes('T1071'), 'the replayed answer is redacted too');
  const e = await w.call('/v1/intelligence/enrich', { key, method: 'POST', headers: { 'idempotency-key': 'enrich-g1-0001' }, json: { indicators: ['203.0.113.7'] } }); assert.equal(e.status, 403); assert.equal(e.json.error.required_capability, 'intel.correlation.read');
  assert.equal(await revoke(w.db, w.clock, { subjectId: 'g1', capability: 'ioc.premium.read' }), 1); assert.equal((await w.call('/v1/intelligence/hash/' + w.H, { key })).status, 403, 'revoked: closed at once');
});
test('expired grant, plan downgrade and revoked key close access, including a download token minted before the change (alternate route)', async () => {
  const w = await apiWorld({ policy: enforced() }); const key = await K(w, 'p1', { plan: 'intelligence' });
  const a = await w.call('/v1/premium/releases/prem-1/download', { key }); assert.equal(a.status, 200); const path = new URL(a.json.url).pathname;
  await w.db.prepare("UPDATE tenants SET plan = 'community' WHERE id = 'p1'").run();          // what a canceled/expired subscription does (stripe.js sync / sweepPastDue)
  const d = await w.call(path, { key }); assert.equal(d.status, 403); assert.equal(d.json.error.code, 'not_entitled'); assert.equal(d.json.error.required_capability, 'rules.premium.download');
  assert.equal((await w.call('/v1/premium/releases', { key })).status, 403);
  await w.db.prepare("INSERT INTO entitlement_grants(subject_kind,subject_id,capability,granted_at,expires_at,revoked_at,source,reason,granted_by) VALUES ('organization','p1','rules.premium.read','2026-10-01T00:00:00Z','2026-10-23T09:00:00Z',NULL,'manual','trial','admin:test')").run();   // a trial grant that has since expired (grant() refuses a past expiry)
  assert.equal((await w.call('/v1/premium/releases', { key })).status, 403, 'an expired grant gives nothing');
  const { revokeKey } = await import('../src/auth.js'); await revokeKey(w.db, w.clock, 'p1', key.split('_')[1]); assert.equal((await w.call('/v1/account/entitlements', { key })).status, 401);
  assert.equal((await w.call('/v1/premium/releases', { key: key.slice(0, -3) + 'abc' })).status, 401, 'a tampered key is just unauthenticated');
});
test('grants are validated and stored only as manual or subscription (the preview is never stored); the contract example validates', async () => {
  const w = await apiWorld();
  await assert.rejects(grant(w.db, w.clock, { subjectId: 't1', capability: 'rules.premium.read', source: 'preview', reason: 'x', grantedBy: 'a' }), /preview is never stored/);
  await assert.rejects(grant(w.db, w.clock, { subjectId: 't1', capability: 'root', reason: 'x', grantedBy: 'a' }), /Unknown capability/);
  await assert.rejects(grant(w.db, w.clock, { subjectId: 't1', capability: 'rules.premium.read' }), /reason/);
  const ex = JSON.parse(readFileSync(new URL('../../contracts/v1/examples/entitlements-manual-poc.json', import.meta.url), 'utf8')); assert.deepEqual(validate(SCHEMA, ex, 'example'), []);
  assert.ok(validate(SCHEMA, { ...ex, isPremium: true }, 'x').length > 0, 'unknown fields are refused by the contract');
});
test('ENFORCED with an explicit PoC metadata grant: only that organization gets it, and it is visible in its entitlements', async () => {
  const w = await apiWorld({ policy: enforced() }); const a = await K(w, 'r1'), b = await K(w, 'r2');
  await grant(w.db, w.clock, { subjectId: 'r1', capability: 'research.poc.metadata.read', reason: 'reviewed research partner', grantedBy: 'admin:test', expiresAt: '2026-12-01T00:00:00Z' });
  const ea = await w.call('/v1/account/entitlements', { key: a }), eb = await w.call('/v1/account/entitlements', { key: b });
  assert.ok(ea.json.capabilities.includes('research.poc.metadata.read')); assert.equal(ea.json.entitlements.source, 'manual'); assert.equal(ea.json.entitlements.expires_at, '2026-12-01T00:00:00Z');
  assert.ok(!eb.json.capabilities.includes('research.poc.metadata.read')); assert.deepEqual(validate(SCHEMA, ea.json.entitlements, 'e'), []);
});

// ---- Codex review entitlements-20261101 round 1: two MEDIUM findings ----
test('M1: a tenant override that charges cannot keep the preview: the policy is refused, and even a stored doc enforces for that tenant', () => {
  const d = clone(SEED); d.entitlements = { access_mode: 'OPEN_PREMIUM_PREVIEW' };
  d.overrides = [...(d.overrides || []), { tenant_id: 't1', product: 'api', mode: 'PAID', until: '2027-01-01T00:00:00Z', reason: 'negotiated paid pilot' }];
  assert.ok(validatePolicy(d).some((e) => /cannot be combined/.test(e)), 'validation covers tenant overrides');
  assert.equal(accessMode(d, 'PAID'), 'ENFORCED', 'defence in depth: the effective mode of that tenant is PAID, so no preview');
  assert.equal(accessMode(d, 'FREE_LAUNCH'), 'OPEN_PREMIUM_PREVIEW', 'other tenants keep the preview');
  for (const c of PREMIUM) assert.equal(can(P({ accessMode: accessMode(d, 'PAID'), features: [] }), c, NOW), false, c);
});
test('M2: an empty, malformed or past expiry is refused when granting, and a stored unparseable timestamp fails closed (never permanent access)', async () => {
  const w = await apiWorld(), base = { subjectId: 't1', capability: 'research.poc.metadata.read', reason: 'reviewed research partner', grantedBy: 'admin:test' };
  for (const expiresAt of ['', 'tomorrow', '2026-13-01T00:00:00Z', 1893456000000, '2020-01-01T00:00:00Z']) await assert.rejects(grant(w.db, w.clock, { ...base, expiresAt }), /expires_at must be null or a future/, String(expiresAt));
  for (const bad of [{ expires_at: '' }, { revoked_at: '' }, { granted_at: '' }, { expires_at: 'never' }]) assert.equal(can(P({ grants: [G('research.poc.metadata.read', bad)] }), 'research.poc.metadata.read', NOW), false, JSON.stringify(bad));
  assert.equal(can(P({ grants: [G('research.poc.metadata.read')] }), 'research.poc.metadata.read', NOW), true, 'null expiry is still a valid permanent grant');
});
test('Codex round 2 (MEDIUM): the entitlements snapshot lists only current grants, at most 200, so a long grant history never breaks the contract', async () => {
  const { snapshot } = await import('../src/entitlements.js');
  const old = Array.from({ length: 250 }, (_, i) => G('rules.premium.read', { granted_at: '2026-01-01T00:00:00Z', revoked_at: `2026-02-01T00:00:${String(i % 60).padStart(2, '0')}Z` }));
  const cur = G('research.poc.metadata.read'), ctx = { tenant: { id: 'org1', plan: 'community' }, policy: { version: 3 } };
  const ent = resolve(P({ grants: [...old, cur] }), NOW), snap = snapshot(ctx, null, ent, [...old, cur], NOW);
  assert.equal(snap.grants.length, 1); assert.equal(snap.grants[0].capability, 'research.poc.metadata.read'); assert.deepEqual(validate(SCHEMA, snap, 'snapshot'), []);
});
test('Codex round 2 (MEDIUM, large): the account endpoint advertises exactly what the premium routes enforce, each resolved with its own product policy', async () => {
  // premium product charges (PAID) while the api product stays in the free launch: a community key gets the api preview but NOT the premium routes
  const d = clone(SEED); d.products = { ...(d.products || {}), premium: { mode: 'PAID' } }; delete d.entitlements;
  const w = await apiWorld({ policy: d }); const key = await K(w);
  const ent = (await w.call('/v1/account/entitlements', { key })).json, list = await w.call('/v1/premium/releases', { key }), ioc = await w.call('/v1/intelligence/ioc/search', { key, method: 'POST', json: { values: ['203.0.113.7'] } });
  assert.equal(ent.capabilities.includes('rules.premium.read'), list.status === 200, `advertised ${ent.capabilities.includes('rules.premium.read')} vs route ${list.status}`);
  assert.equal(ent.capabilities.includes('ioc.premium.read'), ioc.status === 200, `advertised ${ent.capabilities.includes('ioc.premium.read')} vs route ${ioc.status}`);
  for (const c of PUBLIC) assert.ok(ent.capabilities.includes(c), c);
});
test('the Worker deployed BEFORE migration 0004: every route keeps working, no explicit grant is read (fail closed), and granting says the table is missing', async () => {
  const w = await apiWorld(); const key = await K(w); await w.db.prepare('DROP TABLE entitlement_grants').run();
  const e = await w.call('/v1/account/entitlements', { key }); assert.equal(e.status, 200); assert.ok(!e.json.capabilities.includes('research.poc.metadata.read'));
  assert.equal((await w.call('/v1/community/releases')).status, 200);
  await assert.rejects(grant(w.db, w.clock, { subjectId: 't1', capability: 'research.poc.metadata.read', reason: 'reviewed research partner', grantedBy: 'admin:test' }), /no such table/);
});
test('Codex entitlements-final (HIGH): an IOC grant never exposes CVE records that the CVE route refuses (ioc search and enrich, REST and MCP)', async () => {
  const d = enforced(); const w = await apiWorld({ policy: d }); const key = await K(w);
  await grant(w.db, w.clock, { subjectId: 't1', capability: 'ioc.premium.read', reason: 'ioc pilot without cve licence', grantedBy: 'admin:test' });
  await grant(w.db, w.clock, { subjectId: 't1', capability: 'intel.correlation.read', reason: 'ioc pilot without cve licence', grantedBy: 'admin:test' });
  const cve = 'CVE-2026-0001';
  assert.equal((await w.call(`/v1/intelligence/cve/${cve}`, { key })).status, 403, 'the dedicated CVE route refuses');
  for (const json of [{ values: [cve] }, { value: cve.toLowerCase() }, { values: ['203.0.113.7', cve] }]) { const r = await w.call('/v1/intelligence/ioc/search', { key, method: 'POST', json }); assert.equal(r.status, 403, JSON.stringify(json)); assert.ok(!JSON.stringify(r.json).includes('kev_listed')); }
  const en = await w.call('/v1/intelligence/enrich', { key, method: 'POST', headers: { 'idempotency-key': 'enrich-cve-1' }, json: { indicators: [cve] } }); assert.equal(en.status, 403);
  const m = await mcp(w, key, 'tools/call', { name: 'macguard_search_iocs', arguments: { values: [cve] } }); assert.equal(m.json.result.isError, true);
  const ok = await w.call('/v1/intelligence/ioc/search', { key, method: 'POST', json: { values: ['203.0.113.7'] } }); assert.equal(ok.status, 200, 'non-CVE indicators are still served under the IOC grant');
});
test('Codex entitlements-final fix round (HIGH): replaying an Idempotency-Key whose stored answer holds CVE records re-applies the CVE gate after a downgrade', async () => {
  const w = await apiWorld({ policy: enforced() }); const key = await K(w, 'p2', { plan: 'intelligence' }), cve = 'CVE-2026-0001', h = { 'idempotency-key': 'replay-cve-0001' };
  const first = await w.call('/v1/intelligence/ioc/search', { key, method: 'POST', headers: h, json: { values: [cve] } }); assert.equal(first.status, 200, 'allowed while the plan includes intel');
  await w.db.prepare("UPDATE tenants SET plan = 'community' WHERE id = 'p2'").run();
  for (const c of ['ioc.premium.read', 'intel.correlation.read']) await grant(w.db, w.clock, { subjectId: 'p2', capability: c, reason: 'ioc pilot without cve licence', grantedBy: 'admin:test' });
  const replay = await w.call('/v1/intelligence/ioc/search', { key, method: 'POST', headers: h, json: { values: ['203.0.113.7'] } });
  assert.equal(replay.status, 403, 'the stored CVE answer is not handed out'); assert.ok(!JSON.stringify(replay.json).includes('CVE-2026-0001'));
  const fresh = await w.call('/v1/intelligence/ioc/search', { key, method: 'POST', headers: { 'idempotency-key': 'replay-ioc-0002' }, json: { values: ['203.0.113.7'] } }); assert.equal(fresh.status, 200, 'IOC-only work still allowed');
});
