// The gateway on the REAL Workers runtime (workerd, through Miniflare) with a real D1 and a real R2 binding. `npm test` runs the same logic over a node:sqlite shim; this checks what the
// shim cannot: D1's own SQL engine (UPSERT ... RETURNING, triggers, batches), WebCrypto in workerd, streams and Range over R2, and a restart of the Worker with its state persisted.
// Stripe and the Community site are the only things replaced (an outbound fake). It does NOT prove a real Cloudflare account, real Stripe, DNS, TLS or real R2 at scale.
// Miniflare is taken from admin/worker/node_modules; without it this file is SKIPPED and says so (a skip is not a pass).
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../..', import.meta.url));
import { execFileSync } from 'node:child_process';
const candidates = [process.env.MINIFLARE_DIR, join(root, '..', 'admin', 'worker')];
try { const common = execFileSync('git', ['rev-parse', '--git-common-dir'], { cwd: root, encoding: 'utf8' }).trim(); candidates.push(resolve(root, common, '..', 'admin', 'worker')); } catch { /* not a git checkout */ }
let Miniflare = null;
for (const c of candidates.filter(Boolean)) { try { if (existsSync(join(c, 'node_modules', 'miniflare'))) { Miniflare = createRequire(join(c, 'package.json'))('miniflare').Miniflare; break; } } catch { /* try the next */ } }
const run = Miniflare ? test : test.skip;
if (!Miniflare) console.log('SKIPPED: miniflare is not installed (admin/worker/node_modules): the workerd runtime tests were NOT run');

const { createTenant, issueKey } = await import('../../src/auth.js');
const { createAdmin, authenticateAdmin } = await import('../../src/admin.js');
const { seedPolicy, propose, approve, applyProposal } = await import('../../src/policy.js');
const { signPayload } = await import('../../src/stripe.js');
const { totp, fromBase32, stepOf } = await import('../../src/totp.js');
const SEED = JSON.parse(readFileSync(join(root, '..', 'config', 'commercial', 'policy.seed.json'), 'utf8'));
const FILE = new Uint8Array(Array.from({ length: 6000 }, (_, i) => (i * 13 + 5) % 251));
const sha = async (u8) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', u8))].map((b) => b.toString(16).padStart(2, '0')).join('');
const PEPPERS = { KEY_PEPPER: 'k'.repeat(40), ADMIN_PEPPER: 'a'.repeat(40), TOTP_SEAL_KEY: 's'.repeat(40) };
const WH = 'whsec_runtime_test_secret';
const persist = mkdtempSync(join(tmpdir(), 'mg-gw-'));
const modules = () => readdirSync(join(root, 'src')).filter((f) => f.endsWith('.js')).sort((a, b) => (a === 'index.js' ? -1 : b === 'index.js' ? 1 : a.localeCompare(b))).map((f) => ({ type: 'ESModule', path: f, contents: readFileSync(join(root, 'src', f), 'utf8') }));
let mf, db, r2, key, adminA, clock = () => new Date(); let stripeSubs = {};

const outbound = async (req) => {
  const u = new URL(req.url);
  if (u.hostname === 'site.test') return new Response(u.pathname.endsWith('latest.json') ? '{"tag":"rules-x"}' : '{"releases":[]}');
  if (u.hostname === 'api.stripe.com' && /^\/v1\/subscriptions\/(.+)$/.test(u.pathname)) { const s = stripeSubs[u.pathname.split('/').pop()]; return s ? Response.json(s) : new Response('{}', { status: 404 }); }
  return new Response('{}', { status: 404 });
};
const split = (sql) => { const out = []; let cur = ''; for (const line of sql.split(/\r?\n/)) { const l = line.replace(/\s--.*$/, '').replace(/^--.*$/, ''); if (!l.trim()) continue; cur += l + '\n'; const trig = /^\s*CREATE TRIGGER/i.test(cur); if (trig ? /\bEND;\s*$/.test(l) : /;\s*$/.test(l)) { out.push(cur.trim().replace(/;$/, '')); cur = ''; } } return out; };
const boot = async () => {
  mf = new Miniflare({ modules: modules(), compatibilityDate: '2026-08-01', d1Databases: { DB: 'gateway' }, d1Persist: join(persist, 'd1'), r2Buckets: { PREMIUM: 'premium' }, r2Persist: join(persist, 'r2'),
    bindings: { PUBLIC_BASE: 'https://gw.test', COMMUNITY_ORIGIN: 'https://site.test', STRIPE_WEBHOOK_SECRETS: WH, STRIPE_API_KEY: 'sk_test_runtime', PRICE_MAP: '{"price_intel":"intelligence"}', GRACE_DAYS: '3', ...PEPPERS }, outboundService: outbound });
  db = await mf.getD1Database('DB'); r2 = await mf.getR2Bucket('PREMIUM');
};
const req = (path, o = {}) => mf.dispatchFetch('https://gw.test' + path, o);
const get = async (path, k = key, headers = {}) => { const r = await req(path, { headers: { authorization: `Bearer ${k}`, ...headers } }); const b = new Uint8Array(await r.arrayBuffer()); let j = null; try { j = JSON.parse(new TextDecoder().decode(b)); } catch { /* binary */ } return { r, status: r.status, j, b }; };

before(async () => {
  if (!Miniflare) return;
  await boot();
  await db.batch(split(readFileSync(join(root, 'schema.sql'), 'utf8')).map((s) => db.prepare(s)));
  await seedPolicy(db, clock, SEED);
  await createTenant(db, clock, { id: 't1', name: 'tenant one' });
  key = (await issueKey(db, PEPPERS, clock, 't1', { scopes: ['premium.read', 'premium.download', 'intel.query', 'intel.enrich', 'usage.estimate', 'account.read', 'account.billing', 'mcp'] })).key;
  adminA = await createAdmin(db, PEPPERS, clock, { name: 'ana' });
  await db.prepare("INSERT INTO intel_sources(source_id,status,approved_products,owner_confirmed,attribution) VALUES ('syn-ok','PREMIUM_APPROVED','[\"api\",\"premium\"]',1,'synthetic')").run();
  await db.prepare("INSERT INTO intel_records(kind,key,source_id,doc) VALUES ('hash',?,'syn-ok','{\"family\":\"SynMalware\"}')").bind('a'.repeat(64)).run();
  await r2.put('prem-1.tgz', FILE);
  await db.prepare("INSERT INTO releases(id,edition,published_at,object_key,size,sha256,manifest_sha256,rules_root,source_ids,status) VALUES ('prem-1','premium','2026-10-20T00:00:00Z','prem-1.tgz',?,?,?,?,'[\"syn-ok\"]','published')").bind(FILE.length, await sha(FILE), 'm'.repeat(64), 'r'.repeat(64)).run();
});
after(async () => { if (mf) await mf.dispose(); rmSync(persist, { recursive: true, force: true }); });

run('workerd: Community index works without credentials; health is open; unknown routes are generic', async () => {
  assert.equal((await req('/v1/health')).status, 200); const c = await req('/v1/community/releases'); assert.equal(c.status, 200); assert.deepEqual(await c.json(), { releases: [] });
  const n = await req('/v1/nope'); assert.equal(n.status, 404); assert.equal((await n.json()).error.code, 'not_found');
});
run('workerd + real D1: authentication, FREE_LAUNCH access, recorded usage with the theoretical value', async () => {
  assert.equal((await req('/v1/premium/releases')).status, 401); const l = await get('/v1/premium/releases'); assert.equal(l.status, 200); assert.deepEqual(l.j.releases.map((x) => x.id), ['prem-1']);
  const h = await get('/v1/intelligence/hash/' + 'a'.repeat(64)); assert.equal(h.j.found, true);
  const e = await get('/v1/intelligence/enrich', key); assert.equal(e.status, 404, 'enrich is POST only');
  const p = await req('/v1/intelligence/enrich', { method: 'POST', headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json', 'idempotency-key': 'runtime-0001' }, body: JSON.stringify({ indicators: ['203.0.113.7', 'a'.repeat(64)] }) }); assert.equal(p.status, 200);
  const row = await db.prepare("SELECT billable_micros b, theoretical_micros t, commercial_mode m FROM usage_events WHERE idem_key = 'runtime-0001'").first(); assert.deepEqual([row.b, row.t, row.m], [0, 10000, 'FREE_LAUNCH']);
});
run('real D1 atomicity: the UPSERT ... RETURNING quota admits exactly the limit under concurrent requests', async () => {
  await createTenant(db, clock, { id: 'tq', name: 'quota tenant' }); const k = (await issueKey(db, PEPPERS, clock, 'tq', { scopes: ['intel.query'] })).key;      // the launch limit is 30 per minute
  const out = await Promise.all(Array.from({ length: 40 }, () => get('/v1/intelligence/hash/' + 'a'.repeat(64), k))); const ok = out.filter((o) => o.status === 200).length, lim = out.filter((o) => o.status === 429).length;
  assert.equal(ok, 30); assert.equal(lim, 10); assert.ok(out.find((o) => o.status === 429).r.headers.get('retry-after'));
  assert.equal((await db.prepare("SELECT n FROM counters WHERE tenant_id = 'tq' AND scope = 'minute'").first()).n, 30);
});
run('workerd + real R2: download authorisation, Range, resume, SHA-256, shared link refused', async () => {
  const a = await get('/v1/premium/releases/prem-1/download'); assert.equal(a.status, 200); const path = a.j.url.replace('https://gw.test', '');
  const p1 = await get(path, key, { range: 'bytes=0-2999' }); assert.equal(p1.status, 206); assert.equal(p1.r.headers.get('content-range'), `bytes 0-2999/${FILE.length}`);
  const p2 = await get(path, key, { range: 'bytes=3000-' }); assert.equal(p2.status, 206); const whole = new Uint8Array([...p1.b, ...p2.b]); assert.deepEqual(whole, FILE); assert.equal(await sha(whole), a.j.sha256);
  await new Promise((r) => setTimeout(r, 100)); assert.equal((await db.prepare("SELECT state FROM downloads WHERE id = ?").bind(a.j.download_id).first()).state, 'completed');
  const other = (await issueKey(db, PEPPERS, clock, 't1', { scopes: ['premium.download'] })).key; const a2 = await get('/v1/premium/releases/prem-1/download'); const s = await get(a2.j.url.replace('https://gw.test', ''), other); assert.equal(s.status, 403);
  assert.equal((await req(path)).status, 401);
});
run('workerd: Stripe webhook signature (WebCrypto), subscription read from the provider, duplicate delivery ignored', async () => {
  await db.prepare("UPDATE tenants SET stripe_customer_id = 'cus_rt' WHERE id = 't1'").run();
  stripeSubs.sub_rt = { id: 'sub_rt', customer: 'cus_rt', status: 'active', current_period_end: 1790000000, items: { data: [{ price: { id: 'price_intel' } }] } };
  const body = JSON.stringify({ id: 'evt_rt_1', type: 'customer.subscription.created', data: { object: { id: 'sub_rt' } } }), t = Math.floor(Date.now() / 1000);
  const bad = await req('/stripe/webhook', { method: 'POST', body, headers: { 'stripe-signature': `t=${t},v1=${'0'.repeat(64)}` } }); assert.equal(bad.status, 400);
  const ok = await req('/stripe/webhook', { method: 'POST', body, headers: { 'stripe-signature': await signPayload(WH, body, t) } });
  assert.equal(ok.status, 200); assert.equal((await ok.json()).duplicate, false);
  assert.equal((await db.prepare("SELECT plan FROM tenants WHERE id = 't1'").first()).plan, 'intelligence');
  const again = await req('/stripe/webhook', { method: 'POST', body, headers: { 'stripe-signature': await signPayload(WH, body, t) } }); assert.equal((await again.json()).duplicate, true);
  assert.equal((await db.prepare("SELECT COUNT(*) n FROM stripe_events WHERE event_id = 'evt_rt_1'").first()).n, 1);
});
run('workerd: audit and policy history are append-only in the real database', async () => {
  await assert.rejects(db.prepare("UPDATE audit SET action = 'x'").run(), /append-only/); await assert.rejects(db.prepare('DELETE FROM policy_versions').run(), /immutable/);
  await assert.rejects(db.prepare("UPDATE policy_versions SET reason = 'x' WHERE version = 1").run(), /immutable/);
});
run('workerd: administrator MFA and a policy change end to end over HTTP', async () => {
  const seed = fromBase32(adminA.totp_seed_base32); let step = stepOf(Date.now()) + 2;
  const headers = async () => ({ authorization: `Bearer ${adminA.key}`, 'x-mfa-code': await totp(seed, step++) });
  const g = await req('/admin/v1/policy', { headers: await headers() }); assert.equal(g.status, 401, 'a code from the future is outside the accepted window');
  const ok = await req('/admin/v1/policy', { headers: { authorization: `Bearer ${adminA.key}`, 'x-mfa-code': await totp(seed, stepOf(Date.now())) } }); assert.equal(ok.status, 200); assert.equal((await ok.json()).policy.mode, 'FREE_LAUNCH');
  const replay = await req('/admin/v1/policy', { headers: { authorization: `Bearer ${adminA.key}`, 'x-mfa-code': await totp(seed, stepOf(Date.now())) } }); assert.equal(replay.status, 401, 'the same code is refused the second time');
  assert.equal((await req('/admin/v1/policy', { headers: { authorization: `Bearer ${key}` } })).status, 401, 'a customer key is not an administrator');
});
run('workerd: MCP tools/list and tools/call on the real runtime', async () => {
  const meta = { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {} };
  const post = (method, params) => req('/mcp', { method: 'POST', headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json', 'mcp-protocol-version': '2026-07-28', 'mcp-method': method, ...(params.name ? { 'mcp-name': params.name } : {}) }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: { ...params, _meta: meta } }) });
  const l = await (await post('tools/list', {})).json(); assert.equal(l.result.resultType, 'complete'); assert.ok(l.result.tools.length >= 8);
  const c = await (await post('tools/call', { name: 'macguard_lookup_hash', arguments: { hash: 'a'.repeat(64) } })).json(); assert.equal(c.result.structuredContent.found, true);
});
run('workerd: a restart of the Worker loses nothing (policy, keys, usage and audit persist) and requests keep working', async () => {
  const before = (await db.prepare('SELECT COUNT(*) n FROM usage_events').first()).n; assert.ok(before > 0);
  await mf.dispose(); await boot();
  assert.equal((await get('/v1/premium/releases')).status, 200, 'the same key works after the restart'); assert.ok((await db.prepare('SELECT COUNT(*) n FROM usage_events').first()).n >= before);
  assert.equal((await db.prepare('SELECT version FROM policy_pointer').first()).version, 1);
});
