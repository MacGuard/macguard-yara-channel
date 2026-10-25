import http from 'node:http';
import { createHash } from 'node:crypto';
import { world, SEED, clone, paid } from './helpers.js';
import { createHandler } from '../src/index.js';
import { signPayload, StripeApi } from '../src/stripe.js';

export const FILE = new Uint8Array(Array.from({ length: 5000 }, (_, i) => (i * 7 + 3) % 251));
export const FILE_SHA = createHash('sha256').update(FILE).digest('hex');
export const WH = 'whsec_test_secret_for_unit_tests_only';

export function fakeR2() {
  const objs = new Map(), r2 = { fail: false, missing: false, objs, gets: 0 };
  r2.get = async (key, opts) => {
    r2.gets++; if (r2.fail) throw new Error('r2 internal: bucket=private-bucket account=123 secret=hunter2'); if (r2.missing || !objs.has(key)) return null;
    const all = objs.get(key), part = opts?.range ? all.slice(opts.range.offset, opts.range.offset + opts.range.length) : all;
    return { size: all.length, body: new ReadableStream({ start(c) { c.enqueue(part); c.close(); } }), arrayBuffer: async () => new Uint8Array(part).buffer };
  };
  r2.putFail = false; r2.corrupt = false;
  r2.put = async (key, data) => { if (r2.putFail) throw new Error('r2 put refused'); objs.set(key, r2.corrupt ? new Uint8Array([1, 2, 3]) : new Uint8Array(data)); };
  return r2;
}
export async function fakeStripe() {
  const st = { subs: new Map(), reqs: [], meter: new Map(), checkouts: 0 };
  const server = http.createServer((req, res) => {
    let body = ''; req.on('data', (c) => (body += c)); req.on('end', () => {
      st.reqs.push({ method: req.method, url: req.url, auth: req.headers.authorization, idem: req.headers['idempotency-key'], body });
      const json = (code, o) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
      let m;
      if (req.method === 'GET' && (m = /^\/v1\/subscriptions\/(.+)$/.exec(req.url))) return st.subs.has(m[1]) ? json(200, st.subs.get(m[1])) : json(404, { error: { message: 'no such subscription: secret detail' } });
      if (req.method === 'POST' && req.url === '/v1/checkout/sessions') { st.checkouts++; return json(200, { id: 'cs_test_1', url: 'https://checkout.stripe.test/c/cs_test_1' }); }
      if (req.method === 'POST' && req.url === '/v1/billing/meter_events') { const p = new URLSearchParams(body); const id = p.get('identifier'); if (st.meterFail) return json(500, {}); st.meter.set(id, Object.fromEntries(p)); return json(200, { object: 'billing.meter_event', identifier: id }); }
      json(404, {});
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  st.url = `http://127.0.0.1:${server.address().port}`; server.unref(); st.close = () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); });
  st.sub = (id, customer, status, price = 'price_intel', extra = {}) => st.subs.set(id, { id, object: 'subscription', customer, status, current_period_end: 1790000000, items: { data: [{ price: { id: price } }] }, ...extra });
  return st;
}

export async function apiWorld({ policy = SEED, stripe = null, facilitator = null, envExtra = {} } = {}) {
  const w = await world({ policy }), r2 = fakeR2();
  const origin = { releases: JSON.stringify({ releases: [{ tag: 'rules-20261021-1' }] }), latest: JSON.stringify({ tag: 'rules-20261021-1' }), calls: [], fail: false };
  const env = { ...w.env, DB: w.db, PREMIUM: r2, PUBLIC_BASE: 'https://gw.test', COMMUNITY_ORIGIN: 'https://site.test', MCP_ALLOWED_ORIGINS: 'https://agent.example', STRIPE_WEBHOOK_SECRETS: WH, STRIPE_API_KEY: 'sk_test_fake_for_local_server_only', GRACE_DAYS: '3',
    PRICE_MAP: JSON.stringify({ price_intel: 'intelligence', price_biz: 'business' }), PRICE_IDS: JSON.stringify({ intelligence: 'price_intel' }), CHECKOUT_SUCCESS_URL: 'https://gw.test/ok', CHECKOUT_CANCEL_URL: 'https://gw.test/no', ...envExtra,
    fetchImpl: async (u) => { origin.calls.push(u); if (origin.fail) throw new Error('down'); return new Response(u.endsWith('latest.json') ? origin.latest : origin.releases, { status: 200 }); } };
  const handle = createHandler({ clock: w.clock, stripe: (e) => new StripeApi({ baseUrl: stripe?.url, apiKey: e.STRIPE_API_KEY }), facilitator });
  const waits = []; const ectx = { waitUntil: (p) => waits.push(p) };
  const call = async (path, { method = 'GET', key = null, headers = {}, json = undefined, body = undefined } = {}) => {
    const h = { ...(key ? { authorization: `Bearer ${key}` } : {}), ...headers }; let b = body;
    if (json !== undefined) { b = JSON.stringify(json); h['content-type'] = 'application/json'; }
    const res = await handle(new Request('https://gw.test' + path, { method, headers: h, body: b }), env, ectx); await Promise.all(waits.splice(0));
    const text = await res.clone().text(); let js = null; try { js = JSON.parse(text); } catch { /* binary or empty */ }
    return { res, status: res.status, json: js, text, bytes: new Uint8Array(await res.arrayBuffer()) };
  };
  // sources, records and releases (synthetic)
  const src = (id, status, products, owner) => w.db.prepare('INSERT INTO intel_sources(source_id,status,approved_products,owner_confirmed,attribution) VALUES (?,?,?,?,?)').bind(id, status, JSON.stringify(products), owner ? 1 : 0, `${id} (synthetic)`).run();
  await src('syn-ok', 'PREMIUM_APPROVED', ['api', 'premium'], true); await src('syn-review', 'LICENSE_REVIEW', [], false); await src('syn-noowner', 'PREMIUM_APPROVED', ['api', 'premium'], false);
  const rec = (kind, key, source, doc, exp = null) => w.db.prepare('INSERT INTO intel_records(kind,key,source_id,doc,expires_at) VALUES (?,?,?,?,?)').bind(kind, key, source, JSON.stringify(doc), exp).run();
  const H = 'a'.repeat(64);
  await rec('hash', H, 'syn-ok', { family: 'SynMalware', first_seen: '2026-10-01', malware: ['SynMalware'], attack: ['T1059'] }); await rec('hash', H, 'syn-review', { family: 'MUST-NOT-APPEAR' }); await rec('hash', 'b'.repeat(64), 'syn-noowner', { family: 'MUST-NOT-APPEAR' });
  await rec('cve', 'CVE-2026-0001', 'syn-ok', { kev_listed: true, epss: '0.620', cvss: '9.8', malware: ['SynMalware'] }); await rec('cve', 'CVE-2026-0001', 'syn-review', { epss: '0.99' });
  await rec('ioc', '203.0.113.7', 'syn-ok', { type: 'ipv4', malware: ['SynMalware'], cve: ['CVE-2026-0001'], attack: ['T1071'] }, '2027-01-01T00:00:00Z'); await rec('ioc', '203.0.113.8', 'syn-ok', { type: 'ipv4' }, '2026-10-01T00:00:00Z');
  const rel = (id, sources, key = id + '.tgz') => { r2.objs.set(key, FILE); return w.db.prepare("INSERT INTO releases(id,edition,published_at,object_key,size,sha256,manifest_sha256,rules_root,source_ids,status) VALUES (?,?,?,?,?,?,?,?,?,'published')").bind(id, 'premium', '2026-10-20T00:00:00Z', key, FILE.length, FILE_SHA, 'm'.repeat(64), 'r'.repeat(64), JSON.stringify(sources)).run(); };
  await rel('prem-1', ['syn-ok']); await rel('prem-bad', ['syn-ok', 'syn-review']);
  return { ...w, env, r2, origin, call, handle, H, rel, rec, src, stripe, waits };
}
export { SEED, clone, paid, signPayload };
