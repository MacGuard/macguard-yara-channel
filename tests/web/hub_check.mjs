// Runs the REAL hub scripts (web/common.js, kevstatic.js, vulns.js, vuln.js, vulnrecord.js, hub.js) in a minimal DOM stub against a fixture "server":
//   static mode: kev/index.json + year shards (hashed like the build does); API mode: macguard.intel-search/1 and macguard.intel-vulnerability/1 answers.
// It records every URL requested. usage: node tests/web/hub_check.mjs <fixture-dir>   (prints one JSON line for tests/test_portal_hub.py)
import vm from 'node:vm';
import { readFileSync, existsSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
const root = new URL('../../', import.meta.url), fxDir = process.argv[2];
const read = (p) => readFileSync(new URL(p, root), 'utf8');
class Node {
  constructor(tag, id) { this.tag = tag; this.id = id; this.kids = []; this.attrs = {}; this._t = ''; this.value = ''; this.disabled = false; this.hidden = false; this.className = ''; this.h = {}; }
  setAttribute(k, v) { this.attrs[k] = String(v); } getAttribute(k) { return this.attrs[k] ?? null; } removeAttribute(k) { delete this.attrs[k]; }
  appendChild(c) { this.kids.push(c); return c; } get childNodes() { return this.kids; } cloneNode() { return this; }
  set textContent(v) { this._t = String(v); this.kids = []; } get textContent() { return this._t + this.kids.map((k) => k.textContent).join(''); }
  addEventListener(t, f) { (this.h[t] ||= []).push(f); } fire(t, ev = {}) { for (const f of this.h[t] || []) f({ preventDefault() {}, ...ev }); }
  find(tag) { return [this.tag === tag ? [this] : [], ...this.kids.map((k) => (k.find ? k.find(tag) : []))].flat(); }
}
const tick = () => new Promise((r) => setTimeout(r, 0)), settle = async () => { for (let i = 0; i < 40; i++) await tick(); };
function page({ api = '', search = '', files = {}, apiAnswers = {}, hold = null }) {
  const byId = {}, requested = [];
  const node = (id) => (byId[id] ||= new Node('div', id));
  const meta = api ? { getAttribute: () => api } : null;
  const document = { createElement: (t) => new Node(t), createTextNode: (s) => ({ tag: '#text', textContent: String(s), find: () => [] }), getElementById: node,
    querySelector: (q) => (q.startsWith('meta[name="mg-vuln-api"]') ? meta : q === '#vtable tbody' ? node('vtable-tbody') : q === '#intel-table tbody' ? node('intel-tbody') : null),
    querySelectorAll: () => [], readyState: 'complete', documentElement: {}, body: { classList: { add() {}, toggle() {}, contains: () => false } }, title: '' };
  const location = { search, href: '' };
  const respond = (body, type = 'application/json') => { const bytes = typeof body === 'string' ? Buffer.from(body) : Buffer.from(JSON.stringify(body));
    return { ok: true, status: 200, headers: { get: () => type }, json: async () => JSON.parse(bytes.toString()), arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.length), text: async () => bytes.toString() }; };
  const fetch = async (u) => { requested.push(String(u));
    if (api && String(u).startsWith(api)) { const path = String(u).slice(api.length); if (hold && path.startsWith(hold.prefix)) await hold.promise; const k = Object.keys(apiAnswers).find((p) => path.startsWith(p)); if (!k) return { ok: false, status: 404, headers: { get: () => 'application/json' } }; return respond(apiAnswers[k]); }
    if (files[u] !== undefined) return respond(files[u]); return { ok: false, status: 404, headers: { get: () => 'text/html' } }; };
  const ctx = { document, location, fetch, URLSearchParams, TextEncoder, TextDecoder, AbortController, setTimeout, clearTimeout, console, navigator: { language: 'es' },
    localStorage: { getItem: () => null, setItem() {} }, crypto: webcrypto };
  vm.createContext(ctx); ctx.window = ctx;
  const run = (f) => vm.runInContext(read('web/' + f), ctx);
  return { ctx, node, requested, run };
}
const fx = (n) => JSON.parse(readFileSync(`${fxDir}/${n}`, 'utf8'));
const files = {}; for (const n of ['kev/index.json', 'kev/2021.json', 'kev/2024.json', 'hub.json', 'sources.json']) if (existsSync(`${fxDir}/${n}`)) files[n] = readFileSync(`${fxDir}/${n}`, 'utf8');
const out = {};
const rows = (p) => p.node('vtable-tbody').kids.map((tr) => tr.kids.map((td) => td.textContent));
// 1. identifier detection (common.js)
{ const p = page({}); p.run('common.js'); const k = (v) => { const r = p.ctx.MG.idKind(v); return r ? r.kind + ' ' + r.id : null; };
  out.kinds = ['cve-2024-3094', 'EUVD-2025-12345', 'GCVE-1-2025-0001', 'ghsa-2345-6789-cfgh', 'CWE-079', 'A'.repeat(64), 'sid:2000105', '1:2000105', 'openssl 3.0', 'CVE-24-1', '<b>', 'x'.repeat(200)].map(k); }
// 2. explorer, static mode, no API configured: lists KEV newest first, searches a CVE and text, never calls a non-site URL
{ const p = page({ files }); for (const f of ['common.js', 'kevstatic.js', 'vulns.js']) p.run(f); await settle();
  out.static_first = { rows: rows(p), mode: p.node('vmode').textContent, disabled: p.node('f-cvss-min').disabled };
  p.node('vq').value = 'CVE-2021-44228'; p.node('vform').fire('submit'); await settle(); out.static_cve = rows(p);
  p.node('vq').value = 'apache'; p.node('vform').fire('submit'); await settle(); out.static_text = rows(p);
  p.node('vq').value = 'EUVD-2025-1'; p.node('vform').fire('submit'); await settle(); out.static_euvd = { rows: rows(p), mode: p.node('vmode').textContent };
  p.node('vq').value = 'CWE-502'; p.node('vform').fire('submit'); await settle(); out.static_cwe = { rows: rows(p), mode: p.node('vmode').textContent };   // hub-qa r2 F3
  out.static_requests = p.requested; }
// 3. explorer with a tampered shard: refused, nothing shown
{ const bad = { ...files, 'kev/2024.json': files['kev/2024.json'].replace('Example', 'Tampered') };
  const p = page({ files: bad }); for (const f of ['common.js', 'kevstatic.js', 'vulns.js']) p.run(f); await settle(); out.tampered = { rows: rows(p), count: p.node('vcount').textContent, mode: p.node('vmode').textContent }; }
// 4. no verified KEV package at all: explicit unavailable state
{ const p = page({ files: { 'sources.json': files['sources.json'] } }); for (const f of ['common.js', 'kevstatic.js', 'vulns.js']) p.run(f); await settle(); out.nokev = { rows: rows(p), mode: p.node('vmode').textContent }; }
// 4b. the build's explicit "unavailable" KEV index (no package): unavailable state, no shard requested, nothing shown (QA: no 404 in the console)
{ const p = page({ files: { 'sources.json': files['sources.json'], 'kev/index.json': JSON.stringify({ schema: 'macguard.portal-kev-index/1', available: false, shards: [], reason: 'no verified CISA KEV package in this build' }) } });
  for (const f of ['common.js', 'kevstatic.js', 'vulns.js']) p.run(f); await settle(); out.kev_unavailable = { rows: rows(p), mode: p.node('vmode').textContent, requests: p.requested }; }
// 5. explorer, API mode: bounded query string, rows, keyset paging, restricted marker
{ const api = 'https://api.example.test'; const p = page({ api, files, apiAnswers: { '/v1/vulns/sources': fx('api-sources.json'), '/v1/vulns/search': fx('api-search.json') } });
  for (const f of ['common.js', 'kevstatic.js', 'vulns.js']) p.run(f); await settle();
  p.node('vq').value = 'CVE-2024-3094'; p.node('f-kev').value = '1'; p.node('f-cvss-min').value = '7'; p.node('f-epss').value = '5'; p.node('vform').fire('submit'); await settle();
  out.api = { rows: rows(p), next: !p.node('vnext').disabled, requests: p.requested.filter((u) => u.startsWith(api)) };
  p.node('vnext').fire('click'); await settle(); out.api_next = p.requested.filter((u) => u.includes('cursor=')); }
// 5b. hub-qa r2 F2: the access selector is a view filter, never sent to the gateway (which rejects unknown parameters)
{ const api = 'https://api.example.test'; const p = page({ api, files, apiAnswers: { '/v1/vulns/sources': fx('api-sources.json'), '/v1/vulns/search': fx('api-search.json') } });
  for (const f of ['common.js', 'kevstatic.js', 'vulns.js']) p.run(f); await settle();
  p.node('vq').value = 'xz'; p.node('f-access').value = 'premium'; p.node('vform').fire('submit'); await settle();
  out.api_access = { requests: p.requested.filter((u) => u.startsWith(api + '/v1/vulns/search')), rows: rows(p) }; }
// 5c. Codex pr81 F2: a new search (or a reset) while a request is pending supersedes it; the stale answer is never rendered
for (const action of ['resubmit', 'reset']) { const api = 'https://api.example.test'; let release; const promise = new Promise((r) => { release = r; });
  const p = page({ api, files, hold: { prefix: '/v1/vulns/search?q=oldq', promise },
    apiAnswers: { '/v1/vulns/sources': fx('api-sources.json'), '/v1/vulns/search?q=oldq': fx('api-search.json'), '/v1/vulns/search?q=newq': { schema: 'macguard.intel-search/1', items: [], next_cursor: null } } });
  for (const f of ['common.js', 'kevstatic.js', 'vulns.js']) p.run(f); await settle();
  p.node('vq').value = 'oldq'; p.node('vform').fire('submit'); await settle();
  if (action === 'resubmit') { p.node('vq').value = 'newq'; p.node('vform').fire('submit'); } else { p.node('vq').value = ''; p.node('vform').fire('reset'); }
  await settle(); release(); await settle(); await new Promise((r) => setTimeout(r, 5)); await settle();
  out['api_race_' + action] = { requests: p.requested.filter((u) => u.startsWith(api + '/v1/vulns/search')), rows: rows(p), count: p.node('vcount').textContent }; }
// 6. vulnerability page, static KEV: a listed CVE, a CVE not in KEV, a non-CVE id
for (const [name, id] of [['vuln_kev', 'CVE-2021-44228'], ['vuln_notkev', 'CVE-2020-0001'], ['vuln_euvd', 'EUVD-2025-1'], ['vuln_bad', 'CVE-1']]) {
  const p = page({ files, search: '?id=' + encodeURIComponent(id) }); for (const f of ['common.js', 'vulnrecord.js', 'kevstatic.js', 'vuln.js']) p.run(f); await settle();
  out[name] = { body: p.node('vbody').textContent, state: p.node('vstate').textContent, links: p.node('vbody').find('a').map((a) => a.attrs.href) }; }
// 7. vulnerability page, API: a record with a withheld (Premium) section
{ const api = 'https://api.example.test', rec = JSON.parse(read('tests/web/fixtures/vuln-record.json')); rec.detections = { restricted: true, capability: 'intel.correlation.read' };
  const p = page({ api, files, search: '?id=' + rec.id, apiAnswers: { '/v1/vulns/': rec } }); for (const f of ['common.js', 'vulnrecord.js', 'kevstatic.js', 'vuln.js']) p.run(f); await settle();
  out.vuln_api = { body: p.node('vbody').textContent, requests: p.requested }; }
// 7b. the gateway's REAL shape (gateway/src/vulns.js): {record, restricted:[{section, capability}]} with the section REMOVED from the record (Codex hub-qa F5)
{ const api = 'https://api.example.test', rec = JSON.parse(read('tests/web/fixtures/vuln-record.json')); rec.detections = [];
  const p = page({ api, files, search: '?id=' + rec.id, apiAnswers: { '/v1/vulns/': { record: rec, restricted: [{ section: 'detections', capability: 'rules.premium.read' }], access_mode: 'ENFORCED' } } });
  for (const f of ['common.js', 'vulnrecord.js', 'kevstatic.js', 'vuln.js']) p.run(f); await settle();
  out.vuln_api_real = { body: p.node('vbody').textContent }; }
// 8. hub: stats only from hub.json, search routes by kind
{ const p = page({ files }); p.run('common.js'); p.run('hub.js'); await settle();
  out.hub = { stats: p.node('hub-stats').textContent, integrity: p.node('hub-int').textContent, recent: p.node('hub-rec').textContent };
  p.node('hub-q').value = 'cve-2021-44228'; p.node('hub-form').fire('submit'); out.hub_go_cve = p.ctx.location.href;
  p.node('hub-q').value = 'openssl'; p.node('hub-form').fire('submit'); out.hub_go_text = p.ctx.location.href; }
console.log(JSON.stringify(out));
