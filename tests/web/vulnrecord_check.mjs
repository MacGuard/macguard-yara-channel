// Renders the synthetic fixture with the REAL web/common.js + web/vulnrecord.js in a minimal DOM stub, and validates it against the R1 contract.
// usage: node tests/web/vulnrecord_check.mjs <contract.json | -> ; prints one JSON line with the checks for tests/test_portal.py
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
const root = new URL('../../', import.meta.url);
const read = (p) => readFileSync(new URL(p, root), 'utf8');
class Node { constructor(tag) { this.tag = tag; this.kids = []; this.attrs = {}; this._t = ''; }
  setAttribute(k, v) { this.attrs[k] = String(v); } appendChild(c) { this.kids.push(c); return c; }
  set textContent(v) { this._t = String(v); this.kids = []; } get textContent() { return this._t + this.kids.map((k) => k.textContent).join(''); }
  find(tag) { return [this.tag === tag ? [this] : [], ...this.kids.map((k) => (k.find ? k.find(tag) : []))].flat(); } }
const text = (s) => ({ tag: '#text', textContent: String(s), find: () => [] });
const document = { createElement: (t) => new Node(t), createTextNode: text, querySelectorAll: () => [], querySelector: () => null, getElementById: () => null, documentElement: {} };
const ctx = { document, TextEncoder, navigator: { language: 'es' }, localStorage: { getItem: () => null, setItem() {} }, console };
vm.createContext(ctx); ctx.window = ctx;
vm.runInContext(read('web/common.js'), ctx); vm.runInContext(read('web/vulnrecord.js'), ctx);
const fx = JSON.parse(read('tests/web/fixtures/vuln-record.json'));
const render = (rec, lang = 'es', held = []) => { const box = new Node('div'); const ok = ctx.MG.renderVuln(box, rec, lang, held); return { ok, text: box.textContent, links: box.find('a').length, scripts: box.find('script').length }; };
const out = { es: render(fx), en: render(fx, 'en'), held: render(fx, 'es', ['detections', 'indicators']),
  badSchema: render({ ...fx, schema: 'x' }), badId: render({ ...fx, id: 'CVE-99-1' }), exec: render({ ...fx, poc_references: [{ ...fx.poc_references[0], executable_content: true }] }),
  badEpss: render({ ...fx, epss: { ...fx.epss, probability: 7 } }), missingList: render({ ...fx, detections: undefined }) };
let contract = null;
if (process.argv[2] && process.argv[2] !== '-') { const { validate } = await import(new URL('gateway/src/schema.js', root)); contract = validate(JSON.parse(readFileSync(process.argv[2], 'utf8')), fx, 'fixture'); }
console.log(JSON.stringify({ ...out, contract }));
