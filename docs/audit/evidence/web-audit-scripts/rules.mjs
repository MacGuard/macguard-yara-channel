// Functional test of rules.html + index + releases on one host. usage: node rules.mjs gh|cf
import { chromium } from 'playwright'; import fs from 'fs';
const D = '/private/tmp/claude-501/-Users-dmuino-Downloads-macguard-yara-channel/82cd2f90-db22-4237-8d88-d9b30daab0c1/scratchpad/web-audit';
const hk = process.argv[2] || 'gh'; const B = { gh: 'https://macguard.github.io/macguard-yara-channel/', cf: 'https://macguard-rules.pages.dev/' }[hk];
const out = {}; const log = (k, v) => { out[k] = v; console.log(k, JSON.stringify(v).slice(0, 400)); };
const br = await chromium.launch({ headless: true });
const ONLYSTATES = process.env.ONLYSTATES === '1';
const ctx = await br.newContext({ viewport: { width: 1280, height: 900 }, serviceWorkers: 'block' }); const page = await ctx.newPage(); page.setDefaultTimeout(30000);
const errs = []; page.on('console', m => m.type() === 'error' && errs.push(m.text())); page.on('pageerror', e => errs.push(String(e)));
const T = s => page.locator(s);
await page.goto(B + 'rules.html', { waitUntil: 'networkidle' }); await page.waitForFunction(() => /\d/.test(document.getElementById('count').textContent) && document.querySelectorAll('#rules-table tbody tr').length > 0);
log('count', await T('#count').textContent()); log('pageinfo', await T('#pageinfo').textContent()); log('rows', await T('#rules-table tbody tr').count());
log('pkgHref', await T('#dl-pkg').getAttribute('href')); log('pkgNote', await T('#dl-pkg-note').textContent()); log('verbox', (await T('#ver').innerText()).slice(0, 600));
log('options', await page.evaluate(() => Object.fromEntries(['f-src', 'f-cat', 'f-plat', 'f-val'].map(i => [i, [...document.getElementById(i).options].map(o => o.value)]))));
// header-only / cell sample
log('row0', await page.evaluate(() => [...document.querySelector('#rules-table tbody tr').children].map(c => c.innerText.slice(0, 60))));
log('colWidths', await page.evaluate(() => { const t = document.getElementById('rules-table'); return { tableW: t.scrollWidth, wrapW: t.parentElement.clientWidth }; }));
await page.screenshot({ path: `${D}/shots/${hk}_rules_loaded.png`, fullPage: false });
// search
const total = await page.evaluate(() => parseInt(document.getElementById('count').textContent));
const timeFilter = async (fn) => page.evaluate(async (f) => { const t0 = performance.now(); await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r))); return 0; }, 0);
async function timed(action) { const t0 = Date.now(); await action(); await page.evaluate(() => new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))); return Date.now() - t0; }
const q = T('#q');
for (const term of ['apt', 'APT', 'zzzzqq', 'f3ee4198', '  mimikatz ', 'rules/community', '%', '<img src=x>', '.*']) {
  const ms = await timed(() => q.fill(term)); log('search:' + term, { ms, count: await T('#count').textContent(), rows: await T('#rules-table tbody tr').count() });
}
log('emptyStateText', await T('#rules-table tbody').innerText());
await q.fill('');
// filters
for (const [id, vals] of [['f-src', ['nextron', 'community']], ['f-cat', ['apt', 'malware', 'webshell', 'webshells', 'mal', 'configured']], ['f-plat', ['macOS', 'unspecified', 'Windows']], ['f-val', ['compiled']]]) for (const v of vals) {
  const ms = await timed(() => T('#' + id).selectOption(v)); log(`filter:${id}=${v}`, { ms, count: await T('#count').textContent() }); await T('#' + id).selectOption('');
}
await T('#f-plat').selectOption('macOS'); log('macOS rows', await page.evaluate(() => [...document.querySelectorAll('#rules-table tbody tr')].map(r => r.children[0].innerText + '|' + r.children[2].innerText))); await T('#f-plat').selectOption('');
// sort
for (const s of ['name', 'category', 'source', 'bytes', 'changed']) { await T('#sort').selectOption(s); log('sort:' + s, await page.evaluate(() => [...document.querySelectorAll('#rules-table tbody tr')].slice(0, 3).map(r => r.children[0].innerText + '|' + r.children[1].innerText + '|' + r.children[7].innerText + '|' + r.children[9].innerText))); }
await T('#sort').selectOption('name');
// sorted by bytes desc correctness over whole catalog
const cat = await (await fetch(B + 'catalog.json')).json();
const exp = [...cat.files].sort((a, b) => a.name.localeCompare(b.name) || a.path.localeCompare(b.path)).slice(0, 3).map(f => f.name);
log('sortNameFirst3', { expected: exp, got: await page.evaluate(() => [...document.querySelectorAll('#rules-table tbody tr')].slice(0, 3).map(r => r.children[0].innerText)) });
// pagination
for (const sz of ['25', '50', '100']) { await T('#size').selectOption(sz); log('size' + sz, { rows: await T('#rules-table tbody tr').count(), info: await T('#pageinfo').textContent() }); }
await T('#size').selectOption('50');
const pagesN = parseInt((await T('#pageinfo').textContent()).split(' ').pop());
await T('#next').click(); log('next', await T('#pageinfo').textContent()); log('prev disabled after next', await T('#prev').isDisabled());
for (let i = 0; i < pagesN; i++) { if (await T('#next').isDisabled()) break; await T('#next').click(); }
log('lastPage', { info: await T('#pageinfo').textContent(), rows: await T('#rules-table tbody tr').count(), nextDisabled: await T('#next').isDisabled() });
await T('#q').fill('apt'); log('pageResetOnSearch', await T('#pageinfo').textContent()); await T('#q').fill('');
// scrollIntoView behaviour: after Next, is focus lost?
await T('#next').focus(); log('focusAfterNextDisabled', await page.evaluate(() => document.activeElement.id));
// per-file verify (first 3 rows + one more)
await T('#size').selectOption('25');
for (let i = 0; i < 3; i++) { const row = T('#rules-table tbody tr').nth(i); await row.locator('button').click(); await page.waitForFunction((i) => /[✔✘]|No se/.test(document.querySelectorAll('#rules-table tbody tr')[i].children[10].innerText), i, { timeout: 30000 }); log('verify' + i, await row.locator('td').nth(10).innerText()); }
// download link of a file: GET and compare hash
const href = await T('#rules-table tbody tr').first().locator('a').first().getAttribute('href'); log('firstHref', href);
const dl = await page.evaluate(async (h) => { const r = await fetch(h); const b = await r.arrayBuffer(); const d = await crypto.subtle.digest('SHA-256', b); return { st: r.status, ct: r.headers.get('content-type'), cd: r.headers.get('content-disposition'), sha: [...new Uint8Array(d)].map(x => x.toString(16).padStart(2, '0')).join(''), n: b.byteLength }; }, href); log('firstDownload', dl);
// package check
await T('#pkg-check').click(); await page.waitForFunction(() => /[✔✘]|No se/.test(document.getElementById('pkg-out').textContent), null, { timeout: 60000 }); log('pkgcheck', await T('#pkg-out').textContent());
// language switch
await T('#lang').selectOption('en'); log('en', { h1: await T('h1').textContent(), count: await T('#count').textContent(), th: await T('#rules-table thead th').allInnerTexts(), placeholder: await T('#q').getAttribute('placeholder'), sortopts: await T('#sort option').allInnerTexts(), pkgnote: await T('#dl-pkg-note').textContent(), ver: (await T('#ver').innerText()).slice(0, 300), lang: await page.evaluate(() => document.documentElement.lang) });
await page.screenshot({ path: `${D}/shots/${hk}_rules_en.png` });
await T('#lang').selectOption('es');
log('consoleErrors', errs);
// ---- mutation / states via request interception (local fulfilment, no extra load)
for (const [name, fn] of Object.entries({
  catalog500: r => r.url().endsWith('catalog.json') ? r.fulfill({ status: 500, body: 'x' }) : r.continue(),
  catalogEmpty: r => r.url().endsWith('catalog.json') ? r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ count: 0, files: [] }) }) : r.continue(),
  catalogSlow: async r => { if (r.url().endsWith('catalog.json')) await new Promise(x => setTimeout(x, 4000)); return r.continue(); },
  releasesMissing: r => r.url().endsWith('releases.json') ? r.fulfill({ status: 404, body: 'no' }) : r.continue(),
  verMissing: r => r.url().endsWith('verification.json') ? r.fulfill({ status: 404, body: 'no' }) : r.continue(),
  tarTampered: r => r.url().endsWith('rules-release.tar.gz') ? r.fulfill({ status: 200, contentType: 'application/gzip', body: Buffer.from('tampered') }) : r.continue(),
})) {
  const p2 = await ctx.newPage(); await p2.route('**/*', rt => { rt.url = () => rt.request().url(); return fn(rt); }); const e2 = []; p2.on('pageerror', e => e2.push(String(e)));
  await p2.goto(B + 'rules.html', { waitUntil: 'domcontentloaded' }); await p2.waitForTimeout(name === 'catalogSlow' ? 1500 : 3500);
  const mid = await p2.locator('#count').textContent();
  if (name === 'tarTampered') { await p2.waitForTimeout(3000); await p2.locator('#pkg-check').click(); await p2.waitForTimeout(2500); }
  if (name === 'catalogSlow') await p2.waitForTimeout(5000);
  log('state:' + name, { count: mid, countAfter: await p2.locator('#count').textContent(), rows: await p2.locator('#rules-table tbody tr').count(), tbody: (await p2.locator('#rules-table tbody').innerText()).slice(0, 100), ver: (await p2.locator('#ver').innerText()).slice(0, 150), pkgout: await p2.locator('#pkg-out').textContent(), dlnote: await p2.locator('#dl-pkg-note').textContent(), pageerrors: e2 });
  await p2.screenshot({ path: `${D}/shots/${hk}_rules_state_${name}.png` }); await p2.close();
}
// ---- JS disabled
const nj = await br.newContext({ javaScriptEnabled: false, viewport: { width: 1280, height: 800 } }); const pj = await nj.newPage(); await pj.goto(B + 'rules.html'); log('noJS', { count: await pj.locator('#count').textContent(), noscript: (await pj.locator('noscript').first().innerText().catch(() => '')).slice(0, 100) }); await pj.screenshot({ path: `${D}/shots/${hk}_rules_nojs.png` });
await pj.goto(B + 'index.html'); log('noJS index', { latest: await pj.locator('#latest-state').textContent(), pending: await pj.locator('.status').first().textContent(), chart: await pj.locator('#act-chart').innerHTML() }); await pj.screenshot({ path: `${D}/shots/${hk}_index_nojs.png`, fullPage: true });
await br.close(); fs.writeFileSync(`${D}/out/rules_${hk}.json`, JSON.stringify(out, null, 1));
