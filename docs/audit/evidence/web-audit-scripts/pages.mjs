// index / releases / transparency functional tests incl. tampered Merkle inputs (local interception). usage: node pages.mjs gh|cf
import { chromium } from 'playwright'; import fs from 'fs';
const D = '/private/tmp/claude-501/-Users-dmuino-Downloads-macguard-yara-channel/82cd2f90-db22-4237-8d88-d9b30daab0c1/scratchpad/web-audit';
const hk = process.argv[2] || 'gh'; const B = { gh: 'https://macguard.github.io/macguard-yara-channel/', cf: 'https://macguard-rules.pages.dev/' }[hk];
const out = {}; const log = (k, v) => { out[k] = v; console.log(k, JSON.stringify(v).slice(0, 500)); };
const br = await chromium.launch({ headless: true });
const ctx = await br.newContext({ viewport: { width: 1280, height: 900 }, serviceWorkers: 'block' }); const page = await ctx.newPage(); page.setDefaultTimeout(30000);
const errs = []; page.on('console', m => m.type() === 'error' && errs.push(m.text())); page.on('pageerror', e => errs.push(String(e)));
const latest = await (await fetch(B + 'latest.json')).json();
// ---------- index
await page.goto(B, { waitUntil: 'networkidle' }); await page.waitForTimeout(1500);
const txt = async s => (await page.locator(s).first().innerText().catch(() => '')).replace(/\s+/g, ' ');
log('idx.latest', { state: await txt('#latest-state'), facts: await txt('#latest-facts'), dl: await txt('#latest-dl'), note: await txt('#latest-note') });
log('idx.stats', await txt('.stats'));
log('idx.status', await page.locator('.status').allInnerTexts());
log('idx.tiles', { run: await txt('#tiles-run'), runsum: await txt('#run-sum'), rel: await txt('#tiles-rel'), relsub: await txt('#rel-sub'), dist: await txt('#tiles-dist'), gap: await txt('#dist-gap'), dl: await txt('#dl-real'), note: await txt('#act-note'), legend: await txt('#act-legend') });
log('idx.chartSvg', await page.evaluate(() => { const s = document.querySelector('#act-chart svg'); return s ? { w: s.getAttribute('viewBox'), role: s.getAttribute('role'), aria: s.getAttribute('aria-label'), title: !!s.querySelector('title'), texts: [...s.querySelectorAll('text')].map(t => t.textContent).slice(0, 40), rects: s.querySelectorAll('rect').length } : (document.getElementById('act-chart').getAttribute('role') + '|' + document.getElementById('act-chart').innerHTML.slice(0, 200)); }));
log('idx.links', await page.evaluate(() => [...document.querySelectorAll('#latest-dl a,#latest-facts a')].map(a => a.textContent + ' -> ' + a.href)));
await page.screenshot({ path: `${D}/shots/${hk}_index_full.png`, fullPage: true });
// numbers vs latest.json
const body = await page.locator('main').innerText();
const num = n => [n.toLocaleString('es-ES'), n.toLocaleString('en-US'), String(n)];
log('idx.numbersPresent', { files: num(latest.stats.files).some(x => body.includes(x)), yara: num(latest.stats.yara_rules).some(x => body.includes(x)), sha: body.includes(latest.package_sha256.slice(0, 12)), msha: body.includes(latest.manifest_sha256.slice(0, 12)) });
// view / range switches
for (const [v, r] of [['changes', '30'], ['rules', '14'], ['rules', '7']]) { await page.locator('#act-view').selectOption(v); await page.locator('#act-range').selectOption(r); await page.waitForTimeout(300); log(`idx.chart ${v}/${r}`, { bars: await page.locator('#act-chart rect').count(), tableRows: await page.locator('#act-table tbody tr').count(), texts: await page.evaluate(() => [...document.querySelectorAll('#act-chart text')].map(t => t.textContent).join(',').slice(0, 200)) }); }
await page.locator('#act-view').selectOption('rules'); await page.locator('#act-range').selectOption('30');
await page.screenshot({ path: `${D}/shots/${hk}_index_chart.png` });
log('idx.table', await page.evaluate(() => { document.querySelector('details').open = true; return [...document.querySelectorAll('#act-table tbody tr')].slice(-3).map(r => r.innerText.replace(/\s+/g, ' ')); }));
// language: fr/de
for (const l of ['en', 'fr', 'de', 'es']) { await page.locator('#lang').selectOption(l); await page.waitForTimeout(300); log('idx.lang.' + l, { html: await page.evaluate(() => document.documentElement.lang), h1: await txt('h1'), nav: await txt('nav'), act: await txt('#act-h'), latestH: await txt('#latest-h'), run: await txt('#h-run'), flow: await txt('#overview h2'), status: await page.locator('.status').allInnerTexts() }); if (l === 'fr') await page.screenshot({ path: `${D}/shots/${hk}_index_fr.png`, fullPage: true }); }
// lang persistence across pages
await page.locator('#lang').selectOption('en'); await page.goto(B + 'rules.html'); await page.waitForTimeout(800); log('lang.persist rules', await page.locator('h1').textContent()); await page.locator('#lang').selectOption('es');
await page.goto(B + 'docs/index.html'); await page.waitForTimeout(500); log('docs.index', { url: page.url(), h1: await page.locator('h1').first().textContent(), links: await page.locator('main a').count() });
// theme dark
await page.goto(B); await page.locator('#theme').click(); await page.waitForTimeout(300); await page.screenshot({ path: `${D}/shots/${hk}_index_dark.png`, fullPage: true });
log('theme.persist', await page.evaluate(() => localStorage.getItem('theme'))); await page.evaluate(() => localStorage.clear());
// ---------- releases
await page.goto(B + 'releases.html', { waitUntil: 'networkidle' }); await page.waitForTimeout(1200);
log('rel.state', await txt('#rel-state')); log('rel.rows', await page.evaluate(() => [...document.querySelectorAll('#rel-table tbody tr')].map(r => r.innerText.replace(/\s+/g, ' ').slice(0, 400))));
log('rel.links', await page.evaluate(() => [...document.querySelectorAll('#rel-table tbody tr:first-child a')].map(a => a.textContent + ' -> ' + a.href)));
log('rel.headers', await page.locator('#rel-table thead th').allInnerTexts()); log('rel.hasCompare', await page.evaluate(() => /compar|diff|changes\.json|CHANGELOG/i.test(document.body.innerText + [...document.links].map(l => l.href).join(' '))));
await page.screenshot({ path: `${D}/shots/${hk}_releases.png`, fullPage: true });
await page.setViewportSize({ width: 390, height: 844 }); await page.screenshot({ path: `${D}/shots/${hk}_releases_m.png`, fullPage: true }); log('rel.m.tablescroll', await page.evaluate(() => { const w = document.querySelector('.tablewrap'); return { sw: w.scrollWidth, cw: w.clientWidth, tabindex: w.getAttribute('tabindex'), role: w.getAttribute('role') }; }));
await page.setViewportSize({ width: 1280, height: 900 });
// ---------- transparency
async function transp(name, route, wait = 6000) {
  const p = await ctx.newPage(); if (route) await p.route('**/*', route); const e = []; p.on('pageerror', x => e.push(String(x)));
  await p.goto(B + 'transparency.html', { waitUntil: 'networkidle' }); await p.waitForTimeout(1200);
  const facts = (await p.locator('#facts').innerText()).replace(/\s+/g, ' ').slice(0, 700); const logState = await p.locator('#log-state').textContent();
  await p.locator('#verify').click(); await p.waitForFunction(() => { const l = document.querySelectorAll('#checks li'); return l.length >= 3 && /Calculando|Computing/.test(document.getElementById('checks').innerText) === false; }, null, { timeout: wait * 4 }).catch(() => { });
  await p.waitForTimeout(1500);
  const checks = await p.locator('#checks li').allInnerTexts(); log('tr.' + name, { logState, facts: name === 'ok' ? facts : undefined, checks, pageerrors: e }); await p.screenshot({ path: `${D}/shots/${hk}_transp_${name}.png`, fullPage: name === 'ok' }); await p.close(); return checks;
}
const flip = s => { const a = s.split(''); a[10] = a[10] === 'a' ? 'b' : 'a'; return a.join(''); };
const mut = async (urlEnd, f, ct = 'text/plain') => (r) => r.request().url().endsWith(urlEnd) ? r.fetch().then(async resp => { const t = await resp.text(); return r.fulfill({ response: resp, body: f(t), contentType: ct }); }) : r.continue();
await transp('ok', null);
await transp('logLineTampered', async r => { const u = r.request().url(); if (u.endsWith('logs/log.jsonl')) { const resp = await r.fetch(); const t = await resp.text(); const ls = t.split('\n'); ls[5] = ls[5].replace(/"message":"/, '"message":"X'); return r.fulfill({ response: resp, body: ls.join('\n') }); } return r.continue(); });
await transp('logTruncated', async r => { const u = r.request().url(); if (u.endsWith('logs/log.jsonl')) { const resp = await r.fetch(); const t = await resp.text(); return r.fulfill({ response: resp, body: t.split('\n').slice(0, 40).join('\n') }); } return r.continue(); });
await transp('checkpointRootTampered', async r => { const u = r.request().url(); if (u.endsWith('logs/checkpoint.txt')) { const resp = await r.fetch(); const t = await resp.text(); const l = t.split('\n'); const root = Buffer.from(l[2], 'base64'); root[0] ^= 1; l[2] = root.toString('base64'); return r.fulfill({ response: resp, body: l.join('\n') }); } return r.continue(); });
await transp('proofTampered', async r => { const u = r.request().url(); if (u.endsWith('inclusion-proof.json')) { const resp = await r.fetch(); const j = JSON.parse(await resp.text()); j.proof[0] = flip(j.proof[0]); return r.fulfill({ response: resp, body: JSON.stringify(j) }); } return r.continue(); });
await transp('proofEntryTampered', async r => { const u = r.request().url(); if (u.endsWith('inclusion-proof.json')) { const resp = await r.fetch(); const j = JSON.parse(await resp.text()); j.entry = j.entry.replace(/.$/, c => c === 'x' ? 'y' : 'x'); return r.fulfill({ response: resp, body: JSON.stringify(j) }); } return r.continue(); });
await transp('proofMissing', r => r.request().url().endsWith('inclusion-proof.json') ? r.fulfill({ status: 404, body: 'no' }) : r.continue());
await transp('consistencyTampered', async r => { const u = r.request().url(); if (u.endsWith('consistency.json')) { const resp = await r.fetch(); if (resp.status() !== 200) return r.fulfill({ response: resp }); const j = JSON.parse(await resp.text()); j.proof[0] = flip(j.proof[0]); return r.fulfill({ response: resp, body: JSON.stringify(j) }); } return r.continue(); });
await transp('logMissing', r => r.request().url().endsWith('logs/log.jsonl') ? r.fulfill({ status: 404, body: 'no' }) : r.continue());
// "more" pagination + log table
await page.goto(B + 'transparency.html', { waitUntil: 'networkidle' }); await page.waitForTimeout(1200);
log('tr.rows', await page.locator('#log-table tbody tr').count()); await page.locator('#more').click(); log('tr.rows after more', await page.locator('#log-table tbody tr').count()); log('tr.logState', await page.locator('#log-state').textContent());
log('tr.sample', await page.evaluate(() => [...document.querySelectorAll('#log-table tbody tr')].slice(0, 3).map(r => r.innerText.replace(/\s+/g, ' '))));
log('tr.verifierLink', await page.evaluate(async () => { const a = [...document.querySelectorAll('a')].find(x => /verify_public_release\.py$/.test(x.href)); const r = await fetch(a.href); const t = await r.text(); const s = await (await fetch(a.href + '.sha256')).text(); const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(t)); return { href: a.href, download: a.hasAttribute('download'), status: r.status, len: t.length, shaFile: s.trim().slice(0, 80), shaComputed: [...new Uint8Array(d)].map(x => x.toString(16).padStart(2, '0')).join('') }; }));
log('consoleErrors', errs);
await br.close(); fs.writeFileSync(`${D}/out/pages_${hk}.json`, JSON.stringify(out, null, 1));
