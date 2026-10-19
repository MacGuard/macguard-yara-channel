// Docs pages: diagrams, toolbar, language switch, links/anchors. usage: node docs.mjs gh|cf [all|sample]
import { chromium } from 'playwright'; import fs from 'fs';
const D = '/private/tmp/claude-501/-Users-dmuino-Downloads-macguard-yara-channel/82cd2f90-db22-4237-8d88-d9b30daab0c1/scratchpad/web-audit';
const hk = process.argv[2] || 'gh'; const mode = process.argv[3] || 'all'; const B = { gh: 'https://macguard.github.io/macguard-yara-channel/', cf: 'https://macguard-rules.pages.dev/' }[hk];
const pages = JSON.parse(fs.readFileSync('/Users/dmuino/Downloads/macguard-yara-channel/docs-src/pages.json', 'utf8')).map(p => p.slug);
let list = []; for (const l of ['es', 'en']) for (const s of pages) list.push(`docs/${l}/${s}.html`);
if (mode === 'sample') list = ['docs/es/architecture.html', 'docs/en/merkle.html', 'docs/en/overview.html'];
const out = { pages: {} }; const br = await chromium.launch({ headless: true });
for (const vp of [[1280, 900, 'd'], [390, 844, 'm']]) {
  if (mode === 'sample' && vp[2] === 'm') continue;
  const ctx = await br.newContext({ viewport: { width: vp[0], height: vp[1] }, serviceWorkers: 'block', acceptDownloads: true });
  for (const p of list) {
    const page = await ctx.newPage(); page.setDefaultTimeout(30000); const r = out.pages[p + '|' + vp[2]] = { console: [], failed: [] };
    page.on('console', m => ['error', 'warning'].includes(m.type()) && r.console.push(m.text().slice(0, 200))); page.on('pageerror', e => r.console.push('PAGEERR ' + e)); page.on('requestfailed', q => r.failed.push(q.url()));
    const t0 = Date.now();
    try {
      await page.goto(B + p, { waitUntil: 'domcontentloaded' });
      await page.waitForFunction(() => window.__docsDiagrams && window.__docsDiagrams.done, null, { timeout: 40000 }).catch(() => r.console.push('DIAGRAMS NOT DONE'));
      r.doneMs = Date.now() - t0;
      r.diag = await page.evaluate(() => window.__docsDiagrams);
      r.figs = await page.evaluate(() => [...document.querySelectorAll('figure.diagram')].map(f => { const s = f.querySelector('.dg-stage svg'); const st = f.querySelector('.dg-stage'); if (!s) return { name: f.dataset.diagram, svg: false }; const vb = s.getAttribute('viewBox').split(/[ ,]+/).map(Number); const sc = s.getBoundingClientRect().width / vb[2]; let m = 1e9; s.querySelectorAll('text,tspan').forEach(t => { const fs = parseFloat(getComputedStyle(t).fontSize); if (fs > 0) m = Math.min(m, fs); }); return { name: f.dataset.diagram, vbw: Math.round(vb[2]), vbh: Math.round(vb[3]), scale: +sc.toFixed(2), minFontPx: +(m * sc).toFixed(1), stageScroll: st.scrollWidth > st.clientWidth + 1, stageW: st.clientWidth, role: s.getAttribute('role'), label: !!s.getAttribute('aria-label'), caption: f.querySelector('figcaption') && f.querySelector('figcaption').textContent.slice(0, 60), stageFocusable: st.getAttribute('tabindex'), codeOpen: f.querySelector('.dg-code') && f.querySelector('.dg-code').open }; }));
      r.title = await page.title(); r.h1 = await page.locator('h1').first().textContent(); r.overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      r.hreflang = await page.evaluate(() => [...document.querySelectorAll('link[rel=alternate]')].map(l => l.getAttribute('hreflang') + '=' + l.getAttribute('href')));
      r.langSwitch = await page.evaluate(() => { const a = document.getElementById('lang-switch'); return a && { href: a.getAttribute('href'), text: a.textContent, hreflang: a.getAttribute('hreflang'), lang: a.getAttribute('lang') }; });
      r.tocBroken = await page.evaluate(() => [...document.querySelectorAll('.toc a')].filter(a => !document.getElementById(a.getAttribute('href').slice(1))).map(a => a.getAttribute('href')));
      r.tableCount = await page.locator('article table').count(); r.tablesNoWrap = await page.evaluate(() => [...document.querySelectorAll('article table')].filter(t => !t.closest('.tablewrap,[tabindex]') && t.scrollWidth > t.parentElement.clientWidth + 1).length);
      r.imgNoAlt = await page.locator('article img:not([alt])').count();
      r.codeBlocks = await page.locator('.codeblock').count(); r.copyBtns = await page.locator('.codeblock .copy').count();
      r.headingSkips = await page.evaluate(() => { let prev = 1, bad = []; document.querySelectorAll('h1,h2,h3,h4').forEach(h => { const l = +h.tagName[1]; if (l > prev + 1) bad.push(h.textContent.slice(0, 30)); prev = l; }); return bad; });
      if (vp[2] === 'd' && p === 'docs/es/architecture.html') await page.screenshot({ path: `${D}/shots/${hk}_doc_arch_d.png`, fullPage: true });
      if (vp[2] === 'm' && p === 'docs/es/architecture.html') await page.screenshot({ path: `${D}/shots/${hk}_doc_arch_m.png`, fullPage: true });
    } catch (e) { r.error = String(e).slice(0, 200); }
    console.log(p, vp[2], r.error || '', JSON.stringify(r.diag), 'min', (r.figs || []).map(f => f.minFontPx).join(','), 'cons', r.console.length); await page.close();
  }
  await ctx.close();
}
// toolbar + switch on one diagram page (desktop)
const ctx = await br.newContext({ viewport: { width: 1280, height: 900 }, acceptDownloads: true, serviceWorkers: 'block' }); await ctx.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: new URL(B).origin }).catch(() => { });
const page = await ctx.newPage(); page.setDefaultTimeout(20000);
const tb = out.toolbar = {};
await page.goto(B + 'docs/es/architecture.html'); await page.waitForFunction(() => window.__docsDiagrams && window.__docsDiagrams.done, null, { timeout: 40000 });
const fig = page.locator('figure.diagram').first(); const w = () => fig.locator('.dg-stage svg').evaluate(s => s.getBoundingClientRect().width);
tb.buttons = await fig.locator('.dg-bar button').evaluateAll(bs => bs.map(b => ({ t: b.textContent, label: b.getAttribute('aria-label'), w: Math.round(b.getBoundingClientRect().width), h: Math.round(b.getBoundingClientRect().height) })));
tb.w0 = await w(); await fig.locator('.dg-bar button').nth(1).click(); tb.zoomIn = await w(); await fig.locator('.dg-bar button').nth(0).click(); await fig.locator('.dg-bar button').nth(0).click(); tb.zoomOut = await w(); await fig.locator('.dg-bar button').nth(3).click(); tb.oneToOne = await w(); await fig.locator('.dg-bar button').nth(2).click(); tb.fit = await w();
for (let i = 0; i < 12; i++) await fig.locator('.dg-bar button').nth(1).click(); tb.maxZoom = await w(); for (let i = 0; i < 20; i++) await fig.locator('.dg-bar button').nth(0).click(); tb.minZoom = await w();
await fig.locator('.dg-bar button').nth(2).click();
const dl = page.waitForEvent('download', { timeout: 10000 }); await fig.locator('.dg-bar button').nth(6).click(); const d = await dl.catch(() => null); tb.svgDownload = d ? { name: d.suggestedFilename() } : 'none'; if (d) { const pth = await d.path(); const t = fs.readFileSync(pth, 'utf8'); tb.svgDownload.bytes = t.length; tb.svgDownload.xmlHeader = t.slice(0, 40); tb.svgDownload.hasForeign = /foreignObject/.test(t); await d.delete(); }
await fig.locator('.dg-bar button').nth(5).click(); tb.copyLabelAfter = await fig.locator('.dg-bar button').nth(5).textContent(); tb.clip = (await page.evaluate(() => navigator.clipboard.readText()).catch(e => 'ERR ' + e)).slice(0, 60);
await fig.locator('.dg-bar button').nth(4).click(); await page.waitForTimeout(600); tb.fullscreen = await page.evaluate(() => !!document.fullscreenElement || !!document.querySelector('.dg-full')); await page.keyboard.press('Escape'); await page.waitForTimeout(400);
tb.keyZoom = await (async () => { const st = fig.locator('.dg-stage'); await st.focus().catch(() => { }); const a = await w(); await page.keyboard.press('+'); return { before: a, after: await w(), focusable: await st.getAttribute('tabindex') }; })();
tb.codeBlocksCopy = await (async () => { const b = page.locator('.codeblock .copy').first(); if (!(await b.count())) return 'no code blocks'; await b.click(); return await b.textContent(); })();
await page.screenshot({ path: `${D}/shots/${hk}_doc_toolbar.png` });
// dark mode re-render
const t1 = Date.now(); await page.locator('#theme').click(); await page.waitForFunction(() => window.__docsDiagrams.done); tb.darkRerenderMs = Date.now() - t1; await page.screenshot({ path: `${D}/shots/${hk}_doc_dark.png`, fullPage: true });
// language switch
await page.evaluate(() => localStorage.clear()); await page.locator('#lang-switch').click(); await page.waitForLoadState(); tb.switchedTo = page.url(); tb.switchTitle = await page.title();
// docs nav links count / pager
tb.sideNav = await page.locator('.docs-nav a').count(); tb.pager = await page.locator('nav.pager a').allInnerTexts();
// docs/index
await page.goto(B + 'docs/index.html'); tb.docsIndex = { url: page.url(), body: (await page.locator('body').innerText()).slice(0, 300) };
await br.close(); fs.writeFileSync(`${D}/out/docs_${hk}_${mode}.json`, JSON.stringify(out, null, 1));
console.log(JSON.stringify(out.toolbar).slice(0, 2500));
