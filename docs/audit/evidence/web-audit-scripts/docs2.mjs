// Diagram legibility per figure + toolbar probes (non-crashing). usage: node docs2.mjs gh
import { chromium } from 'playwright'; import fs from 'fs';
const D = '/private/tmp/claude-501/-Users-dmuino-Downloads-macguard-yara-channel/82cd2f90-db22-4237-8d88-d9b30daab0c1/scratchpad/web-audit';
const B = 'https://macguard.github.io/macguard-yara-channel/'; const out = { figs: {}, tb: {} };
const br = await chromium.launch({ headless: true });
const ctx = await br.newContext({ viewport: { width: 1280, height: 900 }, acceptDownloads: true, serviceWorkers: 'block' }); const page = await ctx.newPage(); page.setDefaultTimeout(15000);
for (const p of ['docs/es/architecture.html', 'docs/es/sigstore.html', 'docs/es/release.html', 'docs/es/sources.html']) {
  const t0 = Date.now(); await page.goto(B + p); await page.waitForFunction(() => window.__docsDiagrams && window.__docsDiagrams.done, null, { timeout: 40000 });
  out.figs[p] = { ms: Date.now() - t0, figs: await page.evaluate(() => [...document.querySelectorAll('figure.diagram')].map(f => { const s = f.querySelector('.dg-stage svg'), st = f.querySelector('.dg-stage'); const vb = s.getAttribute('viewBox').split(/[ ,]+/).map(Number); const sc = s.getBoundingClientRect().width / vb[2]; let m = 1e9; s.querySelectorAll('text,tspan').forEach(t => { const x = parseFloat(getComputedStyle(t).fontSize); if (x > 0) m = Math.min(m, x); }); return { id: f.id, vb: vb.slice(2).map(Math.round), scale: +sc.toFixed(2), minPx: +(m * sc).toFixed(1), scrolls: st.scrollWidth > st.clientWidth + 1, stageTabindex: st.getAttribute('tabindex') }; })) };
  console.log(p, JSON.stringify(out.figs[p]));
}
await page.goto(B + 'docs/es/architecture.html'); await page.waitForFunction(() => window.__docsDiagrams.done);
const fig = page.locator('figure.diagram').first(); const bar = fig.locator('.dg-bar button'); const w = () => fig.locator('.dg-stage svg').evaluate(s => Math.round(s.getBoundingClientRect().width));
const tb = out.tb; tb.buttons = await bar.evaluateAll(bs => bs.map(b => [b.textContent, b.getAttribute('aria-label'), Math.round(b.getBoundingClientRect().width) + 'x' + Math.round(b.getBoundingClientRect().height)]));
tb.w0 = await w(); await bar.nth(1).click(); tb.zoomIn = await w(); await bar.nth(0).click(); await bar.nth(0).click(); tb.zoomOut = await w(); await bar.nth(3).click(); tb.oneToOne = await w(); await bar.nth(2).click(); tb.fit = await w();
for (let i = 0; i < 12; i++) await bar.nth(1).click(); tb.maxZoom = await w(); for (let i = 0; i < 20; i++) await bar.nth(0).click(); tb.minZoom = await w(); await bar.nth(2).click();
const dl = page.waitForEvent('download', { timeout: 8000 }).catch(() => null); await bar.nth(6).click(); const d = await dl; if (d) { const t = fs.readFileSync(await d.path(), 'utf8'); tb.svg = { name: d.suggestedFilename(), bytes: t.length, foreign: /foreignObject/.test(t), head: t.slice(0, 50) }; await d.delete(); } else tb.svg = 'no download';
tb.keyZoom = await (async () => { const st = fig.locator('.dg-stage'); const a = await w(); await st.focus().catch(() => { }); await page.keyboard.press('+'); return { a, b: await w(), tabindex: await st.getAttribute('tabindex') }; })();
await page.evaluate(() => window.scrollTo(0, 0));
// fullscreen
await bar.nth(4).click(); await page.waitForTimeout(700); tb.fs = await page.evaluate(() => ({ native: !!document.fullscreenElement, cls: document.querySelector('.dg-full') ? 'dg-full' : null }));
await page.keyboard.press('Escape'); await page.waitForTimeout(500); tb.afterEsc = await page.evaluate(() => ({ native: !!document.fullscreenElement, cls: !!document.querySelector('.dg-full') }));
tb.themeClickable = await page.locator('#theme').click({ timeout: 4000 }).then(() => true).catch(() => false);
tb.afterThemeIntercept = await page.evaluate(() => { const b = document.getElementById('theme').getBoundingClientRect(); const e = document.elementFromPoint(b.x + b.width / 2, b.y + b.height / 2); return e && (e.tagName + '.' + e.className + '#' + e.id); });
await page.screenshot({ path: `${D}/shots/gh_doc_toolbar2.png` });
console.log(JSON.stringify(tb));
await br.close(); fs.writeFileSync(`${D}/out/docs2_gh.json`, JSON.stringify(out, null, 1));
