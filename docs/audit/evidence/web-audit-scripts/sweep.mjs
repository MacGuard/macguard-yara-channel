// Generic per-page sweep: console/network/meta/axe/overflow/zoom/keyboard. One browser instance. usage: node sweep.mjs [gh|cf]
import { chromium } from 'playwright'; import fs from 'fs'; import path from 'path'; import { createRequire } from 'module';
const require = createRequire(import.meta.url); const axeSrc = fs.readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
const D = path.dirname(new URL(import.meta.url).pathname); fs.mkdirSync(D + '/shots', { recursive: true }); fs.mkdirSync(D + '/out', { recursive: true });
const HOSTS = { gh: 'https://macguard.github.io/macguard-yara-channel/', cf: 'https://macguard-rules.pages.dev/' };
const which = process.argv[2] ? [process.argv[2]] : ['gh', 'cf'];
const PAGES = ['', 'rules.html', 'releases.html', 'transparency.html', 'docs/index.html', 'docs/es/overview.html', 'docs/en/overview.html', 'docs/es/architecture.html', 'docs/en/merkle.html'];
const VPS = { d1280: [1280, 800], m390: [390, 844], z200: [640, 800], z400: [320, 800] };
const browser = await chromium.launch({ headless: true });
const results = {};
for (const hk of which) for (const p of PAGES) for (const [vk, [w, h]] of Object.entries(VPS)) {
  const key = `${hk}|${p || 'index'}|${vk}`; const r = results[key] = { console: [], pageerrors: [], failed: [], bad: [], origins: {} };
  const ctx = await browser.newContext({ viewport: { width: w, height: h }, acceptDownloads: false, serviceWorkers: 'block' }); const page = await ctx.newPage(); page.setDefaultTimeout(30000);
  page.on('console', m => { if (['error', 'warning'].includes(m.type())) r.console.push(m.type() + ': ' + m.text().slice(0, 300)); });
  page.on('pageerror', e => r.pageerrors.push(String(e).slice(0, 300)));
  page.on('requestfailed', q => r.failed.push(q.url() + ' ' + (q.failure() || {}).errorText));
  page.on('response', s => { const u = new URL(s.url()); r.origins[u.origin] = (r.origins[u.origin] || 0) + 1; if (s.status() >= 400) r.bad.push(s.status() + ' ' + s.url()); });
  const t0 = Date.now();
  try {
    const resp = await page.goto(HOSTS[hk] + p, { waitUntil: 'networkidle', timeout: 45000 });
    r.finalUrl = page.url(); r.status = resp.status(); r.loadMs = Date.now() - t0;
    await page.waitForTimeout(1500);
    if (/docs\//.test(p)) await page.waitForFunction(() => !window.__docsDiagrams || window.__docsDiagrams.done, null, { timeout: 30000 }).catch(() => r.console.push('diagrams not done'));
    r.title = await page.title(); r.lang = await page.evaluate(() => document.documentElement.lang);
    r.meta = await page.evaluate(() => [...document.querySelectorAll('meta[property],meta[name],link[rel=canonical],link[rel=alternate]')].map(m => m.outerHTML.slice(0, 220)));
    r.overflow = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth }));
    r.clipped = await page.evaluate(() => { const o = []; document.querySelectorAll('body *').forEach(e => { const b = e.getBoundingClientRect(); if (b.width && b.right > document.documentElement.clientWidth + 1 && !e.closest('.tablewrap,pre,.dg-stage,table,.codeblock')) o.push((e.tagName + '#' + e.id + '.' + e.className).slice(0, 60) + ' right=' + Math.round(b.right)); }); return o.slice(0, 8); });
    r.headings = await page.evaluate(() => [...document.querySelectorAll('h1,h2,h3,h4')].map(h => h.tagName + ':' + h.textContent.trim().slice(0, 50)));
    r.landmarks = await page.evaluate(() => [...document.querySelectorAll('main,nav,aside,header,footer,[role=main],[role=navigation],[role=banner],[role=contentinfo]')].map(e => e.tagName.toLowerCase() + (e.getAttribute('aria-label') ? '[' + e.getAttribute('aria-label') + ']' : '') + (e.closest('main') && e.tagName !== 'MAIN' ? '(in main)' : '')));
    if (vk === 'd1280' || vk === 'm390') {
      await page.addScriptTag({ content: axeSrc });
      const ax = await page.evaluate(async () => { const x = await axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice'] }, resultTypes: ['violations', 'incomplete'] }); const f = a => a.map(v => ({ id: v.id, impact: v.impact, help: v.help, n: v.nodes.length, sample: v.nodes.slice(0, 3).map(n => ({ t: n.target.join(' '), s: (n.failureSummary || '').split('\n').slice(0, 3).join(' | ').slice(0, 260) })) })); return { violations: f(x.violations), incomplete: f(x.incomplete) }; });
      r.axe = ax;
    }
    await page.screenshot({ path: `${D}/shots/${hk}_${(p || 'index').replace(/[\/.]/g, '_')}_${vk}.png`, fullPage: true }).catch(() => { });
    if (vk === 'd1280') { // keyboard walk
      const seq = []; await page.evaluate(() => { document.activeElement && document.activeElement.blur(); window.scrollTo(0, 0); });
      for (let i = 0; i < 45; i++) { await page.keyboard.press('Tab'); const s = await page.evaluate(() => { const e = document.activeElement; if (!e || e === document.body) return null; const b = e.getBoundingClientRect(), cs = getComputedStyle(e); return { tag: e.tagName, id: e.id, txt: (e.textContent || e.value || '').trim().slice(0, 30), label: e.getAttribute('aria-label'), outline: cs.outlineStyle + ' ' + cs.outlineWidth + ' ' + cs.outlineColor, boxShadow: cs.boxShadow !== 'none', vis: b.width > 0 && b.height > 0, inView: b.bottom > 0 && b.top < innerHeight, w: Math.round(b.width), h: Math.round(b.height) }; }); seq.push(s); }
      r.tab = seq; const keys = seq.filter(Boolean).map(s => s.tag + '#' + s.id + ':' + s.txt); r.tabUnique = new Set(keys).size; r.tabCount = keys.length;
      r.tabNoIndicator = seq.filter(s => s && /none/.test(s.outline) && !s.boxShadow).map(s => s.tag + '#' + s.id + ':' + s.txt);
    }
  } catch (e) { r.error = String(e).slice(0, 300); }
  await ctx.close(); console.log(key, r.status, r.error || '', 'console', r.console.length, 'ax', r.axe ? r.axe.violations.length : '-');
}
await browser.close();
fs.writeFileSync(`${D}/out/sweep_${which.join('_')}.json`, JSON.stringify(results, null, 1));
