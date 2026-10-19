import { chromium } from '../node_modules/playwright/index.mjs';
import { readFileSync } from 'node:fs';
const axeSrc = readFileSync(new URL('../node_modules/axe-core/axe.min.js', import.meta.url), 'utf8');
const base = process.argv[2];
const pages = ['index.html','rules.html','releases.html','transparency.html','docs/en/architecture.html','docs/en/merkle.html','docs/es/overview.html'];
const browser = await chromium.launch();
const out = [];
for (const dark of [false, true]) for (const [w,h] of [[1280,900],[390,800]]) {
  const ctx = await browser.newContext({ viewport: { width: w, height: h } });
  for (const p of pages) {
    const page = await ctx.newPage(); const errs = [];
    page.on('console', m => { if (m.type()==='error') errs.push(m.text().slice(0,160)); }); page.on('pageerror', e => errs.push(String(e).slice(0,160)));
    await page.goto(base + p, { waitUntil: 'networkidle' });
    if (dark) await page.evaluate(() => { document.body.classList.add('dark'); });
    await page.waitForTimeout(1200);
    await page.evaluate(axeSrc);
    const r = await page.evaluate(async () => await axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22aa'] } }));
    out.push({ p, w, dark, errs, v: r.violations.map(v => `${v.impact}:${v.id}(${v.nodes.length})`) });
    await page.close();
  }
  await ctx.close();
}
await browser.close();
for (const o of out) console.log(`${o.dark?'dark ':'light'} ${o.w} ${o.p}: ${o.v.join(', ') || 'none'}${o.errs.length ? ' | console: ' + o.errs.join(' ; ') : ''}`);
