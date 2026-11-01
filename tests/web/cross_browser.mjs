// The portal in Chromium, Firefox and WebKit (Playwright). Serves a built site from memory-patched files, then per engine:
//  1. runs tests/web/e2e.html (normal, tampered log, missing inclusion proof) and requires DONE with no FAIL;
//  2. loads key pages and requires no page error, console error, failed request or CSP violation;
//  3. requires every Mermaid diagram of two docs pages to render (window.__docsDiagrams) and fit without horizontal page scroll;
//  4. runs axe-core (WCAG 2.x A/AA + 2.2 AA) at 1280 and 390 px, light and dark.
// The site needs verification.json (written by the site workflow from the release history); copy the live one next to a local build.
// usage: PW_DIR=<dir with node_modules/playwright and axe-core> [PW_EXECUTABLE_WEBKIT=<pw_run.sh>] node tests/web/cross_browser.mjs <site-dir> [engine,engine]
import { createRequire } from 'node:module';
import { createServer } from 'node:http';
import { readFileSync, existsSync, statSync } from 'node:fs';
import { join, extname, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(join(process.env.PW_DIR || process.cwd(), 'x.js'));
const pw = require('playwright');
const axeSrc = readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
const here = fileURLToPath(new URL('.', import.meta.url));
const site = normalize(process.argv[2] || 'site');
const engines = (process.argv[3] || 'chromium,firefox,webkit').split(',');
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.jsonl': 'text/plain', '.txt': 'text/plain', '.png': 'image/png', '.svg': 'image/svg+xml' };

function serve(mode) {
  const srv = createServer((req, res) => {
    let p = decodeURIComponent(new URL(req.url, 'http://x').pathname); if (p.endsWith('/')) p += 'index.html';
    const file = p === '/__e2e.html' ? join(here, 'e2e.html') : join(site, normalize(p));
    if (!file.startsWith(site) && p !== '/__e2e.html') { res.writeHead(403).end(); return; }
    if (mode === 'missing' && p === '/inclusion-proof.json') { res.writeHead(404).end(); return; }
    if (!existsSync(file) || statSync(file).isDirectory()) { res.writeHead(404).end('not found'); return; }
    let body = readFileSync(file);
    if (mode === 'tamper' && p === '/logs/log.jsonl') { const l = body.toString().split('\n'); l[3] = l[3].replace('"event"', '"evenT"'); body = Buffer.from(l.join('\n')); }
    res.writeHead(200, { 'Content-Type': TYPES[extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store' }).end(body);
  });
  return new Promise((ok) => srv.listen(0, '127.0.0.1', () => ok({ srv, base: `http://127.0.0.1:${srv.address().port}` })));
}

const results = []; const rec = (engine, name, ok, detail = '') => { results.push({ engine, name, ok, detail }); console.log(`${ok ? 'PASS' : 'FAIL'} [${engine}] ${name}${detail ? ' — ' + detail : ''}`); };

for (const name of engines) {
  const exe = process.env['PW_EXECUTABLE_' + name.toUpperCase()];   // optional: a browser build patched to find user-space libraries (no sudo)
  const browser = await pw[name].launch(exe ? { executablePath: exe } : {});
  try {
    for (const mode of ['', 'tamper', 'missing']) {
      const { srv, base } = await serve(mode); const page = await browser.newPage({ viewport: { width: 1100, height: 900 } });
      await page.goto(`${base}/__e2e.html${mode ? '?mode=' + mode : ''}`);
      try { await page.waitForFunction(() => /DONE/.test(document.getElementById('result').textContent), null, { timeout: 90000 }); } catch { /* reported below */ }
      const t = await page.textContent('#result');
      rec(name, `e2e${mode ? ' ' + mode : ''}`, /DONE/.test(t) && !/FAIL/.test(t), (t.match(/FAIL[^\n]*/g) || []).slice(0, 3).join(' | ') || `${(t.match(/PASS/g) || []).length} checks`);
      await page.close(); srv.close();
    }
    const { srv, base } = await serve('');
    const pages = ['index.html', 'catalog.html', 'vulnerabilities.html', 'vuln.html?id=CVE-2021-44228', 'indicators.html', 'guide.html', 'packages.html', 'plans.html', 'rules.html', 'releases.html', 'transparency.html', 'docs/en/merkle.html', 'docs/es/architecture.html', '404.html'];
    for (const [w, h] of [[1280, 900], [390, 800]]) {
      const ctx = await browser.newContext({ viewport: { width: w, height: h } });
      for (const p of pages) {
        const page = await ctx.newPage(); const bad = [];
        await page.addInitScript(() => { window.__csp = []; document.addEventListener('securitypolicyviolation', (e) => window.__csp.push(e.violatedDirective + ' ' + e.blockedURI)); });
        page.on('pageerror', (e) => bad.push('pageerror: ' + String(e).slice(0, 120)));
        page.on('console', (m) => { if (m.type() === 'error' && !(p === '404.html' && /404/.test(m.text()))) bad.push('console: ' + m.text().slice(0, 120)); });
        page.on('requestfailed', (r) => bad.push('requestfailed: ' + r.url().slice(-60)));
        await page.goto(`${base}/${p}`, { waitUntil: 'networkidle' });
        if (p.startsWith('docs/')) { try { await page.waitForFunction(() => window.__docsDiagrams && window.__docsDiagrams.done, null, { timeout: 60000 }); } catch { bad.push('diagrams did not finish'); } }
        else await page.waitForTimeout(1500);
        const d = await page.evaluate(() => ({ csp: window.__csp, diag: window.__docsDiagrams || null, overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth }));
        if (d.csp.length) bad.push('CSP violations: ' + d.csp.slice(0, 3).join('; '));
        if (d.diag) { if (d.diag.errors.length || d.diag.rendered !== d.diag.total || d.diag.total === 0) bad.push(`diagrams ${d.diag.rendered}/${d.diag.total} errors=${JSON.stringify(d.diag.errors).slice(0, 120)}`); }
        if (d.overflow > 1) bad.push(`horizontal page scroll ${d.overflow}px`);
        await page.evaluate(axeSrc);
        for (const dark of [false, true]) {
          if (dark) { await page.evaluate(() => document.body.classList.add('dark')); await page.waitForTimeout(300); }
          const ax = await page.evaluate(async () => (await axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'] } })).violations.map((v) => `${v.id}(${v.nodes.length})`));
          if (ax.length) bad.push(`axe${dark ? ' dark' : ''}: ` + ax.join(','));
        }
        rec(name, `${p} @${w}`, bad.length === 0, bad.join(' | ') || (d.diag ? `${d.diag.rendered} diagrams` : ''));
        await page.close();
      }
      await ctx.close();
    }
    // 5. accessibility interactions of the docs (WCAG 4.1.3, 2.4.11/2.1.2), with the element Fullscreen API removed as on iPhone Safari
    { const ctx = await browser.newContext({ viewport: { width: 390, height: 800 } });
      await ctx.addInitScript(() => { Object.defineProperty(Element.prototype, 'requestFullscreen', { value: undefined, configurable: true }); });
      const page = await ctx.newPage(); await page.goto(`${base}/docs/en/merkle.html`, { waitUntil: 'networkidle' });
      await page.waitForFunction(() => window.__docsDiagrams && window.__docsDiagrams.done, null, { timeout: 60000 }).catch(() => {});
      await page.click('.codeblock .copy'); await page.waitForTimeout(500);
      const said = await page.evaluate(() => { const s = document.querySelector('.sr-status[role="status"]'); return s ? s.textContent : null; });
      rec(name, 'docs: copying code is announced in a status message', said === 'Copied', `status=${JSON.stringify(said)}`);
      const fig = '#fig-rules-merkle'; await page.locator(`${fig} .dg-bar button[aria-label="Full screen"]`).click(); await page.waitForTimeout(300);
      const inside = []; for (let i = 0; i < 25; i++) { await page.keyboard.press(i < 20 ? 'Tab' : 'Shift+Tab'); inside.push(await page.evaluate((f) => document.querySelector(f).contains(document.activeElement), fig)); }
      const overlay = await page.evaluate((f) => document.querySelector(f).classList.contains('dg-full'), fig); await page.keyboard.press('Escape');
      const closed = await page.evaluate((f) => !document.querySelector(f).classList.contains('dg-full'), fig);
      rec(name, 'docs: the full-screen fallback overlay keeps keyboard focus inside and Escape closes it', overlay && inside.every(Boolean) && closed, `overlay=${overlay} inside=${inside.filter(Boolean).length}/25 closed=${closed}`);
      await ctx.close(); }
    // 6. reflow at 320 CSS px (WCAG 1.4.10, = 1280 px at 400 %) and text spacing (1.4.12): no horizontal page scroll. Spanish is the longer
    //    language; the home also in English, whose activity select ("Changes between releases") overflowed by 41 px in WebKit with text spacing
    for (const [p, lang] of [['vulnerabilities.html', 'es'], ['vuln.html?id=CVE-2021-44228', 'es'], ['vuln.html?id=bad', 'es'], ['index.html', 'es'], ['index.html', 'en']]) {
      const ctx = await browser.newContext({ viewport: { width: 320, height: 800 } }); await ctx.addInitScript((l) => { try { localStorage.setItem('lang', l); } catch {} }, lang);
      const page = await ctx.newPage(); await page.goto(`${base}/${p}`, { waitUntil: 'networkidle' }); await page.waitForTimeout(1000);
      const sx = () => page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth); const plain = await sx();
      await page.addStyleTag({ content: '*{line-height:1.5!important;letter-spacing:0.12em!important;word-spacing:0.16em!important}p{margin-bottom:2em!important}' }); const spaced = await sx();
      rec(name, `reflow 320 px + text spacing (${lang}): ${p}`, plain <= 1 && spaced <= 1, `overflow ${plain}px, with text spacing ${spaced}px`); await ctx.close();
    }
    // 7. target size (WCAG 2.5.8): undersized links (< 24 px) in " · " link lists must keep 24 px between centres of each line fragment, also
    //    when the list wraps; table cells of packages/releases wrapped at a 15 px pitch
    for (const [p, w] of [['packages.html', 320], ['packages.html', 1280], ['releases.html', 320], ['releases.html', 1280]]) {
      const ctx = await browser.newContext({ viewport: { width: w, height: 800 } }); const page = await ctx.newPage();
      await page.goto(`${base}/${p}`, { waitUntil: 'networkidle' }); await page.waitForTimeout(1000);
      const bad = await page.evaluate(() => {
        const T = [...document.querySelectorAll('main a[href]')].filter((e) => e.getClientRects().length && !e.closest('details:not([open])'));
        const fr = []; T.forEach((e, i) => { for (const r of e.getClientRects()) if (r.width >= 1 && r.height >= 1) fr.push({ i, small: r.width < 24 || r.height < 24, x: r.left + r.width / 2, y: r.top + r.height / 2, r }); });
        const out = []; for (const f of fr) { if (!f.small) continue; const e = T[f.i], par = e.parentElement;
          const own = [...par.childNodes].filter((n) => n.nodeType === 3).map((n) => n.textContent).join(''); if (/[A-Za-zÁÉÍÓÚáéíóúñ]{3,}/.test(own)) continue;   // a link inside a sentence is exempt
          for (const g of fr) { if (g.i === f.i) continue; const q = g.r, dx = Math.max(q.left - f.x, 0, f.x - q.right), dy = Math.max(q.top - f.y, 0, f.y - q.bottom);
            if (Math.hypot(dx, dy) < 12 || (g.small && Math.hypot(f.x - g.x, f.y - g.y) < 24)) { out.push(`${e.textContent.trim().slice(0, 24)} ~ ${T[g.i].textContent.trim().slice(0, 24)}`); break; } } }
        return out; });
      rec(name, `target size 24 px or spacing (2.5.8) at ${w} px: ${p}`, bad.length === 0, bad.length ? `${bad.length} too close: ${bad.slice(0, 3).join(' | ')}` : 'ok'); await ctx.close();
    }
    srv.close();
  } finally { await browser.close(); }
}
const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} checks passed on ${engines.join(', ')}`);
process.exit(failed.length ? 1 : 0);
