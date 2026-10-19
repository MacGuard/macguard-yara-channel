// The portal in Chromium, Firefox and WebKit (Playwright). Serves a built site from memory-patched files, then per engine:
//  1. runs tests/web/e2e.html (normal, tampered log, missing inclusion proof) and requires DONE with no FAIL;
//  2. loads key pages and requires no page error, console error, failed request or CSP violation;
//  3. requires every Mermaid diagram of two docs pages to render (window.__docsDiagrams) and fit without horizontal page scroll;
//  4. runs axe-core (WCAG 2.x A/AA + 2.2 AA) at 1280 and 390 px, light and dark.
// The site needs verification.json (written by the site workflow from the release history); copy the live one next to a local build.
// usage: PW_DIR=<dir with node_modules/playwright and axe-core> node tests/web/cross_browser.mjs <site-dir> [engine,engine]
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
  const browser = await pw[name].launch();
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
    const pages = ['index.html', 'rules.html', 'releases.html', 'transparency.html', 'docs/en/merkle.html', 'docs/es/architecture.html', '404.html'];
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
    srv.close();
  } finally { await browser.close(); }
}
const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} checks passed on ${engines.join(', ')}`);
process.exit(failed.length ? 1 : 0);
