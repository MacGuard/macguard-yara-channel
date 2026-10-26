// Screenshots of the key screens against the real Worker handler on the dev server (synthetic data), for before/after comparison of the design.
// usage: node tools/screenshots.mjs OUTDIR [light|dark|both]
import { chromium } from 'playwright';
import { mkdirSync } from 'node:fs';
import { startServer, openAs, VIEWPORTS } from '../test/ui/harness.mjs';

const out = process.argv[2], schemes = process.argv[3] === 'light' || process.argv[3] === 'dark' ? [process.argv[3]] : ['light', 'dark'];
if (!out) { console.error('usage: screenshots.mjs OUTDIR [light|dark|both]'); process.exit(2); }
mkdirSync(out, { recursive: true });
const SCREENS = [['dashboard', '#/dashboard', '.kpis'], ['quarantine', '#/quarantine', '.rule, .empty'], ['published', '#/published', '.rule, .empty'], ['intel-sources', '#/intel?group=sources', '.dt'], ['intel-vulns', '#/intel?group=vulnerabilities', '.dt-sel tbody tr'],
  ['logs', '#/logs', '.dt.log tbody tr'], ['restore', '#/restore', '.rs-ind'], ['audit', '#/audit', '.events, .card'], ['quarantine-other', '#/quarantine?fam=other', '.dt-sel tbody tr[data-id]'], ['sources', '#/sources', 'tr[data-source]'], ['logs-chain', '#/logs?tab=chain', '#h-chain'], ['activity', '#/activity', '.strip, .card']];
const srv = await startServer(['--published', '--synthetic']), browser = await chromium.launch();
try {
  for (const scheme of schemes) {
    const ctx = await openAs(browser, srv, 'admin', VIEWPORTS.desktop, { colorScheme: scheme }); const page = await ctx.newPage();
    for (const [name, hash, sel] of SCREENS) {
      await page.goto(srv.base + '/' + hash, { waitUntil: 'domcontentloaded' }); await page.waitForSelector(sel, { timeout: 15000 }).catch(() => {}); await page.waitForTimeout(600);
      if (name === 'intel-vulns') { await page.locator('.dt-sel tbody tr').first().click().catch(() => {}); await page.waitForTimeout(500); }
      await page.screenshot({ path: `${out}/${name}-${scheme}.png`, fullPage: false });
    }
    await ctx.close();
  }
} finally { await browser.close(); srv.stop(); }
console.log('saved to', out);
