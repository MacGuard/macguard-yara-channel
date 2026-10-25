// The Intelligence screen in real browsers against the real Worker handler: families by group with their real states and concrete causes, YARA as the only live reading, role gating, keyboard and WCAG 2.2 AA.
// UI_ENGINES=chromium,firefox,webkit (default: chromium only).
import test, { describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { chromium, firefox, webkit } from 'playwright';
import { startServer, openAs, VIEWPORTS } from './harness.mjs';

const AXE = readFileSync(createRequire(import.meta.url).resolve('axe-core/axe.min.js'), 'utf8');
const ENGINES = { chromium, firefox, webkit }, WANT = (process.env.UI_ENGINES || 'chromium').split(','), WCAG = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];
async function open(browser, srv, role, vp, hash, scheme = 'light') {
  const ctx = await openAs(browser, srv, role, vp, { colorScheme: scheme }); const page = await ctx.newPage(); page.errors = [];
  page.on('console', (m) => { if (m.type() === 'error' && !/status of 4\d\d/.test(m.text()) && !(page.axeRan && /Refused to apply a stylesheet/.test(m.text()))) page.errors.push(m.text()); });
  await page.goto(srv.base + '/' + hash, { waitUntil: 'domcontentloaded' }); await page.waitForSelector('#page-title'); return page;
}
async function axeViolations(page) { assert.deepEqual(page.errors, [], 'no console error before axe runs'); page.axeRan = true; await page.evaluate(AXE); const r = await page.evaluate((tags) => axe.run(document, { runOnly: { type: 'tag', values: tags }, resultTypes: ['violations'] }), WCAG); return r.violations.map((v) => `${v.id} (${v.impact}): ${v.nodes.slice(0, 3).map((n) => n.target.join(' ')).join(' | ')}`); }
const noHScroll = (page) => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1);

for (const name of WANT) {
  describe(name, () => {
    let browser, srv;
    before(async () => { browser = await ENGINES[name].launch(); srv = await startServer(['--published']); });
    after(async () => { await browser.close(); srv.stop(); });

    test('the four groups show every family with its real state, concrete causes and honest empties; YARA is the only live row', async () => {
      const page = await open(browser, srv, 'reviewer', VIEWPORTS.desktop, '#/dashboard'); await page.getByRole('link', { name: 'Inteligencia' }).click(); await page.waitForSelector('.in-table');
      let t = await page.locator('.in-table').innerText(); assert.match(t, /YARA \(Community channel\)/); assert.match(t, /en directo/i); assert.match(t, /Publicada/); assert.match(t, /Suricata \(ET Open\)/); assert.match(t, /Retenida por política/); assert.match(t, /No hay vectores de tráfico por regla/); assert.match(t, /Sigma/); assert.match(t, /YARA-X/);
      assert.equal(await page.locator('.in-table .chip-ok', { hasText: 'Publicada' }).count(), 1, 'only one family is Published');
      await page.getByRole('button', { name: /Indicadores/ }).click(); await page.waitForFunction(() => /Feodo/.test(document.querySelector('.in-table').innerText)); t = await page.locator('.in-table').innerText(); assert.match(t, /Feodo/); assert.match(t, /Sin datos/); assert.match(t, /Todos los registros han caducado/); assert.match(t, /Bloqueada/); assert.match(t, /No existe conector/);
      await page.getByRole('button', { name: /Vulnerabilidades/ }).click(); await page.waitForFunction(() => /NVD/.test(document.querySelector('.in-table').innerText)); t = await page.locator('.in-table').innerText(); for (const n of ['NVD', 'OSV', 'CISA KEV', 'EUVD', 'CERT-EU']) assert.match(t, new RegExp(n)); assert.match(t, /1\.?756/); assert.match(t, /Licencia pendiente de revisión legal/);
      await page.getByRole('button', { name: /Contexto/ }).click(); await page.waitForFunction(() => /EPSS/.test(document.querySelector('.in-table').innerText)); t = await page.locator('.in-table').innerText(); assert.match(t, /EPSS/); assert.match(t, /395\.249/); assert.match(t, /ATT&CK/);
      assert.match(await page.locator('main').innerText(), /config\/intel-families\.json/); assert.deepEqual(page.errors, []);
    });

    test('a viewer neither sees the entry nor can read the API; the group in the URL survives a reload', async () => {
      const v = await open(browser, srv, 'viewer', VIEWPORTS.desktop, '#/dashboard'); assert.equal(await v.getByRole('link', { name: 'Inteligencia' }).count(), 0);
      assert.equal(await v.evaluate(() => fetch('/api/intel/families').then((r) => r.status)), 403);
      const page = await open(browser, srv, 'admin', VIEWPORTS.desktop, '#/intel?group=vulnerabilities'); await page.waitForSelector('.in-table'); assert.match(await page.locator('.in-table').innerText(), /NVD/);
      await page.reload({ waitUntil: 'domcontentloaded' }); await page.waitForSelector('.in-table'); assert.match(await page.locator('.in-table').innerText(), /NVD/);
    });

    for (const [vpName, vp] of [['desktop', VIEWPORTS.desktop], ['phone', VIEWPORTS.iphone]]) for (const scheme of ['light', 'dark']) test(`layout and WCAG 2.2 AA of Intelligence — ${vpName}, ${scheme}`, async () => {
      const page = await open(browser, srv, 'reviewer', vp, '#/intel?group=detections', scheme); await page.waitForSelector('.in-table');
      assert.equal(await noHScroll(page), true, 'the page does not scroll sideways: the table scrolls inside its own region'); assert.deepEqual(await axeViolations(page), [], `${vpName} ${scheme}`);
    });
  });
}
