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

    test('Fuentes: every source with its real last run, connection state and reasons; sources without a connector say why; nothing is invented', async () => {
      const page = await open(browser, srv, 'reviewer', VIEWPORTS.desktop, '#/dashboard'); await page.getByRole('link', { name: 'Inteligencia' }).click(); await page.waitForSelector('table.in-wide');
      const t = await page.locator('table.in-wide').innerText(); assert.match(t, /CISA Known Exploited Vulnerabilities/); assert.match(t, /Conectada/); assert.match(t, /1\.?25|120/); assert.match(t, /MalwareBazaar/); assert.match(t, /Bloqueada/); assert.match(t, /clave API/); assert.match(t, /No programada/); assert.match(t, /Parcial/);
      assert.match(await page.locator('main').innerText(), /ejecuciones locales promovidas/); assert.deepEqual(page.errors, []);
    });

    test('families: records are paginated, filterable, searchable without losing focus, and open a side sheet with the rule text, provenance and quality verdicts', async () => {
      const page = await open(browser, srv, 'reviewer', VIEWPORTS.desktop, '#/intel?group=vulnerabilities'); await page.waitForSelector('.dt-sel tbody tr'); assert.match(await page.locator('p[aria-live=polite]').first().innerText(), /160 registros/);
      assert.equal(await page.locator('.dt-sel tbody tr').count(), 50); await page.getByRole('button', { name: 'Cargar más' }).click(); await page.waitForFunction(() => document.querySelectorAll('.dt-sel tbody tr').length === 100);
      await page.click('#ix-search'); await page.keyboard.type('CVE-2025-200', { delay: 30 }); await page.waitForFunction(() => document.querySelectorAll('.dt-sel tbody tr').length === 10); assert.equal(await page.evaluate(() => document.activeElement.id), 'ix-search', 'typing keeps the focus');
      await page.locator('.dt-sel tbody tr').first().click(); await page.waitForSelector('.sheet-side:not([hidden]) h2'); const sh = await page.locator('.sheet-side').innerText(); assert.match(sh, /NVD record/); assert.match(sh, /Fuente y procedencia/); assert.match(sh, /nvd\.nist\.gov/);
      await page.keyboard.press('Escape'); assert.equal(await page.locator('.sheet-side').isHidden(), true);
      await page.goto(srv.base + '/#/intel?group=detections'); await page.waitForFunction(() => /ET TEST trojan/.test(document.querySelector('.dt-sel') ? document.querySelector('.dt-sel').innerText : '')); await page.locator('.dt-sel tbody tr', { hasText: 'ET TEST trojan' }).click(); await page.waitForSelector('.sheet-side:not([hidden]) pre');
      const rule = await page.locator('.sheet-side').innerText(); assert.match(rule, /alert tcp any any -> any 80/); assert.match(rule, /Calidad por regla/); assert.match(rule, /NOT_RUN/); assert.match(rule, /INCONCLUSIVE/);
      await page.goto(srv.base + '/#/intel?group=vulnerabilities'); await page.waitForFunction(() => /CVE-2024-1000|CVE-2025/.test(document.querySelector('.dt-sel') ? document.querySelector('.dt-sel').innerText : '')); await page.locator('.dt-sel tbody tr').first().click(); await page.waitForSelector('.sheet-side:not([hidden]) h2');
      assert.equal(await page.locator('.sheet-side a[href^="javascript"]').count(), 0, 'a non-http reference is never a link'); assert.deepEqual(page.errors, []);
    });

    test('indicators and context show their real records; an expired indicator is EXPIRED, not hidden and not green', async () => {
      const page = await open(browser, srv, 'reviewer', VIEWPORTS.desktop, '#/intel?group=indicators'); await page.waitForSelector('.dt-sel tbody tr'); const t = await page.locator('.dt-sel').innerText(); assert.match(t, /203\.0\.113\.7/); assert.match(t, /Caducado/);
      await page.goto(srv.base + '/#/intel?group=context'); await page.waitForFunction(() => /Command and Scripting/.test(document.querySelector('.dt-sel') ? document.querySelector('.dt-sel').innerText : '')); assert.match(await page.locator('.dt-sel').innerText(), /Command and Scripting Interpreter/);
    });

    test('Logs: structured rows with level and component, filters that keep working, a detail sheet with every field, and a link to one run', async () => {
      const page = await open(browser, srv, 'reviewer', VIEWPORTS.desktop, '#/dashboard'); await page.getByRole('link', { name: 'Logs' }).click(); await page.waitForSelector('.dt.log tbody tr[tabindex]'); assert.equal(await page.locator('.dt.log tbody tr[tabindex]').count(), 3);
      await page.getByRole('group', { name: 'Nivel' }).getByRole('button', { name: /WARN/ }).click(); await page.waitForFunction(() => document.querySelectorAll('.dt.log tbody tr[tabindex]').length === 2);
      await page.locator('.dt.log tbody tr[tabindex]').first().click(); await page.waitForSelector('.sheet-side:not([hidden]) dl'); const d = await page.locator('.sheet-side').innerText(); assert.match(d, /component/); assert.match(d, /run_id/); assert.match(d, /run-kev|run-nvd/);
      await page.getByRole('link', { name: 'Ver solo esta ejecución' }).click(); await page.waitForFunction(() => location.hash.includes('run_id=')); assert.match(await page.locator('#lg-status').innerText(), /eventos cargados/);
      await page.locator('#lg-live').uncheck(); assert.match(await page.locator('#lg-status').innerText(), /pausa/); assert.deepEqual(page.errors, []);
      const v = await open(browser, srv, 'viewer', VIEWPORTS.desktop, '#/dashboard'); assert.equal(await v.getByRole('link', { name: 'Logs' }).count(), 0);
    });

    test('dashboard, activity, quarantine and published show the real Intelligence data with period, unit, source and coverage; nothing published outside YARA', async () => {
      const page = await open(browser, srv, 'reviewer', VIEWPORTS.desktop, '#/dashboard'); await page.waitForSelector('.charts'); const t = await page.locator('.charts').innerText();
      assert.match(t, /Registros por familia/); assert.match(t, /Periodo: 2026-10-25/); assert.match(t, /D1 macguard-intel/); assert.match(t, /no es una serie temporal continua/); assert.match(t, /Funcionalmente verificadas: 0/); assert.equal(await page.locator('.charts svg').count(), 3);
      assert.match(await page.locator('main').innerText(), /Retenidas, en cuarentena y rechazadas por familia/); assert.match(await page.locator('.mf-matrix').innerText(), /CVE[\s\S]*ATT|ATT[\s\S]*CVE/, 'the dashboard matrix covers the other families');
      await page.goto(srv.base + '/#/quarantine?fam=other'); await page.waitForSelector('.dt-sel tbody tr'); assert.match(await page.locator('main').innerText(), /Suricata/); assert.match(await page.locator('main').innerText(), /Otras familias/);
      await page.goto(srv.base + '/#/published?fam=other'); await page.waitForFunction(() => /Ningún elemento de estas familias está aprobado o publicado/.test(document.body.innerText));
      await page.goto(srv.base + '/#/activity'); await page.waitForFunction(() => /Ejecuciones de ingesta de Intelligence/.test(document.body.innerText)); assert.match(await page.locator('main').innerText(), /cisa-kev/);
      const v = await open(browser, srv, 'viewer', VIEWPORTS.desktop, '#/dashboard'); await v.waitForSelector('.kpis'); assert.equal(await v.locator('.charts').count(), 0, 'a viewer does not get the Intelligence charts'); assert.deepEqual(page.errors, []);
    });

    test('a viewer neither sees the entry nor can read the API; the group in the URL survives a reload', async () => {
      const v = await open(browser, srv, 'viewer', VIEWPORTS.desktop, '#/dashboard'); assert.equal(await v.getByRole('link', { name: 'Inteligencia' }).count(), 0);
      assert.equal(await v.evaluate(() => fetch('/api/intel/families').then((r) => r.status)), 403);
      const page = await open(browser, srv, 'admin', VIEWPORTS.desktop, '#/intel?group=vulnerabilities'); await page.waitForSelector('.dt-sel tbody tr'); assert.match(await page.locator('.dt-sel').innerText(), /CVE-2024-1000/);
      await page.reload({ waitUntil: 'domcontentloaded' }); await page.waitForSelector('.dt-sel tbody tr'); assert.match(await page.locator('.dt-sel').innerText(), /CVE-2024-1000/);
    });

    for (const [vpName, vp] of [['desktop', VIEWPORTS.desktop], ['phone', VIEWPORTS.iphone]]) for (const scheme of ['light', 'dark']) test(`layout and WCAG 2.2 AA of Intelligence — ${vpName}, ${scheme}`, async () => {
      const page = await open(browser, srv, 'reviewer', vp, '#/intel?group=detections', scheme); await page.waitForSelector('.dt-sel tbody tr');
      assert.equal(await noHScroll(page), true, 'the page does not scroll sideways: the table scrolls inside its own region'); assert.deepEqual(await axeViolations(page), [], `${vpName} ${scheme}`);
      for (const hash of ['#/intel?group=sources', '#/logs', '#/dashboard']) { await page.goto(srv.base + '/' + hash); await page.waitForSelector(hash === '#/dashboard' ? '.charts' : '.dt'); assert.equal(await noHScroll(page), true, hash); assert.deepEqual(await axeViolations(page), [], `${hash} ${vpName} ${scheme}`); }
    });
  });
}
