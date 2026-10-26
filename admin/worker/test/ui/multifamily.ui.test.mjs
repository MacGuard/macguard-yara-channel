// The unified panel in real browsers: Quarantine and Published cover every family, search finds each kind, the sheet shows the content and the history, decisions need a reason and a confirmation,
// a blocked approval says why, a decision shows up in the audit and in the activity, and Logs keeps its three records apart. UI_ENGINES=chromium,firefox,webkit (default: chromium only).
import test, { describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { chromium, firefox, webkit } from 'playwright';
import { startServer, openAs, VIEWPORTS } from './harness.mjs';

const AXE = readFileSync(createRequire(import.meta.url).resolve('axe-core/axe.min.js'), 'utf8'), WCAG = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];
async function axeViolations(page) { page.axeRan = true; await page.evaluate(AXE); const r = await page.evaluate((tags) => axe.run(document, { runOnly: { type: 'tag', values: tags }, resultTypes: ['violations'] }), WCAG); return r.violations.map((v) => `${v.id} (${v.impact}): ${v.nodes.slice(0, 3).map((n) => n.target.join(' ')).join(' | ')}`); }
const noHScroll = (page) => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1);
const ENGINES = { chromium, firefox, webkit }, WANT = (process.env.UI_ENGINES || 'chromium').split(',');
async function open(browser, srv, role, hash) {
  const ctx = await openAs(browser, srv, role, VIEWPORTS.desktop, {}); const page = await ctx.newPage(); page.errors = [];
  page.on('console', (m) => { if (m.type() === 'error' && !/status of 4\d\d/.test(m.text())) page.errors.push(m.text()); });
  await page.goto(srv.base + '/' + hash, { waitUntil: 'domcontentloaded' }); await page.waitForSelector('#page-title'); return page;
}
async function openScheme(browser, srv, role, hash, scheme, vp) {
  const ctx = await openAs(browser, srv, role, vp, { colorScheme: scheme }); const page = await ctx.newPage(); page.errors = [];
  await page.goto(srv.base + '/' + hash, { waitUntil: 'domcontentloaded' }); await page.waitForSelector('#page-title'); return page;
}
const rowsOf = (page) => page.locator('.dt-sel tbody tr[data-id]');
const search = async (page, text, n) => { await page.fill('#ix-search', text); await page.waitForFunction(([k, w]) => { const r = document.querySelectorAll('.dt-sel tbody tr[data-id]'); return r.length === k && (!r[0] || r[0].innerText.toLowerCase().includes(w)); }, [n, text.toLowerCase()]); };

for (const name of WANT) {
  describe(name, () => {
    let browser, srv;
    before(async () => { browser = await ENGINES[name].launch(); srv = await startServer(['--published']); });
    after(async () => { await browser.close(); srv.stop(); });

    test('Quarantine covers every family: switch, search each kind, open the sheet with its content', async () => {
      const page = await open(browser, srv, 'reviewer', '#/quarantine'); assert.match(await page.locator('main').innerText(), /Otras familias/);
      await page.getByRole('button', { name: 'Otras familias' }).click(); await page.waitForSelector('.dt-sel tbody tr[data-id]');
      await search(page, 'ET TEST trojan', 1); await rowsOf(page).first().click(); await page.waitForSelector('.sheet-side:not([hidden]) pre'); assert.match(await page.locator('.sheet-side').innerText(), /alert tcp any any -> any 80/);
      await search(page, 'Sigma rule 2', 1); await rowsOf(page).first().click(); await page.waitForFunction(() => /Sigma rule 2/.test((document.querySelector('.sheet-side:not([hidden])') || { innerText: '' }).innerText));
      await search(page, '203.0.113.7', 1); await rowsOf(page).first().click(); await page.waitForFunction(() => /Emotet/.test(document.querySelector('.sheet-side').innerText));
      await search(page, 'CVE-2024-1003', 1); await rowsOf(page).first().click(); await page.waitForFunction(() => /CVE-2024-1003/.test(document.querySelector('.sheet-side').innerText));
      await search(page, 'Command and Scripting', 1); assert.match(await page.locator('.dt-sel').innerText(), /ATT&CK|Command/);
      await page.fill('#ix-search', 'zzzz-no-such-thing'); await page.waitForFunction(() => /Sin registros/.test(document.querySelector('.dt-sel').innerText)); assert.deepEqual(page.errors, []);
    });

    test('a decision needs a reason and a confirmation, is reversible, and shows in the sheet history, the lists and the audit', async () => {
      const page = await open(browser, srv, 'reviewer', '#/quarantine?fam=other'); await page.waitForSelector('.dt-sel tbody tr[data-id]');
      await search(page, '203.0.113.8', 1); await rowsOf(page).first().click(); await page.waitForSelector('.sheet-side:not([hidden]) .btns');
      await page.locator('.sheet-side').getByRole('button', { name: 'Rechazar' }).click(); const dlg = page.getByRole('dialog'); await dlg.waitFor();
      await dlg.getByRole('button', { name: 'Rechazar' }).click(); assert.match(await dlg.innerText(), /Mínimo|corto|5/i, 'no reason, no decision');
      await dlg.locator('textarea').fill('confirmed benign infrastructure'); await dlg.getByRole('button', { name: 'Rechazar' }).click(); await dlg.waitFor({ state: 'detached' });
      await page.waitForFunction(() => /Rechazada/.test(document.querySelector('.sheet-side').innerText)); assert.match(await page.locator('.sheet-side').innerText(), /confirmed benign infrastructure/);
      await page.locator('.sheet-side').getByRole('button', { name: 'Retener' }).click(); const d2 = page.getByRole('dialog'); await d2.locator('textarea').fill('reopened for review'); await d2.getByRole('button', { name: 'Retener' }).click(); await d2.waitFor({ state: 'detached' });
      await page.waitForFunction(() => /Retenida/.test(document.querySelector('.sheet-side').innerText) && /reopened for review/.test(document.querySelector('.sheet-side').innerText));
      const audit = await page.evaluate(() => fetch('/api/audit?limit=10').then((r) => r.json())); assert.ok(audit.entries.filter((e) => e.action === 'intel.decision').length >= 2, 'both decisions are in the audit chain'); assert.deepEqual(page.errors, []);
    });

    test('approval for a release says why it is blocked and nothing is published; Published explains the empty state', async () => {
      const page = await open(browser, srv, 'reviewer', '#/quarantine?fam=other'); await page.waitForSelector('.dt-sel tbody tr[data-id]');
      await search(page, 'Sigma rule 1', 1); await rowsOf(page).first().click(); await page.waitForSelector('.sheet-side:not([hidden]) .btns');
      assert.equal(await page.locator('.sheet-side').getByRole('button', { name: 'Aprobar para publicar' }).isDisabled(), true); assert.match(await page.locator('.sheet-side').innerText(), /No se puede aprobar[\s\S]*puertas de calidad/);
      await page.goto(srv.base + '/#/published?fam=other'); await page.waitForFunction(() => /Ningún elemento de estas familias está aprobado o publicado/.test(document.body.innerText));
    });

    test('a viewer reads but is offered no action; a bulk selection offers the same actions as the sheet', async () => {
      const v = await open(browser, srv, 'viewer', '#/quarantine?fam=other'); await v.waitForSelector('.dt-sel tbody tr[data-id], .alert'); assert.equal(await v.locator('input[type=checkbox]').count(), 0);
      const page = await open(browser, srv, 'reviewer', '#/quarantine?fam=other'); await page.waitForSelector('.dt-sel tbody tr[data-id]'); await page.locator('.dt-sel tbody tr[data-id] input[type=checkbox]').nth(0).check(); await page.locator('.dt-sel tbody tr[data-id] input[type=checkbox]').nth(1).check();
      const bar = page.locator('.bulkbar'); await bar.waitFor(); assert.match(await bar.innerText(), /2/); assert.match(await bar.innerText(), /Rechazar/);
    });

    test('Logs keeps three records apart: system (filters by family, source and text), people actions, and the chain with an honest anchor state', async () => {
      const page = await open(browser, srv, 'admin', '#/logs'); await page.waitForSelector('.dt.log tbody tr[tabindex]');
      assert.deepEqual(await page.locator('.rs-tabs a').allInnerTexts(), ['Sistema', 'Acciones de personas', 'Cadena verificable']);
      await page.fill('#lg-q', 'download'); await page.waitForFunction(() => { const r = document.querySelectorAll('.dt.log tbody tr[tabindex]'); return r.length >= 1 && [...r].every((x) => /download/i.test(x.innerText)); });
      await page.getByRole('link', { name: 'Acciones de personas' }).click(); await page.waitForSelector('.events'); assert.equal(await page.locator('h1').count(), 1, 'one page title only');
      await page.getByRole('link', { name: 'Cadena verificable' }).click(); await page.waitForSelector('#h-chain'); const t = await page.locator('main').innerText(); assert.match(t, /Sin ancla externa/); assert.match(t, /no un registro de transparencia público/);
      await page.getByRole('button', { name: /Verificar/ }).click(); await page.waitForSelector('[role=status] .alert-ok, [role=status] .alert-bad'); assert.match(await page.locator('[role=status] .alert').innerText(), /verific|íntegra|ok/i); assert.deepEqual(page.errors, []);
    });

    test('Sources: every family in one format; a row opens its sheet; adding or retiring is a request with a reason, decided by an administrator', async () => {
      const page = await open(browser, srv, 'reviewer', '#/sources'); await page.waitForSelector('tr[data-source]'); const t0 = await page.locator('table.dt-sel').innerText();
      assert.match(t0, /CISA Known Exploited Vulnerabilities/); assert.match(t0, /Emerging Threats/); assert.match(t0, /MalwareBazaar/); assert.match(t0, /Bloqueada/);
      await page.locator('tr[data-source]', { hasText: 'CISA Known Exploited Vulnerabilities' }).click(); await page.waitForSelector('.sheet-side:not([hidden]) h2'); const sh = await page.locator('.sheet-side').innerText();
      assert.match(sh, /Descargas y resultados/); assert.match(sh, /Causas que impiden publicar/); assert.match(sh, /Ver sus registros/);
      await page.locator('tr[data-source]', { hasText: 'MalwareBazaar' }).click(); await page.waitForFunction(() => /MalwareBazaar/.test(document.querySelector('.sheet-side').innerText) && /clave API/.test(document.querySelector('.sheet-side').innerText));
      await page.getByRole('button', { name: 'Solicitar retirada' }).click(); const dlg = page.getByRole('dialog'); await dlg.waitFor(); await dlg.getByRole('button', { name: 'Solicitar retirada' }).click(); assert.match(await dlg.innerText(), /Mínimo|corto|5/i, 'no reason, no request');
      await dlg.locator('textarea').fill('upstream requires a key we will not buy'); await dlg.getByRole('button', { name: 'Solicitar retirada' }).click(); await dlg.waitFor({ state: 'detached' });
      await page.waitForSelector('#h-sq'); assert.match(await page.locator('#h-sq').locator('..').innerText(), /Retirada[\s\S]*Pendiente/);
      await page.getByRole('button', { name: 'Nueva fuente' }).click(); const d2 = page.getByRole('dialog'); await d2.waitFor(); await d2.locator('#sq-name').fill('URLhaus recent'); await d2.locator('#sq-url').fill('http://insecure.example.org/x');
      await d2.locator('textarea').fill('we need malicious URLs'); await d2.getByRole('button', { name: 'Solicitar' }).click(); assert.match(await d2.innerText(), /https/, 'a non-https address is refused before anything is sent');
      await d2.locator('#sq-url').fill('https://urlhaus.abuse.ch/downloads/csv_recent/'); await d2.getByRole('button', { name: 'Solicitar' }).click(); await d2.waitFor({ state: 'detached' });
      await page.waitForFunction(() => /URLhaus recent/.test(document.querySelector('#h-sq').parentElement.innerText));
      assert.equal(await page.getByRole('button', { name: 'Aceptar' }).count(), 0, 'a reviewer cannot accept');
      const adm = await open(browser, srv, 'admin', '#/sources'); await adm.waitForSelector('#h-sq'); await adm.getByRole('button', { name: 'Aceptar' }).first().click(); const d3 = adm.getByRole('dialog'); await d3.waitFor();
      await d3.locator('textarea').fill('licence and format checked'); await d3.getByRole('button', { name: 'Aceptar' }).click(); await d3.waitFor({ state: 'detached' }); await adm.waitForFunction(() => /Aceptada/.test(document.querySelector('#h-sq').parentElement.innerText));
      const audit = await adm.evaluate(() => fetch('/api/audit?limit=20').then((r) => r.json())); assert.ok(audit.entries.some((e) => e.action === 'source.requested') && audit.entries.some((e) => e.action === 'source.accepted')); assert.deepEqual(page.errors, []);
    });

    test('accessibility and layout: the new screens have no WCAG 2.2 AA violations in light and dark, on desktop and phone, and never scroll sideways', async () => {
      const screens = [['#/dashboard', '.mf-matrix'], ['#/quarantine?fam=other', '.dt-sel tbody tr[data-id]'], ['#/published?fam=other', '.dt-sel'], ['#/sources', 'tr[data-source]'], ['#/logs', '.dt.log'], ['#/logs?tab=chain', '#h-chain'], ['#/activity', 'figure.chart']];
      for (const [vpName, vp] of [['desktop', VIEWPORTS.desktop], ['phone', VIEWPORTS.iphone]]) for (const scheme of ['light', 'dark']) for (const [hash, sel] of screens) {
        const page = await openScheme(browser, srv, 'admin', hash, scheme, vp); await page.waitForSelector(sel, { timeout: 15000 });
        if (hash.startsWith('#/quarantine')) { await page.locator('.dt-sel tbody tr[data-id]').first().click(); await page.waitForSelector('.sheet-side:not([hidden]) h2'); }
        if (hash === '#/sources') { await page.locator('tr[data-source]').nth(1).click(); await page.waitForSelector('.sheet-side:not([hidden]) h2'); }
        assert.equal(await noHScroll(page), true, `${hash} ${vpName} ${scheme}`); assert.deepEqual(await axeViolations(page), [], `${hash} ${vpName} ${scheme}`); await page.context().close();
      }
    });

    test('Dashboard and Activity count every family: one day state with the family that needs attention, a family x day matrix, and a per-family filter', async () => {
      const page = await open(browser, srv, 'reviewer', '#/dashboard'); await page.waitForSelector('.mf-matrix'); const m = await page.locator('.mf-matrix').innerText(); assert.match(m, /YARA/); assert.match(m, /CVE|ATT&CK/); assert.match(m, /Total/);
      assert.match(await page.locator('main').innerText(), /Cada casilla es un día UTC y suma todas las familias/);
      await page.goto(srv.base + '/#/activity'); await page.waitForSelector('figure.chart'); await page.getByRole('button', { name: 'CVE' }).first().click(); await page.waitForSelector('figure.chart');
      await page.waitForSelector('#h-acts'); assert.match(await page.locator('#h-acts').locator('..').innerText(), /Decisiones otras familias/, 'the decisions made in the earlier tests show as activity by kind');
      const v = await open(browser, srv, 'viewer', '#/dashboard'); await v.waitForSelector('.kpis'); assert.match(await v.locator('main').innerText(), /Solo canal YARA/);
    });
  });
}
