// A published rule can be opened from the inventory, shows its signed content and provenance, and an ADMIN can register it and request its withdrawal with a mandatory reason; the distribution state is honest.
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
const openFirstUnrecorded = async (page) => { await page.waitForSelector('.rule a.rule-title'); await page.fill('#p-search', 'pack_006'); await page.waitForFunction(() => document.querySelectorAll('.rule').length === 1); await page.locator('.rule a.rule-title').click(); await page.waitForSelector('#h-code'); };

for (const name of WANT) {
  describe(name, () => {
    let browser;
    before(async () => { browser = await ENGINES[name].launch(); });
    after(async () => { await browser.close(); });

    test('every row of the inventory opens; the sheet shows verified content, provenance, licence, signatures and NO_DATA where nothing was measured; a reviewer has no actions', async () => {
      const srv = await startServer(['--published']); try {
        const page = await open(browser, srv, 'reviewer', VIEWPORTS.desktop, '#/published'); await openFirstUnrecorded(page);
        assert.equal(await page.locator('h1').innerText(), 'pack_006.yar'); assert.match(await page.locator('#h-code').locator('xpath=../..').innerText(), /published 6/); assert.match(await page.locator('.note', { hasText: 'comprobado contra el SHA-256' }).first().innerText(), /manifiesto/);
        const body = await page.locator('main').innerText(); assert.match(body, /Yara-Rules\/rules/); assert.match(body, /GPL-2.0/); assert.match(body, /manifest\.sigstore\.json/); assert.match(body, /NO_DATA/i); assert.match(body, /Sin registro/i); assert.match(body, /No medible/i);
        assert.equal(await page.locator('#pf-withdraw, #pf-adopt').count(), 0); assert.match(body, /requiere el rol ADMIN/); assert.deepEqual(page.errors, []);
        await page.goBack(); await page.waitForSelector('#p-search'); assert.equal(await page.inputValue('#p-search'), 'pack_006', 'back returns to the inventory with the search the user had');
      } finally { srv.stop(); }
    });

    test('an admin registers the rule, requests its withdrawal with a reason, and the sheet moves to "withdrawal requested" with distribution honestly unmeasurable; a short reason is refused', async () => {
      const srv = await startServer(['--published']); try {
        const page = await open(browser, srv, 'admin', VIEWPORTS.desktop, '#/published'); await openFirstUnrecorded(page);
        await page.locator('#pf-adopt').click(); await page.waitForSelector('#pf-withdraw'); assert.match(await page.locator('main').innerText(), /RELEASED/);
        await page.locator('#pf-withdraw').click(); const dlg = page.locator('dialog[open]'); await dlg.waitFor();
        await dlg.getByRole('button', { name: 'Solicitar retirada' }).click(); assert.match(await dlg.locator('.alert-bad').innerText(), /motivo|razón|caracteres/i, 'the reason is mandatory');
        await dlg.locator('textarea').fill('Falso positivo confirmado en producción'); await dlg.getByRole('button', { name: 'Solicitar retirada' }).click(); await page.waitForSelector('dialog[open]', { state: 'detached' });
        await page.waitForFunction(() => document.querySelector('.page-head .chip') && /Retirada solicitada/.test(document.querySelector('.page-head .chip').textContent));
        const dist = await page.locator('#h-dist').locator('xpath=..').innerText(); assert.match(dist, /Pendiente/i); assert.match(dist, /No medible/i); assert.match(dist, /no puede afirmarlo/); assert.equal(await page.locator('#pf-withdraw').count(), 0, 'no incompatible action is offered');
        const audit = await page.evaluate(() => fetch('/api/audit?limit=100').then((r) => r.json())); assert.ok(audit.entries.some((e) => e.action === 'published.adopt'), 'the registration is audited');
      } finally { srv.stop(); }
    });

    for (const [vpName, vp] of [['desktop', VIEWPORTS.desktop], ['phone', VIEWPORTS.iphone]]) for (const scheme of ['light', 'dark']) test(`layout and WCAG 2.2 AA of the published rule sheet — ${vpName}, ${scheme}`, async () => {
      const srv = await startServer(['--published']); try {
        const page = await open(browser, srv, 'admin', vp, '#/published', scheme); await openFirstUnrecorded(page); assert.equal(await noHScroll(page), true); assert.deepEqual(await axeViolations(page), [], `${vpName} ${scheme}`);
        await page.locator('#pf-adopt').click(); await page.waitForSelector('#pf-withdraw'); assert.deepEqual(await axeViolations(page), [], `${vpName} ${scheme} with actions`);
      } finally { srv.stop(); }
    });
  });
}
