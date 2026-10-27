// The five roles in the real browsers: what each one sees and can do on screen, the Administration area for ADMIN only (users and the live permission matrix), and the same checks on the server side.
// UI_ENGINES=chromium,firefox,webkit (default: chromium only).
import test, { describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { chromium, firefox, webkit } from 'playwright';
import { startServer, openAs, VIEWPORTS } from './harness.mjs';

const AXE = readFileSync(createRequire(import.meta.url).resolve('axe-core/axe.min.js'), 'utf8');
const ENGINES = { chromium, firefox, webkit }, WANT = (process.env.UI_ENGINES || 'chromium').split(','), WCAG = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];
async function open(browser, srv, role, hash, scheme = 'light', vp = VIEWPORTS.desktop) {
  const ctx = await openAs(browser, srv, role, vp, { colorScheme: scheme }); const page = await ctx.newPage(); page.errors = [];
  page.on('console', (m) => { if (m.type() === 'error' && !/status of 4\d\d/.test(m.text()) && !(page.axeRan && /Refused to apply a stylesheet/.test(m.text()))) page.errors.push(m.text()); });
  await page.goto(srv.base + '/' + hash, { waitUntil: 'domcontentloaded' }); await page.waitForSelector('#page-title'); return page;
}
async function axeViolations(page) { assert.deepEqual(page.errors, [], 'no console error before axe runs'); page.axeRan = true; await page.evaluate(AXE); const r = await page.evaluate((tags) => axe.run(document, { runOnly: { type: 'tag', values: tags }, resultTypes: ['violations'] }), WCAG); return r.violations.map((v) => `${v.id} (${v.impact}): ${v.nodes.slice(0, 3).map((n) => n.target.join(' ')).join(' | ')}`); }
const nav = (page) => page.locator('.sidebar .nav a').allInnerTexts();
const status = (page, path, method = 'GET') => page.evaluate(async ([p, m]) => { const me = await fetch('/api/me').then((r) => r.json()); const r = await fetch(p, { method: m, headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': me.csrf }, body: m === 'GET' ? undefined : '{}' }); return r.status; }, [path, method]);

for (const name of WANT) {
  describe(name, () => {
    let browser, srv;
    before(async () => { browser = await ENGINES[name].launch(); srv = await startServer(['--published']); });
    after(async () => { await browser.close(); srv.stop(); });

    test('each role sees exactly its navigation; Administration only for ADMIN; the server agrees with the screen', async () => {
      const want = { viewer: ['Panel', 'Cuarentena', 'Publicadas', 'Actividad', 'Fuentes'], reviewer: ['Panel', 'Cuarentena', 'Publicadas', 'Inteligencia', 'Actividad', 'Logs', 'Fuentes', 'Restauración', 'Auditoría'],
        publisher: ['Panel', 'Cuarentena', 'Publicadas', 'Inteligencia', 'Actividad', 'Logs', 'Fuentes'], security: ['Panel', 'Cuarentena', 'Publicadas', 'Inteligencia', 'Actividad', 'Logs', 'Fuentes', 'Restauración', 'Auditoría'],
        admin: ['Panel', 'Cuarentena', 'Publicadas', 'Inteligencia', 'Actividad', 'Logs', 'Fuentes', 'Restauración', 'Auditoría', 'Administración'] };
      for (const [role, links] of Object.entries(want)) { const page = await open(browser, srv, role, '#/dashboard'); assert.deepEqual(await nav(page), links, role); assert.deepEqual(page.errors, [], role); }
      const pub = await open(browser, srv, 'publisher', '#/dashboard'), sec = await open(browser, srv, 'security', '#/dashboard');
      assert.equal(await status(pub, '/api/members'), 403); assert.equal(await status(sec, '/api/members'), 403); assert.equal(await status(pub, '/api/audit'), 403, 'a publisher does not read the audit'); assert.equal(await status(sec, '/api/audit'), 200);
      assert.equal(await status(pub, '/api/decisions', 'POST'), 403, 'a publisher does not review'); assert.equal(await status(sec, '/api/policies/withdrawals', 'POST'), 403, 'a security administrator does not withdraw'); assert.equal(await status(sec, '/api/restore/event', 'POST'), 400, 'a drill step is allowed (the body is then validated)');
      await pub.goto(srv.base + '/#/admin'); await pub.waitForSelector('#page-title'); assert.doesNotMatch(await pub.locator('main').innerText(), /Usuarios y permisos/, 'typing the address does not open the Administration area');
    });

    test('a publisher sees the withdrawal and revocation actions on a published rule but no review controls; a security administrator sees neither', async () => {
      for (const [role, expectWithdraw] of [['publisher', true], ['security', false], ['reviewer', false]]) {
        const page = await open(browser, srv, role, '#/published'); await page.waitForSelector('.rule a.rule-title'); await page.fill('#p-search', 'pack_006'); await page.waitForFunction(() => document.querySelectorAll('.rule').length === 1); await page.locator('.rule a.rule-title').click(); await page.waitForSelector('#h-code');
        assert.equal(await page.locator('#pf-adopt, #pf-withdraw, #pf-revoke').count() > 0, expectWithdraw, role);
      }
      const admin = await open(browser, srv, 'admin', '#/quarantine'); await admin.waitForSelector('.rule'); assert.ok(await admin.locator('.rule input[type=checkbox]').count() > 0, 'an admin can select candidates');
      const pub = await open(browser, srv, 'publisher', '#/quarantine'); await pub.waitForSelector('.rule'); assert.equal(await pub.locator('.rule input[type=checkbox]').count(), 0, 'a publisher cannot decide on candidates: no selection boxes');
    });

    test('Administration: users and permissions with five roles in the editor, and the live matrix; a role grant to a verified identity appears with its label', async () => {
      const page = await open(browser, srv, 'admin', '#/admin'); await page.waitForSelector('.person'); assert.match(await page.locator('main').innerText(), /Usuarios y permisos/);
      const card = page.locator('.person', { has: page.locator('strong:text-is("pat")') }); assert.match(await card.innerText(), /Publicador/); const sec = page.locator('.person', { has: page.locator('strong:text-is("sec")') }); assert.match(await sec.innerText(), /Administrador de seguridad/);
      await card.getByRole('button', { name: 'Cambiar rol' }).click(); const dlg = page.locator('dialog[open]'); await dlg.waitFor(); assert.equal(await dlg.locator('input[type=radio]').count(), 5, 'five roles to choose from'); for (const r of ['Lector', 'Revisor', 'Publicador', 'Administrador de seguridad', 'Administrador']) assert.ok((await dlg.innerText()).includes(r), r);
      await dlg.getByRole('button', { name: 'Cancelar' }).click();
      await page.getByRole('button', { name: 'Matriz de permisos' }).click(); await page.waitForSelector('.dt'); const m = await page.locator('main').innerText(); assert.match(m, /Publicaciones/); assert.match(m, /publication\.withdraw\.request/); assert.match(m, /requiere segunda identidad|crítica/); assert.match(m, /Tus roles: Administrador/);
      assert.ok(await page.locator('.dt tbody tr').count() > 35, 'every permission is listed'); assert.deepEqual(page.errors, []);
      const sec2 = await open(browser, srv, 'security', '#/admin?tab=matrix'); assert.doesNotMatch(await sec2.locator('main').innerText(), /publication\.withdraw\.request/, 'the matrix is not shown to non-administrators');
    });

    for (const scheme of ['light', 'dark']) test(`WCAG 2.2 AA of the Administration screens — ${scheme}`, async () => {
      const page = await open(browser, srv, 'admin', '#/admin', scheme); await page.waitForSelector('.person'); assert.deepEqual(await axeViolations(page), [], `users ${scheme}`);
      await page.goto(srv.base + '/#/admin?tab=matrix'); await page.waitForSelector('.dt'); assert.deepEqual(await axeViolations(page), [], `matrix ${scheme}`);
    });
  });
}
