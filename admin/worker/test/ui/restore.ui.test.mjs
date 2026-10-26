// Restauración y recuperación in real browsers against the real Worker handler (faked GitHub, synthetic backup records): navigation by role, honest states, the step assistant (a step is done only when its check
// passes), parameter safety, ES/EN, responsive layout and WCAG 2.2 AA (axe) in both themes. UI_ENGINES=chromium,firefox,webkit (default: chromium only, to spare the machine).
import test, { describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { chromium, firefox, webkit } from 'playwright';
import { startServer, openAs, VIEWPORTS } from './harness.mjs';

const AXE = readFileSync(createRequire(import.meta.url).resolve('axe-core/axe.min.js'), 'utf8');
const ENGINES = { chromium, firefox, webkit }, WANT = (process.env.UI_ENGINES || 'chromium').split(','), WCAG = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];
async function newPage(browser, srv, role, vp, opts = {}) {
  const ctx = await openAs(browser, srv, role, vp, opts); const page = await ctx.newPage(); page.errors = []; page.scheme = opts.colorScheme;
  page.on('console', (m) => { if (m.type() === 'error' && !/status of 4\d\d/.test(m.text()) && !(page.axeRan && /Refused to apply a stylesheet/.test(m.text()))) page.errors.push(m.text()); });   // WebKit reports the <style> that axe-core itself injects: ignored only after axe ran, and the app's own sheets are checked before page.on('pageerror', (e) => page.errors.push(String(e)));
  await page.route(/^https:\/\/github\.com\//, (r) => r.fulfill({ status: 200, contentType: 'text/html', body: '<title>GitHub</title>' })); return page;
}
const goto = async (page, srv, hash) => { await page.goto(srv.base + hash, { waitUntil: 'domcontentloaded' }); if (page.scheme) await page.emulateMedia({ colorScheme: page.scheme }); await page.waitForSelector('#page-title'); };
async function axeViolations(page) { assert.deepEqual(page.errors, [], 'no console error before axe runs'); page.axeRan = true; await page.evaluate(AXE); const r = await page.evaluate((tags) => axe.run(document, { runOnly: { type: 'tag', values: tags }, resultTypes: ['violations'] }), WCAG); return r.violations.map((v) => `${v.id} (${v.impact}): ${v.nodes.slice(0, 3).map((n) => n.target.join(' ')).join(' | ')}`); }
const noHScroll = (page) => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1);

for (const name of WANT) {
  describe(name, () => {
    let browser, srv, srvDown;
    before(async () => { browser = await ENGINES[name].launch(); srv = await startServer(); srvDown = await startServer([], { restoreDown: 'runs' }); });
    after(async () => { await browser.close(); srv.stop(); srvDown.stop(); });

    test('navigation by role: a reviewer and an admin see the Restauración entry; a viewer neither sees it nor can open it', async () => {
      for (const role of ['reviewer', 'admin']) { const page = await newPage(browser, srv, role, VIEWPORTS.desktop); await goto(page, srv, '/#/dashboard'); assert.equal(await page.getByRole('link', { name: 'Restauración' }).count(), 1, role); await page.getByRole('link', { name: 'Restauración' }).click(); await page.waitForSelector('h1:has-text("Restauración y recuperación")'); assert.deepEqual(page.errors, []); }
      const v = await newPage(browser, srv, 'viewer', VIEWPORTS.desktop); await goto(v, srv, '/#/dashboard'); assert.equal(await v.getByRole('link', { name: 'Restauración' }).count(), 0);
      await v.goto(srv.base + '/#/restore'); await v.waitForSelector('#page-title'); assert.notEqual(await v.locator('h1').innerText(), 'Restauración y recuperación', 'a viewer is sent elsewhere');
      const r = await v.evaluate(() => fetch('/api/restore/status').then((x) => x.status)); assert.equal(r, 403);
    });

    test('status: real states with dates and sources; the copies and the signature are VERIFIED, what only the owner can know stays UNKNOWN or NOT RUN', async () => {
      const page = await newPage(browser, srv, 'reviewer', VIEWPORTS.desktop); await goto(page, srv, '/#/restore');
      await page.waitForSelector('.rs-ind');
      const card = (title) => page.locator('.rs-ind', { has: page.getByRole('heading', { name: title, exact: true }) });
      assert.match(await card('Último backup creado').innerText(), /Verificado/); assert.match(await card('Último backup firmado').innerText(), /Verificado/); assert.match(await card('Copias comprobadas').innerText(), /3 \/ 3/);
      assert.match(await card('Último checkpoint confirmado fuera').innerText(), /Desconocido/); assert.match(await card('Última restauración exitosa').innerText(), /No ejecutado/); assert.match(await card('RTO observado (simulacros)').innerText(), /No ejecutado/);
      assert.match(await card('Secretos necesarios (sin valores)').innerText(), /Desconocido/); assert.match(await card('Backblaze B2').innerText(), /Verificado/); assert.match(await card('Último backup creado').innerText(), /GitHub Actions run 5001/);
      assert.match(await page.locator('.rs-pol, section.card').first().innerText(), /age1synthetic/); assert.deepEqual(page.errors, []);
      await page.getByRole('button', { name: 'EN' }).click(); await page.waitForSelector('h1:has-text("Restore and recovery")'); assert.match(await page.locator('.rs-ind').first().innerText(), /Last backup created|Verified/);
    });


    test('a failed export reads as ONE actionable alert on the dashboard and the status tab: cause, since when, what is at risk, last recoverable copy, real links; the skipped phases are not corrupt copies', async () => {
      const bad = await startServer([], { restoreFails: true }); try {
        const page = await newPage(browser, bad, 'reviewer', VIEWPORTS.desktop); await goto(page, bad, '/#/dashboard'); await page.waitForSelector('.alert-card');
        const card = page.locator('.alert-card').first(), txt = await card.innerText();
        assert.match(txt, /Cloudflare rechazó la autenticación/); assert.match(txt, /código 10000/); assert.match(txt, /Account → D1 → Edit/); assert.match(txt, /Última copia recuperable/i); assert.match(txt, /no hay copias dañadas/); assert.match(txt, /Es seguro/);
        assert.equal(await page.locator('.alert-card').count(), 1, 'one alert, not three corrupt copies'); assert.equal(await card.locator('a[href*="/actions/runs/5002"]').count(), 1); assert.equal(await card.locator('a[href*="d1-token-probe.yml"]').count(), 1);
        assert.deepEqual(await axeViolations(page), [], 'dashboard with the alert meets WCAG 2.2 AA'); assert.deepEqual(page.errors, []);
        await page.getByRole('link', { name: 'Restauración' }).click(); await page.waitForSelector('.alert-card'); assert.match(await page.locator('.alert-card').first().innerText(), /Base de datos D1 de la analítica/);
        const viewer = await newPage(browser, bad, 'viewer', VIEWPORTS.desktop); await goto(viewer, bad, '/#/dashboard'); assert.equal(await viewer.locator('.alert-card').count(), 0, 'a viewer cannot read the recovery status');
      } finally { bad.stop(); }
    });

    test('GitHub unreadable: the run-derived indicators say UNKNOWN (never FAILED or NOT RUN) and the screen says which source is missing', async () => {
      const ctx = await openAs(browser, srvDown, 'reviewer', VIEWPORTS.desktop); const page = await ctx.newPage(); await page.goto(srvDown.base + '/#/restore'); await page.waitForSelector('.rs-ind');
      assert.match(await page.locator('.rs-ind', { has: page.getByRole('heading', { name: 'Último backup creado', exact: true }) }).innerText(), /Desconocido/); assert.match(await page.locator('[role=status].alert-warn').innerText(), /backup_runs/);
    });

    test('inventory: one row per run and provider, the failed export is not recoverable, filters work, nothing is "recoverable" for merely existing', async () => {
      const page = await newPage(browser, srv, 'reviewer', VIEWPORTS.desktop); await goto(page, srv, '/#/restore?tab=inventory'); await page.waitForSelector('.rs-table tbody tr');
      assert.equal(await page.locator('.rs-table tbody tr').count(), 6, '2 backup runs x 3 providers'); const text = await page.locator('.rs-table tbody').innerText();
      assert.equal((text.match(/Autenticada, no restaurada/g) || []).length, 3); assert.equal((text.match(/Sin verificar/g) || []).length, 3); assert.doesNotMatch(text, /Restauración demostrada/);
      await page.selectOption('#f-prov', 'b2'); assert.equal(await page.locator('.rs-table tbody tr').count(), 2); await page.selectOption('#f-prov', ''); await page.selectOption('#f-state', 'AUTHENTICATED'); assert.equal(await page.locator('.rs-table tbody tr').count(), 3);
      await page.fill('#f-seq', '5'); assert.match(await page.locator('.rs-table tbody').innerText(), /Ninguna copia coincide/);
    });

    test('assistant: a step is done only when its check passes; wrong output does not advance; "Next" stays disabled; progress survives a reload; secrets pasted are refused and discarded', async () => {
      const page = await newPage(browser, srv, 'reviewer', VIEWPORTS.desktop); await goto(page, srv, '/#/restore?tab=assistant'); await page.getByRole('heading', { name: 'Simulacro de recuperación (sin afectar producción)' }).waitFor();
      await page.locator('.rs-procs li', { hasText: 'Simulacro' }).getByRole('button').click(); await page.waitForSelector('.rs-detail h2'); await page.getByRole('button', { name: 'Simulacro con evidencias' }).click(); assert.match(await page.locator('.rs-step-link[aria-current=step]').innerText(), /Equipo: sistema operativo/);
      const next = page.getByRole('button', { name: 'Siguiente' }); assert.equal(await next.isDisabled(), true);
      await page.locator('#ob-machine_os').fill('Windows x64'); await page.getByRole('button', { name: 'Comprobar', exact: true }).click(); assert.match(await page.locator('.rs-result').innerText(), /NO coincide/); assert.equal(await next.isDisabled(), true); assert.match(await page.locator('.rs-result').innerText(), /Darwin arm64/);
      await page.locator('#ob-machine_os').fill('Darwin arm64'); await page.getByRole('button', { name: 'Comprobar', exact: true }).click(); await page.waitForSelector('.alert-ok'); assert.equal(await next.isDisabled(), false);
      await page.reload({ waitUntil: 'domcontentloaded' }); await page.waitForSelector('.rs-detail h2'); assert.match(await page.locator('.rs-step-link').first().innerText(), /Hecho/); assert.equal(await page.evaluate(() => JSON.stringify(Object.keys(localStorage).filter((k) => k.startsWith('mg_restore_v1_')))), '["mg_restore_v1_drill"]');
      const stored = await page.evaluate(() => localStorage.getItem('mg_restore_v1_drill')); assert.doesNotMatch(stored, /Darwin|AGE-SECRET|observed/, 'only identifiers and states are stored');
      await next.click(); await page.getByRole('button', { name: /Herramientas instaladas|Equipo: herramientas/ }).first().waitFor().catch(() => {}); await page.locator('.rs-step-link', { hasText: 'herramientas instaladas' }).click();
      await page.locator('#ob-machine_tools').fill('OK cosign\n' + ['AGE', 'SECRET', 'KEY', '1QYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQS'].join('-') + ''); await page.getByRole('button', { name: 'Comprobar', exact: true }).click();
      assert.match(await page.locator('.rs-result').innerText(), /parece una clave/); assert.equal(await page.locator('#ob-machine_tools').inputValue(), '', 'the pasted secret is discarded from the field');
    });

    test('parameters: a hostile value is flagged and the command is never rendered; valid values render a quoted command, and the copy button holds exactly what is shown', async () => {
      const page = await newPage(browser, srv, 'reviewer', VIEWPORTS.desktop); await goto(page, srv, '/#/restore?tab=assistant&proc=drill'); await page.getByRole('button', { name: 'Simulacro con evidencias' }).click(); 
      await page.locator('.rs-step-link', { hasText: 'Descargar la copia con la credencial READ' }).click(); assert.match(await page.locator('.rs-detail').innerText(), /se muestran cuando completes los requisitos/); assert.equal(await page.locator('.rs-cmd, textarea').count(), 0, 'a blocked step shows no command and no check');
      await page.evaluate(() => localStorage.setItem('mg_restore_v1_drill', JSON.stringify({ run: 'aaaaaaaa-bbbb', values: {}, idx: 0, steps: { pick_backup: { state: 'done' }, bw_unlock: { state: 'done' } } }))); await page.reload({ waitUntil: 'domcontentloaded' }); await page.waitForSelector('.rs-detail h2');
      await page.locator('.rs-step-link', { hasText: 'Descargar la copia con la credencial READ' }).click();
      const stamp = page.locator('#pv-drill-stamp'), prov = page.locator('#pv-drill-provider');
      await stamp.fill('20261025T032300Z; rm -rf ~'); await stamp.blur(); await prov.fill('b2'); await prov.blur();
      assert.equal(await page.locator('#pv-drill-stamp').getAttribute('aria-invalid'), 'true'); assert.equal(await page.locator('.rs-code', { hasText: 'rm -rf' }).count(), 0); assert.match(await page.locator('.alert-warn[role=status]', { hasText: 'Rellena primero' }).innerText(), /Sello del backup/);
      await page.locator('#pv-drill-stamp').fill('20261025T032300Z'); await page.locator('#pv-drill-stamp').blur(); await page.waitForSelector('.rs-cmd');
      const shown = await page.locator('.rs-cmd .rs-code code').innerText(); assert.match(shown, /--only b2 --stamp 20261025T032300Z /); assert.doesNotMatch(shown, /rm -rf|;\s*rm/);
      await page.context().grantPermissions(['clipboard-read', 'clipboard-write']).catch(() => {}); await page.getByRole('button', { name: 'Copiar comando' }).click();
      const copied = await page.evaluate(() => navigator.clipboard.readText().catch(() => null)); if (copied !== null) assert.equal(copied, shown, 'the clipboard holds exactly the displayed command');
      await prov.fill("b2'; id #"); await prov.blur(); assert.equal(await page.locator('.rs-cmd').count(), 0, 'the command disappears when a value stops being valid');
    });

    test('permissions: a reviewer reads a protected procedure but cannot record steps; an admin can; the compromise procedure starts with declaration and containment', async () => {
      const rev = await newPage(browser, srv, 'reviewer', VIEWPORTS.desktop); await goto(rev, srv, '/#/restore?tab=assistant&proc=compromise');
      assert.match(await rev.locator('.rs-detail').innerText(), /Modo lectura/); assert.equal(await rev.locator('.rs-detail textarea, .rs-detail .rs-attest').count(), 0);
      const names = await rev.locator('.rs-step-link span:nth-child(2)').allInnerTexts(); assert.match(names[0], /Declarar el incidente/); assert.match(names[1], /Contención inicial/);
      const adm = await newPage(browser, srv, 'admin', VIEWPORTS.desktop); await goto(adm, srv, '/#/restore?tab=assistant&proc=compromise'); await adm.getByRole('button', { name: 'Recuperación real' }).click(); assert.equal(await adm.locator('.rs-detail .rs-attest').count(), 1, 'the first step asks for an attestation');
      await adm.getByRole('button', { name: 'Confirmar y registrar' }).click(); assert.match(await adm.locator('.rs-attest .rs-bad').innerText(), /Marca todas/);
      const confirm = async () => { for (const c of await adm.locator('.rs-attest input[type=checkbox]').all()) await c.check(); await adm.getByRole('button', { name: 'Confirmar y registrar' }).click(); };
      await confirm(); await adm.getByText(/autorización de dos identidades/).first().waitFor({ timeout: 8000 });
      await adm.waitForTimeout(500); const refused = await adm.evaluate(() => fetch('/api/audit?family=restore').then((r) => r.json())); assert.ok(!refused.entries.some((e) => e.action === 'restore.step_done' && e.target === 'compromise'), 'nothing was recorded without the authorisation of two identities (the recorded path is covered in approvals_api.test.js)');
      return;
      let audit; for (let i = 0; i < 20; i++) { audit = await adm.evaluate(() => fetch('/api/audit?family=restore').then((r) => r.json())); if (audit.entries.some((e) => e.action === 'restore.step_done' && e.target === 'compromise')) break; await adm.waitForTimeout(150); } assert.ok(audit.entries.some((e) => e.action === 'restore.step_done' && e.target === 'compromise'), 'recorded in the audit chain');
    });

    for (const [vpName, vp] of [['desktop', VIEWPORTS.desktop], ['phone', VIEWPORTS.iphone]]) for (const scheme of ['light', 'dark']) test(`layout and WCAG 2.2 AA: status, assistant step and inventory — ${vpName}, ${scheme}`, async () => {
      const page = await newPage(browser, srv, 'admin', vp, { colorScheme: scheme });
      for (const hash of ['/#/restore', '/#/restore?tab=assistant&proc=drill', '/#/restore?tab=inventory']) {
        await goto(page, srv, hash); await page.waitForSelector('.rs-ind, .rs-detail, .rs-table'); assert.equal(await noHScroll(page), true, `${hash}: no horizontal page scroll`);
        const v = await axeViolations(page); assert.deepEqual(v, [], `${hash} ${scheme}`);
      }
      await goto(page, srv, '/#/restore?tab=assistant&proc=drill'); await page.getByRole('button', { name: 'Simulacro con evidencias' }).click(); await page.waitForSelector('.rs-detail h2');
      assert.deepEqual(await axeViolations(page), [], `run mode ${scheme}`); assert.deepEqual(page.errors, []);
    });

    test('guide mode: a reviewer walks every step of a protected procedure with Next and Previous, each blocked Next says why, nothing is recorded, and the progress survives a reload', async () => {
      const page = await newPage(browser, srv, 'reviewer', VIEWPORTS.desktop); const posts = []; page.on('request', (r) => { if (r.method() === 'POST' && /\/api\/restore\/event/.test(r.url())) posts.push(r.url()); });
      await goto(page, srv, '/#/restore?tab=assistant&proc=compromise'); const total = await page.locator('.rs-step-link').count(); assert.ok(total >= 5);
      const next = page.getByRole('button', { name: 'Siguiente' }), prev = page.getByRole('button', { name: 'Anterior' });
      assert.equal(await page.getByRole('button', { name: 'Recuperación real' }).isDisabled(), true); assert.match(await page.locator('#rs-mode-note').innerText(), /Solo un ADMIN/);
      for (let i = 0; i < total; i++) {
        const last = i === total - 1;
        if (!last) { assert.equal(await next.isDisabled(), true, `step ${i + 1}: Next waits for the read confirmation`); assert.match(await page.locator('#rs-next-h').innerText(), /He leído este paso/, 'the reason is visible next to the button'); }
        await page.getByRole('button', { name: 'He leído este paso' }).click(); assert.match(await page.locator('.alert-ok').innerText(), /Paso leído/);
        if (!last) { assert.equal(await next.isDisabled(), false); await next.click(); await page.waitForFunction((n) => document.querySelector('.rs-step-head .note').textContent.includes(`${n} /`), i + 2); }
      }
      assert.equal(await next.isDisabled(), true); assert.match(await page.locator('#rs-next-h').innerText(), /último paso/);
      await prev.click(); await page.waitForFunction((n) => document.querySelector('.rs-step-head .note').textContent.includes(`${n} /`), total - 1); assert.equal(await next.isDisabled(), false, 'a step already read lets you go forward again');
      assert.deepEqual(posts, [], 'guide mode records nothing in the audit chain'); assert.equal(await page.locator('.rs-step-link.st-done').count(), 0, 'read is not done');
      await page.reload({ waitUntil: 'domcontentloaded' }); await page.waitForSelector('.rs-detail h2'); assert.equal(await page.locator('.rs-step-link.st-read').count(), total);
      const kinds = await page.locator('.rs-step-head .badge-day-info').allInnerTexts(); assert.ok(kinds.length >= 1);
    });

    test('run mode (drill): Next stays disabled until real evidence matches, and the screen says exactly what to do', async () => {
      const page = await newPage(browser, srv, 'reviewer', VIEWPORTS.desktop); await goto(page, srv, '/#/restore?tab=assistant&proc=drill'); await page.getByRole('button', { name: 'Simulacro con evidencias' }).click();
      assert.equal(await page.getByRole('button', { name: 'Siguiente' }).isDisabled(), true); assert.match(await page.locator('#rs-next-h').innerText(), /pega su salida|Marcar como hecho|confirmaciones/);
    });
  });
}
