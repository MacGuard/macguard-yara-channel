// Real browsers (Chromium, Firefox, WebKit) against the real Worker handler and a real in-memory D1; only GitHub is faked.
// Covers: sign-in states, role gating, decision flows, members administration, responsive layout invariants and WCAG 2.2 AA (axe) in both themes and languages.
// UI_ENGINES=chromium,firefox,webkit (default all)   UI_SHOTS=/dir  saves a screenshot of every checked screen for human review.
import test, { describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { chromium, firefox, webkit, devices } from 'playwright';
import { startServer, openAs, VIEWPORTS } from './harness.mjs';

const AXE = readFileSync(createRequire(import.meta.url).resolve('axe-core/axe.min.js'), 'utf8');
const ENGINES = { chromium, firefox, webkit }, WANT = (process.env.UI_ENGINES || 'chromium,firefox,webkit').split(',');
const SHOTS = process.env.UI_SHOTS; if (SHOTS) mkdirSync(SHOTS, { recursive: true });
const WCAG = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];

async function newPage(browser, srv, role, vp, opts = {}) {
  const ctx = await openAs(browser, srv, role, vp, opts); const page = await ctx.newPage();
  page.scheme = opts.colorScheme;
  page.errors = []; page.urls = [];
  page.on('console', (m) => { if (m.type() === 'error' && !/status of 4\d\d/.test(m.text())) page.errors.push(m.text()); }); page.on('pageerror', (e) => page.errors.push(`pageerror: ${e.message}`));
  page.on('request', (r) => page.urls.push(r.url()));
  await page.route(/^https:\/\/github\.com\//, (r) => r.fulfill({ status: 200, contentType: 'text/html', body: '<title>GitHub</title>authorize' }));
  return page;
}
const shot = async (page, name) => { if (SHOTS) await page.screenshot({ path: `${SHOTS}/${name}.png`, fullPage: false }); };
async function axeViolations(page) {
  await page.evaluate(AXE);
  const r = await page.evaluate((tags) => axe.run(document, { runOnly: { type: 'tag', values: tags }, resultTypes: ['violations'] }), WCAG);
  return r.violations.map((v) => `${v.id} (${v.impact}): ${v.nodes.slice(0, 3).map((n) => n.target.join(' ')).join(' | ')} — ${v.help}`);
}
const layout = (page) => page.evaluate(() => {
  const W = document.documentElement.clientWidth, bad = [];
  for (const el of document.querySelectorAll('body *')) {
    if (el.closest('.sr, .skip, dialog:not([open]), svg')) continue; const r = el.getBoundingClientRect(); if (!r.width || !r.height) continue;
    if (r.right > W + 1 || r.left < -1) { let p = el.parentElement, scroller = false; while (p && p !== document.body) { if (getComputedStyle(p).overflowX !== 'visible') { scroller = true; break; } p = p.parentElement; } if (!scroller) bad.push(`${el.tagName.toLowerCase()}.${String(el.className).slice(0, 30)} right=${Math.round(r.right)}`); }
  }
  const sha = [...document.querySelectorAll('.shafull, .sha')].map((e) => ({ h: Math.round(e.getBoundingClientRect().height), full: e.classList.contains('shafull') }));
  return { scrollW: document.documentElement.scrollWidth, W, bad: bad.slice(0, 6), shaTooTall: sha.filter((s) => s.h > (s.full ? 70 : 34)).length };
});
const goto = async (page, srv, hash) => { await page.goto(srv.base + hash, { waitUntil: 'domcontentloaded' }); if (page.scheme) await page.emulateMedia({ colorScheme: page.scheme });   /* Firefox applies the emulation only once a document is loaded */ await page.waitForSelector('h1', { state: 'attached' }); await page.waitForLoadState('networkidle').catch(() => {}); };

for (const name of WANT) {
  describe(`${name}`, () => {
    let browser, srv;
    before(async () => { browser = await ENGINES[name].launch(); srv = await startServer(); });
    after(async () => { await browser.close(); srv.stop(); });
    const mobile = () => (name === 'webkit' ? { viewport: devices['iPhone 14'].viewport, device: { userAgent: devices['iPhone 14'].userAgent, hasTouch: true, isMobile: false } } : { viewport: VIEWPORTS.iphone });

    test('anonymous visitors see only the sign-in screen; nothing about the quarantine is requested or rendered', async () => {
      const page = await newPage(browser, srv, null, VIEWPORTS.desktop); await goto(page, srv, '/');
      assert.equal(await page.locator('h1').innerText(), 'Acceso restringido');
      const btn = page.getByRole('link', { name: 'Continuar con GitHub' }); assert.equal(await btn.getAttribute('href'), '/auth/login'); assert.equal(await btn.locator('svg.ic.fill').count(), 1, 'GitHub mark');
      assert.equal(await page.locator('main svg path[d^="M8 0C3.58"]').count(), 1);
      const text = await page.locator('body').innerText(); assert.doesNotMatch(text, /nextron|rule_|\.yar|SHA-256|PENDING|Pendientes/i);
      assert.deepEqual(page.urls.filter((u) => u.startsWith(srv.base) && !/\.(js|css|svg)$/.test(u) && !u.endsWith('/')), [`${srv.base}/api/me`], 'the only data request is the identity check');
      assert.deepEqual(page.errors, []); await shot(page, `${name}-login-desktop`);
    });

    test('language and theme: ES/EN works, theme is forced or follows the system, both persist', async () => {
      const page = await newPage(browser, srv, null, VIEWPORTS.desktop, { colorScheme: 'dark' }); await goto(page, srv, '/');
      assert.equal(await page.evaluate(() => getComputedStyle(document.body).backgroundColor), 'rgb(8, 14, 24)', 'follows the system dark theme');
      await page.getByRole('button', { name: 'Claro' }).click(); assert.equal(await page.evaluate(() => document.documentElement.dataset.theme), 'light');
      assert.equal(await page.evaluate(() => getComputedStyle(document.body).backgroundColor), 'rgb(243, 245, 249)');
      await page.getByRole('button', { name: 'EN' }).click(); await page.waitForSelector('h1:has-text("Restricted access")'); assert.equal(await page.locator('h1').innerText(), 'Restricted access'); assert.equal(await page.getByRole('link', { name: 'Continue with GitHub' }).count(), 1);
      assert.equal(await page.evaluate(() => document.documentElement.lang), 'en');
      await page.reload({ waitUntil: 'domcontentloaded' }); await page.waitForSelector('h1');
      assert.equal(await page.locator('h1').innerText(), 'Restricted access'); assert.equal(await page.evaluate(() => document.documentElement.dataset.theme), 'light', 'persisted');
      await page.getByRole('button', { name: 'Automatic' }).click(); assert.equal(await page.evaluate(() => document.documentElement.dataset.theme || 'auto'), 'auto');
    });

    test('the sign-in button gives feedback; the server sends the browser to GitHub with the exact callback, bound state and minimal scope', async () => {
      const page = await newPage(browser, srv, null, VIEWPORTS.desktop); await goto(page, srv, '/');
      await page.route(`${srv.base}/auth/login`, (r) => r.fulfill({ status: 200, contentType: 'text/html', body: '<title>pausa</title>' }));   // hold the redirect so the in-progress state can be observed
      await page.getByRole('link', { name: 'Continuar con GitHub' }).click();
      assert.ok((await page.locator('body').innerText()).includes('Redirigiendo a GitHub…') || page.url().endsWith('/auth/login'), 'immediate feedback');
      const res = await page.context().request.get(`${srv.base}/auth/login`, { maxRedirects: 0 }); assert.equal(res.status(), 302);
      const u = new URL(res.headers().location); assert.equal(u.origin + u.pathname, 'https://github.com/login/oauth/authorize'); assert.equal(u.searchParams.get('redirect_uri'), `${srv.base}/auth/callback`); assert.equal(u.searchParams.get('scope'), 'read:user'); assert.match(u.searchParams.get('state'), /^[0-9a-f]{32}$/); assert.equal(u.searchParams.get('allow_signup'), 'false');
      const sc = res.headers()['set-cookie']; assert.match(sc, /__Host-mg_oauth=[0-9a-f]{32}; Path=\/; HttpOnly; Secure; SameSite=Lax/); assert.ok(sc.includes(u.searchParams.get('state')), 'the state is bound to this browser');
    });

    test('every sign-in state is a designed screen: cancelled, invalid state, GitHub error, service down, no access, expired session', async () => {
      const page = await newPage(browser, srv, null, VIEWPORTS.desktop);
      for (const [e, title] of [['cancelled', 'Has cancelado el acceso'], ['state', 'No hemos podido validar el inicio de sesión'], ['oauth', 'GitHub no ha confirmado el acceso'], ['unavailable', 'Servicio no disponible por ahora']]) {
        await goto(page, srv, `/?e=${e}`); assert.ok((await page.locator('main').innerText()).includes(title), e); assert.equal(await page.evaluate(() => location.search), '', 'the code is removed from the address bar');
        assert.equal(await page.getByRole('link', { name: 'Continuar con GitHub' }).count(), e === 'unavailable' ? 0 : 1); assert.equal(await page.locator('main [role="alert"], main [role="status"]').count() > 0, true);
      }
      const denied = await newPage(browser, srv, 'nobody', VIEWPORTS.desktop); await goto(denied, srv, '/');
      assert.equal(await denied.locator('h1').innerText(), 'Sin acceso a este panel'); assert.ok((await denied.locator('main').innerText()).includes('sam')); assert.doesNotMatch(await denied.locator('body').innerText(), /nextron|Cuarentena|Miembros/);
      await denied.getByRole('button', { name: 'Cerrar sesión' }).click(); await denied.waitForSelector('h1:has-text("Acceso restringido")');
      assert.equal(await denied.locator('h1').innerText(), 'Acceso restringido', 'the session was ended'); assert.equal((await denied.evaluate(() => fetch('/api/me').then((r) => r.status))), 401);
      const exp = await newPage(browser, srv, 'viewer', VIEWPORTS.desktop); await goto(exp, srv, '/#/quarantine'); await exp.waitForSelector('.rule');
      await exp.context().clearCookies(); await exp.getByRole('button', { name: 'Actualizar' }).click(); await exp.waitForSelector('text=Tu sesión ha caducado');
      assert.equal(await exp.getByRole('link', { name: 'Continuar con GitHub' }).count(), 1);
    });

    test('a viewer can read but nothing that decides or administers is offered, and the server refuses it anyway', async () => {
      const page = await newPage(browser, srv, 'viewer', VIEWPORTS.desktop); await goto(page, srv, '/#/quarantine'); await page.waitForSelector('.rule');
      assert.deepEqual(await page.locator('.sidebar .nav a').allInnerTexts(), ['Panel', 'Cuarentena', 'Actividad', 'Fuentes']); assert.equal(await page.locator('.rule input[type=checkbox]').count(), 0); assert.equal(await page.locator('.bulkbar').count(), 0);
      await page.locator('.rule-title').first().click(); await page.waitForSelector('.sheet'); assert.ok((await page.locator('main').innerText()).includes('solo lectura')); assert.equal(await page.getByRole('button', { name: /Aprobar|Rechazar/ }).count(), 0);
      for (const hash of ['/#/audit', '/#/members']) { await goto(page, srv, hash); await page.waitForSelector('.kpis'); assert.equal(await page.locator('h1').innerText(), 'Panel', `${hash} falls back to the dashboard`); }
      const codes = await page.evaluate(async () => Promise.all(['/api/audit', '/api/members', '/api/audit/verify'].map((p) => fetch(p).then((r) => r.status)))); assert.deepEqual(codes, [403, 403, 403]);
      assert.deepEqual(page.errors, []);
    });

    test('a reviewer decides in a batch: exact count, mandatory reason, versions sent, nothing without a reason; approving only changes state', async () => {
      const s = await startServer(); const page = await newPage(browser, s, 'reviewer', VIEWPORTS.desktop);
      try {
        await goto(page, s, '/#/quarantine'); await page.waitForSelector('.rule'); assert.deepEqual(await page.locator('.sidebar .nav a').allInnerTexts(), ['Panel', 'Cuarentena', 'Actividad', 'Fuentes', 'Auditoría']);
        const posts = []; page.on('request', (r) => { if (r.method() === 'POST') posts.push(r); });
        await page.locator('.rule input[type=checkbox]').nth(0).check(); await page.locator('.rule input[type=checkbox]').nth(1).check(); await page.waitForSelector('.bulkbar');
        assert.ok((await page.locator('.bulkbar').innerText()).includes('2 seleccionadas'));
        await page.locator('.bulkbar').getByRole('button', { name: 'Aprobar' }).click(); const dlg = page.locator('dialog[open]'); await dlg.waitFor();
        assert.ok((await dlg.innerText()).includes('exactamente 2 reglas')); assert.ok((await dlg.innerText()).includes('Aprobar no publica nada'));
        await dlg.getByRole('button', { name: 'Aprobar', exact: true }).click(); assert.ok((await dlg.locator('p.alert-bad:visible').innerText()).includes('al menos 5 caracteres')); assert.equal(posts.length, 0, 'no request without a reason');
        await dlg.locator('textarea').fill('Revisadas a mano, regex acotadas'); await Promise.all([page.waitForResponse((r) => r.url().endsWith('/api/decisions') && r.status() === 200), dlg.getByRole('button', { name: 'Aprobar', exact: true }).click()]);
        const body = JSON.parse(posts.find((r) => r.url().endsWith('/api/decisions')).postData()); assert.equal(body.action, 'approve'); assert.equal(body.ids.length, 2); assert.equal(body.confirm_count, 2); assert.match(body.request_id, /^req_[A-Za-z0-9_-]{16,}$/); assert.deepEqual(Object.keys(body.expect).sort(), [...body.ids].sort()); assert.equal(body.reason, 'Revisadas a mano, regex acotadas');
        await page.waitForSelector('.pill:has-text("Aprobadas") b:text-is("2")'); assert.equal(await page.locator('.bulkbar').count(), 0); assert.equal(await page.locator('.pill:has-text("Pendientes") b').innerText(), '5', 'only the two selected rules changed');
        await page.getByRole('button', { name: /Aprobadas/ }).first().click(); await page.waitForFunction(() => document.querySelectorAll('.rule').length === 2); assert.equal(await page.locator('.rule .badge-approved').count(), 2);
        assert.ok((await page.locator('.rule').first().innerText()).includes('Aprobada · pendiente de validación'), 'technical state translated');
        assert.doesNotMatch(await page.locator('body').innerText(), /APPROVED_PENDING_VALIDATION|UNDER_REVIEW/);
        const audit = await page.evaluate(() => fetch('/api/audit?family=decision').then((r) => r.json())); assert.equal(audit.entries[0].action, 'decision.approve'); assert.equal(audit.entries[0].detail.applied.length, 2); assert.equal(audit.entries[0].actor, 'rita');
        const outward = page.urls.filter((u) => !u.startsWith(s.base) && !u.startsWith('https://avatars.githubusercontent.com')); assert.deepEqual(outward, [], 'no request leaves the panel');
        await goto(page, s, '/#/audit'); await page.waitForSelector('.event'); assert.ok((await page.locator('.event').first().innerText()).includes('rita aprobó 2 reglas')); assert.ok((await page.locator('.event').first().innerText()).includes('Revisadas a mano'));
        assert.equal(await page.getByRole('button', { name: /Verificar la cadena/ }).count(), 0, 'chain verification is for administrators');
        assert.deepEqual(page.errors, []);
      } finally { await page.context().close(); s.stop(); }
    });

    test('a candidate with a technical finding cannot be approved: the control is disabled with the reason, in the list and in the sheet; reject and hold stay available', async () => {
      const s = await startServer(['--blocked']); const page = await newPage(browser, s, 'reviewer', VIEWPORTS.desktop);
      try {
        await goto(page, s, '/#/quarantine'); await page.waitForSelector('.rule');
        const row = page.locator('.rule', { hasText: 'truncated.yar' }); assert.ok((await row.innerText()).includes('No aprobable'));
        await row.locator('input[type=checkbox]').check(); await page.waitForSelector('.bulkbar');
        assert.equal(await page.locator('.bulkbar').getByRole('button', { name: 'Aprobar' }).isDisabled(), true); assert.ok((await page.locator('.bulkbar').innerText()).includes('no se pueden aprobar'));
        assert.equal(await page.locator('.bulkbar').getByRole('button', { name: 'Rechazar' }).isEnabled(), true);
        await row.locator('input[type=checkbox]').uncheck(); await page.locator('.rule', { hasText: 'rule_1.yar' }).locator('input[type=checkbox]').check();
        assert.equal(await page.locator('.bulkbar').getByRole('button', { name: 'Aprobar' }).isEnabled(), true, 'a judgement-only rule stays approvable');
        await row.locator('.rule-title').click(); await page.waitForSelector('.code');
        assert.equal(await page.getByRole('button', { name: 'Aprobar' }).isDisabled(), true); assert.ok((await page.locator('#not-approvable').innerText()).includes('ninguna aprobación humana'));
        assert.equal(await page.getByRole('button', { name: 'Rechazar' }).isEnabled(), true); assert.equal(await page.getByRole('button', { name: 'Mantener en cuarentena' }).isEnabled(), true);
        assert.deepEqual(await axeViolations(page), [], 'the not-approvable sheet meets WCAG 2.2 AA');
        assert.deepEqual(page.errors, []);
      } finally { await page.context().close(); s.stop(); }
    });
    test('the sheet shows what a rule needs, what needs it, whether approving will take effect and what would come back; an approval that cannot take effect is disabled', async () => {
      const s = await startServer(['--deps']); const page = await newPage(browser, s, 'reviewer', VIEWPORTS.desktop);
      try {
        const open = async (file) => { await goto(page, s, '/#/quarantine'); await page.waitForSelector('.rule'); await page.locator('.rule-title', { hasText: file }).click(); await page.waitForSelector('#h-dep'); };
        await open('shared_base.yar');
        let card = page.locator('section', { has: page.locator('#h-dep') }); let txt = (await card.innerText()).replace(/\s+/g, ' ');
        assert.ok(txt.includes('podrá entrar en el conjunto publicable de la siguiente ejecución diaria') && txt.includes('Aprobar no publica nada'), txt);
        assert.ok(txt.includes('Dependen de ella') && txt.includes('uses_base_1.yar') && txt.includes('uses_base_2.yar') && txt.includes('Volvería sola al conjunto'));
        assert.ok(txt.includes('Reglas que volverían al conjunto publicable con esta aprobación'));
        assert.equal(await page.getByRole('button', { name: 'Aprobar' }).isEnabled(), true);
        await open('uses_base_1.yar'); card = page.locator('section', { has: page.locator('#h-dep') }); txt = (await card.innerText()).replace(/\s+/g, ' ');
        assert.ok(txt.includes('Necesita estas reglas') && txt.includes('shared_base.yar') && txt.includes('Falta aprobarla') && txt.includes('Aprobarla sola no tendrá efecto todavía'), txt);
        assert.equal(await page.getByRole('button', { name: 'Aprobar' }).isEnabled(), true, 'a conditional approval is allowed');
        assert.equal(await card.locator('a[href^="#/rules/"]').first().innerText(), 'rules/community/pack/shared_base.yar', 'the needed rule is a link to its own sheet');
        await open('uses_cuckoo.yar'); card = page.locator('section', { has: page.locator('#h-dep') }); txt = (await card.innerText()).replace(/\s+/g, ' ');
        assert.ok(txt.includes('Bloqueada: no se puede aprobar') && txt.includes('Aprobarla no tendrá efecto: necesita rules/community/pack/needs_cuckoo.yar'), txt);
        assert.equal(await page.getByRole('button', { name: 'Aprobar' }).isDisabled(), true); assert.equal(await page.getByRole('button', { name: 'Rechazar' }).isEnabled(), true);
        assert.deepEqual(await axeViolations(page), [], 'the dependency card meets WCAG 2.2 AA');
        assert.deepEqual(page.errors, []);
        const dark = await newPage(browser, s, 'reviewer', VIEWPORTS.desktop, { colorScheme: 'dark' });   // a page that starts in the dark theme: no transitions in flight when contrast is measured
        try { await goto(dark, s, '/#/quarantine'); await dark.waitForSelector('.rule'); await dark.locator('.rule-title', { hasText: 'uses_cuckoo.yar' }).click(); await dark.waitForSelector('#h-dep'); assert.deepEqual(await axeViolations(dark), [], 'and in the dark theme'); } finally { await dark.context().close(); }
      } finally { await page.context().close(); s.stop(); }
    });
    test('an administrator manages members: resolve the real account, grant, history, revoke; self and non-personal accounts are refused', async () => {
      const s = await startServer(); const page = await newPage(browser, s, 'admin', VIEWPORTS.desktop);
      try {
        await goto(page, s, '/#/members'); await page.waitForSelector('.person');
        const names = await page.locator('.person .person-head strong').allInnerTexts(); assert.deepEqual(names.sort(), ['ada', 'rita', 'sam', 'vera']);
        const card = (n) => page.locator('.person', { has: page.locator(`strong:text-is("${n}")`) });
        assert.equal(await card('ada').getByRole('button', { name: 'Cambiar rol' }).count(), 0, 'no self-service role change'); assert.ok((await card('ada').innerText()).includes('no puedes cambiar tu propio rol'));
        assert.ok((await card('ada').innerText()).includes('ID de GitHub 13')); assert.equal(await card('ada').locator('img.avatar, .avatar').count(), 1);
        assert.ok((await card('sam').innerText()).includes('Inició sesión sin autorización')); assert.ok((await card('rita').innerText()).includes('Repositorio GitHub')); assert.ok((await card('vera').innerText()).includes('Concesión manual'));
        await page.getByRole('button', { name: 'Añadir miembro' }).click(); const dlg = page.locator('dialog[open]'); await dlg.waitFor();
        await dlg.locator('#md-login').fill('acme-org'); await dlg.getByRole('button', { name: 'Buscar cuenta' }).click(); await dlg.locator('p.alert-bad:visible').waitFor(); assert.ok((await dlg.innerText()).includes('Solo se admiten cuentas personales'));
        await dlg.locator('#md-login').fill('ghost-nobody'); await dlg.getByRole('button', { name: 'Buscar cuenta' }).click(); await page.waitForSelector('dialog[open] :text("GitHub no conoce esa cuenta")');
        await dlg.locator('#md-login').fill('newbie'); await dlg.locator('#md-login').press('Enter'); await dlg.locator('.lookup').waitFor();
        assert.ok((await dlg.locator('.lookup').innerText()).includes('newbie') && (await dlg.locator('.lookup').innerText()).includes('ID de GitHub 900')); assert.equal(await dlg.locator('.lookup img.avatar, .lookup .avatar').count(), 1);
        await dlg.getByLabel(/^Revisor/).check(); await dlg.getByRole('button', { name: 'Guardar' }).click(); assert.ok((await dlg.locator('p.alert-bad:visible').innerText()).includes('al menos 5 caracteres'));
        await dlg.locator('textarea').fill('Nuevo revisor del canal comunitario'); await Promise.all([page.waitForResponse((r) => r.url().endsWith('/api/members') && r.request().method() === 'POST' && r.status() === 200), dlg.getByRole('button', { name: 'Guardar' }).click()]);
        await card('newbie').waitFor(); assert.ok((await card('newbie').innerText()).includes('Revisor')); assert.ok((await card('newbie').innerText()).includes('Concesión manual'));
        await card('newbie').getByRole('button', { name: 'Historial' }).click(); await card('newbie').locator('.history .quote').waitFor(); assert.ok((await card('newbie').locator('.history').innerText()).includes('Nuevo revisor del canal comunitario'));
        await card('newbie').getByRole('button', { name: 'Revocar concesión' }).click(); const rd = page.locator('dialog[open]'); await rd.locator('textarea').fill('Ya no participa en el proyecto');
        await Promise.all([page.waitForResponse((r) => r.url().endsWith('/api/members') && r.request().method() === 'POST' && r.status() === 200), rd.getByRole('button', { name: 'Revocar concesión' }).click()]);
        await page.getByRole('button', { name: /Revocados/ }).click(); await page.waitForFunction(() => document.querySelectorAll('.person').length === 1); assert.ok((await page.locator('.person').innerText()).includes('Permiso revocado'));
        const entries = await page.evaluate(() => fetch('/api/audit?family=member').then((r) => r.json())); assert.deepEqual(entries.entries.map((e) => [e.detail.from_role, e.detail.to_role]).slice(0, 3), [['REVIEWER', null], [null, 'REVIEWER'], [null, 'VIEWER']]);
        assert.ok(entries.entries.every((e) => e.detail.reason && e.detail.user_id && e.actor === 'ada'));
        assert.ok((await page.locator('.matrix').innerText()).includes('Gestionar miembros y permisos')); assert.deepEqual(page.errors, []);
      } finally { await page.context().close(); s.stop(); }
    });

    test('regressions kept from the first panel: rule code is inert text, resource bars, chain verification, a forged session is anonymous, reviewers cannot administer', async () => {
      const page = await newPage(browser, srv, 'admin', VIEWPORTS.desktop); await goto(page, srv, '/#/quarantine'); await page.waitForSelector('.rule');
      assert.ok((await page.locator('.pill:has-text("Todos") b').innerText()) === '7', 'count cards'); assert.ok((await page.locator('.pill:has-text("Pendientes") b').innerText()) === '7');
      await page.locator('.rule-title', { hasText: 'evil.yar' }).click(); await page.waitForSelector('.code');
      assert.ok((await page.locator('pre.code').innerText()).includes('<img src=x onerror="window.__xss=1">'), 'shown verbatim as text'); assert.equal(await page.locator('pre.code img').count(), 0);
      assert.equal(await page.evaluate(() => window.__xss), undefined, 'the rule text never executed'); assert.ok(await page.locator('.meter .bar').count() >= 2, 'resource bars'); assert.ok((await page.locator('.meter').first().innerText()).includes('CPU'));
      await goto(page, srv, '/#/audit'); await page.getByRole('button', { name: /Verificar la cadena/ }).click(); await page.waitForSelector('.alert-ok'); assert.ok((await page.locator('.alert-ok').innerText()).includes('Cadena íntegra'));
      await page.context().close();
      const forged = await newPage(browser, { ...srv, sessions: { ...srv.sessions, x: '0'.repeat(64) } }, 'x', VIEWPORTS.desktop); await goto(forged, srv, '/'); assert.equal(await forged.locator('h1').innerText(), 'Acceso restringido'); assert.equal(await forged.locator('.rule').count(), 0); await forged.context().close();
      const rev = await newPage(browser, srv, 'reviewer', VIEWPORTS.desktop); await goto(rev, srv, '/#/quarantine'); await rev.waitForSelector('.rule');
      assert.deepEqual(await rev.evaluate(async () => Promise.all(['/api/members', '/api/audit/verify'].map((p) => fetch(p).then((r) => r.status)))), [403, 403]); await rev.context().close();
    });

    test('dashboard, calendar, charts and sources show real records with their provenance; missing data is SIN DATOS, never zero', async () => {
      const page = await newPage(browser, srv, 'viewer', VIEWPORTS.desktop); await goto(page, srv, '/#/dashboard'); await page.waitForSelector('.kpis .kpi');
      const kpi = async (label) => (await page.locator('.kpi', { has: page.locator(`.kpi-label:text-is("${label}")`) }).innerText()).replace(/\s+/g, ' ');
      assert.match(await kpi('Reglas por revisar'), /^Reglas por revisar 7 /i); assert.match(await kpi('Última ejecución diaria'), /En curso.*Programada/i); assert.match(await kpi('Último día observado'), /1184 .*1174 aceptadas · 6 en cuarentena · 4 rechazadas/i);
      assert.match(await kpi('Éxito de ejecuciones programadas (30 d)'), /93\.8% 15 de 16 días/i); assert.match(await kpi('Última release publicada'), /independiente del resultado de la ejecución/i);
      assert.match(await kpi('Duración media (7 d)'), /min/i); assert.ok((await page.locator('.freshness').innerText()).includes('GitHub Actions')); assert.ok((await page.locator('.freshness').innerText()).includes('cuota de GitHub: 4981 de 5000'));
      assert.equal(await page.locator('.strip li').count(), 14); assert.equal(await page.locator('.chart-svg').count(), 1);
      await page.getByRole('link', { name: 'Abrir actividad' }).click(); await page.waitForSelector('table.cal');
      assert.equal(await page.locator('table.cal button').count(), 30); const lab = (re) => page.locator('table.cal button', { hasText: '' }).filter({ has: page.locator('.cal-n') }).evaluateAll((els, src) => els.map((e) => e.getAttribute('aria-label')).filter((l) => new RegExp(src).test(l)), re);
      const states = await page.locator('table.cal button').evaluateAll((els) => els.map((e) => e.getAttribute('aria-label').split(': ')[1].split(' (')[0].split('.')[0]));
      for (const want of ['OK', 'Fallo', 'Cancelada', 'Sin ejecución', 'Aviso', 'En curso', 'Anterior al registro']) assert.ok(states.includes(want), `calendar has a "${want}" day (${[...new Set(states)]})`);
      const click = async (re) => { const n = await page.locator('table.cal button').evaluateAll((els, src) => els.findIndex((e) => new RegExp(src).test(e.getAttribute('aria-label'))), re); assert.ok(n >= 0, re); await page.locator('table.cal button').nth(n).click(); await page.waitForTimeout(150); return (await page.locator('#cal-detail').innerText()).replace(/\s+/g, ' '); };
      let d = await click(': Fallo'); assert.ok(d.includes('una ejecución manual posterior terminó bien') && d.includes('El fallo no se oculta')); assert.ok(d.includes('Programada') && d.includes('Manual')); const link = page.locator('#cal-detail a', { hasText: 'Abrir en GitHub' }).first(); assert.match(await link.getAttribute('href'), /^https:\/\/github\.com\/MacGuard\/macguard-yara-channel\/actions\/runs\/\d+$/); assert.equal(await link.getAttribute('rel'), 'noopener noreferrer');
      d = await click(': Sin ejecución'); assert.ok(d.includes('no hay observación')); d = await click(': Cancelada'); assert.ok(d.includes('Cancelada'));
      d = await click('\\(manual\\)'); assert.ok(d.includes('solo hubo ejecuciones manuales')); d = await click(': Aviso'); assert.ok(d.includes('10 reglas ya publicadas')); assert.ok(d.includes('Release publicada'), 'a published release is its own fact'); assert.ok(d.includes('Una ejecución correcta puede no generar release') || d.includes('hechos distintos'));
      await page.getByText('Leyenda y definiciones').click(); assert.ok((await page.locator('.legend.wide').innerText()).includes('no es un acierto ni un cero'));
      assert.equal(await page.locator('.chart-svg').count(), 3); assert.equal(await page.locator('figure.chart').nth(0).locator('tbody tr').count(), 30);
      await page.getByRole('button', { name: '7 días' }).click(); assert.equal(await page.locator('figure.chart').nth(0).locator('tbody tr').count(), 7); assert.ok(await page.locator('.event.hist').count() >= 5, 'history follows the period');
      await page.getByRole('link', { name: 'Fuentes' }).first().click(); await page.waitForSelector('.person'); assert.equal(await page.locator('.person').count(), 3);
      const nex = (await page.locator('.person', { has: page.locator('strong:text-is("nextron")') }).innerText()).replace(/\s+/g, ' '); assert.ok(nex.includes('3ce6640c26') && nex.includes('Sincronizada') && /En cuarentena ahora 7/i.test(nex), nex);
      assert.ok((await page.locator('.person', { has: page.locator('strong:text-is("yara-x")') }).innerText()).includes('Motor YARA-X')); assert.ok((await page.locator('main').innerText()).includes('todavía no se publica'));
      for (const a of await page.locator('.person a[href^="https://github.com/"]').all()) { assert.equal(await a.getAttribute('target'), '_blank'); assert.equal(await a.getAttribute('rel'), 'noopener noreferrer'); } assert.deepEqual(page.errors, []);
      await page.getByRole('button', { name: 'EN' }).click(); await page.waitForSelector('h1:has-text("YARA sources")'); await page.getByRole('link', { name: 'Dashboard' }).first().click(); await page.waitForSelector('.kpi-label:text-is("Rules to review")'); assert.ok((await page.locator('main').innerText()).toLowerCase().includes('scheduled-run success'));
      await page.context().close();
      const s2 = await startServer([], { opsDown: 'stats' }); const p2 = await newPage(browser, s2, 'viewer', VIEWPORTS.desktop);
      try {
        await goto(p2, s2, '/#/dashboard'); await p2.waitForSelector('.kpis'); assert.ok((await p2.locator('main').innerText()).includes('Datos parciales: no se pudo leer estadísticas del sitio')); assert.match(await p2.locator('.kpi', { has: p2.locator('.kpi-label:text-is("Último día observado")') }).innerText(), /SIN DATOS/i);
        await goto(p2, s2, '/#/activity'); await p2.waitForSelector('figure.chart'); assert.equal(await p2.locator('figure.chart .nodata').count(), 3 - 1, 'the charts without real data say SIN DATOS (the duration chart still has run data)'); assert.ok((await p2.locator('figure.chart .nodata').first().innerText()).includes('SIN DATOS'));
      } finally { await p2.context().close(); s2.stop(); }
    });

    test('layout holds at iPhone, tablet and desktop: no page overflow, no clipped elements, SHA-256 never broken vertically', async () => {
      const vps = [['iphone', mobile().viewport], ['tablet', VIEWPORTS.tablet], ['desktop', VIEWPORTS.desktop]];
      for (const [vn, vp] of vps) {
        const page = await newPage(browser, srv, 'admin', vp, vn === 'iphone' ? mobile().device : {});
        for (const hash of ['/#/dashboard', '/#/quarantine', '/#/activity', '/#/sources', '/#/audit', '/#/members']) {
          await goto(page, srv, hash); await page.waitForSelector('main h1'); await page.waitForTimeout(500); const l = await layout(page);
          assert.ok(l.scrollW <= l.W, `${vn}${hash}: page scrolls horizontally (${l.scrollW} > ${l.W})`); assert.deepEqual(l.bad, [], `${vn}${hash}`); assert.equal(l.shaTooTall, 0, `${vn}${hash}: SHA wraps vertically`);
          await shot(page, `${name}-${vn}-${hash.replace(/\W/g, '')}`);
        }
        await goto(page, srv, '/#/quarantine'); await page.locator('.rule-title').first().click(); await page.waitForSelector('.sheet'); const l = await layout(page);
        assert.ok(l.scrollW <= l.W, `${vn} rule sheet overflows`); assert.deepEqual(l.bad, [], `${vn} rule`); assert.equal(l.shaTooTall, 0, `${vn} rule SHA`); await shot(page, `${name}-${vn}-rule`);
        const anon = await newPage(browser, srv, null, vp, vn === 'iphone' ? mobile().device : {}); await goto(anon, srv, '/'); const la = await layout(anon); assert.ok(la.scrollW <= la.W, `${vn} sign-in overflows`); assert.deepEqual(la.bad, []); await shot(anon, `${name}-${vn}-login`);
        await page.context().close(); await anon.context().close();
      }
    });

    test('WCAG 2.2 AA (axe): sign-in, quarantine, rule, audit, members and dialogs, light and dark, Spanish and English, desktop and phone', async () => {
      const failures = [];
      for (const [scheme, locale] of [['light', 'es-ES'], ['dark', 'en-GB']]) {
        for (const [vn, vp, dev] of [['desktop', VIEWPORTS.desktop, {}], ['phone', mobile().viewport, mobile().device]]) {
          const anon = await newPage(browser, srv, null, vp, { colorScheme: scheme, locale, device: dev }); await goto(anon, srv, '/');
          failures.push(...(await axeViolations(anon)).map((v) => `[login ${scheme} ${vn}] ${v}`));
          await goto(anon, srv, '/?e=state'); failures.push(...(await axeViolations(anon)).map((v) => `[login-error ${scheme} ${vn}] ${v}`)); await anon.context().close();
          const page = await newPage(browser, srv, 'admin', vp, { colorScheme: scheme, locale, device: dev });
          for (const hash of ['/#/dashboard', '/#/quarantine', '/#/activity', '/#/sources', '/#/audit', '/#/members']) { await goto(page, srv, hash); await page.waitForTimeout(600); failures.push(...(await axeViolations(page)).map((v) => `[${hash} ${scheme} ${vn}] ${v}`)); }
          await goto(page, srv, '/#/quarantine'); await page.locator('.rule-title').first().click(); await page.waitForSelector('.sheet'); failures.push(...(await axeViolations(page)).map((v) => `[rule ${scheme} ${vn}] ${v}`));
          await goto(page, srv, '/#/quarantine'); await page.locator('.rule input[type=checkbox]').first().check(); await page.locator('.bulkbar').getByRole('button').nth(2).click(); await page.waitForSelector('dialog[open]'); failures.push(...(await axeViolations(page)).map((v) => `[decision dialog ${scheme} ${vn}] ${v}`));
          await page.keyboard.press('Escape'); await goto(page, srv, '/#/members'); await page.waitForSelector('.person'); await page.getByRole('button', { name: /Añadir miembro|Add member/ }).click(); await page.waitForSelector('dialog[open]'); failures.push(...(await axeViolations(page)).map((v) => `[member dialog ${scheme} ${vn}] ${v}`));
          await page.context().close();
        }
      }
      const denied = await newPage(browser, srv, 'nobody', VIEWPORTS.desktop); await goto(denied, srv, '/'); failures.push(...(await axeViolations(denied)).map((v) => `[denied] ${v}`)); await denied.context().close();
      assert.deepEqual([...new Set(failures)], []);
    });

    test('keyboard: skip link first, visible focus ring, Escape closes the dialog and returns focus, drawer menu on small screens', async () => {
      const page = await newPage(browser, srv, 'reviewer', VIEWPORTS.desktop); await goto(page, srv, '/#/quarantine'); await page.waitForSelector('.rule');
      await page.keyboard.press(name === 'webkit' ? 'Alt+Tab' : 'Tab'); assert.equal(await page.evaluate(() => document.activeElement.className), 'skip');   // Safari tabs only to form controls unless Option is held assert.ok((await page.locator('.skip').boundingBox()).y >= 0);
      await page.keyboard.press('Enter'); assert.equal(await page.evaluate(() => document.activeElement.id), 'main');
      await page.locator('.rule input[type=checkbox]').first().focus(); await page.keyboard.press('Space'); await page.waitForSelector('.bulkbar');
      const opener = page.locator('.bulkbar').getByRole('button', { name: 'Mantener en cuarentena' }); await opener.focus(); await page.keyboard.press('Enter'); await page.waitForSelector('dialog[open]');
      assert.equal(await page.evaluate(() => document.activeElement.tagName), 'TEXTAREA'); await page.keyboard.press('Escape'); await page.waitForFunction(() => !document.querySelector('dialog[open]'));
      assert.equal(await page.evaluate(() => document.activeElement.textContent.includes('Mantener')), true, 'focus returns to the control that opened it');
      await page.keyboard.press(name === 'webkit' ? 'Alt+Shift+Tab' : 'Shift+Tab'); const ring = await page.evaluate(() => { const s = getComputedStyle(document.activeElement); return { style: s.outlineStyle, w: parseFloat(s.outlineWidth) }; }); assert.ok(ring.style !== 'none' && ring.w >= 2, JSON.stringify(ring));
      const phone = await newPage(browser, srv, 'reviewer', mobile().viewport, mobile().device); await goto(phone, srv, '/#/quarantine'); assert.equal(await phone.locator('.sidebar').isVisible(), false);
      await phone.getByRole('button', { name: 'Menú' }).click(); await phone.waitForSelector('dialog.drawer[open]'); await phone.locator('dialog.drawer a', { hasText: 'Auditoría' }).click(); await phone.waitForSelector('.events, .empty');
      assert.equal(await phone.locator('dialog.drawer[open]').count(), 0, 'the drawer closes after navigating'); assert.equal(await phone.locator('h1').innerText(), 'Auditoría');
      await page.context().close(); await phone.context().close();
    });
  });
}
