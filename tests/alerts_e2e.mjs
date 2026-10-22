// End-to-end test of the Subscriptions and Alerts pages in a REAL browser against the REAL reference backend (python3 -m alerts serve), over HTTP.
// Run by tests/test_alerts_e2e.py, which starts the server, seeds synthetic alerts, runs the matcher between phases and checks the e-mail files.
// usage: node alerts_e2e.mjs <phase: a|b|axe> <baseUrl> <stateFile> <nodeModulesDir>
import { createRequire } from 'node:module';
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const [phase, base, stateFile, nm] = process.argv.slice(2);
const require = createRequire(join(nm, 'x.js'));
const { chromium } = require('playwright');
const state = JSON.parse(readFileSync(stateFile, 'utf8'));
const results = [];
const ok = (name, cond, detail) => { results.push({ name, ok: !!cond, detail: cond ? undefined : String(detail) }); };
const P = (p) => base + '/intelligence/alerts/' + p;

async function text(page, sel) { return (await page.locator(sel).first().textContent()) || ''; }
async function waitText(page, sel, re, ms = 20000) { await page.waitForFunction(([s, r]) => new RegExp(r).test((document.querySelector(s) || {}).textContent || ''), [sel, re.source], { timeout: ms }); }
async function login(page, email, password, totp) {
  await page.fill('#au-email', email); await page.fill('#au-pass', password); if (totp) await page.fill('#au-totp', totp);
  await page.click('#auth button[data-t="au_login"]');
  await page.waitForSelector('#auth-body >> text=/Signed in as|Sesión iniciada como/', { timeout: 15000 });
}
async function register(page, email, password) {
  await page.fill('#au-email', email); await page.fill('#au-pass', password); await page.click('#auth button[data-t="au_register"]');
  await waitText(page, '#au-msg', /account exists|cuenta ya existe/);
}

const browser = await chromium.launch();
try {
  if (phase === 'a') {
    const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
    const page = await ctx.newPage();
    const errors = []; page.on('pageerror', (e) => errors.push(e.message)); page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });

    // 1. explore: real data from the service, the same filter language, reasons for every match
    await page.goto(P('index.html?lang=en'));
    await waitText(page, '#count', /alerts/);
    const all = parseInt((await text(page, '#count')).match(/\d+/)[0], 10);
    ok('explore shows every seeded alert', all >= state.alerts_total, `${all} < ${state.alerts_total}`);
    await page.check('#fo-windows'); await page.selectOption('#f-sev', 'high'); await page.click('#f-apply');
    await waitText(page, '#count', new RegExp('^' + state.windows_high + ' alerts'));
    ok('a combined filter selects the right alerts', (await page.locator('#results > li').count()) === state.windows_high, await text(page, '#count'));
    await page.locator('#results > li details summary').first().click();
    const why = await text(page, '#results > li details ul');
    ok('every match says why', /curated-mapping:technology-map@1/.test(why) && /Operating system|Sistema operativo/i.test(why), why);
    await page.click('#f-reset'); await waitText(page, '#count', new RegExp('^' + Math.min(all, 50) + ' alerts|^\\d+ alerts'));
    await page.fill('#f-ids', 'not-an-id'); await page.click('#f-apply');
    ok('an invalid identifier is refused with a message', /not valid|no es válido/i.test(await text(page, '#f-error')), await text(page, '#f-error'));
    await page.click('#f-reset');
    await page.locator('#results > li h3 a').first().click();
    await page.waitForSelector('#alert h2');
    ok('the detail shows each source with its evidence', (await page.locator('#alert details').count()) >= 1 && /f\.json|channel|logs/.test(await text(page, '#alert')), await text(page, '#alert'));

    // 2. preferences: register, sign in, add an e-mail channel, confirm it by the link that was e-mailed (a GET shows a button, only the POST confirms)
    await page.goto(P('preferences.html?lang=en'));
    await page.waitForSelector('#au-email');
    await register(page, state.email, state.password);
    await login(page, state.email, state.password);
    await page.fill('#ch-email', state.email); await page.click('#ch-email-add');
    await waitText(page, '#ch-new', /waiting for confirmation/);
    const qp = (x) => x.replace(/=\r?\n/g, '').replace(/=([0-9A-F]{2})/g, (m, h) => String.fromCharCode(parseInt(h, 16)));
    const eml = readdirSync(state.outbox).filter((f) => f.endsWith('.eml')).map((f) => qp(readFileSync(join(state.outbox, f), 'utf8'))).join('\n');
    const m = eml.match(/https?:\/\/[^\s]*\/api\/v1\/channels\/confirm\?token=[\w-]+/);
    ok('a confirmation link was e-mailed', m, eml.slice(0, 300));
    const link = m[0].replace(/^https?:\/\/[^/]+/, base);
    const cpage = await ctx.newPage(); const netlog = []; cpage.on('response', (r) => netlog.push(r.request().method() + ' ' + r.status() + ' ' + r.url().replace(/token=[\w-]+/, 'token=<t>'))); cpage.on('console', (m) => netlog.push('console ' + m.text()));
    await cpage.goto(link);
    ok('the confirmation page does not confirm by itself', (await cpage.locator('button').count()) === 1 && /pending|Pulsa|Press/.test(await cpage.content()), await cpage.content());
    await cpage.click('button'); try { await cpage.waitForSelector('text=/OK/', { timeout: 8000 }); } catch (e) { ok('the confirmation POST succeeded', false, netlog.join(' | ')); throw e; }
    await cpage.close();
    await page.reload(); await page.waitForSelector('#channels li');
    ok('the channel is active after confirming', /active|activo/.test(await text(page, '#channels')), await text(page, '#channels'));

    // 3. create a subscription in the UI: filter, preview (real alerts, nothing sent), channel, save
    await page.goto(P('subscribe.html?lang=en'));
    await page.waitForSelector('#sb-name');
    await page.fill('#sb-name', 'Windows high');
    await page.check('#fo-windows'); await page.selectOption('#f-sev', 'high');
    await page.click('#sb-preview'); await waitText(page, '#pv-count', /matches/);
    const pv = parseInt((await text(page, '#pv-count')).match(/\d+/)[0], 10);
    ok('the preview counts real matches and says it is computed by the service', pv === state.windows_high && /computed by the service/.test(await text(page, '#pv-count')), await text(page, '#pv-count'));
    ok('the preview is clearly not a notification', /not notifications that were sent/.test(await text(page, '#p-h + p')), await text(page, '#p-h + p'));
    await page.locator('#sb-channels input[type=checkbox]').first().check();
    await page.click('#sb-save-active'); await waitText(page, '#sb-status', /Subscription saved/);
    ok('the filter is shown as data', /"field": "os"/.test(await text(page, '#sb-json')), await text(page, '#sb-json'));
    await page.click('#sb-test'); await waitText(page, '#sb-status', /Test sent/);
    await page.goto(P('mine.html?lang=en')); await page.waitForSelector('#mine .result');
    ok('the subscription is listed and active', /Windows high/.test(await text(page, '#mine')) && /active/.test(await text(page, '#mine')), await text(page, '#mine'));
    await page.click('#mine button[data-t="m_suspend"]'); await page.waitForSelector('#mine button[data-t="m_resume"]');
    await page.click('#mine button[data-t="m_resume"]'); await page.waitForSelector('#mine button[data-t="m_suspend"]');
    await page.click('#mine button[data-t="m_duplicate"]'); await page.waitForFunction(() => document.querySelectorAll('#mine .result').length === 2);
    ok('suspend, resume and duplicate work', true);
    const dup = page.locator('#mine .result', { hasText: '(copia)' });      // the duplicate, whatever the list order is
    await dup.locator('button[data-t="m_delete"]').click();
    ok('deleting needs a second, explicit click', (await page.locator('#mine button[data-t="m_confirm_delete"]').count()) === 1);
    await page.click('#mine button[data-t="m_confirm_delete"]'); await page.waitForFunction(() => document.querySelectorAll('#mine .result').length === 1);
    ok('no script error on any page of phase A', errors.length === 0, errors.join(' | '));
  }

  if (phase === 'b') {
    const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
    const page = await ctx.newPage();
    const errors = []; page.on('pageerror', (e) => errors.push(e.message));
    await page.goto(P('history.html?lang=en')); await page.waitForSelector('#au-email');
    await login(page, state.email, state.password);
    await page.waitForSelector('#matches article');
    const h = await text(page, '#matches');
    ok('the history shows the matches with kind, changes and reasons', h.includes(state.new_key) && /new/.test(h), h.slice(0, 400));
    ok('the exploitation update appears as its own entry', h.includes('exploitation_added'), h.slice(0, 600));
    ok('deliveries are listed as sent', /sent/.test(await text(page, '#deliveries')), await text(page, '#deliveries'));
    const unread = await page.locator('#matches button[data-t="hi_read"]').count();
    await page.locator('#matches button[data-t="hi_read"]').first().click();
    await page.waitForFunction((n) => document.querySelectorAll('#matches button[data-t="hi_read"]').length === n - 1, unread);
    await page.locator('#matches button[data-t="hi_ack"]').first().click(); await page.waitForSelector('#matches >> text=/acknowledged/');
    await page.check('#hi-unread'); await page.waitForTimeout(500);
    ok('unread filter hides what was read', (await page.locator('#matches article').count()) === unread - 1, await page.locator('#matches article').count());

    // private RSS feed: the URL is shown once, works without a session, is private, and dies when revoked
    await page.goto(P('preferences.html?lang=en')); await page.waitForSelector('#tk-add');
    await page.fill('#tk-label', 'my reader'); await page.click('#tk-add'); await page.waitForSelector('#tk-new code');
    const url = (await text(page, '#tk-new code')).trim();
    ok('the feed address is shown with a warning that it is the secret', /IS the secret/.test(await text(page, '#tk-new')), await text(page, '#tk-new'));
    ok('the token is long and random-looking', /\/feeds\/private\/[A-Za-z0-9_-]{43,}\.xml$/.test(url), url);
    const path = url.replace(/^https?:\/\/[^/]+/, '');
    const anon = await browser.newContext(); const r1 = await anon.request.get(base + path);
    const xml = await r1.text();
    ok('the private feed works without a session and carries the match', r1.status() === 200 && xml.includes(state.new_key) && /<rss version="2.0">/.test(xml), r1.status() + xml.slice(0, 200));
    ok('the private feed is never cacheable and not indexable', r1.headers()['cache-control'] === 'private, no-store' && /noindex/.test(r1.headers()['x-robots-tag'] || ''), JSON.stringify(r1.headers()));
    await page.reload(); await page.waitForSelector('#tokens table');
    const listing = await text(page, '#tokens');
    ok('the token is not shown again in the list', !url.includes('/') || !listing.includes(path.split('/').pop().replace('.xml', '')), listing);
    await page.click('#tokens button[data-t="tk_revoke"]'); await page.waitForSelector('#tokens >> text=/revoked/');
    const r2 = await anon.request.get(base + path);
    ok('a revoked feed stops working at once', r2.status() === 404, r2.status());
    await anon.close();

    // webhook with an unsafe destination is refused in the UI with the reason
    await page.fill('#ch-url', 'https://169.254.169.254/latest/meta-data/'); await page.click('#ch-hook-add');
    await waitText(page, '#ch-new', /refused/);
    ok('an unsafe webhook destination is refused', /refused/.test(await text(page, '#ch-new')), await text(page, '#ch-new'));

    // organisations (the reference server runs this test without the MFA requirement, which has its own API tests)
    await page.goto(P('org.html?lang=en')); await page.waitForSelector('#og-add');
    await page.fill('#og-name', 'Acme Security'); await page.click('#og-add'); await waitText(page, '#og-status', /OK/);
    await page.waitForSelector('#og-pick option', { state: 'attached' });
    await page.fill('#mb-email', state.second_email); await page.selectOption('#mb-role', 'viewer'); await page.click('#mb-add'); await waitText(page, '#og-status', /OK/);
    await page.waitForSelector('#members >> text=' + state.second_email);      // the list is redrawn after the request: wait for the new row, not for the old table
    ok('the member was added with the role', /Viewer|Lector/i.test(await text(page, '#members')) && (await text(page, '#members')).includes(state.second_email), await text(page, '#members'));
    await page.fill('#un-name', 'Operations'); await page.click('#un-add-unit'); await page.waitForSelector('#units >> text=/Operations/');
    await page.waitForSelector('#audit table');
    ok('the audit log lists who did what and its hash chain is intact', /org\.create/.test(await text(page, '#audit')) && /member\.add/.test(await text(page, '#audit')) && /intact|íntegra/i.test(await text(page, '#audit')), await text(page, '#audit'));

    // Spanish: every label is translated, no key leaks into the page
    await page.goto(P('index.html?lang=es')); await page.waitForSelector('#count');
    const keys = await page.evaluate(() => Array.from(document.querySelectorAll('[data-t]')).filter((e) => e.getAttribute('data-t') === e.textContent.trim()).map((e) => e.getAttribute('data-t')));
    ok('no translation key shows through in Spanish', keys.length === 0, keys.join(','));
    ok('the page is in Spanish', /Filtros/.test(await page.locator('body').innerText()), 'not Spanish');
    ok('no script error on any page of phase B', errors.length === 0, errors.join(' | '));
  }

  if (phase === 'axe') {
    const axeSrc = join(nm, 'axe-core', 'axe.min.js');
    const pages = ['index.html', 'alert.html?id=' + state.alert_id, 'subscribe.html', 'mine.html', 'history.html', 'sources.html', 'preferences.html', 'org.html'];
    for (const [vw, vh, label] of [[1280, 900, 'desktop'], [390, 844, 'mobile']]) {
      for (const dark of [false, true]) {
        const ctx = await browser.newContext({ viewport: { width: vw, height: vh }, bypassCSP: true });   // only to inject axe: the pages' own policy forbids inline scripts
        const page = await ctx.newPage();
        await page.goto(P('mine.html?lang=en')); await page.waitForSelector('#au-email'); await login(page, state.email, state.password);
        for (const p of pages) {
          for (const lang of ['en', 'es']) {
            await page.goto(P(p + (p.includes('?') ? '&' : '?') + 'lang=' + lang + (dark ? '&theme=dark' : '&theme=light')));
            await page.waitForFunction(() => { const s = document.getElementById('load-state'); return s && s.className !== '' && !/Cargando|Loading/.test(s.textContent); }, null, { timeout: 30000 });
            await page.waitForTimeout(400);
            await page.addScriptTag({ path: axeSrc });
            const res = await page.evaluate(() => window.axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'] } }).then((r) => r.violations.map((v) => ({ id: v.id, impact: v.impact, nodes: v.nodes.slice(0, 3).map((n) => n.target.join(' ') + ' :: ' + (n.failureSummary || '').split('\n')[1]) }))));
            ok(`axe: ${p.split('?')[0]} ${lang} ${label}${dark ? ' dark' : ''}`, res.length === 0, JSON.stringify(res));
            const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
            ok(`no horizontal page scroll: ${p.split('?')[0]} ${lang} ${label}${dark ? ' dark' : ''}`, overflow <= 0, overflow);
          }
        }
        await ctx.close();
      }
    }
  }
} catch (e) {
  results.push({ name: 'the script threw', ok: false, detail: String(e && e.stack || e).slice(0, 1500) });
} finally {
  await browser.close();
}
console.log(JSON.stringify(results));
process.exit(results.every((r) => r.ok) ? 0 : 1);
