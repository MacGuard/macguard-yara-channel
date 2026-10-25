// The search boxes keep their node, focus, caret and text while the list reloads under them: typing a whole phrase, deleting, pasting, accents, filters and back-navigation, in the real browsers.
// UI_ENGINES=chromium,firefox,webkit (default: chromium only).
import test, { describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium, firefox, webkit } from 'playwright';
import { startServer, openAs, VIEWPORTS } from './harness.mjs';

const ENGINES = { chromium, firefox, webkit }, WANT = (process.env.UI_ENGINES || 'chromium').split(',');
const PHRASE = 'pack_005 ünïcode áéíóú ñ', ROUTES = [['#/published', '#p-search'], ['#/quarantine', '#q-search']];
const open = async (browser, srv, role, vp, hash, opts = {}) => { const ctx = await openAs(browser, srv, role, vp, opts); const page = await ctx.newPage(); await page.goto(srv.base + '/' + hash, { waitUntil: 'domcontentloaded' }); await page.waitForSelector('#page-title'); return page; };
const focused = (page) => page.evaluate(() => document.activeElement && document.activeElement.id);

for (const name of WANT) {
  describe(name, () => {
    let browser, qsrv, psrv;
    before(async () => { browser = await ENGINES[name].launch(); qsrv = await startServer(); psrv = await startServer(['--published']); });
    after(async () => { await browser.close(); qsrv.stop(); psrv.stop(); });

    for (const [hash, sel] of ROUTES) {
      test(`${hash}: 24 characters typed with a real keyboard keep the same input focused and nothing is lost, and the list follows`, async () => {
        const page = await open(browser, hash === '#/published' ? psrv : qsrv, 'reviewer', VIEWPORTS.desktop, hash); await page.waitForSelector(`${sel}`); await page.waitForSelector('.rule, .empty');
        await page.evaluate((s) => { window.__node = document.querySelector(s); }, sel);
        await page.click(sel); await page.keyboard.type(PHRASE, { delay: 40 });
        assert.equal(await page.inputValue(sel), PHRASE, 'every character arrived'); assert.equal(await focused(page), sel.slice(1), 'focus never left the input');
        await page.waitForTimeout(700); assert.equal(await page.evaluate((s) => window.__node === document.querySelector(s), sel), true, 'the input node is the same one: the view was not rebuilt'); assert.equal(await focused(page), sel.slice(1));
        assert.match(page.url(), /q=/, 'the filter is in the URL');
        for (let i = 0; i < 5; i++) await page.keyboard.press('Backspace'); assert.equal(await page.inputValue(sel), PHRASE.slice(0, -5)); assert.equal(await focused(page), sel.slice(1));
      });

      test(`${hash}: caret and selection survive a reload of the list; paste works; clearing restores the full list`, async () => {
        const page = await open(browser, hash === '#/published' ? psrv : qsrv, 'reviewer', VIEWPORTS.desktop, hash); await page.waitForSelector('.rule, .empty'); const before = await page.locator('.rule').count();
        await page.click(sel); await page.keyboard.type('pack_0'); await page.waitForTimeout(600); await page.evaluate((q) => document.querySelector(q).setSelectionRange(0, 0), sel); await page.keyboard.type('x'); await page.waitForTimeout(600);
        assert.equal(await page.evaluate((s) => document.querySelector(s).selectionStart, sel), 1, 'caret stays where the user put it'); assert.equal(await page.inputValue(sel), 'xpack_0');
        await page.fill(sel, 'pack_005'); await page.waitForTimeout(700); assert.equal(await focused(page), sel.slice(1));
        await page.fill(sel, ''); await page.waitForFunction((n) => document.querySelectorAll('.rule').length === n, before); assert.equal(await page.locator('.rule').count(), before);
      });

      test(`${hash}: a late answer to an earlier search never overwrites the list of the latest one`, async () => {
        const page = await open(browser, hash === '#/published' ? psrv : qsrv, 'reviewer', VIEWPORTS.desktop, hash); await page.waitForSelector('.rule, .empty');
        let n = 0; await page.route(/\/api\/(published|candidates)\?/, async (r) => { const mine = ++n; if (mine === 1) await new Promise((res) => setTimeout(res, 900)); await r.continue(); });
        await page.click(sel); await page.keyboard.type('zzzzzz'); await page.waitForTimeout(450); await page.fill(sel, ''); await page.waitForTimeout(1600);
        assert.equal(await page.inputValue(sel), ''); assert.ok(await page.locator('.rule').count() > 0, 'the list shows the latest (empty) search, not the stale "zzzzzz" one');
      });
    }

    test('phone keyboard: typing in the published search on a phone viewport keeps focus', async () => {
      const page = await open(browser, psrv, 'reviewer', VIEWPORTS.iphone, '#/published', { device: { hasTouch: true } }); await page.waitForSelector('#p-search'); await page.tap('#p-search'); await page.keyboard.type('pack_00', { delay: 60 }); await page.waitForTimeout(700);
      assert.equal(await page.inputValue('#p-search'), 'pack_00'); assert.equal(await focused(page), 'p-search');
    });

    test('Back returns to the filtered state: the search text and the URL come back after following a result', async () => {
      const page = await open(browser, psrv, 'reviewer', VIEWPORTS.desktop, '#/published'); await page.waitForSelector('.rule a.rule-title'); const name = (await page.locator('.rule a.rule-title').first().innerText()).trim();
      await page.click('#p-search'); await page.keyboard.type(name, { delay: 20 }); await page.waitForFunction((n) => location.hash.includes('q=' + encodeURIComponent(n)) || location.hash.includes('q=' + n), name);
      await page.waitForFunction(() => document.querySelectorAll('.rule').length >= 1 && document.querySelectorAll('.rule').length < 50);
      await page.locator('.rule a.rule-title').first().click(); await page.waitForFunction(() => location.hash.startsWith('#/rules/')); await page.goBack(); await page.waitForSelector('#p-search');
      assert.equal(await page.inputValue('#p-search'), name, 'the search comes back with its text'); assert.match(await page.evaluate(() => location.hash), /q=/);
    });
  });
}
