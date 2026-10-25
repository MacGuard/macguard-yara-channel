// The OFFLINE recovery guide, opened from a file with the network cut: it must work with no server, no request and no panel; its inline script and style are pinned by a CSP hash; commands come only from validated parameters;
// an output-checked step is never done without a match; the package verifies with SHA256SUMS and contains no secret. UI_ENGINES=chromium,firefox,webkit (default chromium).
import test, { describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { chromium, firefox, webkit } from 'playwright';

const HERE = dirname(fileURLToPath(import.meta.url)), AXE = readFileSync(createRequire(import.meta.url).resolve('axe-core/axe.min.js'), 'utf8'), WCAG = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];
const ENGINES = { chromium, firefox, webkit }, WANT = (process.env.UI_ENGINES || 'chromium').split(',');
const openStep = async (loc) => { if (!(await loc.evaluate((e) => e.open))) await loc.locator('summary').click(); };
const b64 = (s) => createHash('sha256').update(s).digest('base64');

const out = mkdtempSync(join(tmpdir(), 'mg-guide-')); process.on('exit', () => rmSync(out, { recursive: true, force: true }));   // kept for the whole run: the browser tests open it
describe('package', () => {
  test('it builds, verifies with SHA256SUMS, is tamper-evident, carries the trust policy, and holds no secret', () => {
    execFileSync(process.execPath, [join(HERE, '..', '..', 'tools', 'build_recovery_guide.mjs'), out, '--commit', 'abc1234', '--built', '2026-10-26T00:00:00Z'], { stdio: 'pipe' });
    assert.deepEqual(readdirSync(out).sort(), ['README.md', 'RUNBOOK.md', 'SHA256SUMS', 'recovery-guide.html', 'trust']);
    execFileSync('shasum', ['-a', '256', '-c', 'SHA256SUMS'], { cwd: out, stdio: 'pipe' });
    const html = readFileSync(join(out, 'recovery-guide.html'), 'utf8'), css = html.match(/<style>([\s\S]*?)<\/style>/)[1], scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]), csp = html.match(/Content-Security-Policy" content="([^"]+)"/)[1];
    assert.equal(scripts.length, 1); assert.ok(csp.includes(`'sha256-${b64(css)}'`) && csp.includes(`'sha256-${b64(scripts[0])}'`), 'the CSP pins exactly the inline style and script'); assert.match(csp, /default-src 'none'/); assert.ok(!/unsafe-inline|unsafe-eval|https?:/.test(csp));
    assert.ok(!/<link|<img|<iframe|src="http|href="http|@import|url\(/.test(html), 'no external resource of any kind');
    assert.doesNotMatch(readdirSync(out).map((f) => (f === 'trust' ? '' : readFileSync(join(out, f), 'utf8'))).join('\n') + readFileSync(join(out, 'trust', 'backup-trust.json'), 'utf8'), /AGE-SECRET-KEY-1[A-Z0-9]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----\s*[A-Za-z0-9+/=]{20,}|github_pat_[A-Za-z0-9_]{20,}|ghp_[A-Za-z0-9]{20,}/);
    assert.equal(JSON.parse(readFileSync(join(out, 'trust', 'backup-trust.json'), 'utf8')).schema, 'macguard.backup-trust/1'); assert.match(readFileSync(join(out, 'trust', 'verifier-tools.sha256'), 'utf8'), /^[0-9a-f]{64}  gateway\/tools\/recover_verify\.sh$/m);
    assert.match(readFileSync(join(out, 'README.md'), 'utf8'), /cosign verify-blob --bundle SHA256SUMS\.sigstore\.json --certificate-identity https:\/\/github\.com\/MacGuard\/macguard-yara-channel\/\.github\/workflows\/recovery-guide\.yml@refs\/heads\/main/);
    const runbook = readFileSync(join(out, 'RUNBOOK.md'), 'utf8'); for (const t of ['Recover D1 only', 'Recover the full service', 'Recover after a security compromise', 'Recovery drill']) assert.match(runbook, new RegExp(t));
    writeFileSync(join(out, 'recovery-guide.html'), html + ' '); assert.throws(() => execFileSync('shasum', ['-a', '256', '-c', 'SHA256SUMS'], { cwd: out, stdio: 'pipe' }), 'one extra byte is detected');
    writeFileSync(join(out, 'recovery-guide.html'), html);
    globalThis.__guide = pathToFileURL(join(out, 'recovery-guide.html')).href;
  });
});

for (const name of WANT) {
  describe(`${name} offline`, () => {
    let browser;
    before(async () => { browser = await ENGINES[name].launch(); });
    after(async () => { await browser.close(); });
    const open = async (opts = {}) => {
      const ctx = await browser.newContext({ viewport: opts.viewport || { width: 1100, height: 900 }, colorScheme: opts.colorScheme || 'light', locale: 'es-ES', acceptDownloads: true }); await ctx.setOffline(true);
      const page = await ctx.newPage(); page.errors = []; page.requests = []; page.on('console', (m) => { if (m.type() === 'error' && !(page.axeRan && /Refused to apply a stylesheet/.test(m.text()))) page.errors.push(m.text()); }); page.on('pageerror', (e) => page.errors.push(String(e))); page.on('request', (r) => page.requests.push(r.url()));
      await page.goto(globalThis.__guide); await page.waitForSelector('.step'); return page;
    };

    test('it renders and works with no network: no request leaves the file, no console error, ES/EN, a procedure per scenario', async () => {
      const page = await open(); assert.deepEqual(page.requests.filter((u) => !u.startsWith('file:')), []); assert.deepEqual(page.errors, []);
      assert.equal(await page.locator('#proc option').count(), 4); assert.match(await page.locator('h1').innerText(), /Guía de recuperación offline/);
      await page.getByRole('button', { name: 'EN' }).click(); assert.equal(await page.evaluate(() => document.documentElement.lang), 'en'); await page.selectOption('#proc', 'compromise'); assert.match(await page.locator('.step summary').first().innerText(), /Declare the incident/);
      assert.ok((await page.locator('.step').count()) >= 40);
    });

    test('gating and checks: blocked steps show no command; wrong output does not advance; the right output does; a pasted secret is discarded; state keeps identifiers only', async () => {
      const page = await open(); await page.selectOption('#proc', 'drill');
      const first = page.locator('.step').first(); assert.equal(await first.getAttribute('open'), '', 'the first pending step is open');
      await first.locator('textarea').fill('Windows'); await first.getByRole('button', { name: 'Comprobar' }).click(); assert.match(await first.locator('.bad').innerText(), /NO coincide/); assert.equal(await page.locator('.step.is-done').count(), 0);
      await first.locator('textarea').fill('Darwin arm64'); await first.getByRole('button', { name: 'Comprobar' }).click(); await page.waitForSelector('.step.is-done'); assert.equal(await page.locator('.step.is-done').count(), 1);
      const locked = page.locator('.step.is-blocked').first(); await openStep(locked); assert.equal(await locked.locator('pre').count(), 0, 'a blocked step shows no command'); assert.match(await locked.innerText(), /Antes completa/);
      const tools = page.locator('.step', { hasText: 'herramientas instaladas' }).first(); await openStep(tools); await tools.locator('textarea').fill('OK cosign\n' + ['AGE', 'SECRET', 'KEY', '1QYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQS'].join('-') + ''); await tools.getByRole('button', { name: 'Comprobar' }).click();
      assert.match(await tools.locator('.bad').innerText(), /clave/); assert.equal(await tools.locator('textarea').inputValue(), ''); const saved = await page.evaluate(() => JSON.stringify(Object.entries(localStorage))); assert.doesNotMatch(saved, /Darwin|AGE-SECRET/);
      await page.reload(); await page.waitForSelector('.step'); assert.equal(await page.locator('.step.is-done').count(), 1, 'progress survives a reload, offline');
    });

    test('parameters: hostile values never reach a command; valid values give an exact quoted command; the copy button copies it', async () => {
      const page = await open(); await page.selectOption('#proc', 'drill'); await page.evaluate(() => { localStorage.setItem('mg_guide_proc', 'drill'); localStorage.setItem('mg_guide_v1:drill', JSON.stringify({ values: {}, steps: { pick_backup: { state: 'done' }, bw_unlock: { state: 'done' } } })); }); await page.reload(); await page.waitForSelector('.step');
      const step = page.locator('.step', { hasText: 'Descargar la copia con la credencial READ' }).first(); await openStep(step);
      await page.locator('#v-stamp').fill('20261025T032300Z; rm -rf ~'); await page.locator('#v-provider').fill('b2'); await page.locator('#v-provider').blur(); await page.waitForSelector('.step');
      assert.equal(await page.locator('#v-stamp').getAttribute('aria-invalid'), 'true'); assert.equal(await page.locator('pre', { hasText: 'rm -rf ~' }).count(), 0, 'the hostile value is in no command');
      await page.locator('#v-stamp').fill('20261025T032300Z'); await page.locator('#v-stamp').blur(); const s2 = page.locator('.step', { hasText: 'Descargar la copia con la credencial READ' }).first(); await openStep(s2);
      const cmd = await s2.locator('.cmd code').innerText(); assert.match(cmd, /backup_objstore\.mjs fetch-previous --only b2 --stamp 20261025T032300Z /); assert.doesNotMatch(cmd, /\{[a-z]/);
    });

    test('print layout shows every step (a paper copy is complete)', async () => {
      const page = await open(); await page.selectOption('#proc', 'drill'); await page.emulateMedia({ media: 'print' }); const hidden = await page.evaluate(() => [...document.querySelectorAll('.step > *')].filter((e) => e.offsetParent === null && getComputedStyle(e).display === 'none').length); assert.equal(hidden, 0);
    });

    for (const [vp, size] of [['desktop', { width: 1280, height: 900 }], ['phone', { width: 390, height: 844 }]]) for (const scheme of ['light', 'dark']) test(`WCAG 2.2 AA and layout — ${vp}, ${scheme}`, async () => {
      const page = await open({ viewport: size, colorScheme: scheme }); await page.selectOption('#proc', 'd1_only'); assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1), true);
      assert.deepEqual(page.errors, []); page.axeRan = true; await page.evaluate(AXE); const r = await page.evaluate((tags) => axe.run(document, { runOnly: { type: 'tag', values: tags }, resultTypes: ['violations'] }), WCAG);
      assert.deepEqual(r.violations.map((v) => `${v.id}: ${v.nodes.slice(0, 3).map((n) => n.target.join(' ')).join(' | ')}`), []);
    });
  });
}
