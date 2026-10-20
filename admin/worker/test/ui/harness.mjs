// Starts the real Worker handler (seeded in-memory D1, faked GitHub) on a free port for browser tests, and gives each role a ready session.
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createServer } from 'node:net';
import { execFileSync } from 'node:child_process';
import https from 'node:https';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

let cert;   // one throwaway self-signed certificate for 127.0.0.1 per test run, kept in a private temp dir, never in the repository
function tlsFiles() {
  if (cert) return cert; const dir = mkdtempSync(join(tmpdir(), 'mg-ui-tls-')); const cnf = join(dir, 'o.cnf');
  writeFileSync(cnf, '[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nCN=127.0.0.1\n[v3]\nsubjectAltName=IP:127.0.0.1\n');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-config', cnf, '-keyout', join(dir, 'k.pem'), '-out', join(dir, 'c.pem')], { stdio: 'ignore' });
  return (cert = { key: join(dir, 'k.pem'), cert: join(dir, 'c.pem') });
}

const free = () => new Promise((res) => { const s = createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); }); });
export async function startServer(args = []) {
  const port = await free(); const base = `https://127.0.0.1:${port}`, t = tlsFiles();
  const child = spawn(process.execPath, ['--no-warnings', fileURLToPath(new URL('../devserver.js', import.meta.url)), String(port), ...args], { stdio: ['ignore', 'pipe', 'ignore'], env: { ...process.env, MG_TLS_KEY: t.key, MG_TLS_CERT: t.cert } }); process.on('exit', () => child.kill());   // never leave the server behind, whatever ends the test run
  await new Promise((res, rej) => { const to = setTimeout(() => rej(new Error('dev server did not start')), 20000); child.stdout.on('data', (d) => { if (String(d).includes('ready')) { clearTimeout(to); res(); } }); child.on('exit', (c) => rej(new Error(`dev server exited ${c}`))); });
  const sessions = await new Promise((res, rej) => https.get(`${base}/__sessions`, { rejectUnauthorized: false }, (r) => { let d = ''; r.on('data', (c) => (d += c)); r.on('end', () => res(JSON.parse(d))); }).on('error', rej));
  return { base, port, sessions, stop: () => { child.kill(); child.stdout.destroy(); } };
}
/** A context already signed in as `role` (viewer | reviewer | admin), or anonymous when role is null. */
export async function openAs(browser, srv, role, viewport, opts = {}) {
  const ctx = await browser.newContext({ viewport, colorScheme: opts.colorScheme || 'light', locale: opts.locale || 'es-ES', ignoreHTTPSErrors: true, ...(opts.device || {}) });
  if (role) await ctx.addCookies([{ name: '__Host-mg_session', value: srv.sessions[role], domain: '127.0.0.1', path: '/', secure: true, httpOnly: true, sameSite: 'Strict' }]);
  // Hermetic: GitHub avatars are answered locally (a 1x1 PNG), so tests never depend on the network.
  const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==', 'base64');
  await ctx.route('https://avatars.githubusercontent.com/**', (r) => r.fulfill({ status: 200, contentType: 'image/png', body: PNG }));
  ctx.setDefaultTimeout(10000); ctx.setDefaultNavigationTimeout(15000);
  return ctx;
}
export const VIEWPORTS = { iphone: { width: 390, height: 844 }, tablet: { width: 820, height: 1180 }, desktop: { width: 1440, height: 900 } };
