// Runs the real worker handler behind a plain HTTP server with a seeded in-memory database, for browser tests only.
import http from 'node:http';
import https from 'node:https';
import { readFileSync, existsSync } from 'node:fs';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { world, cand, actionsToken } from './helpers.js';
import * as store from '../src/store.js';

const root = fileURLToPath(new URL('../public/', import.meta.url));
const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' };
const port = Number(process.argv[2] || 8790);
const w = await world();
const tls = process.env.MG_TLS_KEY && process.env.MG_TLS_CERT ? { key: readFileSync(process.env.MG_TLS_KEY), cert: readFileSync(process.env.MG_TLS_CERT) } : null;   // browsers refuse __Host- cookies over plain http (WebKit), so the browser tests run over TLS like production
const scheme = tls ? 'https' : 'http';
w.env.PUBLIC_URL = `${scheme}://127.0.0.1:${port}`;
w.deps.now = () => Math.floor(Date.now() / 1000);   // a real clock: long browser and pipeline runs must not outlive the fixed test clock
const items = []; const empty = process.argv.includes('--empty');
for (let i = 0; i < 6; i++) items.push(cand(String(i), `rules/community/pack/rule_${i}.yar`, { reasons: i % 2 ? ['costly-regex'] : ['filesize-loop', 'unknown-module'], metrics: { cpu_s: 0.4 + i, rss_mb: 30 + i * 12, compile_s: 0.8, scan_p95_s: 0.03 } }));
items.push(cand('9', 'rules/community/pack/evil.yar', { reasons: ['costly-regex'], content_b64: Buffer.from('<img src=x onerror="window.__xss=1"> rule X { condition: true }').toString('base64') }));
if (!empty) await w.submit(items);
const sessions = {
  viewer: await w.login('vera', { pull: true }, { id: 11 }), reviewer: await w.login('rita', { push: true }, { id: 12 }), admin: await w.login('ada', { admin: true }, { id: 13 }),
  nobody: await w.login('sam', { pull: true }, { id: 14 }),   // signed in with GitHub but holds no role
};
w.account('newbie', 900); w.account('acme-org', 901, 'Organization');   // exist on the faked GitHub, for the add-member flow
for (const u of Object.values(sessions)) await w.call('GET', '/api/me', { user: u });   // every session asks GitHub once, so the member list knows each repository permission
for (const [l, id] of [['ada', 13], ['rita', 12], ['vera', 11], ['sam', 14]]) await store.appendAudit(w.db, { actor: l, role: 'NONE', action: 'session.login', target: 'session', detail: { user_id: id } }, new Date().toISOString());
await w.grant(sessions.admin, 'vera', 'VIEWER');
w.env.ASSETS = { fetch: async (req) => {
  const p = new URL(req.url).pathname; const f = normalize(join(root, p === '/' ? 'index.html' : p));
  if (!f.startsWith(root) || !existsSync(f)) return new Response('not found', { status: 404 });
  return new Response(readFileSync(f), { headers: { 'Content-Type': types[extname(f)] || 'application/octet-stream' } });
} };
(tls ? https.createServer(tls, handler) : http.createServer(handler)).listen(port, '127.0.0.1', () => console.log('ready', port));
async function handler(req, res) {
  const chunks = []; for await (const c of req) chunks.push(c);
  if (req.url === '/__sessions') { res.setHeader('Content-Type', 'application/json'); return res.end(JSON.stringify(Object.fromEntries(Object.entries(sessions).map(([k, v]) => [k, v.sid])))); }
  if (req.url.startsWith('/__oidc')) {   // emulates the GitHub Actions token endpoint for the python client tests
    const u = new URL(req.url, 'http://x'); if (req.headers.authorization !== 'bearer test-request-token') { res.statusCode = 401; return res.end('{}'); }
    const t = await actionsToken(w.key, { aud: u.searchParams.get('audience'), job_workflow_ref: `${w.env.REPO}/.github/workflows/${u.searchParams.get('workflow') || 'daily.yml'}@refs/heads/main` });
    res.setHeader('Content-Type', 'application/json'); return res.end(JSON.stringify({ value: t }));
  }
  const { handle } = await import('../src/index.js');
  const r = await handle(new Request(`${scheme}://127.0.0.1:${port}${req.url}`, { method: req.method, headers: req.headers, body: chunks.length ? Buffer.concat(chunks) : undefined }), w.env, w.deps);
  const hdr = Object.fromEntries(r.headers); if (hdr['content-security-policy']) hdr['content-security-policy'] = hdr['content-security-policy'].replace("; frame-ancestors 'none'", "; frame-src 'self'"); /* test server only: the harness frames the panel */
  res.writeHead(r.status, hdr); res.end(Buffer.from(await r.arrayBuffer()));
}
