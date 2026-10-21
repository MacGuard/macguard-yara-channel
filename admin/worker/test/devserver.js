// Runs the real worker handler behind a plain HTTP server with a seeded in-memory database, for browser tests only.
import http from 'node:http';
import https from 'node:https';
import { readFileSync, existsSync } from 'node:fs';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { world, cand, actionsToken } from './helpers.js';
import * as store from '../src/store.js';
import { installOps } from './ops_fixture.js';

const root = fileURLToPath(new URL('../public/', import.meta.url));
const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' };
const port = Number(process.argv[2] || 8790);
const w = await world();
const tls = process.env.MG_TLS_KEY && process.env.MG_TLS_CERT ? { key: readFileSync(process.env.MG_TLS_KEY), cert: readFileSync(process.env.MG_TLS_CERT) } : null;   // browsers refuse __Host- cookies over plain http (WebKit), so the browser tests run over TLS like production
const scheme = tls ? 'https' : 'http';
w.env.PUBLIC_URL = `${scheme}://127.0.0.1:${port}`;
w.deps.now = () => Math.floor(Date.now() / 1000);   // a real clock: long browser and pipeline runs must not outlive the fixed test clock
const items = []; const empty = process.argv.includes('--empty');
const many = process.argv.includes('--published') ? Array.from({ length: 120 }, (_, i) => ({ path: `rules/${i % 2 ? 'nextron' : 'community'}/pack_${String(i).padStart(3, '0')}.yar`, sha256: createHash('sha256').update(`published ${i}`).digest('hex'), bytes: 100 + i, source: i % 2 ? 'nextron' : 'community' })) : [];
for (let i = 0; i < 6; i++) items.push(cand(String(i), `rules/community/pack/rule_${i}.yar`, { ...(i % 2 ? { findings_schema: 1, engine: 'YARA 4.5.0', findings: [{ code: 'costly-regex', severity: 'review', detail: 'regex /(a+)+b/ risk 7: nested quantifier', observed: 7, threshold: 6, unit: 'risk score' }] } : {}), reasons: i % 2 ? ['costly-regex'] : ['filesize-loop', 'unknown-module'], metrics: { cpu_s: 0.4 + i, rss_mb: 30 + i * 12, compile_s: 0.8, scan_p95_s: 0.03 } }));
items.push(cand('9', 'rules/community/pack/evil.yar', { reasons: ['costly-regex'], content_b64: Buffer.from('<img src=x onerror="window.__xss=1"> rule X { condition: true }').toString('base64') }));
if (process.argv.includes('--blocked')) items.push(cand('t', 'rules/community/pack/truncated.yar', { reasons: ['ends-mid-file'], findings_schema: 1, findings: [{ code: 'ends-mid-file', severity: 'truncated', detail: 'the file ends inside rule R' }] }));   // a technical finding: not approvable
if (process.argv.includes('--deps')) items.push(   // a shared dependency (approvable) with two dependents, and a dependency that can never be approved with one dependent
  cand('c', 'rules/community/pack/shared_base.yar', { reasons: ['matches-benign-corpus'] }), cand('d1', 'rules/community/pack/uses_base_1.yar', { reasons: ['dependency-not-validated'], depends_on: ['rules/community/pack/shared_base.yar'] }),
  cand('d2', 'rules/community/pack/uses_base_2.yar', { reasons: ['dependency-not-validated'], depends_on: ['rules/community/pack/shared_base.yar'] }),
  cand('b', 'rules/community/pack/needs_cuckoo.yar', { reasons: ['blocked-module'] }), cand('x', 'rules/community/pack/uses_cuckoo.yar', { reasons: ['dependency-not-validated'], depends_on: ['rules/community/pack/needs_cuckoo.yar'] }));
if (process.argv.includes('--synthetic')) items.push(cand('z', 'synthetic-quarantine-test/s1.yar', { source: 'synthetic-test', reasons: ['synthetic-test'] }));
if (many.length) items.push(cand('n', many[0].path, { source: 'community', reasons: ['costly-regex'] }));   // a newer version of a published file waits in quarantine
if (!empty) await w.submit(items);
if (process.argv.includes('--released') && !empty) {   // one pending rule that the pipeline then published: the release callback with the evidence GitHub serves
  const first = items[0]; await w.release('rules-20261021-900', [first]);
  await w.call('POST', '/api/pipeline/released', { bearer: await w.pipelineToken('publish.yml', { run_id: '900', run_attempt: '1' }), body: { tag: 'rules-20261021-900', hashes: [first.sha256], run_url: `${w.env.PUBLIC_URL}/runs/900` } });
}
if (many.length && !empty) {   // the current signed release lists 120 files the panel never saw, plus one rule the pipeline published after it was quarantined
  const first = items[0]; await w.release('rules-20261021-900', [{ path: first.path, sha256: first.sha256, bytes: first.bytes, source: first.source }, ...many]);
  await w.call('POST', '/api/pipeline/released', { bearer: await w.pipelineToken('publish.yml', { run_id: '900', run_attempt: '1' }), body: { tag: 'rules-20261021-900', hashes: [first.sha256], run_url: `${w.env.PUBLIC_URL}/runs/900` } });
}
const sessions = {
  viewer: await w.login('vera', { pull: true }, { id: 11 }), reviewer: await w.login('rita', { push: true }, { id: 12 }), admin: await w.login('ada', { admin: true }, { id: 13 }),
  nobody: await w.login('sam', { pull: true }, { id: 14 }),   // signed in with GitHub but holds no role
};
installOps(w, { down: (process.env.MG_OPS_DOWN || '').split(',').filter(Boolean) });   // pipeline records the panel reads (faked GitHub, site and raw files)
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
  if (req.url.startsWith('/__release') && req.method === 'POST') {   // test-only: what GitHub serves for a public release (python client tests need the evidence the Worker now reads itself)
    const u = new URL(req.url, 'http://x'); const files = JSON.parse(Buffer.concat(chunks).toString() || '[]'); await w.release(u.searchParams.get('tag'), files);
    res.setHeader('Content-Type', 'application/json'); return res.end('{"ok":true}');
  }
  const { handle } = await import('../src/index.js');
  const r = await handle(new Request(`${scheme}://127.0.0.1:${port}${req.url}`, { method: req.method, headers: req.headers, body: chunks.length ? Buffer.concat(chunks) : undefined }), w.env, w.deps);
  const hdr = Object.fromEntries(r.headers); if (hdr['content-security-policy']) hdr['content-security-policy'] = hdr['content-security-policy'].replace("; frame-ancestors 'none'", "; frame-src 'self'"); /* test server only: the harness frames the panel */
  res.writeHead(r.status, hdr); res.end(Buffer.from(await r.arrayBuffer()));
}
