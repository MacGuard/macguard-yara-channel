// Indicative latency of the gateway on workerd (Miniflare) with real D1 and R2. Sequential and concurrent hash lookups through the full path (auth, policy, quota, usage record).
// Not a capacity test: one machine, local storage, no network, other processes running. Usage: node tools/bench.mjs [--json]
import { createRequire } from 'node:module';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('..', import.meta.url));
const common = execFileSync('git', ['rev-parse', '--git-common-dir'], { cwd: root, encoding: 'utf8' }).trim();
const dir = [process.env.MINIFLARE_DIR, resolve(root, '..', 'admin', 'worker'), resolve(root, common, '..', 'admin', 'worker')].filter(Boolean).find((c) => existsSync(join(c, 'node_modules', 'miniflare')));
if (!dir) { console.log('SKIPPED: miniflare not found'); process.exit(0); }
const { Miniflare } = createRequire(join(dir, 'package.json'))('miniflare');
const { createTenant, issueKey } = await import('../src/auth.js'); const { seedPolicy } = await import('../src/policy.js');
const SEED = JSON.parse(readFileSync(join(root, '..', 'config', 'commercial', 'policy.seed.json'), 'utf8')); SEED.launch.quotas.minute = 1e9; SEED.launch.quotas.day = 1e9; SEED.launch.quotas.month = 1e9;
const P = { KEY_PEPPER: 'k'.repeat(40), ADMIN_PEPPER: 'a'.repeat(40), TOTP_SEAL_KEY: 's'.repeat(40) };
const persist = mkdtempSync(join(tmpdir(), 'mg-bench-'));
const mods = readdirSync(join(root, 'src')).filter((f) => f.endsWith('.js')).sort((a, b) => (a === 'index.js' ? -1 : b === 'index.js' ? 1 : a.localeCompare(b))).map((f) => ({ type: 'ESModule', path: f, contents: readFileSync(join(root, 'src', f), 'utf8') }));
const mf = new Miniflare({ modules: mods, compatibilityDate: '2026-08-01', d1Databases: { DB: 'g' }, d1Persist: join(persist, 'd1'), bindings: P });
const db = await mf.getD1Database('DB'); const stmts = []; let cur = '';
for (const line of readFileSync(join(root, 'schema.sql'), 'utf8').split('\n')) { const l = line.replace(/\s--.*$/, '').replace(/^--.*$/, ''); if (!l.trim()) continue; cur += l + '\n'; if (/^\s*CREATE TRIGGER/i.test(cur) ? /\bEND;\s*$/.test(l) : /;\s*$/.test(l)) { stmts.push(cur.trim().replace(/;$/, '')); cur = ''; } }
await db.batch(stmts.map((s) => db.prepare(s))); const clock = () => new Date(); await seedPolicy(db, clock, SEED); await createTenant(db, clock, { id: 't', name: 't' });
const key = (await issueKey(db, P, clock, 't', { scopes: ['intel.query'] })).key; const H = 'a'.repeat(64);
const hit = () => mf.dispatchFetch('https://gw.test/v1/intelligence/hash/' + H, { headers: { authorization: `Bearer ${key}` } }).then(async (r) => { await r.arrayBuffer(); return r.status; });
const pct = (a, p) => a[Math.min(a.length - 1, Math.floor(a.length * p))];
for (let i = 0; i < 20; i++) await hit();
const seq = []; for (let i = 0; i < 300; i++) { const t = performance.now(); await hit(); seq.push(performance.now() - t); } seq.sort((a, b) => a - b);
const t0 = performance.now(); const codes = await Promise.all(Array.from({ length: 200 }, hit)); const wall = performance.now() - t0;
const out = { requests_sequential: 300, p50_ms: +pct(seq, 0.5).toFixed(2), p95_ms: +pct(seq, 0.95).toFixed(2), p99_ms: +pct(seq, 0.99).toFixed(2), concurrent_200_wall_ms: +wall.toFixed(1), concurrent_ok: codes.filter((c) => c === 200).length,
  usage_events_recorded: (await db.prepare('SELECT COUNT(*) n FROM usage_events').first()).n, note: 'indicative only: local workerd, local D1, no network, machine shared with other processes' };
console.log(JSON.stringify(out, null, process.argv.includes('--json') ? 1 : 0)); await mf.dispose(); rmSync(persist, { recursive: true, force: true });
