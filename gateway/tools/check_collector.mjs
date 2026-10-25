// Read-only check of the live collector after a token has been set: authenticated flag, remaining allowance, recent success ratio and the causes of recent failures. Writes nothing.
// Usage: node tools/check_collector.mjs [--env environments/production.wrangler.toml] [--db macguard-gateway]
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
const arg = (n, d) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : d; };
const env = resolve(arg('--env', 'environments/production.wrangler.toml')), db = arg('--db', 'macguard-gateway'), account = (readFileSync(env, 'utf8').match(/^account_id\s*=\s*"([0-9a-f]{32})"/m) ?? [])[1];
const q = (sql) => { const t = execFileSync('npx', ['--yes', 'wrangler@4.149.0', 'd1', 'execute', db, '--remote', '--config', env, '--json', '--command', sql], { env: { ...process.env, CLOUDFLARE_ACCOUNT_ID: account }, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); return JSON.parse(t.slice(t.indexOf('[')))[0].results; };
const s = q('SELECT last_attempt_at, last_success_at, last_status, last_error, consecutive_failures, rate_remaining, rate_reset_at FROM gh_sync')[0] ?? {}, hasAuth = q("SELECT COUNT(*) n FROM pragma_table_info('gh_sync') WHERE name = 'authenticated'")[0].n;
const auth = hasAuth ? q('SELECT authenticated a FROM gh_sync')[0]?.a : null, runs = q("SELECT status, COUNT(*) n FROM gh_sync_log WHERE observed_at > strftime('%Y-%m-%dT%H:%M:%SZ','now','-1 day') GROUP BY status");
const total = runs.reduce((a, r) => a + r.n, 0), ok = runs.find((r) => r.status === 'ok')?.n ?? 0;
console.log(JSON.stringify({ authenticated: hasAuth ? !!auth : 'unknown (migration 0002 not applied)', last_status: s.last_status, last_success_at: s.last_success_at, consecutive_failures: s.consecutive_failures, rate_remaining: s.rate_remaining, runs_24h: total, ok_24h: ok, success_ratio_24h: total ? +(ok / total).toFixed(3) : null, causes_24h: Object.fromEntries(runs.filter((r) => r.status !== 'ok').map((r) => [r.status, r.n])) }, null, 1));
const healthy = hasAuth && auth && total >= 3 && ok / total >= 0.95; console.error(healthy ? 'HEALTHY: authenticated and >= 95% of recent runs succeeded' : 'NOT YET HEALTHY (needs migration 0002, a token, and a few runs)');
