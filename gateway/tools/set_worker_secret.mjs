// Uploads ONE Worker secret read from standard input, so the value never appears in a command line, a shell history or a chat: `pbpaste | node tools/set_worker_secret.mjs --name GITHUB_TOKEN`.
// The value is trimmed, checked against the shape of that secret, and passed to `wrangler secret put` through a pipe. Only its length is ever printed. `--dry-run` validates without uploading.
// Remote effect when not dry-run: it sets a secret on the Worker named in --env (needs the owner's authorisation). Usage: node tools/set_worker_secret.mjs --name NAME [--env environments/production.wrangler.toml] [--dry-run]
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

export const SHAPES = { GITHUB_TOKEN: /^(?:ghp_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}|gh[ousr]_[A-Za-z0-9]{36,})$/, GUARDOPS_INGEST_TOKEN: /^[A-Za-z0-9_-]{24,255}$/,
  // Gateway peppers and seal key: ONLY for a staging Worker (fresh random values, never the production ones). Rotating them in production would invalidate every API key and administrator, so production refuses them.
  KEY_PEPPER: /^[A-Za-z0-9+/=_-]{32,255}$/, ADMIN_PEPPER: /^[A-Za-z0-9+/=_-]{32,255}$/, TOTP_SEAL_KEY: /^[A-Za-z0-9+/=_-]{32,255}$/ };
export const STAGING_ONLY = new Set(['KEY_PEPPER', 'ADMIN_PEPPER', 'TOTP_SEAL_KEY']);
export const workerName = (envFile) => (readFileSync(envFile, 'utf8').match(/^name\s*=\s*"([^"]+)"/m) ?? [])[1] ?? null;
export function placeAllowed(name, envFile) { return !STAGING_ONLY.has(name) || /-staging$/.test(workerName(envFile) ?? ''); }
export function checkSecret(name, raw) {
  if (!SHAPES[name]) return { ok: false, reason: `unknown secret ${String(name).slice(0, 30)}; allowed: ${Object.keys(SHAPES).join(', ')}` };
  const v = String(raw ?? '').replace(/\s+/g, ''); if (!v) return { ok: false, reason: 'empty input' };
  if (String(raw).trim() !== String(raw).trim().replace(/\s+/g, '')) return { ok: false, reason: 'the value contains whitespace inside it (is the clipboard something else?)' };
  if (!SHAPES[name].test(v)) return { ok: false, reason: `the value does not look like ${name} (wrong length or characters)` };
  return { ok: true, value: v, length: v.length };
}
export function upload(name, value, envFile, run = (args, input) => execFileSync('npx', ['--yes', 'wrangler@4.149.0', ...args], { input, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })) {
  const account = (readFileSync(envFile, 'utf8').match(/^account_id\s*=\s*"([0-9a-f]{32})"/m) ?? [])[1]; if (!account) throw new Error('account_id not found in ' + envFile);
  process.env.CLOUDFLARE_ACCOUNT_ID = account; return run(['secret', 'put', name, '--config', envFile], value);
}
if (process.argv[1]?.endsWith('set_worker_secret.mjs')) {
  const arg = (n, d = null) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : d; };
  let input = ''; for await (const c of process.stdin) input += c;
  const envFile = resolve(arg('--env', 'environments/production.wrangler.toml'));
  if (!placeAllowed(arg('--name'), envFile)) { console.error(`refused: ${arg('--name')} can only be set on a Worker whose name ends in -staging (this one is ${workerName(envFile)}); production secrets are never replaced by this tool`); process.exit(1); }
  const c = checkSecret(arg('--name'), input); if (!c.ok) { console.error('refused: ' + c.reason); process.exit(1); }
  if (process.argv.includes('--dry-run')) { console.log(`ok (dry run): ${arg('--name')} looks valid (${c.length} characters); nothing uploaded`); process.exit(0); }
  try { upload(arg('--name'), c.value, envFile); console.log(`uploaded ${arg('--name')} (${c.length} characters)`); } catch (e) { console.error('upload failed: ' + String(e.message).replace(c.value, '<value>').slice(0, 200)); process.exit(1); }
}
