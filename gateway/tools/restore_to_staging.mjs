// PREPARED, NOT RUN: restores a verified export into a STAGING D1 database to rehearse recovery on real D1. Default is a dry run that prints the exact commands. `--apply` additionally requires
// `--confirm-database <name>` equal to the staging name, and the tool REFUSES any name that is, or starts like, the production database. It never restores over production.
// Usage: node tools/restore_to_staging.mjs --export FILE.sql [--identity KEY] --staging macguard-gateway-staging [--env environments/production.wrangler.toml] [--apply --confirm-database NAME]
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { verifyRestore } from './backup_lib.mjs';

const arg = (n, d = null) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : d; };
const file = arg('--export'), staging = arg('--staging'), identity = arg('--identity'), apply = process.argv.includes('--apply'), PROD = 'macguard-gateway';
if (!file || !staging) { console.error('usage: restore_to_staging.mjs --export FILE --staging NAME [--identity KEY] [--apply --confirm-database NAME]'); process.exit(2); }
if (staging === PROD || !/^[a-z0-9][a-z0-9-]*-(staging|restore-test|scratch)$/.test(staging)) { console.error(`refusing: the target must be a database named like <something>-staging, -restore-test or -scratch, never ${PROD}`); process.exit(2); }
const sql = file.endsWith('.age') ? execFileSync('age', ['-d', '-i', identity, file], { maxBuffer: 1 << 30 }).toString('utf8') : readFileSync(file, 'utf8');
const v = await verifyRestore(sql); for (const c of v.checks) console.log(`${c.ok ? 'PASS' : 'FAIL'}  ${c.name}${c.detail ? ' (' + c.detail + ')' : ''}`); if (!v.ok) { console.error('the export does not verify: nothing will be restored'); process.exit(1); }
const env = resolve(arg('--env', 'environments/production.wrangler.toml')), account = (readFileSync(env, 'utf8').match(/^account_id\s*=\s*"([0-9a-f]{32})"/m) ?? [])[1];
const cmds = [`CLOUDFLARE_ACCOUNT_ID=${account} npx wrangler@4.149.0 d1 create ${staging}`, `CLOUDFLARE_ACCOUNT_ID=${account} npx wrangler@4.149.0 d1 execute ${staging} --remote --file <decrypted export>`, `node tools/d1_backup.mjs --db ${staging} --root <a scratch backup root>   # then compare the two verified manifests`];
console.log((apply ? 'APPLYING:\n' : 'DRY RUN (nothing executed):\n') + cmds.map((c) => '  ' + c).join('\n'));
if (apply) {
  if (arg('--confirm-database') !== staging) { console.error('--apply needs --confirm-database equal to the staging name'); process.exit(2); }
  const tmp = mkdtempSync(join(homedir(), '.mg-restore-')), f = join(tmp, 'restore.sql'); try { writeFileSync(f, sql, { mode: 0o600 }); const run = (...a) => execFileSync('npx', ['--yes', 'wrangler@4.149.0', ...a], { env: { ...process.env, CLOUDFLARE_ACCOUNT_ID: account }, stdio: 'inherit' }); run('d1', 'create', staging); run('d1', 'execute', staging, '--remote', '--file', f, '-y'); } finally { rmSync(tmp, { recursive: true, force: true }); }
}
