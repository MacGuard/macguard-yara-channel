// PREPARED, NOT RUN: restores a verified export into a STAGING D1 database to rehearse recovery on real D1. Default is a dry run that prints the exact commands. `--apply` additionally requires
// `--confirm-database <name>` equal to the staging name, and the tool REFUSES any name that is, or starts like, the production database. It never restores over production.
// Usage: node tools/restore_to_staging.mjs --export FILE.sql [--identity KEY] --staging macguard-gateway-staging [--env environments/production.wrangler.toml] [--apply --confirm-database NAME]
import { chmodSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { verifyRestore } from './backup_lib.mjs';
import { ageDecryptFile } from './stream_io.mjs';
import { privateDir, runTracked } from './private_tmp.mjs';

const arg = (n, d = null) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : d; };
const file = arg('--export'), staging = arg('--staging'), identity = arg('--identity'), apply = process.argv.includes('--apply'), PROD = 'macguard-gateway';
if (!file || !staging) { console.error('usage: restore_to_staging.mjs --export FILE --staging NAME [--identity KEY] [--apply --confirm-database NAME]'); process.exit(2); }
if (staging === PROD || !/^[a-z0-9][a-z0-9-]*-(staging|restore-test|scratch)$/.test(staging)) { console.error(`refusing: the target must be a database named like <something>-staging, -restore-test or -scratch, never ${PROD}`); process.exit(2); }
// Streaming: an .age export is decrypted by age into a private 0600 file (never into this process), verified by sqlite3 from that file, and the same file is what `--apply` uploads.
const work = privateDir(homedir(), '.mg-restore-');   // removed on exit and on signals (private_tmp.mjs)
let plain = file;
if (file.endsWith('.age')) { if (!identity) { console.error('an .age export needs --identity KEYFILE'); process.exit(2); } plain = join(work, 'restore.sql'); try { await ageDecryptFile({ identity, src: file, dst: plain }); } catch (e) { console.error(`the backup does not decrypt: ${String(e.message).slice(0, 160)}`); process.exit(1); } }
const v = await verifyRestore({ file: plain }); for (const c of v.checks) console.log(`${c.ok ? 'PASS' : 'FAIL'}  ${c.name}${c.detail ? ' (' + c.detail + ')' : ''}`); if (!v.ok) { console.error('the export does not verify: nothing will be restored'); process.exit(1); }
const env = resolve(arg('--env', 'environments/production.wrangler.toml')), account = (readFileSync(env, 'utf8').match(/^account_id\s*=\s*"([0-9a-f]{32})"/m) ?? [])[1];
const cmds = [`CLOUDFLARE_ACCOUNT_ID=${account} npx wrangler@4.149.0 d1 create ${staging}`, `CLOUDFLARE_ACCOUNT_ID=${account} npx wrangler@4.149.0 d1 execute ${staging} --remote --file <decrypted export>`, `node tools/d1_backup.mjs --db ${staging} --root <a scratch backup root>   # then compare the two verified manifests`];
console.log((apply ? 'APPLYING:\n' : 'DRY RUN (nothing executed):\n') + cmds.map((c) => '  ' + c).join('\n'));
if (apply) {
  if (arg('--confirm-database') !== staging) { console.error('--apply needs --confirm-database equal to the staging name'); process.exit(2); }
  // async (runTracked), not execFileSync: a signal during the upload must stop it; a deferred signal was lost with execFileSync.
  const tmp = work, f = plain; try { const run = (...a) => runTracked('npx', ['--yes', 'wrangler@4.149.0', ...a], { env: { ...process.env, CLOUDFLARE_ACCOUNT_ID: account } }); await run('d1', 'create', staging); await run('d1', 'execute', staging, '--remote', '--file', f, '-y'); } finally { rmSync(tmp, { recursive: true, force: true }); }
}
