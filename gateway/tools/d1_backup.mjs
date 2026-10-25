// Backs up the gateway D1 database: a READ-ONLY remote export, verified by restoring it into an isolated in-memory database, optionally encrypted with age, written outside any temporary folder
// (default ~/macguard-backups/gateway/<UTC stamp>, mode 700/600), with status.json updated on success AND failure. It never writes to Cloudflare and never restores onto it.
// Secrets are NOT in the backup (Cloudflare cannot return them): see tools/secrets_backup.mjs and docs/analytics/BACKUP-RECOVERY.md.
// Usage: node tools/d1_backup.mjs [--env environments/production.wrangler.toml] [--db macguard-gateway] [--root DIR] [--age-recipient age1...]   (or MACGUARD_BACKUP_AGE_RECIPIENT)
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { runBackup, ROOT_DEFAULT } from './backup_flow.mjs';

const arg = (n, d) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : d; };
const envFile = resolve(arg('--env', 'environments/production.wrangler.toml')), dbName = arg('--db', 'macguard-gateway'), recipient = arg('--age-recipient', process.env.MACGUARD_BACKUP_AGE_RECIPIENT ?? null);
const account = (readFileSync(envFile, 'utf8').match(/^account_id\s*=\s*"([0-9a-f]{32})"/m) ?? [])[1]; if (!account) { console.error('account_id not found in ' + envFile); process.exit(2); }
const wr = (...a) => execFileSync('npx', ['--yes', 'wrangler@4.149.0', ...a], { env: { ...process.env, CLOUDFLARE_ACCOUNT_ID: account }, encoding: 'utf8', timeout: 240000, stdio: ['ignore', 'pipe', 'pipe'] });
let deployments = ''; try { deployments = wr('deployments', 'list', '--config', envFile).replace(/\x1b\[[0-9;]*m/g, '').split('\n').slice(0, 40).join('\n'); } catch { deployments = 'unavailable'; }
const r = await runBackup({ exportFn: async (file) => { wr('d1', 'export', dbName, '--remote', '--output', file, '--config', envFile); }, root: arg('--root', ROOT_DEFAULT), recipient,
  meta: { database: dbName, account_id: account, config: envFile.split('/').pop(), deployments_list: deployments.split('\n') } });
console.log(r.ok ? `BACKUP VERIFIED${r.manifest.encrypted ? ' + ENCRYPTED' : ' (UNENCRYPTED)'}  ${r.dir}  ${r.manifest.stored_bytes} bytes  ${r.checks} checks passed` : `BACKUP FAILED at stage ${r.stage}: ${r.error}`); process.exit(r.ok ? 0 : 1);
