// Backs up the gateway D1 database: a READ-ONLY remote export, verified by restoring it into an isolated in-memory database, optionally encrypted with age, written outside any temporary folder
// (default ~/macguard-backups/gateway/<UTC stamp>, mode 700/600), with status.json updated on success AND failure. It never writes to Cloudflare and never restores onto it.
// Secrets are NOT in the backup (Cloudflare cannot return them): see tools/secrets_backup.mjs and docs/analytics/BACKUP-RECOVERY.md.
// Usage: node tools/d1_backup.mjs [--resource gateway|panel|intel] [--env environments/production.wrangler.toml] [--db macguard-gateway] [--root DIR] [--age-recipient age1...]   (or MACGUARD_BACKUP_AGE_RECIPIENT)
import { classifyFailure, annotation } from './backup_diagnose.mjs';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { homedir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { runBackup, ROOT_DEFAULT } from './backup_flow.mjs';

const arg = (n, d) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : d; };
const RES = JSON.parse(readFileSync(new URL('../environments/backup-resources.json', import.meta.url), 'utf8')).resources, resource = arg('--resource', 'gateway'); if (!RES[resource]) { console.error('unknown --resource ' + resource); process.exit(2); }
const REPO_ROOT = fileURLToPath(new URL('../..', import.meta.url)), envFile = resolve(arg('--env', resolve(REPO_ROOT, RES[resource].wrangler_config))), dbName = arg('--db', RES[resource].database), recipient = arg('--age-recipient', process.env.MACGUARD_BACKUP_AGE_RECIPIENT ?? null);
const account = (readFileSync(envFile, 'utf8').match(/^account_id\s*=\s*"([0-9a-f]{32})"/m) ?? [])[1]; if (!account) { console.error('account_id not found in ' + envFile); process.exit(2); }
// A failing wrangler call reports WHY (its first stderr lines, ANSI removed), not the command line: the token never appears there, and a permission problem is then visible in the run log.
const wr = (...a) => { try { return execFileSync('npx', ['--yes', 'wrangler@4.149.0', ...a], { env: { ...process.env, CLOUDFLARE_ACCOUNT_ID: account }, encoding: 'utf8', timeout: 240000, stdio: ['ignore', 'pipe', 'pipe'] }); } catch (e) { throw new Error(`wrangler ${a.slice(0, 2).join(' ')} failed: ` + String(e.stderr || e.stdout || e.message).replace(/\x1b\[[0-9;]*m/g, '').split('\n').map((l) => l.trim()).filter((l) => l && !/^[─-]+$/.test(l)).slice(0, 6).join(" | ").slice(0, 420)); } };
let deployments = ''; try { deployments = wr('deployments', 'list', '--config', envFile).replace(/\x1b\[[0-9;]*m/g, '').split('\n').slice(0, 40).join('\n'); } catch { deployments = 'unavailable'; }
const verifier = resource === 'panel' ? (await import('../../admin/worker/tools/panel_backup_verify.mjs')) : resource === 'intel' ? (await import('../../admin/worker/tools/intel_backup_verify.mjs')) : null;
const r = await runBackup({ verify: verifier ? (verifier.verifyPanelRestore || verifier.verifyIntelRestore) : undefined, counts: verifier ? (verifier.panelRowCounts || verifier.intelRowCounts) : undefined, schema: RES[resource].manifest_schema, exportFn: async (file) => { wr('d1', 'export', dbName, '--remote', '--output', file, '--config', envFile); }, root: arg('--root', resource === 'gateway' ? ROOT_DEFAULT : join(homedir(), 'macguard-backups', RES[resource].root_name)), recipient,
  meta: { resource, database: dbName, account_id: account, config: envFile.split('/').pop(), deployments_list: deployments.split('\n') } });
if (!r.ok && process.env.GITHUB_ACTIONS) console.log(annotation(resource, classifyFailure(r.stage === 'export' || /wrangler/.test(String(r.error)) ? 'export' : r.stage, r.error)));   // a fixed-vocabulary annotation: the panel shows the cause without reading logs
console.log(r.ok ? `BACKUP VERIFIED${r.manifest.encrypted ? ' + ENCRYPTED' : ' (UNENCRYPTED)'}  ${r.dir}  ${r.manifest.stored_bytes} bytes  ${r.checks} checks passed` : `BACKUP FAILED at stage ${r.stage}: ${r.error}`); process.exit(r.ok ? 0 : 1);
