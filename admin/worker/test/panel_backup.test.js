// Backup of the PANEL's own D1 with the same pipeline as the gateway: the isolated-restore check is the panel's own (base tables, integrity, audit chain, counts), the manifest says which resource and database it is, and
// the chain and prefix are separate. Synthetic data only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { world } from './helpers.js';
import { verifyPanelRestore, panelRowCounts, BASE_TABLES } from '../tools/panel_backup_verify.mjs';
import { dumpSql } from '../../../gateway/tools/backup_lib.mjs';
import { runBackup } from '../../../gateway/tools/backup_flow.mjs';

const HAVE_AGE = (() => { try { execFileSync('which', ['age'], { stdio: 'pipe' }); return true; } catch { return false; } })();
async function panelDump() { const w = await world(); const ada = await w.login('ada', { admin: true }); await w.grant(ada, 'x', 'VIEWER').catch(() => {}); await w.call('GET', '/api/me', { user: ada }); return { w, sql: dumpSql(w.db.raw) }; }

test('a real panel export passes its isolated-restore check; the manifest counts must equal; a missing base table, a broken audit chain or garbage fail', async () => {
  const { w, sql } = await panelDump(); const counts = panelRowCounts(w.db.raw);
  let r = await verifyPanelRestore(sql, { manifest: { row_counts: counts } }); assert.equal(r.ok, true, JSON.stringify(r.checks.filter((c) => !c.ok))); assert.ok(r.checks.length >= 6); assert.ok(BASE_TABLES.every((t) => t in counts));
  r = await verifyPanelRestore(sql, { manifest: { row_counts: { ...counts, audit: counts.audit + 1 } } }); assert.equal(r.ok, false); assert.match(JSON.stringify(r.checks.filter((c) => !c.ok)), /row counts/);
  r = await verifyPanelRestore(sql.replace(/CREATE TABLE "?sessions"?/, 'CREATE TABLE "sessions_renamed"')); assert.equal(r.ok, false, 'a export without a base table never passes');
  const bad = sql.replace(/(INSERT INTO "?audit"?[^;]*?)'([0-9a-f]{64})'/, "$1'" + 'e'.repeat(64) + "'"); if (bad !== sql) { r = await verifyPanelRestore(bad); assert.equal(r.ok, false, 'a tampered audit row is caught'); }
  assert.equal((await verifyPanelRestore('THIS IS NOT SQL;')).ok, false);
});

test('the same backup flow runs with the panel verifier: the manifest names the resource and database, the encrypted copy is separate from the gateway\'s, and a failing verifier stores nothing', { skip: !HAVE_AGE && 'age is needed' }, async () => {
  const { w, sql } = await panelDump(); const root = mkdtempSync(join(homedir(), '.mg-panel-bk-')); try {
    const id = join(root, 'id'); execFileSync('age-keygen', ['-o', id], { stdio: 'pipe' }); const rcpt = readFileSync(id, 'utf8').match(/public key: (age1\S+)/)[1];
    const r = await runBackup({ exportFn: async (f) => writeFileSync(f, sql), root: join(root, 'panel'), recipient: rcpt, verify: verifyPanelRestore, counts: panelRowCounts, schema: 'macguard.panel-backup/1', meta: { resource: 'panel', database: 'macguard-quarantine' } });
    assert.equal(r.ok, true, JSON.stringify(r)); const m = JSON.parse(readFileSync(join(r.dir, 'manifest.json'), 'utf8')); assert.deepEqual([m.schema, m.resource, m.database, m.encrypted], ['macguard.panel-backup/1', 'panel', 'macguard-quarantine', true]); assert.deepEqual(Object.keys(m.row_counts).filter((t) => BASE_TABLES.includes(t)).sort(), [...BASE_TABLES].sort());
    assert.equal(readFileSync(join(r.dir, 'd1-export.sql.age')).subarray(0, 21).toString(), 'age-encryption.org/v1'); assert.equal(existsSync(join(r.dir, 'd1-export.sql')), false, 'no plaintext is kept');
    const dec = execFileSync('age', ['-d', '-i', id, join(r.dir, 'd1-export.sql.age')]).toString(); assert.equal((await verifyPanelRestore(dec)).ok, true, 'it decrypts to an export that restores');
    const bad = await runBackup({ exportFn: async (f) => writeFileSync(f, 'CREATE TABLE only_one(x);'), root: join(root, 'panel2'), recipient: rcpt, verify: verifyPanelRestore, counts: panelRowCounts, schema: 'macguard.panel-backup/1' }); assert.equal(bad.ok, false); assert.equal(bad.stage, 'verify');
    assert.equal(existsSync(join(root, 'panel2', 'status.json')), true); assert.equal(JSON.parse(readFileSync(join(root, 'panel2', 'status.json'), 'utf8')).last_status, 'failed');
  } finally { rmSync(root, { recursive: true, force: true }); }
  void w;
});

test('ci_profile.sh: one profile per resource with its own prefix, database and Ed25519 range; unknown resources are refused; the shell mode quotes values', () => {
  const ROOT = join(new URL('.', import.meta.url).pathname, '..', '..', '..'), run = (...a) => spawnSync('sh', [join(ROOT, 'gateway/tools/ci_profile.sh'), ...a], { cwd: ROOT, encoding: 'utf8' }), kv = (t) => Object.fromEntries(t.trim().split('\n').map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]));
  const g = kv(run('gateway').stdout), p = kv(run('panel').stdout);
  assert.deepEqual([g.PREFIX, g.DBNAME, g.ED_MAX, g.GENESIS], ['gateway-d1', 'macguard-gateway', '1', 'gateway/environments/backup-genesis']); assert.deepEqual([p.PREFIX, p.DBNAME, p.ED_MAX, p.GENESIS], ['panel-d1', 'macguard-quarantine', '0', '']);
  assert.equal(g.SIG_ID, p.SIG_ID, 'one workflow identity for both'); assert.equal(g.RECIPIENT, p.RECIPIENT); assert.match(run('panel', '--shell').stdout, /^ED_PUB='ssh-ed25519 /m); assert.equal(run('nope').status, 2);
  const res = JSON.parse(readFileSync(join(ROOT, 'gateway/environments/backup-resources.json'), 'utf8')).resources; assert.notEqual(res.gateway.prefix, res.panel.prefix); assert.match(readFileSync(join(ROOT, 'gateway/environments/panel-d1.wrangler.toml'), 'utf8'), /database_name = "macguard-quarantine"/);
  assert.ok(!/token|secret|key/i.test(readFileSync(join(ROOT, 'gateway/environments/panel-d1.wrangler.toml'), 'utf8').replace(/^#.*$/gm, '').replace(/database_id|account_id/g, '')), 'the export config holds no credential');
});
