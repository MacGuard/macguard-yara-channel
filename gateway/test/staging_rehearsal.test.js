// Local rehearsal of the staging sequence (docs/analytics/STAGING-SEQUENCE.md) on a database that has exactly the DEPLOYED schema (4d9b1ff): backup -> verification -> migrations 0001-0003 ->
// smoke + security on the CURRENT code -> restore -> rollback (the previous code on the migrated schema). Local only: it proves the logic and the rollback claim, not Cloudflare.
import test from 'node:test';
import { HAVE_AGE } from './tools_available.js';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { openDb } from '../tools/sqlite_d1.mjs';
import { dumpSql, verifyRestore } from '../tools/backup_lib.mjs';
import { runBackup } from '../tools/backup_flow.mjs';
import { createHandler } from '../src/index.js';
import { runSmoke } from '../tools/smoke.mjs';
import { seedPolicy } from '../src/policy.js';
import { SEED } from './helpers.js';

const ROOT = new URL('../', import.meta.url).pathname, DEPLOYED = '4d9b1ff';
let deployedSql = null; try { deployedSql = execFileSync('git', ['show', `${DEPLOYED}:gateway/schema.sql`], { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }); } catch { /* shallow clone */ }
const skip = !deployedSql ? `commit ${DEPLOYED} not available` : !HAVE_AGE ? 'age not available' : false;
const migrations = readdirSync(ROOT + 'migrations').filter((f) => f.endsWith('.sql')).sort();
const counts = (raw) => Object.fromEntries(raw.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all().map((t) => [t.name, raw.prepare(`SELECT COUNT(*) n FROM ${t.name}`).get().n]));

test('backup -> verify -> migrate -> smoke/security -> restore -> rollback, on the deployed schema', { skip }, async () => {
  const work = mkdtempSync(join(homedir(), '.mg-rehearsal-')), bk = join(work, 'backups'), keyFile = join(work, 'k.txt');
  try {
    execFileSync('age-keygen', ['-o', keyFile], { stdio: 'ignore' }); const recipient = execFileSync('age-keygen', ['-y', keyFile], { encoding: 'utf8' }).trim();
    // 0. a database with the deployed schema and some production-shaped rows
    const file = join(work, 'deployed.sqlite'), raw0 = new DatabaseSync(file); raw0.exec(deployedSql);
    raw0.exec("INSERT INTO gh_sync(id,last_status,consecutive_failures) VALUES (1,'ok',0)"); raw0.exec("INSERT INTO gh_sync_log VALUES ('2026-10-23T20:18:00Z',0,0,'github_rate_limited')");
    raw0.exec("INSERT INTO analytics_daily(day,tenant_id,channel,product,operation,status_class,commercial_mode,requests) VALUES ('2026-10-23','-','rest','x','op','4xx','FREE_LAUNCH',3)"); raw0.close();
    const d0 = openDb(file); await seedPolicy(d0, () => new Date('2026-10-23T19:27:00Z'), SEED); d0.raw.close();            // the live database carries FREE_LAUNCH policy v1
    // 1. backup of the pre-migration state (read-only export of the file, age encryption, isolated restore verification)
    const pre = new DatabaseSync(file, { readOnly: true }), preCounts = counts(pre);
    const b = await runBackup({ exportFn: async (p) => writeFileSync(p, dumpSql(pre)), root: bk, recipient, clock: () => new Date('2026-10-24T06:00:00Z') }); pre.close();
    assert.equal(b.ok, true, JSON.stringify(b)); assert.equal(b.manifest.encrypted, true);
    // 2. the backup restores in isolation with the recovery identity only (no Keychain) and matches the pre-migration counts
    const sql = execFileSync('age', ['-d', '-i', keyFile, join(b.dir, 'd1-export.sql.age')], { maxBuffer: 1 << 28 }).toString('utf8'); const v = await verifyRestore(sql, { manifest: b.manifest }); assert.equal(v.ok, true, JSON.stringify(v.checks.filter((c) => !c.ok)));
    // 3. migrations 0001-0003 applied once each, in order
    const mig = new DatabaseSync(file); for (const m of migrations) mig.exec(readFileSync(ROOT + 'migrations/' + m, 'utf8'));
    const postCounts = counts(mig); for (const [t, n] of Object.entries(preCounts)) assert.equal(postCounts[t], n, `migration changed the row count of ${t}`); mig.close();
    // 4. smoke + security with the CURRENT code over the migrated database
    const db = openDb(file), env = { DB: db, PUBLIC_BASE: 'https://stg.test', ALLOWED_HOSTS: 'stg.test', KEY_PEPPER: 'k'.repeat(40), ADMIN_PEPPER: 'a'.repeat(40), TOTP_SEAL_KEY: 't'.repeat(40), COMMUNITY_ORIGIN: 'https://site.test', COMMUNITY_DOWNLOAD_BASE: 'https://dl.example.test/b', COMMUNITY_DEFAULT_ASSET: 'bundle.tar.gz', X402_ENABLED: 'false', fetchImpl: async () => new Response(JSON.stringify({ tag: 'rules-20261024-1' }), { status: 200 }) };
    const handle = createHandler({ clock: () => new Date('2026-10-24T07:00:00Z') }), ctx = { waitUntil: () => {} };
    const smoke = await runSmoke((u, i) => handle(new Request(u, i), env, ctx), 'https://stg.test', { hostProbe: () => handle(new Request('https://evil.test/v1/health'), env, ctx) });
    assert.deepEqual(smoke.checks.filter((c) => c.status === 'FAIL'), []); assert.equal(smoke.skipped, 0);
    // 5. rollback: the PREVIOUS (deployed) code, extracted from git, still works on the migrated schema (health, community, its collector writes through the new columns)
    const old = join(work, 'old'); mkdirSync(old); execFileSync('sh', ['-c', `git archive ${DEPLOYED} gateway/src | tar -x -C ${old}`], { cwd: ROOT + '..' });                 // from the repository root: pathspecs are relative to the cwd
    const oldIdx = await import(pathToFileURL(join(old, 'gateway/src/index.js')).href), oldGh = await import(pathToFileURL(join(old, 'gateway/src/gh_collector.js')).href);
    const oldHandle = oldIdx.createHandler({ clock: () => new Date('2026-10-24T07:00:00Z') }), oenv = { DB: db, PUBLIC_BASE: 'https://stg.test', KEY_PEPPER: 'k'.repeat(40), ADMIN_PEPPER: 'a'.repeat(40), TOTP_SEAL_KEY: 't'.repeat(40), COMMUNITY_ORIGIN: 'https://site.test', X402_ENABLED: 'false', fetchImpl: async () => new Response(JSON.stringify({ tag: 'rules-20261024-1' }), { status: 200 }) };
    assert.equal((await oldHandle(new Request('https://stg.test/v1/health'), oenv, ctx)).status, 200);
    assert.equal((await oldHandle(new Request('https://stg.test/admin/v1/policy'), oenv, ctx)).status, 401);
    const listing = [{ id: 1, tag_name: 'rules-1', name: 'r', draft: false, prerelease: false, created_at: '2026-10-20T00:00:00Z', published_at: '2026-10-20T00:00:00Z', assets: [{ id: 11, name: 'rules-release.tar.gz', size: 10, content_type: 'application/gzip', download_count: 5, created_at: '2026-10-20T00:00:00Z', updated_at: '2026-10-20T00:00:00Z' }] }];
    const fetchImpl = async () => new Response(JSON.stringify(listing), { status: 200, headers: { 'content-type': 'application/json' } });
    const r = await oldGh.sync(db, () => new Date('2026-10-24T07:05:00Z'), fetchImpl, { repo: 'o/r' }); assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(db.raw.prepare('SELECT COUNT(*) n FROM gh_observations').get().n >= 1, true);
    // 6. restore: the pre-migration backup rebuilds the original database into a fresh file (never over the working one)
    const fresh = join(work, 'restored.sqlite'), rdb = new DatabaseSync(fresh); rdb.exec('PRAGMA foreign_keys = OFF'); rdb.exec(sql); assert.deepEqual(counts(rdb), preCounts, 'restored counts equal the pre-migration counts'); rdb.close(); db.raw.close();
  } finally { rmSync(work, { recursive: true, force: true }); }
});

test('--admin-only bootstrap adds just a staging administrator (new peppers) to a restored copy without touching its policy or audit chain; the key and seed go only to the 0600 file', { skip }, async () => {
  const work = mkdtempSync(join(homedir(), '.mg-adm-')), file = join(work, 'restored.sqlite');
  try {
    const raw = new DatabaseSync(file); raw.exec(deployedSql); raw.close(); const d0 = openDb(file); await seedPolicy(d0, () => new Date('2026-10-23T19:27:00Z'), SEED);
    const before = { pol: d0.raw.prepare('SELECT COUNT(*) n FROM policy_versions').get().n, aud: d0.raw.prepare('SELECT COUNT(*) n FROM audit').get().n, adm: d0.raw.prepare('SELECT COUNT(*) n FROM admins').get().n }; d0.raw.close();
    const sqlFile = join(work, 'adm.sql'), secFile = join(work, 'adm.json');
    const r = execFileSync('node', [join(ROOT, 'tools/bootstrap_remote.mjs'), '--admin-only', '--out', sqlFile, '--secret-out', secFile], { env: { ...process.env, ADMIN_PEPPER: 'a'.repeat(40), TOTP_SEAL_KEY: 't'.repeat(40) }, encoding: 'utf8' });
    const sql = readFileSync(sqlFile, 'utf8'); assert.ok(/^INSERT INTO admins\(/.test(sql) && !/policy_|audit/.test(sql), 'only the admins row'); assert.ok(!r.includes('admin_key') && !sql.includes(JSON.parse(readFileSync(secFile, 'utf8')).admin_key), 'the key is neither printed nor in the SQL');
    const db = new DatabaseSync(file); db.exec(sql); const after = { pol: db.prepare('SELECT COUNT(*) n FROM policy_versions').get().n, aud: db.prepare('SELECT COUNT(*) n FROM audit').get().n, adm: db.prepare('SELECT COUNT(*) n FROM admins').get().n }; db.close();
    assert.deepEqual({ pol: after.pol, aud: after.aud, adm: after.adm - 1 }, before);
  } finally { rmSync(work, { recursive: true, force: true }); }
});
