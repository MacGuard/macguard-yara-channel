import test from 'node:test';
import assert from 'node:assert/strict';
import { dumpSql, verifyRestore, rowCounts } from '../tools/backup_lib.mjs';
import { world } from './helpers.js';
import { audit } from '../src/audit.js';

async function populated() {
  const w = await world({ now: '2026-10-23T10:00:00Z' }); await w.tenant('t1'); await w.admin('root');
  await audit(w.db, w.clock, 't1', 'test.event', { a: 1 }); await audit(w.db, w.clock, null, 'test.other', { b: "o'neil" });
  await w.db.prepare("INSERT INTO analytics_daily(day,tenant_id,channel,product,operation,status_class,commercial_mode,requests) VALUES ('2026-10-22','t1','rest','x','op','2xx','FREE_LAUNCH',3)").run();
  return w;
}
const failed = (r) => r.checks.filter((c) => !c.ok).map((c) => c.name);

test('a faithful export restores into an isolated database and passes every integrity check, with row counts equal to the manifest', async () => {
  const w = await populated(); const sql = dumpSql(w.db.raw), r = await verifyRestore(sql, { manifest: { row_counts: rowCounts(w.db.raw) } });
  assert.deepEqual(failed(r), []); assert.equal(r.ok, true); assert.ok(r.checks.length >= 8);
});
test('a truncated export is detected (it fails to load or is missing tables)', async () => {
  const sql = dumpSql((await populated()).db.raw); const cut = sql.slice(0, Math.floor(sql.length * 0.6)); const r = await verifyRestore(cut); assert.equal(r.ok, false);
});
test('an export truncated before the audit and policy tables is a FAILED restore with named checks, never an exception', async () => {
  const sql = dumpSql((await populated()).db.raw); const at = Math.min(...['CREATE TABLE audit', 'CREATE TABLE policy_versions'].map((s) => sql.indexOf(s)).filter((i) => i > 0)); assert.ok(at > 0);
  for (const cut of [sql.slice(0, at), sql.slice(0, Math.floor(sql.length * 0.6)), sql.slice(0, Math.floor(sql.length * 0.3))]) {
    const r = await verifyRestore(cut); assert.equal(r.ok, false);
    for (const c of r.checks.filter((x) => /audit hash chain|policy versions|policy pointer/.test(x.name))) assert.ok(!/no such table|SQLITE_/i.test(c.detail), `fixed text only, not the raw SQLite message: ${c.detail}`);
  }
});
test('a tampered audit row breaks the chain and the restore is refused', async () => {
  const w = await populated(); const sql = dumpSql(w.db.raw).replace("'test.event'", "'test.forged'"); const r = await verifyRestore(sql); assert.equal(r.ok, false); assert.ok(failed(r).includes('audit hash chain intact'));
});
test('a tampered policy document breaks its hash and the restore is refused', async () => {
  const w = await populated(); const sql = dumpSql(w.db.raw).replace('"mode":"FREE_LAUNCH"', '"mode":"PAID"'); const r = await verifyRestore(sql); assert.equal(r.ok, false); assert.ok(failed(r).includes('policy versions: each document matches its hash and the chain links'));
});
test('a missing table or a changed column is reported, and a manifest mismatch is reported', async () => {
  const w = await populated(); const sql = dumpSql(w.db.raw);
  assert.ok(failed(await verifyRestore(sql.replace(/CREATE TABLE leads[\s\S]*?\);\n/, '').replace(/INSERT INTO leads[^\n]*\n/g, ''))).includes('every table of gateway/schema.sql exists with the same columns'));
  const m = { row_counts: { ...rowCounts(w.db.raw), audit: 999 } }; assert.ok(failed(await verifyRestore(sql, { manifest: m })).includes('row counts equal the manifest'));
});
test('restoring never touches the source database', async () => {
  const w = await populated(); const before = JSON.stringify(rowCounts(w.db.raw)); await verifyRestore(dumpSql(w.db.raw)); assert.equal(JSON.stringify(rowCounts(w.db.raw)), before);
});

test('a table created only by a not-yet-applied migration is reported as pending, not as a failed restore', async () => {
  const w = await populated(); const sql = dumpSql(w.db.raw).replace(/CREATE TABLE telemetry_exclusions[^;]*;\n/, '');
  const r = await verifyRestore(sql); assert.equal(r.ok, true); assert.match(r.checks.find((c) => c.name.startsWith('every table')).detail, /PENDING MIGRATION telemetry_exclusions/);
});

test('a column that only a pending ALTER TABLE migration adds is reported as pending; a column that is simply gone is a failure', async () => {
  const w = await populated(); const full = dumpSql(w.db.raw);
  const withoutCol = full.replace(/,\s*authenticated INTEGER NOT NULL DEFAULT 0[^\n]*\n/, '\n').replace(/INSERT INTO gh_sync\(([^)]*)\) VALUES/g, (m) => m);
  const r = await verifyRestore(withoutCol); const c = r.checks.find((x) => x.name.startsWith('every table'));
  assert.equal(c.ok, true, c.detail); assert.match(c.detail, /PENDING MIGRATION gh_sync \(columns authenticated\)/);
  const lost = full.replace('row_digest TEXT NOT NULL, ', ''); assert.notEqual(lost, full);
  const bad = await verifyRestore(lost); const bc = bad.checks.find((x) => x.name.startsWith('every table')); assert.equal(bc.ok, false, 'a column removed without any migration explaining it is not tolerated'); assert.match(bc.detail, /columns differ telemetry_exclusions/);
});
