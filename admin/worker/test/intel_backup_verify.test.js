// Isolated restore check of an INTEL export (what the backup pipeline runs before encrypting): a good export passes every check; each kind of damage is caught by name.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { newDb } from './d1shim.js';
import { seedIntel } from './intel_fixture.js';
import { verifyIntelRestore, intelRowCounts } from '../tools/intel_backup_verify.mjs';

const SCHEMA = ['../migrations-intel/0001_intel.sql', '../migrations-intel/0002_decisions.sql', '../migrations-intel/0003_effective_state.sql'].map((f) => readFileSync(new URL(f, import.meta.url), 'utf8')).join('\n');
const q = (v) => (v === null || v === undefined ? 'NULL' : typeof v === 'number' ? String(v) : `'${String(v).replace(/'/g, "''")}'`);
async function exportOf({ decisions = false } = {}) {   // the SQL a D1 export would contain: schema then rows
  const db = newDb(['../migrations-intel/0001_intel.sql', '../migrations-intel/0002_decisions.sql', '../migrations-intel/0003_effective_state.sql']); await seedIntel(db, { kev: 30 });
  if (decisions) db.raw.prepare("INSERT INTO intel_decisions (record_id, family, action, from_state, to_state, reason, actor, actor_id, at, request_id, audited) VALUES ('ioc:ip:203.0.113.7','ioc','quarantine','EXPIRED','QUARANTINED','backup test decision','rita',12,'2026-10-26T10:00:00Z','req-backup-0000000001',1)").run();
  const lines = [SCHEMA]; for (const t of ['intel_sources', 'intel_runs', 'intel_records', 'intel_events', 'intel_decisions']) for (const r of db.raw.prepare(`SELECT * FROM ${t}`).all()) { const c = Object.keys(r); lines.push(`INSERT INTO ${t} (${c.join(',')}) VALUES (${c.map((k) => q(r[k])).join(',')});`); }
  return { sql: lines.join('\n'), counts: intelRowCounts(db.raw) };
}
const failed = (r) => r.checks.filter((c) => !c.ok).map((c) => c.name);

test('a good export restores, is consistent, and its counts equal the manifest', async () => {
  const { sql, counts } = await exportOf({ decisions: true }); const r = await verifyIntelRestore(sql, { manifest: { row_counts: counts } });
  assert.deepEqual(failed(r), []); assert.equal(r.ok, true); assert.ok(r.checks.length >= 9); assert.ok(counts.intel_records > 40 && counts.intel_decisions === 1);
});
test('damage is caught by name: wrong counts, an orphan record, a broken hash, invalid JSON, a decision for a missing record, an unaudited decision, a truncated export', async () => {
  const { sql, counts } = await exportOf({ decisions: true });
  assert.deepEqual(failed(await verifyIntelRestore(sql, { manifest: { row_counts: { ...counts, intel_records: counts.intel_records + 1 } } })), ['row counts equal the manifest']);
  assert.deepEqual(failed(await verifyIntelRestore(sql + "\nINSERT INTO intel_records (id, family, source_id, run_id, key, doc, doc_sha256) VALUES ('x:1','kev','no-such-source','no-such-run','k','{}','" + 'a'.repeat(64) + "');")).sort(), ['every record points to an existing run', 'every record points to an existing source']);
  assert.deepEqual(failed(await verifyIntelRestore(sql + "\nUPDATE intel_records SET doc_sha256 = '" + 'z'.repeat(64) + "' WHERE id = 'kev:CVE-2024-1000';")), ['every record carries a SHA-256 of its document']);
  assert.deepEqual(failed(await verifyIntelRestore(sql + "\nUPDATE intel_records SET doc = '{oops' WHERE id = 'kev:CVE-2024-1001';")), ['the export loads into an empty database'], 'the schema itself refuses a document that is not JSON');
  assert.deepEqual(failed(await verifyIntelRestore(sql + "\nINSERT INTO intel_decisions (record_id, family, action, from_state, to_state, reason, actor, actor_id, at, request_id, audited) VALUES ('missing:1','kev','hold','x','RETENIDA','orphan decision test','rita',12,'2026-10-26T10:00:00Z','req-backup-0000000002',0);")).sort(), ['every decision points to an existing record', 'no decision is waiting for its audit entry']);
  const cut = sql.slice(0, sql.length - 400); const t = await verifyIntelRestore(cut, { manifest: { row_counts: counts } }); assert.equal(t.ok, false, 'a truncated export never passes');
});
