#!/usr/bin/env node
// Deterministic, representative INTEL fixture for migration trials on a temporary D1: the same rows every run, every family, the real state/verdict mix in proportion, a few thousand rows at most
// (never the 75,148 of production). Prints INSERT statements (data only: the schema comes from migration 0001). Usage: node tools/intel_trial_fixture.mjs [ROWS=1500] > fixture.sql
import { newDb } from '../test/d1shim.js';
import { seedIntel } from '../test/intel_fixture.js';

const rows = Math.min(Math.max(Number(process.argv[2]) || 1500, 100), 5000);
const db = newDb('../migrations-intel/0001_intel.sql');
await seedIntel(db, { kev: rows });
const q = (v) => (v === null || v === undefined ? 'NULL' : typeof v === 'number' ? String(v) : `'${String(v).replace(/'/g, "''")}'`);
const out = [];
for (const t of ['intel_sources', 'intel_runs', 'intel_records', 'intel_events']) {
  const list = db.raw.prepare(`SELECT * FROM ${t}${t === 'intel_events' ? ' ORDER BY id' : ' ORDER BY ' + (t === 'intel_records' ? 'id' : 'rowid')}`).all();
  for (const r of list) { const cols = Object.keys(r); out.push(`INSERT INTO ${t} (${cols.join(',')}) VALUES (${cols.map((c) => q(r[c])).join(',')});`); }
}
process.stdout.write(out.join('\n') + '\n');
