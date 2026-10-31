// Verification of a D1 export in an ISOLATED local SQLite (never the remote database). `verifyRestore` loads a SQL export into a fresh in-memory database and checks structure, integrity and the
// two hash chains the gateway relies on. `dumpSql` produces an export from a local database (used by the tests; production exports come from `wrangler d1 export`).
import { DatabaseSync } from 'node:sqlite';
import { loadExport } from './stream_io.mjs';
import { readdirSync, readFileSync } from 'node:fs';
import { verifyAudit } from '../src/audit.js';
import { canonical, sha256Hex } from '../src/util.js';

const q = (v) => (v === null || v === undefined ? 'NULL' : typeof v === 'number' || typeof v === 'bigint' ? String(v) : `'${String(v).replace(/'/g, "''")}'`);
export function dumpSql(raw) {
  const out = [];
  for (const t of raw.prepare("SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all()) {
    out.push(t.sql + ';');
    for (const r of raw.prepare(`SELECT * FROM ${t.name}`).all()) out.push(`INSERT INTO ${t.name}(${Object.keys(r).join(',')}) VALUES (${Object.values(r).map(q).join(',')});`);
  }
  for (const s of raw.prepare("SELECT sql FROM sqlite_master WHERE type IN ('index','trigger') AND sql IS NOT NULL ORDER BY name").all()) out.push(s.sql + ';');
  return out.join('\n') + '\n';
}
const tables = (raw) => Object.fromEntries(raw.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%'").all().map((t) => [t.name, raw.prepare(`PRAGMA table_info(${t.name})`).all().map((c) => c.name).join(',')]));

export async function verifyRestore(sqlText, { schemaFile = new URL('../schema.sql', import.meta.url), manifest = null } = {}) {
  const checks = [], add = (name, ok, detail = '') => checks.push({ name, ok: !!ok, detail });
  const L = await loadExport(sqlText); if (L.error) { add('the export loads into an empty database', false, L.error); L.close(); return { ok: false, checks }; }   // a string, { file } (streamed) or an already loaded export
  add('the export loads into an empty database', true); const db = L.db; let ref;   // foreign keys are OFF: load order is not dependency order; foreign_key_check below verifies the result
  try {   // the restored database is a plaintext FILE since O1: close it and remove its directory even if a check throws
  ref = new DatabaseSync(':memory:'); ref.exec(readFileSync(schemaFile, 'utf8'));
  const got = tables(db), want = tables(ref); const missing = Object.keys(want).filter((t) => !(t in got)), changed = Object.keys(want).filter((t) => t in got && got[t] !== want[t]);
  // A table that only a not-yet-applied migration creates is reported as pending (a known, documented difference), anything else missing is a failure.
  const pending = new Set(readdirSync(new URL('../migrations/', import.meta.url)).filter((f) => f.endsWith('.sql')).flatMap((f) => [...readFileSync(new URL('../migrations/' + f, import.meta.url), 'utf8').matchAll(/CREATE TABLE (?:IF NOT EXISTS )?(\w+)/g)].map((m) => m[1])));
  // Likewise a column that only a pending `ALTER TABLE ... ADD COLUMN` migration adds: the table then differs only by those columns, which is a known upgrade, not a loss.
  const pendingCols = {}; for (const f of readdirSync(new URL('../migrations/', import.meta.url)).filter((x) => x.endsWith('.sql'))) for (const m of readFileSync(new URL('../migrations/' + f, import.meta.url), 'utf8').matchAll(/ALTER TABLE (\w+) ADD COLUMN (\w+)/g)) (pendingCols[m[1]] ??= new Set()).add(m[2]);
  const colsOf = (spec) => spec.split(',').map((c) => c.split(':')[0]);
  const onlyPendingCols = (t) => { const g = new Set(colsOf(got[t])), w = colsOf(want[t]); return w.filter((c) => !g.has(c)).every((c) => pendingCols[t]?.has(c)) && [...g].every((c) => w.includes(c)) && w.some((c) => !g.has(c)); };
  const pendingColTables = changed.filter(onlyPendingCols);
  for (let i = changed.length - 1; i >= 0; i--) if (pendingColTables.includes(changed[i])) changed.splice(i, 1);
  const realMissing = missing.filter((t) => !pending.has(t)), pend = [...missing.filter((t) => pending.has(t)), ...pendingColTables.map((t) => t + ' (columns ' + [...pendingCols[t]].join(',') + ')')];
  add('every table of gateway/schema.sql exists with the same columns', !realMissing.length && !changed.length, [...realMissing.map((t) => 'missing ' + t), ...changed.map((t) => 'columns differ ' + t), ...pend.map((t) => 'PENDING MIGRATION ' + t + ' (not a loss)')].join('; '));
  const ic = db.prepare('PRAGMA integrity_check').all(); add('SQLite integrity_check', ic.length === 1 && ic[0].integrity_check === 'ok', JSON.stringify(ic).slice(0, 120));
  const fk = db.prepare('PRAGMA foreign_key_check').all(); add('no dangling foreign keys', fk.length === 0, fk.length ? JSON.stringify(fk[0]) : '');
  const shim = { prepare: (sql) => { let a = []; const s = { bind: (...x) => { a = x; return s; }, first: async () => db.prepare(sql).get(...a) ?? null, all: async () => ({ results: db.prepare(sql).all(...a) }) }; return s; } };
  const au = await verifyAudit(shim); add('audit hash chain intact', au.ok, au.ok ? '' : 'breaks at seq ' + au.at);
  let pol = true, why = ''; let prev = '0'.repeat(64);
  for (const r of db.prepare('SELECT * FROM policy_versions ORDER BY version').all()) { if ((await sha256Hex(canonical(JSON.parse(r.doc)))) !== r.doc_sha256 || r.prev_sha256 !== prev && r.version > 1) { pol = false; why = 'version ' + r.version; break; } prev = r.doc_sha256; }
  add('policy versions: each document matches its hash and the chain links', pol, why);
  const ptr = db.prepare('SELECT version FROM policy_pointer').get(); add('a policy pointer exists and points at a stored version', ptr && db.prepare('SELECT 1 x FROM policy_versions WHERE version = ?').get(ptr.version) !== undefined);
  if (manifest) { const counts = Object.fromEntries(Object.keys(got).map((t) => [t, db.prepare(`SELECT COUNT(*) n FROM ${t}`).get().n])); const diff = Object.entries(manifest.row_counts ?? {}).filter(([t, n]) => counts[t] !== n).map(([t, n]) => `${t}: manifest ${n}, restored ${counts[t]}`);
    add('row counts equal the manifest', !diff.length, diff.slice(0, 4).join('; ')); }
  return { ok: checks.every((c) => c.ok), checks };
  } finally { L.close(); ref?.close(); }
}
export const rowCounts = (raw) => Object.fromEntries(Object.keys(tables(raw)).map((t) => [t, raw.prepare(`SELECT COUNT(*) n FROM ${t}`).get().n]));
