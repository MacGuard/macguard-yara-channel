// Isolated restore check of an INTEL D1 export (macguard-intel): the export loads into an empty in-memory SQLite, passes integrity_check, has the base tables, every record points to an existing run and
// source, every decision (if the table exists) points to an existing record, the hashes have the right shape and row counts equal the manifest. Never touches Cloudflare.
// Used by gateway/tools/d1_backup.mjs --resource intel and by tests. A 130 MB export loads in a few seconds on a CI runner.
import { DatabaseSync } from 'node:sqlite';

export const BASE_TABLES = ['intel_events', 'intel_records', 'intel_runs', 'intel_sources'];
export function intelRowCounts(db) { const out = {}; for (const { name } of db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' ORDER BY name").all()) out[name] = db.prepare(`SELECT COUNT(*) AS n FROM "${name}"`).get().n; return out; }
export async function verifyIntelRestore(sql, { manifest = null } = {}) {
  const checks = [], add = (name, ok, detail = '') => checks.push({ name, ok: !!ok, detail });
  const db = new DatabaseSync(':memory:'); db.exec('PRAGMA foreign_keys = OFF');
  try { db.exec(sql); add('the export loads into an empty database', true); } catch (e) { add('the export loads into an empty database', false, String(e.message).slice(0, 100)); return { ok: false, checks }; }
  const ic = db.prepare('PRAGMA integrity_check').get(); add('SQLite integrity_check', ic.integrity_check === 'ok', JSON.stringify(ic));
  const have = new Set(db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map((r) => r.name)), miss = BASE_TABLES.filter((t) => !have.has(t)); add('the base tables of the intelligence store exist', !miss.length, miss.join(', '));
  if (!miss.length) {
    const orphanRuns = db.prepare('SELECT COUNT(*) AS n FROM intel_records r WHERE NOT EXISTS (SELECT 1 FROM intel_runs u WHERE u.id = r.run_id)').get().n; add('every record points to an existing run', orphanRuns === 0, String(orphanRuns));
    const orphanSrc = db.prepare('SELECT COUNT(*) AS n FROM intel_records r WHERE NOT EXISTS (SELECT 1 FROM intel_sources s WHERE s.id = r.source_id)').get().n; add('every record points to an existing source', orphanSrc === 0, String(orphanSrc));
    const badHash = db.prepare("SELECT COUNT(*) AS n FROM intel_records WHERE length(doc_sha256) != 64 OR doc_sha256 GLOB '*[^0-9a-f]*'").get().n; add('every record carries a SHA-256 of its document', badHash === 0, String(badHash));
    const badJson = db.prepare('SELECT COUNT(*) AS n FROM intel_records WHERE NOT json_valid(doc)').get().n; add('every document is valid JSON', badJson === 0, String(badJson));
    if (have.has('intel_decisions')) { const orphanDec = db.prepare('SELECT COUNT(*) AS n FROM intel_decisions d WHERE NOT EXISTS (SELECT 1 FROM intel_records r WHERE r.id = d.record_id)').get().n; add('every decision points to an existing record', orphanDec === 0, String(orphanDec)); const unaud = db.prepare('SELECT COUNT(*) AS n FROM intel_decisions WHERE audited = 0').get().n; add('no decision is waiting for its audit entry', unaud === 0, String(unaud)); }
  }
  if (manifest && manifest.row_counts) { const now = intelRowCounts(db), diff = Object.keys(manifest.row_counts).filter((t) => now[t] !== manifest.row_counts[t]); add('row counts equal the manifest', !diff.length, diff.join(', ')); }
  return { ok: checks.every((c) => c.ok), checks };
}
