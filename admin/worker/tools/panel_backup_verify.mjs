// Isolated restore check of a PANEL D1 export (macguard-quarantine): the export loads into an empty in-memory SQLite, passes integrity_check, has the base tables, no dangling foreign keys, an intact audit hash chain
// and row counts equal to the manifest. Never touches Cloudflare. Used by gateway/tools/d1_backup.mjs --resource panel and by tests.
import { DatabaseSync } from 'node:sqlite';
import { verifyAuditChain } from '../src/anchor.js';

export const BASE_TABLES = ['audit', 'blobs', 'candidates', 'decisions', 'members', 'metrics', 'oauth_states', 'pipeline_runs', 'sessions'];
const shim = (db) => ({ prepare(sql) { let a = []; const s = { bind: (...x) => { a = x; return s; }, first: async () => db.prepare(sql).get(...a) ?? null, all: async () => ({ results: db.prepare(sql).all(...a) }), run: async () => { const r = db.prepare(sql).run(...a); return { meta: { changes: Number(r.changes) } }; } }; return s; } });
export function panelRowCounts(db) { const out = {}; for (const { name } of db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' ORDER BY name").all()) out[name] = db.prepare(`SELECT COUNT(*) AS n FROM "${name}"`).get().n; return out; }
export async function verifyPanelRestore(sql, { manifest = null } = {}) {
  const checks = [], add = (name, ok, detail = '') => checks.push({ name, ok: !!ok, detail });
  const db = new DatabaseSync(':memory:'); db.exec('PRAGMA foreign_keys = OFF');
  try { db.exec(sql); add('the export loads into an empty database', true); } catch (e) { add('the export loads into an empty database', false, String(e.message).slice(0, 100)); return { ok: false, checks }; }
  const ic = db.prepare('PRAGMA integrity_check').get(); add('SQLite integrity_check', ic.integrity_check === 'ok', JSON.stringify(ic));
  const have = new Set(db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map((r) => r.name)); const miss = BASE_TABLES.filter((t) => !have.has(t)); add('the base tables of the panel exist', !miss.length, miss.length ? `missing: ${miss.join(', ')}` : '');
  add('no dangling foreign keys', db.prepare('PRAGMA foreign_key_check').all().length === 0);
  let chain; try { chain = await verifyAuditChain(shim(db)); } catch (e) { chain = { ok: false, error: String(e.message).slice(0, 80) }; } add('audit hash chain intact', chain.ok === true, chain.ok ? `${chain.entries} entries` : JSON.stringify(chain).slice(0, 100));
  if (manifest && manifest.row_counts) { const now = panelRowCounts(db), diff = Object.keys(manifest.row_counts).filter((t) => now[t] !== manifest.row_counts[t]); add('row counts equal the manifest', !diff.length, diff.join(', ')); }
  return { ok: checks.every((c) => c.ok), checks };
}
