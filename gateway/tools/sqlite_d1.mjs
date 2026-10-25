// A D1-shaped wrapper over a node:sqlite FILE (or :memory:), for local tools and offline reports. It runs the same SQL as the Worker. Not used by the Worker itself.
import { DatabaseSync } from 'node:sqlite';
import { existsSync, readFileSync } from 'node:fs';
export function openDb(path = ':memory:', schemaUrl = new URL('../schema.sql', import.meta.url)) {
  const fresh = path === ':memory:' || !existsSync(path), db = new DatabaseSync(path);
  if (fresh) db.exec(readFileSync(schemaUrl, 'utf8'));
  const stmt = (sql) => { let args = []; const s = { bind(...a) { args = a.map((x) => (x === undefined ? null : x)); return s; }, async first() { return db.prepare(sql).get(...args) ?? null; },
    async all() { return { results: db.prepare(sql).all(...args) }; }, async run() { const r = db.prepare(sql).run(...args); return { meta: { changes: Number(r.changes) } }; }, _sql: sql, _args: () => args }; return s; };
  return { prepare: stmt, raw: db, async batch(list) { db.exec('BEGIN'); try { const out = []; for (const s of list) out.push({ meta: { changes: Number(db.prepare(s._sql).run(...s._args()).changes) } }); db.exec('COMMIT'); return out; } catch (e) { db.exec('ROLLBACK'); throw e; } }, close: () => db.close() };
}
