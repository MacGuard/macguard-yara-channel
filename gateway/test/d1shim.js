// A D1-compatible wrapper over node:sqlite so the tests run the REAL SQL of schema.sql (including RETURNING, triggers and batches as one transaction).
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
export function newDb() {
  const db = new DatabaseSync(':memory:');
  db.exec(readFileSync(new URL('../schema.sql', import.meta.url), 'utf8'));
  const stmt = (sql) => {
    let args = [];
    const s = { bind(...a) { args = a.map((x) => (x === undefined ? null : x)); return s; },
      async first() { return db.prepare(sql).get(...args) ?? null; },
      async all() { return { results: db.prepare(sql).all(...args) }; },
      async run() { const r = db.prepare(sql).run(...args); return { meta: { changes: Number(r.changes) } }; }, _sql: sql, _args: () => args };
    return s;
  };
  return { prepare: stmt, raw: db,
    async batch(list) { db.exec('BEGIN'); try { const out = []; for (const s of list) out.push({ meta: { changes: Number(db.prepare(s._sql).run(...s._args()).changes) } }); db.exec('COMMIT'); return out; } catch (e) { db.exec('ROLLBACK'); throw e; } } };
}
export const fixedClock = (iso) => { let t = Date.parse(iso); const c = () => new Date(t); c.advance = (ms) => { t += ms; }; c.set = (i) => { t = Date.parse(i); }; return c; };
