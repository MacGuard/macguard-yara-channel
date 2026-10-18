// A D1-compatible wrapper over node:sqlite so the tests run the real SQL, including batches as one transaction.
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
      async run() { const r = db.prepare(sql).run(...args); return { meta: { changes: Number(r.changes) } }; },
      _exec() { const r = db.prepare(sql).all(...args); return r; }, _sql: sql, _args: () => args };
    return s;
  };
  return {
    prepare: stmt,
    async batch(list) {
      db.exec('BEGIN');
      try { const out = []; for (const s of list) { const sql = s._sql; if (/^\s*(SELECT)/i.test(sql)) out.push({ results: db.prepare(sql).all(...s._args()) }); else { const r = db.prepare(sql).run(...s._args()); out.push({ meta: { changes: Number(r.changes) } }); } } db.exec('COMMIT'); return out; }
      catch (e) { db.exec('ROLLBACK'); throw e; }
    },
    raw: db,
  };
}
