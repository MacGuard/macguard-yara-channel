// Migration 0009 (Codex review of the #53 fix, HIGH): the emergency-review table must reach databases that ALREADY applied 0008, so it is a new
// forward migration instead of an edit of 0008. 0008 stays byte-identical to the version under review; 0009 is idempotent, append-only, mirrored in schema.sql, and reversible.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { newDb } from './d1shim.js';

const read = (f) => readFileSync(new URL(f, import.meta.url), 'utf8');
const M9 = read('../migrations/0009_publication_request_reviews.sql'), R9 = read('../migrations/0009_rollback.sql');
const names = (db) => db.raw.prepare("SELECT name FROM sqlite_master WHERE name LIKE 'publication_request%' ORDER BY name").all().map((r) => r.name);

test('a database that already applied 0008 (no review table) gets it from 0009; applying 0009 again is harmless; 0008 objects are untouched', () => {
  const db = newDb(); db.raw.exec(R9);   // the state of a database migrated up to 0008 only
  const before = names(db); assert.ok(!before.includes('publication_request_reviews') && before.includes('publication_requests'));
  db.raw.exec(M9); db.raw.exec(M9);
  const after = names(db); for (const n of ['publication_request_reviews', 'publication_request_reviews_no_update', 'publication_request_reviews_no_delete']) assert.ok(after.includes(n), n);
  assert.deepEqual(after.filter((n) => !n.startsWith('publication_request_reviews')), before, '0008 objects unchanged');
});
test('0009 reviews are append-only and validated', () => {
  const db = newDb(); const ins = db.raw.prepare('INSERT INTO publication_request_reviews (request_id, at, by_login, by_id, outcome, reason) VALUES (?,?,?,?,?,?)');
  ins.run('r1', '2026-11-01T00:00:00Z', 'ada', 1, 'APPROPRIATE', 'checked the emergency');
  assert.throws(() => db.raw.exec("UPDATE publication_request_reviews SET outcome='INAPPROPRIATE'"), /append-only/);
  assert.throws(() => db.raw.exec('DELETE FROM publication_request_reviews'), /append-only/);
  assert.throws(() => ins.run('r2', 'x', 'ada', 1, 'MAYBE', 'checked the emergency'), /CHECK/);
  assert.throws(() => ins.run('r1', 'x', 'ada', 1, 'APPROPRIATE', 'second review'), /UNIQUE|PRIMARY/);
});
test('schema.sql mirrors every statement of 0009, and the rollback removes only what 0009 added', () => {
  const schema = read('../schema.sql').replace(/\s+/g, ' ');
  for (const stmt of M9.split('\n').filter((l) => !l.startsWith('--')).join('\n').split(';').map((s) => s.replace(/\s+/g, ' ').trim()).filter(Boolean)) assert.ok(schema.includes(stmt), stmt.slice(0, 80));
  const db = newDb(); const all = names(db); db.raw.exec(R9); assert.deepEqual(names(db), all.filter((n) => !n.startsWith('publication_request_reviews')));
});
test('0008 is byte-identical to the migration of the reviewed #53 head (a released migration is never edited)', (t) => {
  let orig; try { orig = execFileSync('git', ['show', '3b900b92e1aff1a99d91377f8dd396dfd9f5d3a6:admin/worker/migrations/0008_publication_requests.sql'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }); } catch { t.skip('git history not available'); return; }
  assert.equal(read('../migrations/0008_publication_requests.sql'), orig);
});
