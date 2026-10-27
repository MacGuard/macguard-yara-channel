// Migration 0006 (five roles) on a copy of today's schema: members are copied verbatim, the widened constraints accept the new roles and still refuse anything else, the guarded rebuild refuses non-empty
// policy tables, every trigger and index comes back, and the rollback is refused while a new role is in use.
import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';

const OLD = readFileSync(new URL('./fixtures/schema_before_0006.sql', import.meta.url), 'utf8');   // the schema production runs today (frozen copy: the test must not depend on git history, which CI does not fetch)
const UP = readFileSync(new URL('../migrations/0006_five_roles.sql', import.meta.url), 'utf8'), DOWN = readFileSync(new URL('../migrations/0006_rollback.sql', import.meta.url), 'utf8'), NOW_SCHEMA = readFileSync(new URL('../schema.sql', import.meta.url), 'utf8');
const UP7 = readFileSync(new URL('../migrations/0007_source_requests.sql', import.meta.url), 'utf8');
const names = (db) => db.prepare("SELECT type, name FROM sqlite_master WHERE type IN ('trigger','index','table') AND name NOT LIKE 'sqlite_%' ORDER BY type, name").all().map((r) => `${r.type}:${r.name}`);
const fresh = () => { const db = new DatabaseSync(':memory:'); db.exec(OLD); db.prepare("INSERT INTO members (login, role, granted_by, at, user_id, updated_at) VALUES ('ada','ADMIN','x','2026-10-01',13,'2026-10-02'), ('rita','REVIEWER','ada','2026-10-01',12,NULL), ('legacy','VIEWER','ada','2026-10-01',NULL,NULL)").run(); return db; };

test('up: members survive verbatim, the new roles are accepted and unknown ones refused, every object comes back, and the result equals a fresh install of the new schema', () => {
  const db = fresh(), before = names(db); db.exec(UP);
  assert.deepEqual(db.prepare('SELECT login, role, granted_by, at, user_id, updated_at FROM members ORDER BY login').all().map((r) => ({ ...r })), [{ login: 'ada', role: 'ADMIN', granted_by: 'x', at: '2026-10-01', user_id: 13, updated_at: '2026-10-02' }, { login: 'legacy', role: 'VIEWER', granted_by: 'ada', at: '2026-10-01', user_id: null, updated_at: null }, { login: 'rita', role: 'REVIEWER', granted_by: 'ada', at: '2026-10-01', user_id: 12, updated_at: null }]);
  const added = names(db).filter((n) => !before.includes(n)); assert.deepEqual(added.filter((n) => !/approvals/.test(n)), [], 'nothing else changes'); assert.ok(added.includes('table:approvals') && added.length === 7, `the approvals table with its index and five triggers: ${added.join(',')}`); assert.deepEqual(before.filter((n) => !names(db).includes(n)), [], 'every previous table, index and trigger comes back'); for (const r of ['PUBLISHER', 'SECURITY_ADMIN']) db.prepare("INSERT INTO members (login, role, granted_by, at, user_id) VALUES (?,?,?,?,?)").run(`u-${r}`.toLowerCase(), r, 'ada', 'now', r.length);
  assert.throws(() => db.prepare("INSERT INTO members (login, role, granted_by, at) VALUES ('x','ROOT','ada','now')").run(), /CHECK/); assert.throws(() => db.prepare("INSERT INTO members (login, role, granted_by, at, user_id) VALUES ('dup','VIEWER','ada','now',13)").run(), /UNIQUE/, 'the unique id index is back');
  db.exec(UP7); db.exec(UP7);   // 0007 applies after 0006 and is idempotent
  const fresh2 = new DatabaseSync(':memory:'); fresh2.exec(NOW_SCHEMA); assert.deepEqual(names(fresh2), names(db), 'migrated (0006 then 0007) and fresh databases have the same objects');
});

test('up: a policy by a PUBLISHER or a SECURITY_ADMIN is accepted after the migration and refused before; the guard refuses a non-empty policy table', () => {
  const ins = (db, role) => db.prepare("INSERT INTO policies (id, scope, scope_key, source, path, sha256, candidate_id, criticality, author, author_id, author_role, reason, created_at, request_id, baseline_tag, baseline_published_at, baseline_manifest_sha256, baseline_rules_root, updated_at) VALUES ('p1','path','path:s:p','s','p',?,'c','STANDARD','u',1,?,'because','t','r1','tag','t',?,?,'t')").run('a'.repeat(64), role, 'b'.repeat(64), 'c'.repeat(64));
  const before = fresh(); assert.throws(() => ins(before, 'PUBLISHER'), /CHECK/);
  const db = fresh(); db.exec(UP); ins(db, 'PUBLISHER'); assert.equal(db.prepare('SELECT author_role FROM policies').get().author_role, 'PUBLISHER'); assert.throws(() => db.prepare("UPDATE policies SET reason = 'edited' WHERE id = 'p1'").run(), /policy version|identity|frozen/i, 'the immutability triggers are back');
  const busy = fresh(); ins(busy, 'ADMIN'); assert.throws(() => busy.exec(UP), /malformed JSON|not-json|json/i); assert.equal(busy.prepare('SELECT COUNT(*) AS n FROM policies').get().n, 1, 'nothing was dropped');
});

test('down: refused while a new role is in use, otherwise back to the three-role constraints with members intact', () => {
  const db = fresh(); db.exec(UP); db.prepare("INSERT INTO members (login, role, granted_by, at, user_id) VALUES ('pub','PUBLISHER','ada','now',77)").run();
  assert.throws(() => db.exec(DOWN), /malformed JSON|not-json|json/i); assert.equal(db.prepare("SELECT COUNT(*) AS n FROM members WHERE role = 'PUBLISHER'").get().n, 1);
  db.prepare("DELETE FROM members WHERE login = 'pub'").run(); db.exec(DOWN); assert.equal(db.prepare('SELECT COUNT(*) AS n FROM members').get().n, 3); assert.throws(() => db.prepare("INSERT INTO members (login, role, granted_by, at) VALUES ('x','PUBLISHER','ada','now')").run(), /CHECK/);
  const o = new DatabaseSync(':memory:'); o.exec(OLD); assert.deepEqual(names(db), names(o), 'the rollback restores the previous object set');
});
