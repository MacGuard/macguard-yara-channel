// Archive phase 1: audit anchors. Fast, no network. The D1 shim runs the real SQL of schema.sql and of migrations/0004.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { newDb } from './d1shim.js';
import { world } from './helpers.js';
import { GENESIS, canonical, chainHash, verifyChain } from '../src/core.js';
import { appendAudit, auditRows } from '../src/store.js';
import { chainHead, writeAnchor, verifyAuditChain, sealSha256, listAnchors, SEAL_SCHEMA, RECEIPT_SCHEMA, AnchorError } from '../src/anchor.js';

const MIG = (n) => readFileSync(new URL(`../migrations/${n}`, import.meta.url), 'utf8');
const T0 = '2026-09-01T00:00:00.000Z';

async function fill(db, n, from = 0) { for (let i = from; i < n + from; i++) await appendAudit(db, { actor: 'ada', role: 'ADMIN', action: 'test.event', target: `t${i}`, detail: { i } }, `2026-09-01T00:00:${String(i % 60).padStart(2, '0')}.000Z`); }
const rows = (db) => auditRows(db, 100000);
/** Seal for audit rows [a..b] (1-based seq); prevSeal is the previous seal object or null. */
async function sealOf(db, a, b, prevSeal = null) {
  const rs = (await rows(db)).filter((r) => r.seq >= a && r.seq <= b);
  const segment = rs.map((r) => canonical(r) + '\n').join('');
  return { schema: SEAL_SCHEMA, period: '2026-09', first_seq: a, last_seq: b, count: rs.length, first_prev_hash: rs[0].prev_hash, head_hash: rs[rs.length - 1].hash,
    segment_sha256: createHash('sha256').update(segment).digest('hex'), prev_seal_sha256: prevSeal ? await sealSha256(prevSeal) : null };
}
async function receiptOf(seal, over = {}) {
  const s = await sealSha256(seal), ct = 'c'.repeat(64);
  const copies = ['r2', 'b2', 'scaleway'].map((p) => ({ provider: p, ciphertext_sha256: ct, seal_sha256: s, readback_verified: true }));
  return { schema: RECEIPT_SCHEMA, seal_sha256: s, segment_sha256: seal.segment_sha256, copies, restore: { ok: true, provider: 'b2', seal_sha256: s, segment_sha256: seal.segment_sha256 }, ...over };
}
const anchorIt = async (db, seal, over = {}) => writeAnchor(db, { seal, receipt: await receiptOf(seal), author: 'owner', ...over }, T0);
/** What pruning would do after the owner authorizes it (test-only; the product has no such action). */
const pruneThrough = (db, seq) => { db.raw.exec('DROP TRIGGER audit_no_delete'); db.raw.exec(`DELETE FROM audit WHERE seq <= ${seq}`); };
const rejects = (p, code) => assert.rejects(p, (e) => e instanceof AnchorError && (!code || e.code === code), code);

test('verifyChain(rows) is unchanged and verifyChain(rows, startHash) starts where told', async () => {
  const db = newDb(); await fill(db, 6); const rs = await rows(db);
  assert.equal((await verifyChain(rs)).ok, true);
  assert.deepEqual(await verifyChain(rs), await verifyChain(rs, GENESIS));
  const tail = rs.slice(3), v = await verifyChain(tail, rs[2].hash);
  assert.equal(v.ok, true); assert.equal(v.head, rs[5].hash); assert.equal(v.entries, 3);
  assert.equal((await verifyChain(tail)).ok, false, 'a tail does not verify from GENESIS');
  assert.equal((await verifyChain(tail, rs[1].hash)).ok, false, 'a wrong start is refused');
});

test('appendAudit continues from the anchor when the audit table is empty, and from GENESIS only in a database that never had either', async () => {
  const fresh = newDb(); assert.equal(await chainHead(fresh), GENESIS);
  const db = newDb(); await fill(db, 5); const seal = await sealOf(db, 1, 5); const head = (await rows(db))[4].hash;
  assert.equal((await anchorIt(db, seal)).status, 'created');
  pruneThrough(db, 5); assert.equal((await rows(db)).length, 0);
  assert.equal(await chainHead(db), head);
  await fill(db, 2, 5); const rs = await rows(db);
  assert.equal(rs[0].prev_hash, head, 'first new entry links to the anchor, not to GENESIS');
  assert.equal((await verifyAuditChain(db)).ok, true);
});

test('the other audit writers (decisions, release, member changes) also read the head through the anchor', async () => {
  const w = await world(); const ada = await w.login('ada', { admin: true }); await fill(w.db, 3);
  const n = (await rows(w.db)).length; const seal = await sealOf(w.db, 1, n); await anchorIt(w.db, seal); pruneThrough(w.db, n);
  w.account('vera', 7); assert.equal((await w.grant(ada, 'vera', 'VIEWER')).status, 200);
  const rs = await rows(w.db); assert.equal(rs[0].prev_hash, seal.head_hash);
  const v = (await w.call('GET', '/api/audit/verify', { user: ada })).data; assert.equal(v.ok, true, JSON.stringify(v)); assert.equal(v.anchor.seq, n);
});

test('writeAnchor refuses unless the segment is proven archived in all three providers and a restore was rehearsed', async () => {
  const db = newDb(); await fill(db, 5); const seal = await sealOf(db, 1, 5); const base = await receiptOf(seal);
  const cases = {
    'two providers only': { ...base, copies: base.copies.slice(0, 2) },
    'a provider twice': { ...base, copies: [base.copies[0], base.copies[0], base.copies[1]] },
    'unknown provider': { ...base, copies: [...base.copies.slice(0, 2), { ...base.copies[2], provider: 'dropbox' }] },
    'read-back not verified': { ...base, copies: [{ ...base.copies[0], readback_verified: false }, ...base.copies.slice(1)] },
    'ciphertext differs between copies': { ...base, copies: [{ ...base.copies[0], ciphertext_sha256: 'd'.repeat(64) }, ...base.copies.slice(1)] },
    'a copy holds another seal': { ...base, copies: [{ ...base.copies[0], seal_sha256: 'e'.repeat(64) }, ...base.copies.slice(1)] },
    'no restore rehearsal': { ...base, restore: undefined },
    'restore failed': { ...base, restore: { ...base.restore, ok: false } },
    'restore of another seal': { ...base, restore: { ...base.restore, seal_sha256: 'f'.repeat(64) } },
    'receipt for another seal': { ...base, seal_sha256: 'a'.repeat(64) },
    'receipt for another segment': { ...base, segment_sha256: 'a'.repeat(64) },
    'wrong schema': { ...base, schema: 'x' },
  };
  for (const [name, receipt] of Object.entries(cases)) await assert.rejects(writeAnchor(db, { seal, receipt, author: 'o' }, T0), (e) => e.code === 'not_archived', name);
  await rejects(writeAnchor(db, { seal, receipt: null, author: 'o' }, T0), 'not_archived');
  await rejects(writeAnchor(db, { seal, receipt: base, author: ' ' }, T0), 'bad_author');
  await rejects(writeAnchor(db, { seal: { ...seal, count: 0 }, receipt: base, author: 'o' }, T0), 'bad_seal');
  await rejects(writeAnchor(db, { seal: { ...seal, head_hash: 'zz' }, receipt: base, author: 'o' }, T0), 'bad_seal');
  assert.equal((await listAnchors(db)).length, 0, 'nothing was written by any refusal');
});

test('an anchor that does not match the audit chain is refused, in code and by the database', async () => {
  const db = newDb(); await fill(db, 5);
  const seal = await sealOf(db, 1, 5); const wrong = { ...seal, head_hash: '1'.repeat(64) };
  await assert.rejects(writeAnchor(db, { seal: wrong, receipt: await receiptOf(wrong), author: 'o' }, T0), (e) => e.code === 'anchor_mismatch');
  assert.throws(() => db.raw.prepare('INSERT INTO audit_anchor (seq, hash, rows, seal_sha256, created_at, author) VALUES (3, ?, 3, ?, ?, ?)').run('1'.repeat(64), 'a'.repeat(64), T0, 'o'), /does not match the audit entry/);
  const second = await sealOf(db, 3, 5);   // does not start where the (absent) previous anchor ends
  await rejects(writeAnchor(db, { seal: second, receipt: await receiptOf(second), author: 'o' }, T0), 'not_continuous');
});

test('anchors are append-only; writing the same anchor twice is idempotent; a different one for the same position is refused', async () => {
  const db = newDb(); await fill(db, 8); const s1 = await sealOf(db, 1, 4), s2 = await sealOf(db, 5, 8, s1);
  assert.equal((await anchorIt(db, s1)).status, 'created'); assert.equal((await anchorIt(db, s1)).status, 'exists');
  await rejects(anchorIt(db, { ...s1, segment_sha256: '9'.repeat(64) }), 'conflict');
  await rejects(anchorIt(db, { ...s2, prev_seal_sha256: null }), 'not_continuous');
  assert.equal((await anchorIt(db, s2)).status, 'created');
  await rejects(anchorIt(db, await sealOf(db, 1, 2)), 'conflict');   // anchors only move forward
  assert.equal((await listAnchors(db)).length, 2);
  assert.throws(() => db.raw.exec("UPDATE audit_anchor SET author = 'x'"), /append-only/);
  assert.throws(() => db.raw.exec('DELETE FROM audit_anchor'), /append-only/);
});

test('two concurrent anchor writers: exactly one wins, the other is told and writes nothing', async () => {
  const db = newDb(); await fill(db, 8); const a = await sealOf(db, 1, 4), b = await sealOf(db, 1, 8);
  const res = await Promise.allSettled([anchorIt(db, a), anchorIt(db, b)]);
  assert.equal(res.filter((r) => r.status === 'fulfilled').length, 1, JSON.stringify(res.map((r) => r.status)));
  const loser = res.find((r) => r.status === 'rejected'); assert.ok(['conflict', 'not_continuous'].includes(loser.reason.code), loser.reason.code);
  assert.equal((await listAnchors(db)).length, 1);
  // The race itself: a writer whose pre-check read is stale (it saw no anchor) is stopped by the condition inside the INSERT.
  const db2 = newDb(); await fill(db2, 8); await anchorIt(db2, await sealOf(db2, 1, 4));
  const stale = { prepare: (sql) => (/FROM audit_anchor ORDER BY seq DESC LIMIT 1/.test(sql) && /^SELECT seq/.test(sql) ? { first: async () => null } : db2.prepare(sql)) };
  await assert.rejects(anchorIt(stale, await sealOf(db2, 1, 8)), (e) => e.code === 'conflict' && /another writer/.test(e.message));
  assert.equal((await listAnchors(db2)).length, 1);
});

test('verification from an anchor: pruned database verifies, and every kind of damage is reported', async () => {
  const mk = async () => { const db = newDb(); await fill(db, 12); const s = await sealOf(db, 1, 5); await anchorIt(db, s); return { db, s }; };
  { const { db } = await mk(); assert.deepEqual({ ...(await verifyAuditChain(db)) }.entries, 12); pruneThrough(db, 5);
    const v = await verifyAuditChain(db); assert.equal(v.ok, true); assert.equal(v.entries, 7); assert.equal(v.anchor.seq, 5); assert.equal(v.complete, true); }
  { const { db } = await mk(); pruneThrough(db, 5); db.raw.exec('DROP TRIGGER audit_anchor_no_delete'); db.raw.exec('DELETE FROM audit_anchor');
    const v = await verifyAuditChain(db); assert.equal(v.ok, false); assert.match(v.error, /anchor missing or not matching/); }
  { const { db } = await mk(); pruneThrough(db, 5); db.raw.exec('DROP TRIGGER audit_anchor_no_delete'); db.raw.exec('DROP TRIGGER audit_anchor_no_update'); db.raw.exec("UPDATE audit_anchor SET hash = '" + '2'.repeat(64) + "'");
    assert.equal((await verifyAuditChain(db)).ok, false, 'anchor not matching'); }
  { const { db } = await mk(); pruneThrough(db, 6); const v = await verifyAuditChain(db);   // one row too many removed: the chain has a hole after the anchor
    assert.equal(v.ok, false); }
  { const { db } = await mk(); db.raw.exec('DROP TRIGGER audit_no_delete'); db.raw.exec('DELETE FROM audit WHERE seq = 9'); const v = await verifyAuditChain(db); assert.equal(v.ok, false); assert.match(v.error, /removed or reordered/); }
  { const { db } = await mk(); db.raw.exec('DROP TRIGGER audit_no_update'); db.raw.exec("UPDATE audit SET detail = '{}' WHERE seq = 8"); const v = await verifyAuditChain(db); assert.equal(v.ok, false); assert.equal(v.at, 8); }
  { const { db } = await mk(); db.raw.exec('DROP TRIGGER audit_no_update'); db.raw.exec(`UPDATE audit SET hash = '${'3'.repeat(64)}' WHERE seq = 5`);   // the row under the anchor was rewritten
    const v = await verifyAuditChain(db); assert.equal(v.ok, false); }
  { const { db } = await mk(); db.raw.exec('DROP TRIGGER audit_no_delete'); db.raw.exec('DELETE FROM audit WHERE seq > 3');   // truncated chain: the anchor lies beyond its end
    const v = await verifyAuditChain(db); assert.equal(v.ok, false); assert.match(v.error, /beyond the end/); }
});

test('verification is paginated with a resume point, never claims more than it read, and does not stop at 100,000 rows', async () => {
  const db = newDb(); await fill(db, 10);
  const full = await verifyAuditChain(db); const paged = await verifyAuditChain(db, { pageSize: 3 }); assert.deepEqual(paged, full);
  const part = await verifyAuditChain(db, { pageSize: 3, maxPages: 2 }); assert.equal(part.complete, false); assert.equal(part.entries, 6); assert.equal(part.verified_through_seq, 6);
  const rest = await verifyAuditChain(db, { pageSize: 3, maxPages: 2, ...part.resume }); assert.equal(rest.complete, true); assert.equal(rest.entries, 4); assert.equal(rest.head, full.head);
  assert.equal((await verifyAuditChain(db, { after: 6, head: '0'.repeat(64) })).ok, false, 'a resume point that is not on the chain is refused');
  // 100,500 rows written straight into the shim with node:crypto (same hash rule): the old route refused anything above 100,000.
  const big = newDb(); let prev = GENESIS; const ins = big.raw.prepare('INSERT INTO audit (at, actor, role, action, target, detail, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?)');
  big.raw.exec('BEGIN');
  for (let i = 0; i < 100500; i++) { const e = { at: T0, actor: 'a', role: 'ADMIN', action: 'x', target: `t${i}`, detail: '{}' }; const h = createHash('sha256').update(prev + canonical(e)).digest('hex'); ins.run(e.at, e.actor, e.role, e.action, e.target, e.detail, prev, h); prev = h; }
  big.raw.exec('COMMIT');
  const first = await verifyAuditChain(big, {}); assert.equal(first.ok, true); assert.equal(first.complete, false); assert.equal(first.entries, 100000);
  const second = await verifyAuditChain(big, first.resume); assert.equal(second.complete, true); assert.equal(second.entries, 500); assert.equal(second.head, prev);
});

test('migration 0004: mirrored in schema.sql, changes no existing row or object, can be rolled back without touching data', async () => {
  const block = (t) => t.slice(t.indexOf('-- BEGIN audit_anchor (0004)'), t.indexOf('-- END audit_anchor (0004)'));
  const schema = readFileSync(new URL('../schema.sql', import.meta.url), 'utf8');
  assert.ok(block(schema).length > 100); assert.equal(block(schema), block(MIG('0004_audit_anchor.sql')), 'schema.sql carries exactly the migration');
  const db = new DatabaseSync(':memory:'); db.exec(schema.slice(0, schema.indexOf('-- Mirrored from migrations/0004')));   // schema without 0004
  const t = '2026-10-20T00:00:00.000Z';
  db.prepare("INSERT INTO members (login, role, granted_by, at) VALUES ('old','VIEWER','adm',?)").run(t);
  db.prepare("INSERT INTO candidates (id, sha256, path, name, source, detected_at, state, updated_at) VALUES ('c1', ?, 'p', 'n', 's', ?, 'PENDING', ?)").run('b'.repeat(64), t, t);
  let prev = GENESIS; for (let i = 0; i < 5; i++) { const e = { at: t, actor: 'a', role: 'ADMIN', action: 'x', target: `t${i}`, detail: '{}' }; const h = await chainHash(prev, e); db.prepare('INSERT INTO audit (at, actor, role, action, target, detail, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?)').run(t, 'a', 'ADMIN', 'x', e.target, '{}', prev, h); prev = h; }
  const snap = () => JSON.stringify({ tables: db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name <> 'audit_anchor' ORDER BY name").all().map((r) => [r.name, db.prepare(`SELECT * FROM "${r.name}" ORDER BY 1`).all()]),
    objects: db.prepare("SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' AND name NOT LIKE 'audit_anchor%' ORDER BY name").all(), seq: db.prepare("SELECT * FROM sqlite_sequence ORDER BY name").all() });
  const before = snap(); const objsBefore = db.prepare("SELECT COUNT(*) AS n FROM sqlite_master").get().n;
  db.exec(MIG('0004_audit_anchor.sql')); assert.equal(snap(), before, 'every existing row, table, index and trigger is identical after 0004');
  db.exec(MIG('0004_audit_anchor.sql')); assert.equal(snap(), before, 'applying it twice is harmless');
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name LIKE 'audit_anchor%'").get().n, 4);
  db.prepare('INSERT INTO audit_anchor (seq, hash, rows, seal_sha256, created_at, author) VALUES (5, ?, 5, ?, ?, ?)').run(prev, 'a'.repeat(64), t, 'o');
  db.exec(MIG('0004_rollback.sql')); assert.equal(snap(), before, 'rollback leaves the data intact');
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM sqlite_master").get().n, objsBefore, 'and removes exactly what 0004 added');
});
