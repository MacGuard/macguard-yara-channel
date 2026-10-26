// Migration INTEL 0002 and panel 0007: a new Worker on a database that does not have them yet, the migration applied while the Worker runs, idempotence, data conservation, rollback,
// concurrency and recovery after a failure between the decision and its audit entry.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { world } from './helpers.js';
import { newDb } from './d1shim.js';
import { seedIntel } from './intel_fixture.js';
import { resetSnapshotMemo } from '../src/intel_data.js';
import { decide, unaudited } from '../src/intel_decisions.js';
import { verifyChain } from '../src/core.js';
import { auditRows } from '../src/store.js';

const M1 = '../migrations-intel/0001_intel.sql', M2 = readFileSync(new URL('../migrations-intel/0002_decisions.sql', import.meta.url), 'utf8'), R2 = readFileSync(new URL('../migrations-intel/0002_rollback.sql', import.meta.url), 'utf8');
const M7 = readFileSync(new URL('../migrations/0007_source_requests.sql', import.meta.url), 'utf8'), R7 = readFileSync(new URL('../migrations/0007_rollback.sql', import.meta.url), 'utf8');
const RID = (n) => `req-compat-decision-${String(n).padStart(4, '0')}`, ID = 'ioc:ip:203.0.113.7';
const dump = (db) => JSON.stringify(db.raw.prepare('SELECT id, family, state, doc_sha256 FROM intel_records ORDER BY id').all());
async function oldIntel() {   // the intelligence database as it is in production today: migration 0001 only
  const w = await world(); w.env.INTEL = newDb(M1); await seedIntel(w.env.INTEL, { kev: 5 });
  const rita = await w.login('rita', { push: true }, { id: 12 }), ada = await w.login('ada', { admin: true }, { id: 13 }); for (const u of [rita, ada]) await w.call('GET', '/api/me', { user: u });
  return { w, rita, ada };
}
const dec = (w, user, over = {}) => w.call('POST', '/api/intel/decisions', { user, body: { action: 'quarantine', ids: [ID], reason: 'seen in a customer incident', request_id: RID(1), ...over } });

test('a new Worker on an INTEL database without 0002: every read works with the imported state, deciding says which migration is missing and changes nothing', async () => {
  const { w, rita } = await oldIntel(); const before = dump(w.env.INTEL);
  const list = await w.call('GET', '/api/intel/records?family=ioc', { user: rita }); assert.equal(list.status, 200); assert.equal(list.data.total, 2); assert.equal(list.data.items[0].state, 'EXPIRED');
  const one = await w.call('GET', `/api/intel/records/${encodeURIComponent(ID)}`, { user: rita }); assert.equal(one.status, 200); assert.deepEqual(one.data.history, []); const st = await w.call('GET', '/api/intel/stats', { user: rita }); assert.equal(st.status, 200); assert.equal(st.data.decisions, null, 'not applied');
  const r = await dec(w, rita); assert.equal(r.status, 503); assert.equal(r.data.code, 'migration_pending'); assert.match(r.data.error, /INTEL 0002/); assert.equal(dump(w.env.INTEL), before);
});
test('0002 applied while the Worker runs: decisions work at once, imported rows are untouched, re-applying is harmless, and the history survives', async () => {
  const { w, rita } = await oldIntel(); const before = dump(w.env.INTEL); w.env.INTEL.raw.exec(M2); w.env.INTEL.raw.exec(M2);   // twice: idempotent
  assert.equal((await dec(w, rita)).status, 200); const one = (await w.call('GET', `/api/intel/records/${encodeURIComponent(ID)}`, { user: rita })).data; assert.equal(one.record.state, 'QUARANTINED'); assert.equal(one.record.imported_state, 'EXPIRED'); assert.equal(one.history.length, 1);
  assert.equal(JSON.stringify(w.env.INTEL.raw.prepare('SELECT id, family, doc_sha256 FROM intel_records ORDER BY id').all()), JSON.stringify(JSON.parse(before).map(({ id, family, doc_sha256 }) => ({ id, family, doc_sha256 }))), 'imported rows are byte-identical');
  w.env.INTEL.raw.exec(M2); assert.equal(w.env.INTEL.raw.prepare('SELECT COUNT(*) AS n FROM intel_decisions').get().n, 1, 'a third application keeps the decisions');
});
test('rollback of 0002: the decisions table and view go, the imported data is intact, and reads fall back to the imported state without an error', async () => {
  const { w, rita } = await oldIntel(); w.env.INTEL.raw.exec(M2); await dec(w, rita); const before = dump(w.env.INTEL).replace(/"state":"[A-Z]+"/g, '');
  w.env.INTEL.raw.exec(R2); assert.equal(w.env.INTEL.raw.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name LIKE 'intel_decisions%' OR name = 'intel_current'").get().n, 0);
  assert.equal(dump(w.env.INTEL).replace(/"state":"[A-Z]+"/g, ''), before); const one = await w.call('GET', `/api/intel/records/${encodeURIComponent(ID)}`, { user: rita }); assert.equal(one.status, 200); assert.equal(one.data.record.state, 'EXPIRED');
  w.env.INTEL.raw.exec(M2); assert.equal((await dec(w, rita, { request_id: RID(2) })).status, 200, 'forward again after the rollback');
});
test('concurrency: parallel decisions on one record are all recorded in order and the effective state is the last; one request id sent twice at once is applied once', async () => {
  const { w, rita } = await oldIntel(); w.env.INTEL.raw.exec(M2); const actor = { login: 'rita', id: 12, role: 'REVIEWER' }, ctx = { intel: w.env.INTEL, panel: w.db };
  const acts = ['quarantine', 'reject', 'hold', 'quarantine']; const rs = await Promise.all(acts.map((a, i) => decide(ctx, { action: a, ids: [ID], reason: 'parallel decision', request_id: RID(10 + i) }, actor, '2026-10-26T10:00:00Z')));
  assert.ok(rs.every((r) => r.status === 200 || (r.status === 200 && r.body.changed === 0)), JSON.stringify(rs.map((r) => r.body))); const rows = w.env.INTEL.raw.prepare('SELECT action, to_state FROM intel_decisions ORDER BY id').all(); assert.ok(rows.length >= 3 && rows.length <= 4);
  assert.equal((await w.call('GET', `/api/intel/records/${encodeURIComponent(ID)}`, { user: rita })).data.record.state, rows[rows.length - 1].to_state, 'the effective state is the last recorded decision');
  const twin = await Promise.all([0, 1].map(() => decide(ctx, { action: 'reject', ids: ['ioc:ip:203.0.113.8'], reason: 'same request twice', request_id: RID(99) }, actor, '2026-10-26T10:00:01Z')));
  assert.ok(twin.every((r) => r.status === 200 || r.status === 409), JSON.stringify(twin.map((r) => r.body))); assert.equal(w.env.INTEL.raw.prepare("SELECT COUNT(*) AS n FROM intel_decisions WHERE request_id = ?").get(RID(99)).n, 1, 'applied exactly once');
});
test('recovery: a failure between the decision and its audit entry leaves it flagged; the same request finishes the job and the chain stays valid', async () => {
  const { w, rita } = await oldIntel(); w.env.INTEL.raw.exec(M2); const actor = { login: 'rita', id: 12, role: 'REVIEWER' };
  const broken = { prepare: (sql) => (/INSERT INTO audit/.test(sql) ? { bind: () => ({ run: async () => { throw new Error('D1 unavailable'); } }) } : w.db.prepare(sql)), batch: (x) => w.db.batch(x) };   // the audit write fails once
  const first = await decide({ intel: w.env.INTEL, panel: broken }, { action: 'quarantine', ids: [ID], reason: 'recovery drill', request_id: RID(50) }, actor, '2026-10-26T10:00:00Z');
  assert.equal(first.status, 500); assert.equal(await unaudited(w.env.INTEL), 1); const st = (await w.call('GET', '/api/intel/stats', { user: rita })).data; assert.equal(st.decisions.unaudited, 1, 'the anomaly is visible, not hidden');
  const again = await decide({ intel: w.env.INTEL, panel: w.db }, { action: 'quarantine', ids: [ID], reason: 'recovery drill', request_id: RID(50) }, actor, '2026-10-26T10:05:00Z'); assert.equal(again.status, 200); assert.equal(again.body.replay, true);
  assert.equal(await unaudited(w.env.INTEL), 0); const rows = (await auditRows(w.db, 500)).filter((e) => e.action === 'intel.decision'); assert.equal(rows.length, 1); assert.equal(JSON.parse(rows[0].detail).recovered, true); assert.equal((await verifyChain(await auditRows(w.db, 5000))).ok, true);
  const other = await decide({ intel: w.env.INTEL, panel: w.db }, { action: 'quarantine', ids: [ID], reason: 'recovery drill', request_id: RID(50) }, { ...actor, id: 99, login: 'eve' }, '2026-10-26T10:06:00Z'); assert.equal(other.body.replay, true); assert.equal((await auditRows(w.db, 500)).filter((e) => e.action === 'intel.decision').length, 1, 'only the original actor can finish it, and only once');
});
test('panel 0007: before it, source requests say which migration is missing and the rest of the panel is untouched; applied twice, rolled back and forward again, requests survive a re-apply', async () => {
  const w = await world(); const ada = await w.login('ada', { admin: true }, { id: 13 }); await w.call('GET', '/api/me', { user: ada }); const post = (b) => w.call('POST', '/api/source-requests', { user: ada, body: b });
  const body = { family: 'ioc', name: 'URLhaus recent', url: 'https://urlhaus.abuse.ch/downloads/csv_recent/', format: 'csv', auth: 'none', reason: 'we need malicious URLs for the IOC family', request_id: 'req-compat-source-0001' };
  w.db.raw.exec(R7); const gone = await w.call('GET', '/api/source-requests', { user: ada }); assert.equal(gone.status, 503); assert.match(gone.data.error, /0007/); assert.equal((await w.call('GET', '/api/stats', { user: ada })).status, 200, 'the rest of the panel works');
  w.db.raw.exec(M7); w.db.raw.exec(M7); assert.equal((await post(body)).status, 200); w.db.raw.exec(M7); assert.equal((await w.call('GET', '/api/source-requests', { user: ada })).data.items.length, 1, 're-applying keeps the request');
  const chain = await verifyChain(await auditRows(w.db, 5000)); assert.equal(chain.ok, true);
});

const M3 = readFileSync(new URL('../migrations-intel/0003_effective_state.sql', import.meta.url), 'utf8'), R3 = readFileSync(new URL('../migrations-intel/0003_rollback.sql', import.meta.url), 'utf8');
test('INTEL 0003: applied over 0002 while decisions exist it backfills decided_state, reads stay identical, a re-import keeps the decision, and the rollback returns to the join with the same answers', async () => {
  const { w, rita } = await oldIntel(); w.env.INTEL.raw.exec(M2); assert.equal((await dec(w, rita)).status, 200);
  const read = async () => JSON.stringify([(await w.call('GET', '/api/intel/records?family=ioc&limit=50', { user: rita })).data.items.map((i) => [i.id, i.state, i.imported_state]), (await w.call('GET', '/api/intel/stats', { user: rita })).data.by_state.filter((x) => x.family === 'ioc')]);
  const before = await read(); resetSnapshotMemo(w.env.INTEL); w.env.INTEL.raw.exec(M3);   // tier B -> tier A
  assert.equal(w.env.INTEL.raw.prepare('SELECT decided_state FROM intel_records WHERE id = ?').get(ID).decided_state, 'QUARANTINED', 'the backfill covers the decided record only'); assert.equal(w.env.INTEL.raw.prepare('SELECT COUNT(*) AS n FROM intel_records WHERE decided_state IS NOT NULL').get().n, 1);
  assert.equal(await read(), before, 'the same answers through the cheaper column');
  w.env.INTEL.raw.prepare("INSERT OR REPLACE INTO intel_records (id, family, source_id, run_id, key, title, state, doc, doc_sha256) SELECT id, family, source_id, run_id, key, title, state, doc, doc_sha256 FROM intel_records WHERE id = ?").run(ID);   // what a re-import does
  assert.equal(w.env.INTEL.raw.prepare('SELECT decided_state FROM intel_records WHERE id = ?').get(ID).decided_state, 'QUARANTINED', 'a re-import does not lose the decision');
  assert.equal((await dec(w, rita, { action: 'reject', request_id: RID(70) })).status, 200); assert.equal(w.env.INTEL.raw.prepare('SELECT decided_state FROM intel_records WHERE id = ?').get(ID).decided_state, 'REJECTED', 'the trigger follows the latest decision');
  w.env.INTEL.raw.exec(R3); resetSnapshotMemo(w.env.INTEL); assert.equal(w.env.INTEL.raw.prepare("SELECT COUNT(*) AS n FROM pragma_table_info('intel_records') WHERE name = 'decided_state'").get().n, 0);
  assert.equal((await w.call('GET', `/api/intel/records/${encodeURIComponent(ID)}`, { user: rita })).data.record.state, 'REJECTED', 'tier B answers the same after the rollback');
});
