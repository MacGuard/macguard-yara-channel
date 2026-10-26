// Row-read budget of the intelligence reads. D1 bills every row a query scans; on 2026-10-26 the free daily quota (5,000,000 rows read) was exhausted because every screen scanned the whole
// records table several times. These tests keep that from coming back: after one snapshot pass, no request may scan the records table, every read must be bounded by an index and a LIMIT,
// and a broad title search must be refused instead of scanning. They run on local SQLite (query plans), never on the productive account.
import test from 'node:test';
import assert from 'node:assert/strict';
import { world } from './helpers.js';
import { newIntelDb, seedIntel } from './intel_fixture.js';
import { SEARCH_SCAN_MAX, resetSnapshotMemo } from '../src/intel_data.js';

const FULL_PASS = /FROM intel_records GROUP BY family, source_id, state/;
function spy(db) {   // records every statement the Worker prepares
  const seen = []; const real = db.prepare.bind(db); db.prepare = (sql) => { seen.push(sql); return real(sql); }; return seen;
}
const plans = (db, sqls) => sqls.filter((s) => /^\s*SELECT/i.test(s) && /intel_records/.test(s)).map((s) => ({ sql: s, plan: db.raw.prepare(`EXPLAIN QUERY PLAN ${s.replace(/\?/g, 'NULL')}`).all().map((r) => r.detail).join(' | ') }));
const scansTable = ({ plan }) => /SCAN intel_records(?! USING)/.test(plan) || /SCAN r(?! USING)/.test(plan) || /USE TEMP B-TREE FOR ORDER BY/.test(plan);
async function setup() {
  const w = await world(); w.env.INTEL = newIntelDb(); await seedIntel(w.env.INTEL, { kev: 400 }); resetSnapshotMemo(w.env.INTEL);
  const rita = await w.login('rita', { push: true }, { id: 12 }); await w.call('GET', '/api/me', { user: rita }); return { w, rita, get: (p) => w.call('GET', p, { user: rita }) };
}

test('after the snapshot, repeated Intelligence screens do not scan the records table at all', async () => {
  const { w, get } = await setup(); const seen = spy(w.env.INTEL);
  for (let i = 0; i < 25; i++) { await get('/api/intel/stats'); await get('/api/intel/sources'); await get('/api/intel/records?family=kev&limit=50'); await get('/api/intel/records?family=suricata,sigma&scope=quarantine&limit=50'); }
  assert.equal(seen.filter((s) => FULL_PASS.test(s)).length, 1, 'ONE pass over the records for 100 requests');
  const bad = plans(w.env.INTEL, seen).filter((p) => !FULL_PASS.test(p.sql)).filter(scansTable); assert.deepEqual(bad.map((b) => b.plan), [], 'no other query scans the table or sorts it');
});
test('every record read is bounded by an index or the primary key and a LIMIT: list, filters, scope, state, identifier search, detail', async () => {
  const { w, get } = await setup(); await get('/api/intel/stats'); const seen = spy(w.env.INTEL);
  for (const q of ['family=kev', 'family=kev&state=RETENIDA', 'family=sigma&state=approved', 'scope=published&family=sigma', 'scope=quarantine', 'family=kev&source=cisa-kev', 'q=CVE-2024-1007', 'family=sigma&q=Sigma%20rule', 'family=kev&held_back=0']) await get(`/api/intel/records?${q}&limit=50`);
  await get(`/api/intel/records/${encodeURIComponent('kev:CVE-2024-1000')}`);
  const records = plans(w.env.INTEL, seen); assert.ok(records.length >= 9); assert.deepEqual(records.filter(scansTable).map((p) => p.plan), [], 'no full scan and no full sort');
  assert.ok(seen.every((s) => !/COUNT\(\*\)[^;]*FROM (intel_records|\(SELECT)/.test(s)), 'no COUNT over the records');
});
test('a broad title search is refused with the reason instead of scanning; an identifier search and a narrowed title search work; totals never need a scan', async () => {
  const { w, get } = await setup(); await get('/api/intel/stats');
  w.env.INTEL.raw.prepare("UPDATE intel_snapshot SET json = ?").run(JSON.stringify({ schema: 1, marker: 'x', cells: [{ family: 'suricata', source_id: 'emerging-threats-open', state: 'RETENIDA', held_back: 1, validated: null, functional: null, performance: null, n: SEARCH_SCAN_MAX + 1000, newest: null }] }));   // pretend the table is big
  const marker = (await get('/api/intel/stats')).data.snapshot_marker; w.env.INTEL.raw.prepare('UPDATE intel_snapshot SET marker = ?').run(marker); resetSnapshotMemo(w.env.INTEL);
  const broad = await get('/api/intel/records?family=suricata&q=trojan%20activity'); assert.equal(broad.status, 400); assert.equal(broad.data.code, 'search_too_broad'); assert.ok(broad.data.candidates > SEARCH_SCAN_MAX);
  const ok = await get('/api/intel/records?family=suricata&q=2000105'); assert.equal(ok.status, 200, 'an identifier is looked up through the key index');
  resetSnapshotMemo(w.env.INTEL); w.env.INTEL.raw.exec('DELETE FROM intel_snapshot'); const small = await get('/api/intel/records?family=sigma&q=Sigma%20rule'); assert.equal(small.status, 200); assert.ok(small.data.items.length >= 1);
});
test('the snapshot is rebuilt only when a promotion changes the data, and a decision never triggers a rebuild', async () => {
  const { w, get } = await setup(); const seen = spy(w.env.INTEL); await get('/api/intel/stats');
  assert.equal(seen.filter((s) => FULL_PASS.test(s)).length, 1);
  const post = (b) => w.call('POST', '/api/intel/decisions', { user: undefined, body: b });   // decisions go through the API in intel_decisions.test.js; here the effect on counts is checked directly
  w.env.INTEL.raw.prepare("INSERT INTO intel_decisions (record_id, family, action, from_state, to_state, reason, actor, actor_id, at, request_id, audited) VALUES ('ioc:ip:203.0.113.7','ioc','quarantine','EXPIRED','QUARANTINED','budget test decision','rita',12,'2026-10-26T10:00:00Z','req-budget-0000000001',1)").run(); void post;
  const st = (await get('/api/intel/stats')).data; assert.equal(st.by_state.find((x) => x.family === 'ioc' && x.state === 'QUARANTINED').n, 1, 'the decision is counted at once'); assert.equal(seen.filter((s) => FULL_PASS.test(s)).length, 1, 'without a new pass');
  w.env.INTEL.raw.prepare("INSERT INTO intel_runs (id, source_id, retrieved_at, state, promoted_at, promoted_by, promotion_sha256) VALUES ('run-new','nvd','2026-10-26T12:00:00Z','COMPLETE','2026-10-26T12:30:00Z','ada','" + 'a'.repeat(64) + "')").run(); resetSnapshotMemo(w.env.INTEL);
  await get('/api/intel/stats'); assert.equal(seen.filter((s) => FULL_PASS.test(s)).length, 2, 'a promotion changes the marker: exactly one new pass');
});

test('when the D1 quota is used up the panel answers 503 with the reset time and changes nothing, instead of a bare 500', async () => {
  const { w, rita } = await setup(); const real = w.db.prepare.bind(w.db); w.db.prepare = (sql) => { if (/FROM candidates/.test(sql)) throw new Error("D1_ERROR: Your account has exceeded D1's free tier daily row read limit. [code: 7500]"); return real(sql); };
  const r = await w.call('GET', '/api/candidates', { user: rita }); assert.equal(r.status, 503); assert.equal(r.data.code, 'd1_quota_exhausted'); assert.match(r.data.resets_at, /T00:00:00\.000Z$/); assert.ok(Number(r.headers.get('Retry-After')) >= 60);
});
