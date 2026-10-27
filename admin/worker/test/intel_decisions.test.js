// Decisions about records of every family but YARA: roles, a closed vocabulary, reasons, idempotency, all-or-nothing batches, stale views, approvals that say why they are blocked,
// an append-only history, the effective state in lists and counts, and one audit entry per request in the hash chain.
import test from 'node:test';
import assert from 'node:assert/strict';
import { world } from './helpers.js';
import { newIntelDb, seedIntel } from './intel_fixture.js';
import { verifyChain } from '../src/core.js';
import { auditRows } from '../src/store.js';

const RID = (n) => `req-intel-decision-${String(n).padStart(4, '0')}`;
async function setup() {
  const w = await world(); w.env.INTEL = newIntelDb(); await seedIntel(w.env.INTEL, { kev: 5 });
  const ada = await w.login('ada', { admin: true }, { id: 13 }), rita = await w.login('rita', { push: true }, { id: 12 }), vera = await w.login('vera', { pull: true }, { id: 11 });
  for (const u of [ada, rita, vera]) await w.call('GET', '/api/me', { user: u }); await w.grant(ada, 'vera', 'VIEWER');
  const post = (user, body) => w.call('POST', '/api/intel/decisions', { user, body }), rec = async (user, id) => (await w.call('GET', `/api/intel/records/${encodeURIComponent(id)}`, { user })).data;
  return { w, ada, rita, vera, post, rec };
}
const body = (over = {}) => ({ action: 'quarantine', ids: ['ioc:ip:203.0.113.7'], reason: 'seen in a customer incident', request_id: RID(1), ...over });

test('only REVIEWER and above decide; the vocabulary, the ids, the reason and the request id are validated', async () => {
  const { post, vera, rita } = await setup();
  assert.equal((await post(vera, body())).status, 403); assert.equal((await post(undefined, body())).status, 401);
  for (const bad of [body({ action: 'publish' }), body({ ids: [] }), body({ ids: ['a b'] }), body({ ids: ['ioc:ip:203.0.113.7', 'ioc:ip:203.0.113.7'] }), body({ reason: '  ab ' }), body({ request_id: 'short' }), body({ ids: Array.from({ length: 51 }, (_, i) => `x:${i}`) }), null])
    assert.equal((await post(rita, bad)).status, 400, JSON.stringify(bad)?.slice(0, 80));
  assert.equal((await post(rita, body({ ids: ['ioc:ip:9.9.9.9'] }))).status, 404); assert.equal((await post(rita, body({ ids: ['yara:something'] }))).status, 404);
});
test('quarantine, reject and hold change the effective state everywhere (record, list filter, counts) while the imported state stays visible; the history is append-only', async () => {
  const { w, rita, post, rec } = await setup(); const id = 'ioc:ip:203.0.113.7';
  const r1 = await post(rita, body()); assert.equal(r1.status, 200, JSON.stringify(r1.data)); assert.equal(r1.data.changed, 1);
  const d = await rec(rita, id); assert.equal(d.record.state, 'QUARANTINED'); assert.equal(d.record.imported_state, 'EXPIRED'); assert.equal(d.history.length, 1); assert.equal(d.history[0].audited, true);
  const list = (await w.call('GET', '/api/intel/records?family=ioc&state=QUARANTINED', { user: rita })).data; assert.equal(list.total, 1); assert.equal(list.items[0].state, 'QUARANTINED');
  assert.equal((await w.call('GET', '/api/intel/records?family=ioc&state=EXPIRED', { user: rita })).data.total, 1, 'the other IOC keeps its imported state');
  const st = (await w.call('GET', '/api/intel/stats', { user: rita })).data.by_state.filter((x) => x.family === 'ioc'); assert.deepEqual(st.map((x) => `${x.state}:${x.n}`).sort(), ['EXPIRED:1', 'QUARANTINED:1']);
  assert.equal((await post(rita, body({ action: 'reject', request_id: RID(2), reason: 'confirmed benign infrastructure' }))).status, 200); assert.equal((await rec(rita, id)).record.state, 'REJECTED');
  assert.equal((await post(rita, body({ action: 'hold', request_id: RID(3), reason: 'reopened for review' }))).status, 200); const h = await rec(rita, id); assert.equal(h.record.state, 'RETENIDA'); assert.deepEqual(h.history.map((x) => x.to_state), ['RETENIDA', 'REJECTED', 'QUARANTINED']);
  await assert.rejects(() => w.env.INTEL.prepare('DELETE FROM intel_decisions').run(), /append-only/); await assert.rejects(() => w.env.INTEL.prepare("UPDATE intel_decisions SET reason = 'edited reason'").run(), /append-only/);
});
test('a request id makes the decision idempotent; reusing it for something else is refused; an unchanged record is not duplicated', async () => {
  const { rita, post, rec } = await setup(); const id = 'ioc:ip:203.0.113.7';
  assert.equal((await post(rita, body())).data.changed, 1); const again = await post(rita, body()); assert.equal(again.status, 200); assert.equal(again.data.replay, true); assert.equal((await rec(rita, id)).history.length, 1);
  assert.equal((await post(rita, body({ ids: ['ioc:ip:203.0.113.8'] }))).status, 409, 'same request id, different records');
  const same = await post(rita, body({ request_id: RID(9) })); assert.equal(same.status, 200); assert.equal(same.data.changed, 0); assert.equal(same.data.unchanged, 1); assert.equal((await rec(rita, id)).history.length, 1);
});
test('a batch is all-or-nothing, and a stale view changes nothing', async () => {
  const { rita, post, rec } = await setup(); const ids = ['ioc:ip:203.0.113.7', 'ioc:ip:203.0.113.8'];
  const stale = await post(rita, body({ ids, expect: { 'ioc:ip:203.0.113.7': 'EXPIRED', 'ioc:ip:203.0.113.8': 'RETENIDA' } })); assert.equal(stale.status, 409); assert.deepEqual(stale.data.stale, [{ id: 'ioc:ip:203.0.113.8', state: 'EXPIRED' }]);
  for (const id of ids) assert.equal((await rec(rita, id)).record.state, 'EXPIRED', 'nothing was changed');
  const ok = await post(rita, body({ ids, request_id: RID(4), expect: { [ids[0]]: 'EXPIRED', [ids[1]]: 'EXPIRED' } })); assert.equal(ok.data.changed, 2);
});
test('approval for publication says why it is blocked and changes nothing; once the evidence allows it, it works and the record is only "approved for the next release"', async () => {
  const { w, rita, post, rec } = await setup(); const sid = 'sigma:u-0';
  const blocked = await post(rita, body({ action: 'approve', ids: [sid], request_id: RID(5), reason: 'quality reviewed by hand' })); assert.equal(blocked.status, 409); assert.equal(blocked.data.blocked[0].id, sid);
  assert.ok(blocked.data.blocked[0].reasons.some((x) => x.code === 'held_back'), JSON.stringify(blocked.data.blocked[0].reasons)); assert.equal((await rec(rita, sid)).approvable.ok, false); assert.equal((await rec(rita, sid)).record.state, 'approved');
  await w.env.INTEL.prepare("UPDATE intel_records SET held_back = 0 WHERE id = ?").bind(sid).run(); await w.env.INTEL.prepare("UPDATE intel_runs SET publishable = 1, blocking = '[]' WHERE id = 'run-sigma'").run();
  assert.equal((await rec(rita, sid)).approvable.ok, true); const ok = await post(rita, body({ action: 'approve', ids: [sid], request_id: RID(6), reason: 'quality reviewed by hand' })); assert.equal(ok.status, 200, JSON.stringify(ok.data)); assert.equal((await rec(rita, sid)).record.state, 'APPROVED');
});
test('every request is one audit entry in the hash chain with the actor, the reason and the ids; the unaudited flag is set only after it', async () => {
  const { w, rita, post } = await setup(); await post(rita, body({ ids: ['ioc:ip:203.0.113.7', 'ioc:ip:203.0.113.8'] }));
  const rows = (await auditRows(w.db, 500)).filter((e) => e.action === 'intel.decision'); assert.equal(rows.length, 1); const d = JSON.parse(rows[0].detail);
  assert.equal(d.count, 2); assert.equal(d.decision, 'quarantine'); assert.equal(d.reason, 'seen in a customer incident'); assert.equal(d.actor_id, 12); assert.deepEqual(d.families, { ioc: 2 }); assert.equal(rows[0].actor, 'rita');
  assert.equal((await verifyChain(await auditRows(w.db, 5000))).ok, true); assert.equal(w.env.INTEL.raw.prepare('SELECT COUNT(*) AS n FROM intel_decisions WHERE audited = 0').get().n, 0);
  assert.equal((await w.call('POST', '/api/intel/decisions', { user: rita, body: body({ request_id: RID(7) }), csrf: false })).status, 403, 'CSRF is enforced');
});

test('the quarantine and published scopes follow the effective state, so a decision moves a record between the pages', async () => {
  const { w, rita, post } = await setup(); const count = async (q) => (await w.call('GET', `/api/intel/records?${q}`, { user: rita })).data;
  const q0 = (await count('scope=quarantine')).total, all = (await count('limit=1')).total; assert.equal(q0, all, 'nothing is published yet: everything is in quarantine'); assert.equal((await count('scope=published')).total, 0);
  const id = 'sigma:u-0'; await w.env.INTEL.prepare("UPDATE intel_records SET held_back = 0 WHERE id = ?").bind(id).run(); await w.env.INTEL.prepare("UPDATE intel_runs SET publishable = 1, blocking = '[]' WHERE id = 'run-sigma'").run();
  assert.equal((await post(rita, body({ action: 'approve', ids: [id], request_id: RID(20), reason: 'quality reviewed by hand' }))).status, 200);
  assert.equal((await count('scope=published')).total, 1); assert.equal((await count('scope=quarantine')).total, q0 - 1); assert.equal((await count('scope=published&family=sigma')).items[0].id, id);
  assert.equal((await post(rita, body({ action: 'quarantine', ids: [id], request_id: RID(21), reason: 'withdrawn before release' }))).status, 200); assert.equal((await count('scope=published')).total, 0);
  assert.equal((await w.call('GET', '/api/intel/records?scope=weird', { user: rita })).status, 400);
});

test('five roles: only REVIEWER and ADMIN decide; PUBLISHER and SECURITY_ADMIN are refused and the refusal is audited; unknown actions get no permission', async () => {
  const { w, ada, rita, post } = await setup(); const ids = ['ioc:ip:203.0.113.7'];
  for (const [login, role, id] of [['pat', 'PUBLISHER', 21], ['sam', 'SECURITY_ADMIN', 22]]) { w.account(login, id); assert.equal((await w.grant(ada, login, role)).status, 200); const u = await w.login(login, { pull: true }, { id }); await w.call('GET', '/api/me', { user: u });
    for (const action of ['quarantine', 'approve']) { const r = await post(u, body({ action, ids, request_id: RID(30 + id + action.length) })); assert.equal(r.status, 403, `${role} ${action}`); assert.equal(r.data.code, 'forbidden'); } }
  assert.ok(w.db.raw.prepare("SELECT COUNT(*) AS n FROM audit WHERE action = 'authz.denied' AND target = '/api/intel/decisions'").get().n >= 4, 'the refusals are in the audit chain');
  assert.equal((await post(rita, body({ action: 'publish' }))).status, 400, 'an unknown action has no permission and is refused'); assert.equal((await post(ada, body({ request_id: RID(40) }))).status, 200); assert.equal(w.env.INTEL.raw.prepare('SELECT COUNT(*) AS n FROM intel_decisions').get().n, 1, 'the refused ones changed nothing');
});

test('future packages read only what a person approved: publish.yml only, eligible records with their decision, blocked ones with the reason, withdrawn ones listed; nothing is published', async () => {
  const { w, rita, post } = await setup(); const id = 'sigma:u-0', get = async (wf, q = '') => w.call('GET', `/api/pipeline/intel-approvals${q}`, { bearer: await w.pipelineToken(wf) });
  assert.equal((await get('daily.yml')).status, 403); assert.equal((await w.call('GET', '/api/pipeline/intel-approvals')).status, 401); assert.equal((await get('publish.yml', '?family=weapon')).status, 400);
  assert.deepEqual((await get('publish.yml')).data.eligible, [], 'nothing is approved yet');
  await w.env.INTEL.prepare('UPDATE intel_records SET held_back = 0 WHERE id = ?').bind(id).run(); await w.env.INTEL.prepare("UPDATE intel_runs SET publishable = 1, blocking = '[]' WHERE id = 'run-sigma'").run();
  assert.equal((await post(rita, body({ action: 'approve', ids: [id], request_id: RID(60), reason: 'quality reviewed by hand' }))).status, 200);
  const s1 = (await get('publish.yml')).data; assert.equal(s1.eligible.length, 1); assert.equal(s1.eligible[0].id, id); assert.equal(s1.eligible[0].decision.by_id, 12); assert.match(s1.eligible[0].doc_sha256, /^[0-9a-f]{64}$/); assert.deepEqual(s1.packages, [{ family: 'sigma', source_id: 'sigmahq', records: 1 }]); assert.equal(s1.note.includes('nothing here is published'), true);
  await w.env.INTEL.prepare('UPDATE intel_records SET held_back = 1 WHERE id = ?').bind(id).run(); const s2 = (await get('publish.yml')).data; assert.deepEqual(s2.eligible, [], 'the evidence is re-checked at read time'); assert.equal(s2.blocked[0].reasons[0].code, 'held_back');
  await w.env.INTEL.prepare('UPDATE intel_records SET held_back = 0 WHERE id = ?').bind(id).run(); await w.env.INTEL.raw.exec('DROP TRIGGER intel_decisions_audit_only'); w.env.INTEL.raw.prepare('UPDATE intel_decisions SET audited = 0').run(); assert.equal((await get('publish.yml')).data.blocked[0].reasons[0].code, 'unaudited_decision', 'an unaudited decision never qualifies');
  w.env.INTEL.raw.prepare('UPDATE intel_decisions SET audited = 1').run(); assert.equal((await post(rita, body({ action: 'quarantine', ids: [id], request_id: RID(61), reason: 'withdrawn before release' }))).status, 200);
  const s3 = (await get('publish.yml')).data; assert.deepEqual(s3.eligible, []); assert.deepEqual(s3.withdrawn_after_approval.map((x) => x.id), [id], 'a package that held it must be revoked');
});
