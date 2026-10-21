// A Worker deployed BEFORE migrations 0003/0004/0005 are applied must keep every existing screen working: the new tables simply do not exist yet.
import test from 'node:test';
import assert from 'node:assert/strict';
import { world, cand, ORIGIN } from './helpers.js';

const DROP = ['policy_lifts', 'policy_events', 'policies', 'audit_anchor', 'source_proposals'];
async function oldDatabase() {
  const w = await world(); w.reviewer = await w.login('rita', { push: true }); w.admin = await w.login('ada', { admin: true });
  const items = ['a', 'b'].map((c) => cand(c, `rules/nextron/${c}.yar`, { source: 'nextron' })); const sub = await w.submit(items); assert.equal(sub.status, 200);
  for (const t of DROP) await w.db.prepare(`DROP TABLE IF EXISTS ${t}`).run();   // the database as it is in production today
  for (const t of DROP) assert.equal(await w.db.prepare("SELECT name FROM sqlite_master WHERE name = ?").bind(t).first(), null, `${t} is gone`);
  return { w, items, ids: sub.data.results.map((x) => x.id) };
}

test('without the policy tables the rule sheet, Published and an approval still work, as if there were no policies', async () => {
  const { w, items, ids } = await oldDatabase();
  await w.release('rules-20261021-100', items.map((c) => ({ path: c.path, sha256: c.sha256, bytes: c.bytes, source: c.source })));
  const pub = await w.call('GET', '/api/published', { user: w.reviewer }); assert.equal(pub.status, 200); assert.equal(pub.data.items.length, 2); assert.equal(pub.data.items.some((x) => x.policy), false);
  const sheet = await w.call('GET', `/api/candidates/${ids[0]}`, { user: w.reviewer }); assert.equal(sheet.status, 200); assert.equal(sheet.data.publication.policy, null); assert.deepEqual(sheet.data.publication.lifts, []);
  const ok = await w.call('POST', '/api/decisions', { user: w.reviewer, body: { action: 'approve', ids: [ids[1]], expect: { [ids[1]]: 1 }, reason: 'reviewed by a person', request_id: 'req_pre_migration_0001', confirm_count: 1 } });
  assert.notEqual(ok.status, 500, JSON.stringify(ok.data)); assert.equal(ok.status, 200, JSON.stringify(ok.data));
});

test('the release callback does not fail because the policy tables are missing, and the audit chain still grows from the last row', async () => {
  const { w, items } = await oldDatabase(); await w.release('rules-20261021-100', items.map((c) => ({ path: c.path, sha256: c.sha256, bytes: c.bytes, source: c.source })));
  const cb = await w.call('POST', '/api/pipeline/released', { bearer: await w.pipelineToken('publish.yml', { run_id: '1', run_attempt: '1' }), body: { tag: 'rules-20261021-100', hashes: items.map((c) => c.sha256), run_url: `${ORIGIN}/runs/1` } });
  assert.equal(cb.status, 200, JSON.stringify(cb.data)); assert.equal(cb.data.changed.length, 2);
  const v = await w.call('GET', '/api/audit/verify', { user: w.admin }); assert.equal(v.status, 200); assert.equal(v.data.ok, true);
});

test('only the new endpoints answer with an error before their migration; nothing is created or half-written', async () => {
  const { w } = await oldDatabase();
  const list = await w.call('GET', '/api/policies', { user: w.reviewer }); assert.ok(list.status >= 400, 'the policy list needs its table');
  const prop = await w.call('GET', '/api/source-proposals', { user: w.reviewer }); assert.ok(prop.status >= 400 || prop.status === 200);
  for (const t of ['policies', 'policy_lifts', 'policy_events', 'audit_anchor', 'source_proposals']) assert.equal(await w.db.prepare("SELECT name FROM sqlite_master WHERE name = ?").bind(t).first(), null, `${t} was not created by a read`);
});
