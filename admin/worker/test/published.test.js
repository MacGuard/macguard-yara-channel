// The "Published" inventory: derived from the signed manifest of the current release and reconciled with D1; the quarantine list never shows published rules.
import test from 'node:test';
import assert from 'node:assert/strict';
import { world, cand, sha, ORIGIN } from './helpers.js';
import { reconcilePublished, SYNTHETIC_SOURCE } from '../src/core.js';

const H = (c) => c.repeat(64).slice(0, 64);
const files = new Map([
  ['rules/community/a.yar', { sha256: H('a'), bytes: 10, source: 'community' }],
  ['rules/community/b.yar', { sha256: H('b'), bytes: 20, source: 'community' }],
  ['rules/nextron/c.yar', { sha256: H('c'), bytes: 30, source: 'nextron' }],
  ['rules/nextron/d.yar', { sha256: H('d'), bytes: 40, source: 'nextron' }],
]);
const rows = [
  { id: 'id-a', path: 'rules/community/a.yar', sha256: H('a'), state: 'RELEASED', release_tag: 'rules-20261021-1' },   // published and recorded
  { id: 'id-b2', path: 'rules/community/b.yar', sha256: H('9'), state: 'PENDING', release_tag: null },                    // a newer version of a published file waits in quarantine
  { id: 'id-c2', path: 'rules/nextron/c.yar', sha256: H('8'), state: 'REJECTED', release_tag: null },                      // a rejected newer version does not change what is published
  { id: 'id-x', path: 'rules/nextron/not-in-release.yar', sha256: H('7'), state: 'PENDING', release_tag: null },          // quarantined, not published: not part of the inventory
];

test('the inventory comes from the signed manifest: every file is listed, with or without a record in D1', () => {
  const r = reconcilePublished(files, rows);
  assert.equal(r.total, 4); assert.deepEqual(r.items.map((x) => x.path), [...files.keys()]);
  const by = Object.fromEntries(r.items.map((x) => [x.path, x]));
  assert.deepEqual([by['rules/community/a.yar'].status, by['rules/community/a.yar'].candidate_id, by['rules/community/a.yar'].release_tag], ['published', 'id-a', 'rules-20261021-1']);
  assert.deepEqual([by['rules/community/b.yar'].status, by['rules/community/b.yar'].candidate_id], ['newer_in_review', null], 'the published version has no record; a newer one is in review');
  assert.equal(by['rules/nextron/c.yar'].status, 'published', 'a rejected newer version does not make the published one "in review"');
  assert.equal(by['rules/nextron/d.yar'].candidate_id, null); assert.equal(r.items.some((x) => x.path.includes('not-in-release')), false);
  assert.deepEqual(r.counts, { total: 4, published: 3, newer_in_review: 1, without_record: 3 }); assert.deepEqual(r.sources, { community: 2, nextron: 2 });
});

test('search, source, status and pagination are applied to the whole catalogue and the counters stay those of the whole catalogue', () => {
  assert.deepEqual(reconcilePublished(files, rows, { q: 'C.YAR' }).items.map((x) => x.path), ['rules/nextron/c.yar']);
  assert.deepEqual(reconcilePublished(files, rows, { q: H('d').slice(0, 8) }).items.map((x) => x.path), ['rules/nextron/d.yar'], 'by SHA-256 prefix');
  assert.equal(reconcilePublished(files, rows, { source: 'nextron' }).total, 2);
  assert.deepEqual(reconcilePublished(files, rows, { status: 'newer_in_review' }).items.map((x) => x.path), ['rules/community/b.yar']);
  assert.equal(reconcilePublished(files, rows, { q: '%' }).total, 0, 'a wildcard matches nothing, not everything');
  const under = new Map([['rules/x/pack_005.yar', { sha256: H('e'), bytes: 1, source: 'x' }], ['rules/x/pack005.yar', { sha256: H('f'), bytes: 1, source: 'x' }]]);
  assert.deepEqual(reconcilePublished(under, [], { q: 'pack_005' }).items.map((x) => x.path), ['rules/x/pack_005.yar'], 'an underscore is searched literally');
  const p2 = reconcilePublished(files, rows, { page: 2, pageSize: 3 }); assert.deepEqual([p2.total, p2.items.length, p2.page, p2.page_size], [4, 1, 2, 3]);
  assert.equal(reconcilePublished(files, rows, { status: 'published', q: 'zzz' }).counts.total, 4);
  assert.equal(reconcilePublished(files, rows, { pageSize: 5000 }).page_size, 100);
});

async function published() {
  const w = await world(); w.reviewer = await w.login('rita', { push: true });
  const items = ['a', 'b'].map((c) => cand(c, `rules/nextron/${c}.yar`, { source: 'nextron' }));
  const sub = await w.submit(items); assert.equal(sub.status, 200);
  return { w, items, ids: sub.data.results.map((x) => x.id) };
}
const entries = (items) => [...items.map((c) => ({ path: c.path, sha256: c.sha256, bytes: c.bytes, source: c.source })), { path: 'rules/community/old.yar', sha256: sha('old'), bytes: 33, source: 'community' }];

test('GET /api/published lists the current signed release, reconciled with D1; a file published before the panel has no record', async () => {
  const { w, items, ids } = await published();
  await w.release('rules-20261021-100', entries(items));
  const cb = await w.call('POST', '/api/pipeline/released', { bearer: await w.pipelineToken('publish.yml', { run_id: '1', run_attempt: '1' }), body: { tag: 'rules-20261021-100', hashes: items.map((c) => c.sha256), run_url: `${ORIGIN}/runs/1` } });
  assert.equal(cb.status, 200);
  const r = await w.call('GET', '/api/published', { user: w.reviewer });
  assert.equal(r.status, 200); assert.equal(r.data.release.tag, 'rules-20261021-100'); assert.equal(r.data.release.files, 3); assert.match(r.data.release.rules_root, /^[0-9a-f]{64}$/);
  const by = Object.fromEntries(r.data.items.map((x) => [x.path, x]));
  assert.deepEqual([by['rules/nextron/a.yar'].status, by['rules/nextron/a.yar'].candidate_id, by['rules/nextron/a.yar'].release_tag, by['rules/nextron/a.yar'].source], ['published', ids[0], 'rules-20261021-100', 'nextron']);
  assert.equal(by['rules/community/old.yar'].candidate_id, null); assert.equal(by['rules/community/old.yar'].source, 'community');
  assert.deepEqual(r.data.counts, { total: 3, published: 3, newer_in_review: 0, without_record: 1 });
  const q = await w.call('GET', '/api/published?q=old&source=community&pageSize=1', { user: w.reviewer }); assert.deepEqual([q.data.total, q.data.items.length], [1, 1]);
});

test('the published inventory needs a signed-in person, is read-only, and does not invent a release when GitHub has none', async () => {
  const { w } = await published();
  assert.equal((await w.call('GET', '/api/published')).status, 401);
  assert.equal((await w.call('POST', '/api/published', { user: w.reviewer, body: {} })).status, 404, 'the inventory cannot be written to');
  assert.equal((await w.call('GET', '/api/published', { user: await w.login('nobody', 'denied') })).status, 403, 'a person without access to the repository gets nothing');
  const none = await w.call('GET', '/api/published', { user: w.reviewer }); assert.notEqual(none.status, 200, 'with no public release the answer is an error, not an empty or made-up list');
  assert.match(String(none.data.error), /could not be read/);
  await w.release('rules-20261021-100', [], { draft: true }); const draft = await w.call('GET', '/api/published', { user: w.reviewer }); assert.notEqual(draft.status, 200, 'a draft is not a public release');
});

test('a manifest whose rules_root does not match its files is never shown as the inventory', async () => {
  const { w, items } = await published(); await w.release('rules-20261021-100', entries(items), { tamperRoot: true });
  const r = await w.call('GET', '/api/published', { user: w.reviewer }); assert.equal(r.status, 422); assert.equal(r.data.items, undefined);
});

test('the quarantine list does not include published rules; they are reachable only by asking for the RELEASED state', async () => {
  const { w, items, ids } = await published(); await w.release('rules-20261021-100', [items[0]].map((c) => ({ path: c.path, sha256: c.sha256, bytes: c.bytes })));
  await w.call('POST', '/api/pipeline/released', { bearer: await w.pipelineToken('publish.yml', { run_id: '1', run_attempt: '1' }), body: { tag: 'rules-20261021-100', hashes: [items[0].sha256], run_url: `${ORIGIN}/runs/1` } });
  const list = (await w.call('GET', '/api/candidates', { user: w.reviewer })).data; assert.deepEqual(list.items.map((c) => c.id), [ids[1]]); assert.equal(list.total, 1);
  assert.deepEqual((await w.call('GET', '/api/candidates?state=RELEASED', { user: w.reviewer })).data.items.map((c) => c.id), [ids[0]]);
  const stats = (await w.call('GET', '/api/stats', { user: w.reviewer })).data; assert.equal(stats.sources.nextron, 1, 'the source counters of the quarantine do not count published rules');
});

test('synthetic candidates of the chain test are kept apart: out of the list, the counters and the public figures unless asked for', async () => {
  const w = await world(); w.reviewer = await w.login('rita', { push: true });
  const real = cand('r', 'rules/nextron/r.yar', { source: 'nextron' }), syn = cand('s', 'synthetic-quarantine-test/s1.yar', { source: SYNTHETIC_SOURCE, reasons: ['synthetic-test'] });
  assert.equal((await w.submit([real, syn])).status, 200);
  const ids = (list) => list.data.items.map((c) => c.path);
  assert.deepEqual(ids(await w.call('GET', '/api/candidates', { user: w.reviewer })), ['rules/nextron/r.yar']);
  assert.deepEqual(ids(await w.call('GET', '/api/candidates?synthetic=1', { user: w.reviewer })).sort(), ['rules/nextron/r.yar', 'synthetic-quarantine-test/s1.yar']);
  assert.deepEqual(ids(await w.call('GET', `/api/candidates?source=${SYNTHETIC_SOURCE}`, { user: w.reviewer })), ['synthetic-quarantine-test/s1.yar'], 'asking for the synthetic source shows it');
  const stats = (await w.call('GET', '/api/stats', { user: w.reviewer })).data; assert.equal(stats.synthetic, 1); assert.equal(stats.counts.PENDING, 1); assert.equal(stats.sources[SYNTHETIC_SOURCE], undefined);
  const pub = (await w.call('GET', '/public/stats')).data; assert.equal(pub.pending_review, 1, 'a test candidate is not a rule waiting for review');
});
