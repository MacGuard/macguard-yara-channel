import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/index.js';
import { apiWorld } from './apiworld.js';
import { downloadSummary } from '../src/gh_collector.js';

// The ten asset names of a real release (as listed by the GitHub API), each with its own counter, so the test proves bundle, manifest, signatures, checkpoint and proofs are never mixed.
const REAL = [['rules-release.tar.gz', 'application/gzip'], ['manifest.json', 'application/json'], ['manifest.sigstore.json', 'application/json'], ['checkpoint.txt', 'text/plain'], ['checkpoint.sigstore.json', 'application/json'],
  ['inclusion-proof.json', 'application/json'], ['consistency.json', 'application/json'], ['release.json', 'application/json'], ['changes.json', 'application/json'], ['CHANGELOG.md', 'text/markdown']];
const rel = (n, extra = 0) => [{ id: 1, tag_name: 'rules-20261021-1', draft: false, prerelease: false, published_at: '2026-10-21T03:57:41Z', created_at: '2026-10-21T03:57:41Z',
  assets: REAL.map(([name, ct], i) => ({ id: 10 + i, name, size: 100, content_type: ct, download_count: i === 0 ? n : i === 1 || i === 2 ? 700 + i * 100 + extra : 200 + i * 10 })) }];
const json = (o, h = {}) => new Response(JSON.stringify(o), { status: 200, headers: { 'content-type': 'application/json', ...h } });
async function fire(w, at, fetchImpl) {                                              // run the real scheduled() handler the way Cloudflare does, with the cron's scheduledTime
  const real = globalThis.fetch, waits = []; globalThis.fetch = fetchImpl;
  try { await worker.scheduled({ scheduledTime: Date.parse(at), cron: '17 * * * *' }, w.env, { waitUntil: (p) => waits.push(p) }); await Promise.all(waits); } finally { globalThis.fetch = real; }
}
const SECRET = { KEY_PEPPER: 'k'.repeat(40), ANALYTICS_PEPPER: 'a'.repeat(40) };

test('cron run 1 records a baseline; run 2 records the variation; timestamps, counters and persistence are exact', async () => {
  const w = await apiWorld({ envExtra: SECRET }); let n = 100;
  w.clock.set('2026-10-23T20:17:00Z'); await fire(w, '2026-10-23T20:17:00Z', async () => json(rel(n)));
  let s = await w.env.DB.prepare('SELECT * FROM gh_sync WHERE id = 1').first(); assert.equal(s.last_status, 'ok'); assert.equal(s.consecutive_failures, 0); assert.equal(s.last_success_at.slice(0, 10), new Date().toISOString().slice(0, 10), 'stamped with the real clock at execution');
  assert.equal((await w.env.DB.prepare("SELECT COUNT(*) n FROM gh_observations WHERE kind='baseline'").first()).n, 10);
  n = 125; await fire(w, '2026-10-23T21:17:00Z', async () => json(rel(n, 10)));
  const d = (await w.env.DB.prepare("SELECT a.name, o.download_count - o.prev_count AS delta FROM gh_observations o JOIN gh_assets a ON a.asset_id = o.asset_id WHERE o.kind = 'delta' ORDER BY a.name").all()).results.map((r) => ({ ...r }));
  assert.deepEqual(d, [{ name: 'manifest.json', delta: 10 }, { name: 'manifest.sigstore.json', delta: 10 }, { name: 'rules-release.tar.gz', delta: 25 }], 'only assets that changed have a delta, each with its own value');
  const sum = await downloadSummary(w.env.DB, () => new Date(), { windowDays: 30 }); assert.equal(sum.totals.bundle_downloads_observed, 25, 'the bundle variation excludes manifest and signature growth'); assert.equal(sum.totals.bundle_downloads_cumulative, 125);
  assert.equal(sum.by_asset_kind.manifest.downloads_cumulative, 810); assert.equal(sum.by_asset_kind.signature.downloads_cumulative, 910 + 240, 'manifest and checkpoint signatures together'); assert.equal(sum.by_asset_kind.checkpoint.downloads_cumulative, 230);
  assert.equal(sum.by_asset_kind.proof.downloads_cumulative, 250 + 260); assert.equal(sum.by_asset_kind.bundle.downloads_cumulative, 125); assert.equal(sum.by_asset_kind.changelog.downloads_cumulative, 290);
  const { dashboard } = await import('../src/dashboards.js'); const dash = await dashboard(w.env.DB, () => new Date(), 'downloads'); const kinds = dash.panels.find((p) => p.id === 'kinds'), rels = dash.panels.find((p) => p.id === 'releases');
  assert.deepEqual(Object.keys(kinds.data).sort(), ['bundle', 'changelog', 'checkpoint', 'manifest', 'metadata', 'proof', 'signature'], 'one line per kind'); assert.equal(rels.data[0].bundle_downloads_cumulative, 125, 'the bundle figure is the bundle alone'); assert.equal(rels.data[0].bundle_downloads_observed, 25);
  assert.equal((await w.env.DB.prepare('SELECT COUNT(*) n FROM gh_sync_log').first()).n >= 1, true);
});
test('a failing GitHub does not throw out of the cron, is recorded, and a later success resets the failure count', async () => {
  const w = await apiWorld({ envExtra: SECRET });
  await fire(w, '2026-10-23T20:17:00Z', async () => json(rel(1)));
  await fire(w, '2026-10-23T21:17:00Z', async () => { throw new Error('network down'); }); await fire(w, '2026-10-23T22:17:00Z', async () => new Response('x', { status: 500 }));
  let s = await w.env.DB.prepare('SELECT * FROM gh_sync WHERE id = 1').first(); assert.equal(s.consecutive_failures, 2); assert.notEqual(s.last_status, 'ok'); assert.ok(s.last_error);
  assert.ok(!s.last_error.includes('network down') || s.last_error.length < 300, 'bounded error text');
  await fire(w, '2026-10-23T23:17:00Z', async () => json(rel(2))); s = await w.env.DB.prepare('SELECT * FROM gh_sync WHERE id = 1').first(); assert.equal(s.consecutive_failures, 0); assert.equal(s.last_status, 'ok');
});
test('the retention step runs only in the 03:xx cron and never deletes anything else', async () => {
  const w = await apiWorld({ envExtra: SECRET }); await w.tenant('t1'); const real = new Date();
  const old = new Date(real.getTime() - 400 * 86400000).toISOString().slice(0, 10), recent = new Date(real.getTime() - 10 * 86400000).toISOString().slice(0, 10);
  for (const d of [old, recent]) await w.env.DB.prepare("INSERT INTO analytics_daily(day,tenant_id,channel,product,operation,status_class,commercial_mode,requests) VALUES (?,'t1','rest','x','op','2xx','FREE_LAUNCH',1)").bind(d).run();
  await w.env.DB.prepare("INSERT INTO cost_entries(entry_id,provider,service,billing_period,kind,amount_micros,currency,source,imported_at) VALUES ('c1','cloudflare','workers','2025-01','confirmed',1,'USD','csv','2025-02-01T00:00:00Z')").run();
  await fire(w, '2026-10-23T04:17:00Z', async () => json(rel(1)));
  assert.equal((await w.env.DB.prepare('SELECT COUNT(*) n FROM analytics_daily').first()).n, 2, 'a 04:17 run does not prune');
  await fire(w, '2026-10-23T03:17:00Z', async () => json(rel(1)));
  assert.deepEqual((await w.env.DB.prepare('SELECT day FROM analytics_daily').all()).results.map((r) => r.day), [recent], 'the 03:17 run removes only the 400-day-old row');
  assert.equal((await w.env.DB.prepare('SELECT COUNT(*) n FROM cost_entries').first()).n, 1, 'financial records are never pruned');
});
