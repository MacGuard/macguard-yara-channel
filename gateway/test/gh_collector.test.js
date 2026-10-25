import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { newDb, fixedClock } from './d1shim.js';
import { downloadSummary, fetchReleases, ingest, kindOf, sync } from '../src/gh_collector.js';

const REPO = 'MacGuard/macguard-yara-channel';
const asset = (id, name, count, size = 1000) => ({ id, name, size, content_type: 'application/octet-stream', download_count: count });
const rel = (id, tag, assets, extra = {}) => ({ id, tag_name: tag, name: tag, draft: false, prerelease: false, created_at: '2026-10-20T00:00:00Z', published_at: '2026-10-20T01:00:00Z', assets, ...extra });
const fakeFetch = (pages, { status = 200, rate = { remaining: '4990', reset: '1790000000' }, fail = false } = {}) => async (url) => {
  if (fail) throw new Error('network down');
  const page = Number(new URL(url).searchParams.get('page') || 1);
  return new Response(JSON.stringify(status === 200 ? (pages[page - 1] ?? []) : { message: 'x' }), { status, headers: { 'x-ratelimit-remaining': rate.remaining, 'x-ratelimit-reset': rate.reset } });
};
const world = () => ({ db: newDb(), clock: fixedClock('2026-10-23T10:00:00Z') });
const obs = async (db) => (await db.prepare('SELECT asset_id, kind, download_count c, prev_count p FROM gh_observations ORDER BY asset_id, observed_at').all()).results.map((r) => ({ ...r }));

test('first reading is a baseline: the cumulative figure is exact, nothing is invented about the past', async () => {
  const { db, clock } = world(); const r = await sync(db, clock, fakeFetch([[rel(1, 'rules-1', [asset(10, 'rules-release.tar.gz', 42), asset(11, 'manifest.json', 40)])]]), { repo: REPO });
  assert.deepEqual([r.ok, r.stats.baselines, r.stats.deltas], [true, 2, 0]);
  const s = await downloadSummary(db, clock); assert.equal(s.totals.bundle_downloads_cumulative, 42); assert.equal(s.totals.bundle_downloads_observed, 0, 'no growth has been observed yet'); assert.equal(s.accuracy.cumulative, 'EXACT');
  assert.equal(s.by_asset_kind.manifest.downloads_cumulative, 40); assert.equal(s.totals.bundle_downloads_cumulative, 42, 'the manifest is not added to the bundle');
  assert.match(s.limitations.join(' '), /not people/);
});
test('second reading records the growth with its exact interval; an unchanged counter writes nothing', async () => {
  const { db, clock } = world(); const f1 = fakeFetch([[rel(1, 'r', [asset(10, 'rules-release.tar.gz', 42)])]]); await sync(db, clock, f1, { repo: REPO });
  clock.advance(3600000); await sync(db, clock, f1, { repo: REPO }); assert.equal((await obs(db)).length, 1, 'unchanged: still only the baseline');
  clock.advance(3600000); await sync(db, clock, fakeFetch([[rel(1, 'r', [asset(10, 'rules-release.tar.gz', 50)])]]), { repo: REPO });
  const o = await db.prepare("SELECT * FROM gh_observations WHERE kind = 'delta'").first(); assert.deepEqual([o.download_count, o.prev_count, o.prev_observed_at, o.observed_at], [50, 42, '2026-10-23T11:00:00Z', '2026-10-23T12:00:00Z']);
  const s = await downloadSummary(db, clock); assert.equal(s.totals.bundle_downloads_observed, 8); assert.equal(s.totals.bundle_downloads_cumulative, 50);
});
test('a replaced asset (same name, new asset_id) is a new series: no delta is ever computed across it', async () => {
  const { db, clock } = world(); await sync(db, clock, fakeFetch([[rel(1, 'r', [asset(10, 'rules-release.tar.gz', 100)])]]), { repo: REPO });
  clock.advance(3600000); const r = await sync(db, clock, fakeFetch([[rel(1, 'r', [asset(77, 'rules-release.tar.gz', 3)])]]), { repo: REPO });
  assert.equal(r.stats.replaced, 1); assert.equal((await db.prepare('SELECT supersedes_asset_id s FROM gh_assets WHERE asset_id = 77').first()).s, 10);
  assert.equal((await db.prepare('SELECT deleted_at d FROM gh_assets WHERE asset_id = 10').first()).d, '2026-10-23T11:00:00Z', 'the old asset is kept, marked gone');
  const s = await downloadSummary(db, clock); assert.equal(s.totals.bundle_downloads_observed, 0); assert.equal(s.totals.bundle_downloads_cumulative, 3, 'only live assets are in the cumulative total');
  assert.ok((await obs(db)).every((x) => x.kind === 'baseline'));
});
test('a counter that falls is a discontinuity: nothing is counted for it, and growth afterwards counts from the new base', async () => {
  const { db, clock } = world(); await sync(db, clock, fakeFetch([[rel(1, 'r', [asset(10, 'rules-release.tar.gz', 100)])]]), { repo: REPO });
  clock.advance(1000); await sync(db, clock, fakeFetch([[rel(1, 'r', [asset(10, 'rules-release.tar.gz', 5)])]]), { repo: REPO });
  clock.advance(1000); await sync(db, clock, fakeFetch([[rel(1, 'r', [asset(10, 'rules-release.tar.gz', 9)])]]), { repo: REPO });
  assert.deepEqual((await obs(db)).map((x) => x.kind), ['baseline', 'discontinuity', 'delta'], 'in the order they happened');
  const s = await downloadSummary(db, clock); assert.equal(s.totals.bundle_downloads_observed, 4, '9 - 5 only'); assert.equal(s.discontinuities_total, 1);
});
test('a removed release stays on record, flagged, and is never counted as zero or negative', async () => {
  const { db, clock } = world(); await sync(db, clock, fakeFetch([[rel(1, 'old', [asset(10, 'rules-release.tar.gz', 7)]), rel(2, 'new', [asset(20, 'rules-release.tar.gz', 3)])]]), { repo: REPO });
  clock.advance(1000); await sync(db, clock, fakeFetch([[rel(2, 'new', [asset(20, 'rules-release.tar.gz', 3)])]]), { repo: REPO });
  const s = await downloadSummary(db, clock); assert.equal(s.releases.find((r) => r.tag === 'old').deleted, true); assert.equal(s.totals.bundle_downloads_cumulative, 3);
  clock.advance(1000); await sync(db, clock, fakeFetch([[rel(1, 'old', [asset(10, 'rules-release.tar.gz', 8)]), rel(2, 'new', [asset(20, 'rules-release.tar.gz', 3)])]]), { repo: REPO });
  assert.equal((await downloadSummary(db, clock)).releases.find((r) => r.tag === 'old').deleted, false, 'it reappeared');
});
test('drafts are ignored; only real classes of asset are reported separately', async () => {
  const { db, clock } = world(); await sync(db, clock, fakeFetch([[rel(1, 'r', [asset(10, 'rules-release.tar.gz', 5)]), rel(2, 'draft', [asset(20, 'rules-release.tar.gz', 999)], { draft: true })]]), { repo: REPO });
  assert.equal((await downloadSummary(db, clock)).totals.bundle_downloads_cumulative, 5);
  const names = { 'rules-release.tar.gz': 'bundle', 'manifest.json': 'manifest', 'manifest.sigstore.json': 'signature', 'checkpoint.sigstore.json': 'signature', 'checkpoint.txt': 'checkpoint', 'inclusion-proof.json': 'proof', 'consistency.json': 'proof', 'release.json': 'metadata', 'changes.json': 'metadata', 'CHANGELOG.md': 'changelog', 'SHA256SUMS': 'checksums', 'README.md': 'documentation', 'tool.bin': 'other' };
  for (const [n, k] of Object.entries(names)) assert.equal(kindOf(n), k, n);
});
test('pagination, an over-long listing and the rate limit are handled as what they are', async () => {
  const many = Array.from({ length: 250 }, (_, i) => rel(i + 1, 'r' + i, [asset(1000 + i, 'rules-release.tar.gz', i)])), pages = [many.slice(0, 100), many.slice(100, 200), many.slice(200)];
  assert.equal((await fetchReleases(fakeFetch(pages), { repo: REPO })).releases.length, 250);
  const { db, clock } = world(); const inc = await sync(db, clock, fakeFetch(pages), { repo: REPO }); assert.equal(inc.ok, true);
  const w2 = world(); const full = Array.from({ length: 100 }, (_, i) => rel(i + 1, 'r', [asset(i + 1, 'a', 1)])); const r2 = await sync(w2.db, w2.clock, fakeFetch(Array(11).fill(full)), { repo: REPO });
  assert.deepEqual([r2.ok, r2.status], [false, 'incomplete']); assert.equal((await w2.db.prepare('SELECT COUNT(*) n FROM gh_releases').first()).n, 0, 'an incomplete listing is never ingested (it could mark releases as removed)');
  const w3 = world(); const limited = await sync(w3.db, w3.clock, fakeFetch([], { status: 403, rate: { remaining: '0', reset: '1790000000' } }), { repo: REPO }); assert.deepEqual([limited.ok, limited.status], [false, 'github_rate_limited']);
  assert.equal((await w3.db.prepare('SELECT consecutive_failures f FROM gh_sync').first()).f, 1);
});
test('failures are recorded, never thrown, and recovery resets the counter; staleness and coverage are measurable', async () => {
  const { db, clock } = world(); const ok = fakeFetch([[rel(1, 'r', [asset(10, 'rules-release.tar.gz', 1)])]]);
  assert.equal((await sync(db, clock, fakeFetch([], { fail: true }), { repo: REPO })).ok, false); assert.equal((await downloadSummary(db, clock)).last_status, 'github_unreachable');
  await sync(db, clock, ok, { repo: REPO }); clock.advance(2 * 86400000); assert.equal((await sync(db, clock, fakeFetch([], { fail: true }), { repo: REPO })).ok, false);
  const s = await downloadSummary(db, clock); assert.equal(s.consecutive_failures, 1); assert.equal(s.staleness_seconds, 2 * 86400); assert.equal(s.last_status, 'github_unreachable');
  assert.ok(s.coverage_of_window < 0.1, 'only two days of a 30-day window are covered'); assert.equal(s.accuracy.observed, 'PARTIAL');
  await sync(db, clock, ok, { repo: REPO }); assert.equal((await downloadSummary(db, clock)).consecutive_failures, 0);
  await assert.rejects(fetchReleases(ok, { repo: 'not a repo' }), /bad repository/);
});
test('re-applying the same listing at the same instant is idempotent', async () => {
  const { db, clock } = world(); const l = [rel(1, 'r', [asset(10, 'rules-release.tar.gz', 5)])]; const at = '2026-10-23T10:00:00Z';
  await ingest(db, REPO, l, at); await ingest(db, REPO, l, at); l[0].assets[0].download_count = 6; await ingest(db, REPO, l, '2026-10-23T11:00:00Z'); await ingest(db, REPO, l, '2026-10-23T11:00:00Z');
  assert.deepEqual((await obs(db)).map((x) => x.kind), ['baseline', 'delta']); assert.equal((await db.prepare('SELECT COUNT(*) n FROM gh_assets').first()).n, 1);
});
test('over a real HTTP boundary: a local server that behaves like the GitHub API (pagination, rate headers, auth header)', async () => {
  const seen = []; const all = Array.from({ length: 130 }, (_, i) => rel(i + 1, 'rules-' + i, [asset(500 + i, 'rules-release.tar.gz', i * 2), asset(900 + i, 'manifest.json', i)]));
  const server = http.createServer((req, res) => { const u = new URL(req.url, 'http://x'); seen.push({ path: u.pathname, page: u.searchParams.get('page'), per: u.searchParams.get('per_page'), ua: req.headers['user-agent'], auth: req.headers.authorization, ver: req.headers['x-github-api-version'] });
    const p = Number(u.searchParams.get('page')); res.writeHead(200, { 'content-type': 'application/json', 'x-ratelimit-remaining': '58', 'x-ratelimit-reset': '1790000000' }); res.end(JSON.stringify(all.slice((p - 1) * 100, p * 100))); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r)); server.unref();
  try {
    const { db, clock } = world(); const r = await sync(db, clock, fetch, { repo: REPO, token: 'ghp_not_a_real_token', baseUrl: `http://127.0.0.1:${server.address().port}` }); assert.equal(r.ok, true);
    assert.deepEqual(seen.map((s) => s.page), ['1', '2']); assert.ok(seen.every((s) => s.path === `/repos/${REPO}/releases` && s.per === '100' && s.ua === 'macguard-analytics' && s.ver === '2022-11-28' && s.auth === 'Bearer ghp_not_a_real_token'));
    const s = await downloadSummary(db, clock); assert.equal(s.releases.length, 130); assert.equal((await db.prepare('SELECT rate_remaining r FROM gh_sync').first()).r, 58);
    assert.ok(!JSON.stringify(await db.prepare('SELECT * FROM gh_sync').first()).includes('ghp_'), 'the token is never stored');
  } finally { server.closeAllConnections?.(); server.close(); }
});

test('two syncs inside the same second never lose the variation (observations are stamped strictly after the previous one)', async () => {
  const { ingest } = await import('../src/gh_collector.js'); const { newDb } = await import('./d1shim.js'); const db = newDb();
  const L = (n) => [{ id: 1, tag_name: 'rules-20261021-1', draft: false, prerelease: false, assets: [{ id: 10, name: 'rules-release.tar.gz', size: 1, download_count: n }] }];
  await ingest(db, 'o/r', L(100), '2026-10-23T20:17:00Z'); await ingest(db, 'o/r', L(130), '2026-10-23T20:17:00Z'); await ingest(db, 'o/r', L(135), '2026-10-23T20:17:00Z');
  const o = (await db.prepare('SELECT kind, download_count, prev_count, observed_at FROM gh_observations ORDER BY observed_at').all()).results.map((r) => ({ ...r }));
  assert.deepEqual(o.map((r) => [r.kind, r.download_count - (r.prev_count ?? r.download_count)]), [['baseline', 0], ['delta', 30], ['delta', 5]]);
  assert.deepEqual(o.map((r) => r.observed_at), ['2026-10-23T20:17:00Z', '2026-10-23T20:17:01Z', '2026-10-23T20:17:02Z']);
});

test('a 403 is classified: a real rate limit says so, any other 403 is github_forbidden with GitHub\'s own message, and the rate headers are stored', async () => {
  const { sync } = await import('../src/gh_collector.js'); const { newDb } = await import('./d1shim.js');
  const mk = (status, remaining, message) => async () => new Response(JSON.stringify({ message }), { status, headers: { 'x-ratelimit-remaining': String(remaining), 'x-ratelimit-reset': '1790000000' } });
  const run = async (f) => { const db = newDb(); const r = await sync(db, () => new Date('2026-10-23T20:18:00Z'), f, { repo: 'o/r' }); return { r, s: await db.prepare('SELECT * FROM gh_sync WHERE id = 1').first() }; };
  let x = await run(mk(403, 0, 'API rate limit exceeded for 203.0.113.9. https://docs.github.com/x')); assert.equal(x.r.status, 'github_rate_limited'); assert.equal(x.s.rate_remaining, 0); assert.ok(x.s.rate_reset_at); assert.ok(!/https?:/.test(x.s.last_error) && !x.s.last_error.includes('203.0.113.9') && x.s.last_error.includes('<ip>'), 'no URL and no address in the stored message');
  x = await run(mk(403, 21, 'Request forbidden by administrative rules.')); assert.equal(x.r.status, 'github_forbidden'); assert.match(x.s.last_error, /forbidden by administrative rules.*remaining 21/); assert.equal(x.s.rate_remaining, 21);
  x = await run(mk(429, 5, 'slow down')); assert.equal(x.r.status, 'github_rate_limited'); x = await run(mk(502, 59, 'bad gateway')); assert.equal(x.r.status, 'github_error');
});

test('a GitHub token is used only when well-formed, is flagged as authenticated, and its value never reaches an error, a log row or the database', async () => {
  const { sync, validToken } = await import('../src/gh_collector.js'); const { newDb } = await import('./d1shim.js'); const TOKEN = 'github_pat_' + 'A1b2C3d4'.repeat(6);
  for (const bad of ['', 'short', 'has space ' + 'x'.repeat(30), 'line\nbreak' + 'x'.repeat(30), 'quote"' + 'x'.repeat(30), null, 123]) assert.equal(validToken(bad), false, JSON.stringify(bad));
  assert.equal(validToken(TOKEN), true);
  const seen = []; const f = async (u, o) => { seen.push(o.headers.authorization ?? null); return new Response(JSON.stringify([]), { status: 200, headers: { 'x-ratelimit-remaining': '4999', 'x-ratelimit-reset': '1790000000' } }); };
  let db = newDb(); let r = await sync(db, () => new Date('2026-10-23T20:00:00Z'), f, { repo: 'o/r', token: TOKEN }); assert.equal(r.authenticated, true); assert.equal(seen.at(-1), `Bearer ${TOKEN}`); assert.equal((await db.prepare('SELECT authenticated a FROM gh_sync').first()).a, 1);
  r = await sync(db, () => new Date('2026-10-23T21:00:00Z'), f, { repo: 'o/r', token: 'bad token\nX-Evil: 1' }); assert.equal(r.authenticated, false); assert.equal(seen.at(-1), null, 'a malformed token is never sent'); assert.equal((await db.prepare('SELECT authenticated a FROM gh_sync').first()).a, 0);
  // GitHub echoing the credential in an error body must not be stored
  db = newDb(); const echo = async () => new Response(JSON.stringify({ message: `Bad credentials ${TOKEN}` }), { status: 403, headers: { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '1790000000' } });
  r = await sync(db, () => new Date('2026-10-23T22:00:00Z'), echo, { repo: 'o/r', token: TOKEN }); assert.equal(r.ok, false);
  const dump = JSON.stringify({ s: await db.prepare('SELECT * FROM gh_sync').first(), l: (await db.prepare('SELECT * FROM gh_sync_log').all()).results, r }); assert.ok(!dump.includes(TOKEN) && !dump.includes('A1b2C3d4'.repeat(3)), 'the token appears nowhere');
});

test('every GitHub denial is told apart: primary limit, secondary limit (with retry-after), rejected token, missing repository, other 403, server error', async () => {
  const { sync } = await import('../src/gh_collector.js'); const { newDb } = await import('./d1shim.js');
  const mk = (status, headers, message) => async () => new Response(JSON.stringify({ message }), { status, headers });
  const run = async (f, token) => { const db = newDb(); const r = await sync(db, () => new Date('2026-10-24T05:00:00Z'), f, { repo: 'o/r', token }); return { r, s: await db.prepare('SELECT * FROM gh_sync WHERE id = 1').first() }; };
  const T = 'github_pat_' + 'A1b2C3d4'.repeat(6);
  let x = await run(mk(403, { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '1792900000' }, 'API rate limit exceeded for 203.0.113.9.')); assert.equal(x.r.status, 'github_rate_limited'); assert.equal(x.s.rate_remaining, 0);
  x = await run(mk(403, { 'retry-after': '90', 'x-ratelimit-remaining': '40' }, 'You have exceeded a secondary rate limit. Please wait a few minutes.')); assert.equal(x.r.status, 'github_secondary_limited'); assert.match(x.s.last_error, /retry-after 90s/); assert.equal(x.s.rate_reset_at, '2026-10-24T05:01:30Z', 'the wait comes from retry-after');
  x = await run(mk(403, { 'x-ratelimit-remaining': '0' }, 'You have exceeded a secondary rate limit.')); assert.equal(x.r.status, 'github_secondary_limited', 'the message decides, even when the primary counter is also 0');
  x = await run(mk(429, { 'x-ratelimit-remaining': '12' }, 'slow down')); assert.equal(x.r.status, 'github_rate_limited');
  x = await run(mk(401, {}, `Bad credentials ${T}`), T); assert.equal(x.r.status, 'github_unauthorized'); assert.match(x.s.last_error, /invalid, expired or revoked/); assert.ok(!x.s.last_error.includes(T));
  x = await run(mk(404, {}, 'Not Found')); assert.equal(x.r.status, 'github_not_found');
  x = await run(mk(403, { 'x-ratelimit-remaining': '21' }, 'Request forbidden by administrative rules.')); assert.equal(x.r.status, 'github_forbidden'); assert.equal(x.s.rate_remaining, 21);
  x = await run(mk(502, {}, 'Bad gateway')); assert.equal(x.r.status, 'github_error');
});
