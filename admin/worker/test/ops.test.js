// Pipeline activity: calendar states, success rate, durations, sources, and the cached, partial-failure-tolerant API. Fixtures mirror the real shapes of the
// GitHub Actions runs API, the releases API, the public stats.json and logs/log.jsonl.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildOverview } from '../src/ops.js';
import { world } from './helpers.js';

const run = (id, event, created, conclusion, mins = 5, status = 'completed') => ({ id, event, status, conclusion, created_at: created, run_started_at: created, updated_at: new Date(Date.parse(created) + mins * 60000).toISOString(), html_url: `https://github.com/MacGuard/x/actions/runs/${id}` });
const statsDay = (date, extra = {}) => ({ date, observed: true, examined: 1184, accepted: 1174, quarantined: 6, rejected: 4, deprecated: 0, accounting_ok: true, performance: { gate_seconds: 150 }, new: null, modified: null, removed: null, ...extra });
const FIX = () => ({
  runs: [
    run(1, 'workflow_dispatch', '2026-10-18T14:23:19Z', 'failure', 2), run(2, 'workflow_dispatch', '2026-10-18T17:33:06Z', 'success', 10),
    run(3, 'schedule', '2026-10-19T03:49:05Z', 'failure', 2), run(4, 'workflow_dispatch', '2026-10-19T12:42:02Z', 'success', 6),
    run(5, 'schedule', '2026-10-21T03:20:00Z', 'success', 9), run(6, 'schedule', '2026-10-22T03:21:00Z', 'cancelled', 1), run(7, 'schedule', '2026-10-23T03:20:00Z', 'success', 9),
    run(8, 'schedule', '2026-10-24T03:20:00Z', 'success', 12), run(9, 'schedule', '2026-10-25T03:20:00Z', null, 8, 'in_progress'),
  ],
  publishRuns: [run(20, 'workflow_run', '2026-10-18T17:43:30Z', 'success', 1)],
  releases: [{ tag_name: 'rules-20261018-2', published_at: '2026-10-18T17:44:25Z', draft: false, prerelease: false, html_url: 'https://github.com/MacGuard/x/releases/tag/rules-20261018-2' }, { tag_name: 'draft-1', published_at: null, draft: true }],
  stats: { days: [statsDay('2026-10-18'), statsDay('2026-10-19'), statsDay('2026-10-21', { accounting_ok: false }), statsDay('2026-10-23', { observed: false })] },
  log: [{ event: 'sources.fetched', time: '2026-10-18T04:10:40Z', run_id: '1', details: { sources: [{ repository: 'a/b', commit: 'c'.repeat(40) }] } }, { event: 'rules.withheld', time: '2026-10-18T16:49:52Z', message: '10 previously published rule files no longer pass the checks and are withheld until resolved.' },
    { event: 'sources.fetched', time: '2026-10-19T12:47:37Z', run_id: '4', details: { sources: [{ repository: 'a/b', commit: 'd'.repeat(40) }] } }],
  sources: { sources: [{ id: 'nextron', repo: 'a/b', kind: 'rules', paths: ['yara'] }, { id: 'none', repo: 'x/y', kind: 'engine', paths: [] }] },
  firstRunAt: '2026-10-18T04:05:48Z',
});
const at = (s) => Date.parse(s);
const day = (o, d) => o.days.find((x) => x.date === d);

test('every day gets one honest state: OK, WARNING, FAIL (recovered or not), CANCELLED, RUNNING, NO RUN, PENDING, BEFORE', () => {
  const o = buildOverview(FIX(), at('2026-10-25T12:00:00Z'), 15);
  assert.equal(o.window.from, '2026-10-11'); assert.equal(o.window.to, '2026-10-25'); assert.equal(o.days.length, 15);
  assert.equal(day(o, '2026-10-17').state, 'BEFORE'); assert.equal(day(o, '2026-10-11').state, 'BEFORE', 'before the first recorded run is not a failure');
  const d18 = day(o, '2026-10-18'); assert.equal(d18.manual_only, true); assert.equal(d18.state, 'WARNING', 'manual success, but 10 published rules are withheld'); assert.deepEqual(d18.reasons, [{ code: 'withheld', n: 10 }]);
  assert.equal(d18.scheduled, null); assert.equal(d18.manual.length, 2); assert.equal(d18.releases[0].tag, 'rules-20261018-2'); assert.equal(d18.publish_runs.length, 1);
  const d19 = day(o, '2026-10-19'); assert.equal(d19.state, 'FAIL', 'the scheduled run is the contract'); assert.equal(d19.recovered, true, 'a manual success the same day is shown, not used to hide the failure'); assert.equal(d19.scheduled.event, 'schedule'); assert.equal(d19.manual[0].conclusion, 'success');
  assert.equal(day(o, '2026-10-20').state, 'NO_RUN', 'a past day with no run is not a pass and not zero');
  const d21 = day(o, '2026-10-21'); assert.equal(d21.state, 'WARNING'); assert.deepEqual(d21.reasons, [{ code: 'accounting' }]);
  assert.equal(day(o, '2026-10-22').state, 'CANCELLED'); assert.equal(day(o, '2026-10-23').state, 'OK'); assert.equal(day(o, '2026-10-23').stats, null, 'observed:false yields no numbers, not zeros');
  assert.equal(day(o, '2026-10-24').state, 'OK'); assert.equal(day(o, '2026-10-25').state, 'RUNNING');
  assert.equal(o.days.filter((d) => d.releases.length).length, 1, 'a release is never inferred from a successful run');
});

test('today is PENDING until the schedule is overdue, then NO RUN', () => {
  const early = buildOverview(FIX(), at('2026-10-26T04:00:00Z'), 3), late = buildOverview(FIX(), at('2026-10-26T07:00:00Z'), 3);
  assert.equal(day(early, '2026-10-26').state, 'PENDING'); assert.equal(day(late, '2026-10-26').state, 'NO_RUN'); assert.equal(day(early, '2026-10-25').state, 'RUNNING');
});

test('success rate counts unique scheduled days as success/(success+failure), excluding cancelled, running and manual-only; durations and trends need real data', () => {
  const o = buildOverview(FIX(), at('2026-10-25T12:00:00Z'), 15), s = o.summary;
  assert.equal(s.scheduled_counted, 4); assert.equal(s.scheduled_ok, 3); assert.equal(s.success_rate, 75);   // 19 fail, 21 ok, 23 ok, 24 ok; 22 cancelled, 25 running, 18 manual-only
  assert.equal(s.cancelled, 1); assert.equal(s.running, 1); assert.equal(s.fail, 1); assert.equal(s.trend_valid, false, 'fewer than 3 runs in each week: no trend');
  assert.equal(buildOverview({ ...FIX(), runs: [] }, at('2026-10-25T12:00:00Z'), 7).summary.success_rate, null, 'no runs: no rate, not 0 or 100');
  const many = { ...FIX(), runs: [] }; for (let i = 0; i < 14; i++) many.runs.push(run(100 + i, 'schedule', `2026-10-${String(12 + i).padStart(2, '0')}T03:20:00Z`, 'success', i < 7 ? 4 : 8));
  const t = buildOverview(many, at('2026-10-25T12:00:00Z'), 14).summary; assert.equal(t.trend_valid, true); assert.equal(t.avg_duration_7d_s, 480); assert.equal(t.avg_duration_prev_7d_s, 240);
});

test('latest run, latest release, last observed day and upstream sources come from the records, with pinned commits from the run log', () => {
  const o = buildOverview(FIX(), at('2026-10-25T12:00:00Z'), 15);
  assert.equal(o.latest.run.id, 9); assert.equal(o.latest.run.conclusion, null); assert.equal(o.latest.release.tag, 'rules-20261018-2'); assert.equal(o.latest.observed_day.date, '2026-10-21'); assert.equal(o.latest.observed_day.quarantined, 6);
  assert.deepEqual(o.sources.map((s) => [s.id, s.commit, s.run_id]), [['nextron', 'd'.repeat(40), '4'], ['none', null, '4']], 'the newest fetch record wins; an unpinned source stays null');
  assert.equal(o.definitions.schedule_utc, '03:17');
});

// ---- API ----
function feed(w, over = {}) {
  const calls = []; const body = (o) => new Response(JSON.stringify(o), { headers: { 'x-ratelimit-remaining': '4990', 'x-ratelimit-limit': '5000' } }); const f = FIX();
  w.route(/actions\/workflows\/daily\.yml\/runs/, (u, i) => { calls.push(['daily', i.headers.Authorization]); return over.runs ? over.runs() : body({ workflow_runs: f.runs }); });
  w.route(/actions\/workflows\/publish\.yml\/runs/, () => { calls.push(['publish']); return body({ workflow_runs: f.publishRuns }); });
  w.route(/\/releases\?per_page/, () => { calls.push(['releases']); return body(f.releases); });
  w.route(/\/stats\.json$/, () => { calls.push(['stats']); return over.stats ? over.stats() : new Response(JSON.stringify(f.stats)); });
  w.route(/logs\/log\.jsonl$/, () => { calls.push(['log']); return new Response(f.log.map((e) => JSON.stringify(e)).join('\n')); });
  w.route(/config\/sources\.json$/, () => { calls.push(['sources']); return new Response(JSON.stringify(f.sources)); });
  return calls;
}
const memCache = () => { const m = new Map(); return { async match(r) { const v = m.get(r.url); return v ? v.clone() : undefined; }, async put(r, res) { m.set(r.url, res.clone()); }, size: () => m.size }; };

test('GET /api/ops/overview: any signed-in role reads it, anonymous 401; GitHub is asked with the person\'s own token; cached for 5 minutes; no token or secret in the answer', async () => {
  const w = await world(); const calls = feed(w); w.deps.cache = memCache(); const vera = await w.login('vera', { pull: true }, { id: 7 });
  assert.equal((await w.call('GET', '/api/ops/overview')).status, 401);
  const ada = await w.login('ada', { admin: true }); await w.grant(ada, 'vera', 'VIEWER');
  const r = await w.call('GET', '/api/ops/overview', { user: ada }); assert.equal(r.status, 200); assert.equal(r.data.cache.hit, false); assert.equal(r.data.days.length, 30); assert.deepEqual(r.data.unavailable, []); assert.equal(r.data.rate.remaining, 4990);
  assert.equal(calls.find((c) => c[0] === 'daily')[1], 'Bearer tok-ada', 'the signed-in person\'s token, never a service credential');
  assert.doesNotMatch(JSON.stringify(r.data), /tok-|csrf|secret|v1\./i); const n = calls.length;
  const again = await w.call('GET', '/api/ops/overview', { user: ada }); assert.equal(again.data.cache.hit, true); assert.equal(calls.length, n, 'served from the cache, GitHub not asked again'); assert.ok(again.data.cache.age_s >= 0);
  assert.equal((await w.call('GET', '/api/ops/overview', { user: vera })).status, 200, 'a viewer gets the same public records');
});

test('a source that cannot be read is reported, never guessed: the rest of the answer still arrives and a partial answer is cached for a minute only', async () => {
  const w = await world(); feed(w, { stats: () => new Response('boom', { status: 500 }), runs: () => new Response('{}', { status: 403 }) }); w.deps.cache = memCache(); const ada = await w.login('ada', { admin: true });
  const r = await w.call('GET', '/api/ops/overview', { user: ada }); assert.equal(r.status, 200);
  assert.deepEqual(r.data.unavailable.map((u) => [u.source, u.reason]).sort(), [['runs', 'rate_limited'], ['stats', 'http_500']]);
  assert.equal(r.data.days.every((d) => d.state === 'NO_RUN' || d.state === 'BEFORE' || d.state === 'PENDING'), true, 'without run data no day is reported as a pass or a failure');
  assert.equal(r.data.latest.run, null); assert.equal(r.data.summary.success_rate, null); assert.ok(r.data.sources.length > 0, 'sources and log still came through');
  const res = await w.deps.cache.match(new Request(`${w.env.PUBLIC_URL}/__cache/ops-overview-v1`)); assert.equal(res.headers.get('Cache-Control'), 'max-age=60');
});

test('a malformed or unreachable source does not break the endpoint', async () => {
  const w = await world(); feed(w, { stats: () => new Response('<html>', { status: 200 }) }); w.route(/releases\?per_page/, () => { throw new Error('network'); }); const ada = await w.login('ada', { admin: true });
  const r = await w.call('GET', '/api/ops/overview', { user: ada }); assert.equal(r.status, 200); assert.deepEqual(r.data.unavailable.map((u) => `${u.source}:${u.reason}`).sort(), ['releases:unreachable', 'stats:malformed']);
});
