import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { evaluate, evaluateCosts, dedupe, formatAlert, run, collect, sendTelegram, TEST_TEXT, watchdog } from '../../../scripts/usage_monitor.mjs';

const cfg = JSON.parse(readFileSync(new URL('../../../config/usage-limits.json', import.meta.url), 'utf8'));
const fx = (n) => JSON.parse(readFileSync(new URL(`../../../tests/fixtures/usage/${n}.json`, import.meta.url), 'utf8'));
const calm = () => Object.fromEntries(Object.keys(cfg.metrics).map((k) => [k, { used: 1 }]));
const at = (h) => new Date(Date.UTC(2026, 9, 27, h, 0, 0));
const lvl = (f, id) => f.find((x) => x.id === id).level;

test('thresholds 50/75/90/100 % map to notice/warning/critical/limit and nothing below 50 % alerts', () => {
  const L = cfg.metrics.d1_rows_read.limit;
  for (const [frac, want] of [[0.49, 'ok'], [0.5, 'notice'], [0.75, 'warning'], [0.9, 'critical'], [1, 'limit'], [1.2, 'limit']]) {
    assert.equal(lvl(evaluate({ ...calm(), d1_rows_read: { used: L * frac } }, cfg, at(1)), 'd1_rows_read'), want, `${frac}`);
  }
});

test('prediction: a day metric on course to exceed its limit warns early, only after enough of the day has elapsed, and never for point-in-time metrics', () => {
  const L = cfg.metrics.d1_rows_read.limit;
  const early = evaluate({ ...calm(), d1_rows_read: { used: L * 0.2 } }, cfg, at(6)).find((x) => x.id === 'd1_rows_read');   // 20 % used at 25 % of the day -> 80 % projected... below 100 %
  assert.equal(early.level, 'ok');
  const fast = evaluate({ ...calm(), d1_rows_read: { used: L * 0.3 } }, cfg, at(6)).find((x) => x.id === 'd1_rows_read');     // 30 % at 25 % of the day -> 120 %
  assert.equal(fast.level, 'warning'); assert.equal(fast.predictive, true); assert.ok(fast.projected > L);
  assert.equal(lvl(evaluate({ ...calm(), d1_rows_read: { used: L * 0.3 } }, cfg, at(1)), 'd1_rows_read'), 'ok', 'too early in the day to extrapolate');
  assert.equal(evaluate({ ...calm(), d1_storage_bytes: { used: 1 } }, cfg, at(6)).find((x) => x.id === 'd1_storage_bytes').projected, undefined);
});

test('a metric that could not be collected is "unknown" with its reason: never ok, never 0 and never an alert by itself', () => {
  const f = evaluate({ ...calm(), r2_storage_bytes: { unavailable: 'HTTP 403' } }, cfg, at(12));
  const r2 = f.find((x) => x.id === 'r2_storage_bytes'); assert.equal(r2.level, 'unknown'); assert.equal(r2.reason, 'HTTP 403');
  assert.deepEqual(dedupe(f, [], {}, at(12)).alerts, []);
});

test('de-duplication: the same level is not re-sent, a higher level is, a lower one is not, and the next UTC day starts over', () => {
  const L = cfg.metrics.d1_rows_read.limit, f = (frac) => evaluate({ ...calm(), d1_rows_read: { used: L * frac } }, cfg, at(23));
  let d = dedupe(f(0.8), [], {}, at(23)); assert.equal(d.alerts.length, 1);
  assert.equal(dedupe(f(0.8), [], d.state, at(23)).alerts.length, 0, 'same level');
  const up = dedupe(f(0.95), [], d.state, at(23)); assert.equal(up.alerts.length, 1); assert.equal(up.alerts[0].level, 'critical');
  assert.equal(dedupe(f(0.8), [], up.state, at(23)).alerts.length, 0, 'improving never alerts');
  assert.equal(dedupe(f(0.8), [], up.state, new Date(Date.UTC(2026, 9, 28, 23))).alerts.length, 1, 'new day');
});

test('costs are kept per currency and per kind, never summed across currencies, and pending amounts are not hidden', () => {
  const c = evaluateCosts(fx('cost-eur').costs, cfg), eur = c.find((x) => x.currency === 'EUR'), usd = c.find((x) => x.currency === 'USD');
  assert.deepEqual([eur.confirmed, eur.estimated, eur.pending, eur.worst_case], [31.5, 22.4, 12, 65.9]);
  assert.equal(eur.level, 'warning', '53.9 EUR known = past the 50 EUR warning; pending is reported separately');
  assert.equal(usd.level, 'unknown'); assert.match(usd.reason, /no threshold is defined for USD/);
});

test('the EUR thresholds are 20/50/100/150 and 150 means containment (a notice, never a billing guarantee)', () => {
  const lv = (amount) => evaluateCosts([{ currency: 'EUR', kind: 'confirmed', amount }], cfg)[0].level;
  assert.deepEqual([19.99, 20, 50, 100, 150].map(lv), ['ok', 'notice', 'warning', 'critical', 'containment']);
  const text = formatAlert(dedupe([], evaluateCosts([{ currency: 'EUR', kind: 'confirmed', amount: 150 }], cfg), {}).alerts[0]);
  assert.match(text, /NO esenciales/); assert.match(text, /no se apaga ningún servicio crítico/); assert.match(text, /no es un límite de facturación/);
});

test('delivery: a sent alert is remembered; a failed one is retried next time and makes the run fail; no channel at all also fails', async () => {
  const metrics = fx('d1-critical').metrics, now = new Date(fx('d1-critical').now), sent = [], keys = (r) => r.alerts.map((a) => a.key).sort();
  const ok = await run({ cfg, metrics, state: {}, now, deliver: async (t) => { sent.push(t); } });
  assert.deepEqual(ok.alerts.map((a) => a.kind).sort(), ['blind', 'usage'], 'the critical D1 level and the unreadable R2 metric'); assert.equal(ok.exit, 2, 'critical exits non-zero so GitHub e-mails the administrators'); assert.deepEqual(ok.failures, []);
  assert.equal((await run({ cfg, metrics, state: ok.state, now, deliver: async (t) => sent.push(t) })).alerts.length, 0, 'not repeated');
  const bad = await run({ cfg, metrics, state: {}, now, deliver: async () => { throw new Error('Telegram HTTP 500'); } });
  assert.equal(bad.exit, 2); assert.equal(bad.failures.length, 2); assert.deepEqual(Object.keys(bad.state), ['__last'], 'nothing recorded as delivered');
  assert.deepEqual(keys(await run({ cfg, metrics, state: bad.state, now, deliver: async (t) => sent.push(t) })), keys(ok), 'all retried');
  const none = await run({ cfg, metrics, state: {}, now, deliver: null }); assert.equal(none.exit, 2); assert.match(none.failures[0], /no notification channel/);
});

test('a calm day produces no alert and exit 0', async () => {
  const r = await run({ cfg, metrics: calm(), state: {}, now: at(12), deliver: async () => { throw new Error('must not be called'); } });
  assert.equal(r.exit, 0); assert.equal(r.alerts.length, 0);
});

test('alert text carries the numbers and the D1 advice, and contains no token-shaped value', () => {
  const f = evaluate(fx('d1-critical').metrics, cfg, new Date(fx('d1-critical').now)), a = dedupe(f, [], {}).alerts[0], t = formatAlert(a);
  assert.match(t, /CRÍTICO/); assert.match(t, /D1 rows read/); assert.match(t, /00:00 UTC/); assert.doesNotMatch(t, /[A-Za-z0-9_-]{32,}/);
});

test('collect: reads D1, Workers and R2 through GraphQL with a Bearer header only; a failing query marks only its own metrics unavailable', async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, auth: init.headers.Authorization, body: init.body });
    if (url.includes('/d1/database')) return { ok: true, json: async () => ({ result: [{ file_size: 100 }, { file_size: 50 }] }) };
    const q = JSON.parse(init.body).query;
    if (q.includes('r2OperationsAdaptiveGroups')) return { ok: false, status: 500 };
    const acct = q.includes('d1Analytics') ? { d1AnalyticsAdaptiveGroups: [{ sum: { rowsRead: 7, rowsWritten: 3 } }, { sum: { rowsRead: 1, rowsWritten: 0 } }] }
      : q.includes('workersInvocations') ? { workersInvocationsAdaptive: [{ sum: { requests: 42 } }] } : { r2StorageAdaptiveGroups: [{ dimensions: { bucketName: 'a', datetime: '2026-10-27T01:00:00Z' }, max: { payloadSize: 1 } }, { dimensions: { bucketName: 'a', datetime: '2026-10-27T09:00:00Z' }, max: { payloadSize: 4 } }, { dimensions: { bucketName: 'b', datetime: '2026-10-27T05:00:00Z' }, max: { payloadSize: 5 } }] };
    return { ok: true, json: async () => ({ data: { viewer: { accounts: [acct] } } }) };
  };
  const m = await collect({ fetchImpl, token: 'T', account: 'A', now: at(12) });
  assert.deepEqual([m.d1_rows_read.used, m.d1_rows_written.used, m.workers_requests.used, m.r2_storage_bytes.used, m.d1_storage_bytes.used], [8, 3, 42, 9, 150]);
  assert.match(m.r2_class_a_ops.unavailable, /HTTP 500/); assert.match(m.r2_class_b_ops.unavailable, /HTTP 500/);
  assert.ok(calls.every((c) => c.auth === 'Bearer T') && calls.every((c) => !c.body || !String(c.body).includes('"T"')), 'the token travels only in the header');
  assert.ok(calls.every((c) => !/mutation/i.test(c.body || '')), 'read-only: no GraphQL mutation');
});

test('Telegram: posts the text to the bot endpoint and raises on a non-OK answer without echoing the token', async () => {
  let seen; await sendTelegram(async (u, i) => { seen = { u, b: JSON.parse(i.body) }; return { ok: true }; }, { token: 'TKN', chat: '123' }, 'hola');
  assert.equal(seen.b.chat_id, '123'); assert.equal(seen.b.text, 'hola');
  await assert.rejects(() => sendTelegram(async () => ({ ok: false, status: 401 }), { token: 'TKN', chat: '1' }, 'x'), (e) => /401/.test(e.message) && !/TKN/.test(e.message));
});

test('the limits file is complete: every metric has a label, a period and a positive limit, and thresholds ascend', () => {
  for (const [id, d] of Object.entries(cfg.metrics)) { assert.ok(d.label && ['day', 'month', 'point'].includes(d.period) && d.limit > 0, id); }
  const t = cfg.thresholds; assert.ok(t.notice < t.warning && t.warning < t.critical && t.critical <= t.limit);
  const e = cfg.costs.currency_thresholds.EUR; assert.deepEqual([e.notice, e.warning, e.critical, e.containment], [20, 50, 100, 150]);
});

test('missed daily run: the age of the last successful daily pipeline alerts at 36 h, 54 h and 65 h; an API failure is "unknown", not zero', async () => {
  const at12 = at(12), lv = (h) => lvl(evaluate({ ...calm(), daily_run_age_hours: { used: h } }, cfg, at12), 'daily_run_age_hours');
  assert.deepEqual([20, 36, 54, 65, 72].map(lv), ['ok', 'notice', 'warning', 'critical', 'limit']);
  const ok = async (u) => ({ ok: true, json: async () => ({ workflow_runs: [{ updated_at: new Date(at12.getTime() - 40 * 3600000).toISOString() }] }) });
  const m = await collect({ fetchImpl: async (u, i) => (u.includes('api.github.com') ? ok(u) : { ok: false, status: 500 }), token: 'T', account: 'A', now: at12, github: { token: 'G', repo: 'o/r' } });
  assert.equal(m.daily_run_age_hours.used, 40);
  const bad = await collect({ fetchImpl: async (u) => (u.includes('api.github.com') ? { ok: false, status: 403 } : { ok: false, status: 500 }), token: 'T', account: 'A', now: at12, github: { token: 'G', repo: 'o/r' } });
  assert.match(bad.daily_run_age_hours.unavailable, /403/);
  const none = await collect({ fetchImpl: async (u) => (u.includes('api.github.com') ? { ok: true, json: async () => ({ workflow_runs: [] }) } : { ok: false, status: 500 }), token: 'T', account: 'A', now: at12, github: { token: 'G', repo: 'o/r' } });
  assert.match(none.daily_run_age_hours.unavailable, /no successful daily run/);
});

test('--test-message sends only the fixed text, needs both Telegram variables, and reads no analytics', async () => {
  const { spawnSync } = await import('node:child_process'), script = new URL('../../../scripts/usage_monitor.mjs', import.meta.url).pathname;
  const env = { PATH: process.env.PATH }, r = spawnSync(process.execPath, [script, '--test-message'], { env, encoding: 'utf8' });
  assert.equal(r.status, 3); assert.match(r.stderr, /TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are required/);
  assert.doesNotMatch(TEST_TEXT, /\d{3,}/, 'no figures in the test text'); assert.match(TEST_TEXT, /No es una alerta de consumo/);
});

test('an unknown or malformed amount is never counted as 0 EUR: the currency is "unknown" and says why', () => {
  const only = (lines) => evaluateCosts(lines, cfg).find((c) => c.currency === 'EUR');
  for (const bad of [null, undefined, NaN, 'n/a', Infinity]) { const c = only([{ currency: 'EUR', kind: 'confirmed', amount: bad }]); assert.equal(c.level, 'unknown', String(bad)); assert.match(c.reason, /unknown or malformed amount/); }
  const mixed = only([{ currency: 'EUR', kind: 'confirmed', amount: 200 }, { currency: 'EUR', kind: 'estimated', amount: null }]);
  assert.equal(mixed.level, 'unknown', 'a known 200 EUR plus an unreadable line is incomplete, never judged as a clean total');
  assert.deepEqual(evaluateCosts([], cfg), [], 'no source at all produces no figure');
  assert.equal(only([{ currency: 'EUR', kind: 'bogus', amount: 5 }]).level, 'unknown');
});

test('a metric that cannot be read is reported ONCE per day as "sin dato"; if every metric is unreadable the monitor declares itself blind and fails', async () => {
  const sent = [], deliver = async (t) => sent.push(t), unk = Object.fromEntries(Object.keys(cfg.metrics).map((k) => [k, { unavailable: 'HTTP 403' }]));
  const r = await run({ cfg, metrics: { ...calm(), r2_storage_bytes: { unavailable: 'HTTP 403' } }, state: {}, now: at(12), deliver });
  assert.equal(r.exit, 0, 'one blind metric alerts but is not an outage'); assert.equal(sent.length, 1); assert.match(sent[0], /sin dato.*R2 storage.*No es 0/);
  assert.equal((await run({ cfg, metrics: { ...calm(), r2_storage_bytes: { unavailable: 'HTTP 403' } }, state: r.state, now: at(13), deliver })).alerts.length, 0, 'not repeated the same day');
  const blind = await run({ cfg, metrics: unk, state: {}, now: at(12), deliver }); assert.equal(blind.exit, 2); assert.ok(blind.failures.some((f) => /blind/.test(f)));
});

test('anomaly: a day metric that jumps by 10 % of its limit between two runs of the same UTC day alerts even far below every threshold; another day or a smaller step does not', async () => {
  const L = cfg.metrics.d1_rows_read.limit, sent = [], deliver = async (t) => sent.push(t);
  const first = await run({ cfg, metrics: { ...calm(), d1_rows_read: { used: 100000 } }, state: {}, now: at(10), deliver }); assert.equal(sent.length, 0);
  const jump = await run({ cfg, metrics: { ...calm(), d1_rows_read: { used: 100000 + L * 0.12 } }, state: first.state, now: at(11), deliver });
  assert.deepEqual(jump.alerts.map((a) => a.kind), ['anomaly']); assert.match(sent[0], /consumo anómalo.*D1 rows read/); assert.equal(jump.findings.find((f) => f.id === 'd1_rows_read').level, 'ok', 'still below every threshold');
  const small = await run({ cfg, metrics: { ...calm(), d1_rows_read: { used: 100000 + L * 0.05 } }, state: first.state, now: at(11), deliver }); assert.equal(small.alerts.length, 0);
  const nextDay = await run({ cfg, metrics: { ...calm(), d1_rows_read: { used: 100000 + L * 0.12 } }, state: first.state, now: new Date(Date.UTC(2026, 9, 28, 11)), deliver }); assert.equal(nextDay.alerts.length, 0, 'the counter reset at 00:00 UTC is not an anomaly');
});

test('watchdog: a monitor with a recent success is alive; a stale one, none at all, or an unreachable API is NOT ok', async () => {
  const mk = (runs, ok = true, status = 200) => async () => ({ ok, status, json: async () => ({ workflow_runs: runs }) }), gh = { token: 'G', repo: 'o/r' }, now = at(12);
  const age = (h) => [{ updated_at: new Date(now.getTime() - h * 3600000).toISOString() }];
  assert.equal((await watchdog({ fetchImpl: mk(age(1)), github: gh, cfg, now })).ok, true);
  const stale = await watchdog({ fetchImpl: mk(age(5)), github: gh, cfg, now }); assert.equal(stale.ok, false); assert.match(stale.reason, /5\.0 h ago/);
  assert.equal((await watchdog({ fetchImpl: mk([]), github: gh, cfg, now })).ok, false);
  const down = await watchdog({ fetchImpl: mk([], false, 503), github: gh, cfg, now }); assert.equal(down.ok, false); assert.match(down.reason, /HTTP 503/);
});
