import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { evaluateAlerts } from '../src/alerts.js';
import { dashboard, report, toCsv, toHtml, DASHBOARDS } from '../src/dashboards.js';
import { importCsv } from '../src/cost.js';
import { createLead } from '../src/crm.js';
import { ingest } from '../src/gh_collector.js';
import { validate } from '../src/schema.js';
import { world } from './helpers.js';

const ALERT = JSON.parse(readFileSync(new URL('../../contracts/v1/alert.schema.json', import.meta.url), 'utf8'));
const byId = (r) => Object.fromEntries(r.alerts.map((a) => [a.rule_id, a]));
const day = (w, d, tenant, extra) => w.db.prepare("INSERT INTO analytics_daily(day,tenant_id,channel,product,operation,status_class,commercial_mode,requests,units,b2,b8) VALUES (?,?,'rest','intel',?,?,'FREE_LAUNCH',?,?,?,?)")
  .bind(d, tenant, extra.op ?? 'intel.hash', extra.sc ?? '2xx', extra.requests, extra.units ?? 0, extra.fast ?? extra.requests, extra.slow ?? 0).run();

test('with no data every alert is INSUFFICIENT_DATA (never silent, never firing) and all conform to the alert contract', async () => {
  const w = await world({ now: '2026-10-23T10:00:00Z' }); const r = await evaluateAlerts(w.db, w.clock);
  assert.equal(r.firing, 0); for (const a of r.alerts) { assert.deepEqual(validate(ALERT, a), [], a.rule_id); }
  for (const id of ['github.collector_stale', 'downloads.anomaly', 'api.error_rate', 'api.latency_p95', 'telemetry.undercount']) assert.equal(byId(r)[id].state, 'INSUFFICIENT_DATA', id);
  assert.match(r.delivery, /never sent/);
});
test('stale or failing collector fires; a healthy one does not', async () => {
  const w = await world({ now: '2026-10-23T10:00:00Z' });
  await w.db.prepare("INSERT INTO gh_sync(id,last_attempt_at,last_success_at,last_status,consecutive_failures,first_success_at) VALUES (1,'2026-10-23T09:00:00Z','2026-10-23T06:00:00Z','failed',3,'2026-10-01T00:00:00Z')").run();
  let r = byId(await evaluateAlerts(w.db, w.clock)); assert.equal(r['github.collector_stale'].state, 'FIRING'); assert.equal(r['github.collector_failing'].state, 'FIRING');
  await w.db.prepare("UPDATE gh_sync SET last_success_at='2026-10-23T09:30:00Z', consecutive_failures=0, last_status='ok'").run();
  r = byId(await evaluateAlerts(w.db, w.clock)); assert.equal(r['github.collector_stale'].state, 'OK'); assert.equal(r['github.collector_failing'].state, 'OK');
});
test('API alerts need volume; 5xx rows fire the error-rate rule only above the threshold; slow buckets fire p95', async () => {
  const w = await world({ now: '2026-10-23T10:00:00Z' }); await w.tenant('t1');
  await day(w, '2026-10-23', 't1', { requests: 50, op: 'ok' }); assert.equal(byId(await evaluateAlerts(w.db, w.clock))['api.error_rate'].state, 'INSUFFICIENT_DATA');
  await day(w, '2026-10-23', 't1', { requests: 250, op: 'ok2' }); await day(w, '2026-10-22', 't1', { requests: 20, sc: '5xx', op: 'bad' });
  let r = byId(await evaluateAlerts(w.db, w.clock)); assert.equal(r['api.error_rate'].state, 'FIRING'); assert.equal(r['api.error_rate'].value, +(20 / 320).toFixed(4)); assert.equal(r['api.latency_p95'].state, 'OK');
  await w.db.prepare("UPDATE analytics_daily SET requests = 5, b2 = 5 WHERE status_class = '5xx'").run(); assert.equal(byId(await evaluateAlerts(w.db, w.clock))['api.error_rate'].state, 'OK');
  await day(w, '2026-10-23', 't1', { requests: 100, fast: 0, slow: 100, op: 'slow' }); assert.equal(byId(await evaluateAlerts(w.db, w.clock))['api.latency_p95'].state, 'FIRING');
});
test('a download spike against a real baseline fires; a cold start never does', async () => {
  const w = await world({ now: '2026-10-23T10:00:00Z' });
  await w.db.prepare("INSERT INTO gh_sync(id,last_attempt_at,last_success_at,last_status,first_success_at) VALUES (1,'2026-10-23T09:50:00Z','2026-10-23T09:50:00Z','ok','2026-10-01T00:00:00Z')").run();
  await w.db.prepare("INSERT INTO gh_releases(release_id,repo,tag,first_observed_at,last_observed_at) VALUES (1,'r','rules-20261001-1','2026-10-01T00:00:00Z','2026-10-23T00:00:00Z')").run();
  await w.db.prepare("INSERT INTO gh_assets(asset_id,release_id,name,kind,size,first_observed_at,last_observed_at,last_count) VALUES (10,1,'rules-release.tar.gz','bundle',1,'2026-10-01T00:00:00Z','2026-10-23T00:00:00Z',0)").run();
  let c = 0; for (let d = 1; d <= 22; d++) { const prev = c; c += 5 + (d % 3); await w.db.prepare("INSERT INTO gh_observations(asset_id,observed_at,download_count,prev_observed_at,prev_count,kind) VALUES (10,?,?,?,?, 'delta')").bind(`2026-10-${String(d).padStart(2, '0')}T12:00:00Z`, c, '2026-09-30T00:00:00Z', prev).run(); }
  assert.equal(byId(await evaluateAlerts(w.db, w.clock))['downloads.anomaly'].state, 'OK');
  await w.db.prepare("INSERT INTO gh_observations(asset_id,observed_at,download_count,prev_observed_at,prev_count,kind) VALUES (10,'2026-10-23T08:00:00Z',?,?,?,'delta')").bind(c + 400, '2026-10-22T12:00:00Z', c).run();
  const a = byId(await evaluateAlerts(w.db, w.clock))['downloads.anomaly']; assert.equal(a.state, 'FIRING'); assert.equal(a.value, 400);
});
test('telemetry.undercount fires when analytics saw fewer metered units than the authoritative ledger', async () => {
  const w = await world({ now: '2026-10-23T10:00:00Z' }); await w.tenant('t1');
  await w.db.prepare("INSERT INTO usage_events(usage_event_id,tenant_id,api_key_id,request_id,operation,pricing_version,units,unit_price_micros,billable_micros,commercial_mode,policy_version,currency,request_status,billing_status,idem_key,created_at) VALUES ('u1','t1','k1','r1','intel.hash','p1',10,0,0,'FREE_LAUNCH',1,'USD','completed','none','i1','2026-10-23T09:00:00Z')").run();
  await day(w, '2026-10-23', 't1', { requests: 3, units: 4 }); assert.equal(byId(await evaluateAlerts(w.db, w.clock))['telemetry.undercount'].state, 'FIRING');
  await w.db.prepare("UPDATE analytics_daily SET units = 10").run(); assert.equal(byId(await evaluateAlerts(w.db, w.clock))['telemetry.undercount'].state, 'OK');
});

test('every dashboard on an empty system shows explicit empty states, never zeros, and Stripe is not simulated', async () => {
  const w = await world({ now: '2026-10-23T10:00:00Z' });
  for (const id of DASHBOARDS) { const d = await dashboard(w.db, w.clock, id); assert.equal(d.schema, 'macguard.dashboard/1'); assert.ok(d.panels.length > 0, id);
    for (const p of d.panels) { assert.ok(p.state && p.source, `${id}.${p.id}`); if (['NO_DATA', 'NOT_APPLICABLE', 'NOT_INSTRUMENTED', 'NOT_YET_OBSERVABLE'].includes(p.state)) assert.equal(p.data, null, `${id}.${p.id} must not show a value`); } }
  const cost = await dashboard(w.db, w.clock, 'cost'); assert.equal(cost.panels.find((p) => p.id === 'stripe').state, 'NOT_INSTRUMENTED');
  await assert.rejects(dashboard(w.db, w.clock, 'nope'), /Unknown dashboard/);
});
test('with real rows the panels carry values; tenant dashboards never expose another tenant, GitHub, CRM or platform alerts', async () => {
  const w = await world({ now: '2026-10-23T10:00:00Z' }); await w.tenant('t1'); await w.tenant('t2');
  await day(w, '2026-10-22', 't1', { requests: 7 }); await day(w, '2026-10-22', 't2', { requests: 11 });
  await importCsv(w.db, w.clock, 'period,service,amount,currency,tenant_id\n2026-10,r2,1.5,USD,t2\n', { provider: 'cloudflare' }); await createLead(w.db, w.clock, { id: 'a' }, { org_name: 'Acme' });
  const all = await dashboard(w.db, w.clock, 'api'), t1 = await dashboard(w.db, w.clock, 'api', { tenantId: 't1' });
  assert.equal(all.panels.find((p) => p.id === 'requests').data.rest.requests, 18); assert.equal(t1.panels.find((p) => p.id === 'requests').data.rest.requests, 7);
  assert.equal((await dashboard(w.db, w.clock, 'cost', { tenantId: 't1' })).panels.find((p) => p.id === 'lines').state, 'NO_DATA', 't1 cannot see the cost allocated to t2');
  assert.equal((await dashboard(w.db, w.clock, 'cost')).panels.find((p) => p.id === 'lines').data.length, 1);
  assert.equal((await dashboard(w.db, w.clock, 'crm', { tenantId: 't1' })).panels[0].state, 'NOT_APPLICABLE'); assert.equal((await dashboard(w.db, w.clock, 'crm')).panels[0].data.NEW_LEAD, 1);
  assert.ok(!(await dashboard(w.db, w.clock, 'overview', { tenantId: 't1' })).panels.some((p) => p.id === 'alerts'));
  assert.equal((await dashboard(w.db, w.clock, 'overview')).panels.find((p) => p.id === 'billed').data, 0, 'billed revenue is a real zero here: telemetry exists and billed nothing');
});
test('reports render as JSON, CSV and HTML with sources; CSV neutralises formulas and HTML escapes', async () => {
  const w = await world({ now: '2026-10-23T10:00:00Z' }); await w.tenant('t1'); await day(w, '2026-10-22', 't1', { requests: 5 });
  await createLead(w.db, w.clock, { id: 'a' }, { org_name: '=HYPERLINK("http://x")' }); await w.db.prepare("UPDATE leads SET org_name = '<script>alert(1)</script>'").run();
  for (const kind of ['daily', 'weekly', 'monthly']) { const r = await report(w.db, w.clock, kind); assert.equal(r.schema, 'macguard.report/1'); assert.ok(r.sections.length); assert.ok(toCsv(r).split('\n')[0].startsWith('dashboard,panel')); }
  assert.ok(!toHtml(await report(w.db, w.clock, 'monthly')).includes('<script>alert')); assert.match(toHtml(await report(w.db, w.clock, 'daily')), /<title>MacGuard daily report<\/title>/);
  const csv = toCsv({ id: 'x', panels: [{ id: 'p', state: 'REAL_VERIFIED', source: 's', accuracy: null, data: { k: '=1+1', l: '+cmd', m: 'a,b' } }] }); assert.match(csv, /,k,'=1\+1/); assert.match(csv, /,l,'\+cmd/); assert.match(csv, /"a,b"/);
  await assert.rejects(report(w.db, w.clock, 'yearly'), /daily, weekly or monthly/);
});

test('Community panels give day/week/month/observed-year windows with their real coverage, bundle only, and null before the first observation', async () => {
  const w = await world({ now: '2026-10-23T12:00:00Z' });
  await w.db.prepare("INSERT INTO gh_sync(id,last_attempt_at,last_success_at,last_status,first_success_at) VALUES (1,'2026-10-23T11:50:00Z','2026-10-23T11:50:00Z','ok','2026-10-13T12:00:00Z')").run();   // observed for 10 days
  await w.db.prepare("INSERT INTO gh_releases(release_id,repo,tag,first_observed_at,last_observed_at) VALUES (1,'o/r','rules-20261001-1','2026-10-13T12:00:00Z','2026-10-23T00:00:00Z')").run();
  await w.db.prepare("INSERT INTO gh_assets(asset_id,release_id,name,kind,size,first_observed_at,last_observed_at,last_count) VALUES (10,1,'rules-release.tar.gz','bundle',1,'x','x',0),(11,1,'manifest.json','manifest',1,'x','x',0)").run();
  const obs = (asset, at, n, prev) => w.db.prepare("INSERT INTO gh_observations(asset_id,observed_at,download_count,prev_count,kind) VALUES (?,?,?,?,'delta')").bind(asset, at, prev + n, prev).run();
  await obs(10, '2026-10-23T08:00:00Z', 7, 100); await obs(10, '2026-10-20T08:00:00Z', 5, 90); await obs(10, '2026-10-14T08:00:00Z', 3, 80); await obs(11, '2026-10-23T09:00:00Z', 400, 0);       // the manifest growth must not appear
  const d = await dashboard(w.db, w.clock, 'downloads'), win = Object.fromEntries(d.panels.find((p) => p.id === 'observed_windows').data.map((x) => [x.window, x]));
  assert.equal(win.day.observed, 7); assert.equal(win.week.observed, 12); assert.equal(win.month.observed, 15); assert.equal(win.year_observed.observed, 15, 'the manifest growth (400) is excluded');
  assert.equal(win.day.coverage, 1); assert.equal(win.week.coverage, 1); assert.equal(win.month.coverage, 0.3333); assert.ok(win.year_observed.coverage < 0.03); assert.equal(win.month.state, 'PARTIAL_COVERAGE'); assert.equal(win.week.state, 'REAL_VERIFIED');
  const tr = d.panels.find((p) => p.id === 'trend').data; assert.equal(tr.length, 30); assert.equal(tr[0].observed, null, 'before the first observation: unknown'); assert.equal(tr.at(-1).day, '2026-10-23'); assert.equal(tr.at(-1).observed, 7); assert.equal(tr.find((x) => x.day === '2026-10-21').observed, 0, 'inside coverage and quiet = a real zero');
});
test('the comparison dashboard shows both products with their own unit, refuses to add them, labels data classes, and hides platform data from tenants', async () => {
  const w = await world({ now: '2026-10-23T12:00:00Z' }); const empty = await dashboard(w.db, w.clock, 'comparison');
  assert.equal(empty.data_class, 'real'); assert.deepEqual(empty.panels.filter((p) => p.state === 'NO_DATA').every((p) => p.data_class === 'absent' && p.data === null), true);
  assert.ok(empty.panels.find((p) => p.id === 'definitions').data.some((t) => /counts people/i.test(t))); assert.equal(empty.panels.find((p) => p.id === 'billed').data, null, 'no telemetry: not zero');
  await w.tenant('t1'); await w.db.prepare("INSERT INTO gh_sync(id,last_attempt_at,last_success_at,last_status,first_success_at) VALUES (1,'2026-10-23T11:50:00Z','2026-10-23T11:50:00Z','ok','2026-10-22T12:00:00Z')").run();
  const syn = await dashboard(w.db, w.clock, 'comparison', { dataClass: 'synthetic' }); assert.equal(syn.data_class, 'synthetic'); assert.ok(syn.panels.some((p) => p.data_class === 'synthetic') && syn.panels.every((p) => ['synthetic', 'absent'].includes(p.data_class)));
  const t = await dashboard(w.db, w.clock, 'comparison', { tenantId: 't1' }); assert.equal(t.panels.find((p) => p.id === 'community').state, 'NOT_APPLICABLE');
});

test('an intermittent collector (most runs fail, never three in a row) is caught by the reliability rule, which waits for enough runs', async () => {
  const w = await world({ now: '2026-10-24T05:00:00Z' }); const log = (at, status) => w.db.prepare('INSERT INTO gh_sync_log(observed_at,releases,assets,status) VALUES (?,?,?,?)').bind(at, status === 'ok' ? 3 : 0, status === 'ok' ? 24 : 0, status).run();
  await w.db.prepare("INSERT INTO gh_sync(id,last_attempt_at,last_success_at,last_status,consecutive_failures,first_success_at) VALUES (1,'2026-10-24T04:17:59Z','2026-10-24T04:17:59Z','ok',0,'2026-10-23T19:27:39Z')").run();
  const rel = async () => byId(await evaluateAlerts(w.db, w.clock))['github.collector_reliability'];
  for (const [at, st] of [['2026-10-24T00:17:59Z', 'ok'], ['2026-10-24T01:17:59Z', 'github_rate_limited']]) await log(at, st); assert.equal((await rel()).state, 'INSUFFICIENT_DATA');
  for (const [at, st] of [['2026-10-24T02:18:00Z', 'github_rate_limited'], ['2026-10-24T03:18:00Z', 'github_rate_limited'], ['2026-10-24T04:17:59Z', 'ok'], ['2026-10-23T23:18:00Z', 'github_rate_limited']]) await log(at, st);
  const r = await rel(); assert.equal(r.state, 'FIRING'); assert.equal(r.value, 0.333); assert.equal(byId(await evaluateAlerts(w.db, w.clock))['github.collector_failing'].state, 'OK', 'the consecutive-failure rule alone would have stayed silent');
});

test('a rejected GitHub token raises its own alert, which clears when a later run succeeds', async () => {
  const w = await world({ now: '2026-10-24T05:00:00Z' });
  await w.db.prepare("INSERT INTO gh_sync(id,last_attempt_at,last_success_at,last_status,consecutive_failures,first_success_at) VALUES (1,'2026-10-24T04:17:59Z','2026-10-23T19:27:39Z','github_unauthorized',1,'2026-10-23T19:27:39Z')").run();
  assert.equal(byId(await evaluateAlerts(w.db, w.clock))['github.token_rejected'].state, 'FIRING');
  await w.db.prepare("UPDATE gh_sync SET last_status = 'ok', consecutive_failures = 0").run(); assert.equal(byId(await evaluateAlerts(w.db, w.clock))['github.token_rejected'].state, 'OK');
});
