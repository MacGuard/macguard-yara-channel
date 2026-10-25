import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { kpis, addDays } from '../src/kpi.js';
import { KPI_CATALOG, ACCURACY } from '../src/kpi_catalog.js';
import { world } from './helpers.js';

const act = (w, day, tenant, kind, actor, premium = 0) => w.db.batch([
  w.db.prepare('INSERT OR IGNORE INTO activity_daily(day,tenant_id,actor_kind,actor_hash,premium) VALUES (?,?,?,?,?)').bind(day, tenant, kind, actor, premium),
  w.db.prepare('INSERT OR IGNORE INTO actor_first_seen(tenant_id,actor_kind,actor_hash,first_day) VALUES (?,?,?,?)').bind(tenant, kind, actor, day),
  w.db.prepare('INSERT OR IGNORE INTO tenant_first_seen(tenant_id,first_day) VALUES (?,?)').bind(tenant, day),
  w.db.prepare("INSERT INTO analytics_daily(day,tenant_id,channel,product,operation,status_class,commercial_mode,requests,b2) VALUES (?,?,'rest','intel','intel.hash','2xx','FREE_LAUNCH',1,1) ON CONFLICT(day,tenant_id,channel,product,operation,status_class,commercial_mode) DO UPDATE SET requests=requests+1,b2=b2+1").bind(day, tenant, ),
]);

test('the catalog is complete, uses known accuracy classes, and the committed contract matches the code', () => {
  assert.equal(new Set(KPI_CATALOG.map((k) => k.metric_id)).size, KPI_CATALOG.length);
  for (const k of KPI_CATALOG) { for (const f of ['metric_id', 'definition', 'time_window', 'source', 'accuracy', 'limitations', 'owner']) assert.ok(k[f], `${k.metric_id}.${f}`); assert.ok(ACCURACY.includes(k.accuracy)); assert.ok('numerator' in k && 'denominator' in k); }
  execFileSync('node', [new URL('../tools/gen_kpi_catalog.mjs', import.meta.url).pathname, '--check']);
});

test('no telemetry is NO_DATA, never zero; humans are not instrumented; payment states are not applicable in FREE_LAUNCH', async () => {
  const w = await world({ now: '2026-10-23T10:00:00Z' }); const k = await kpis(w.db, w.clock);
  for (const id of ['dau', 'mau', 'active_orgs_30d', 'requests_by_channel', 'units_consumed', 'retention_d7']) { assert.equal(k[id].state, 'NO_DATA', id); assert.equal(k[id].value, null, id); }
  assert.equal(k.active_humans.state, 'NOT_INSTRUMENTED'); assert.equal(k.paid_customers.state, 'NOT_APPLICABLE'); assert.equal(k.funnel.value.PAID_ACTIVE.state, 'NOT_APPLICABLE'); assert.equal(k.funnel.value.VISITOR.state, 'NOT_INSTRUMENTED');
});

test('activity, cohorts and retention are computed from real rows, excluding the left-censored first day and immature cohorts', async () => {
  const w = await world({ now: '2026-10-23T10:00:00Z' }); await w.tenant('t1'); await w.tenant('t2');
  await act(w, '2026-09-01', 't1', 'api_key_client', 'A');                                          // first telemetry day: everyone looks new, so A is not a cohort member
  for (const d of ['2026-09-10', '2026-09-17', '2026-10-10', '2026-10-23']) await act(w, d, 't1', 'api_key_client', 'B');
  await act(w, '2026-09-11', 't2', 'authenticated_service', 'C');
  const k = await kpis(w.db, w.clock);
  assert.deepEqual(k.dau.value.by_kind, { authenticated_service: 0, api_key_client: 1, device_identity: 0 }); assert.equal(k.dau.value.total, 1);
  assert.equal(k.mau.value.total, 1, 'only B was active in the last 30 days');
  assert.equal(k.retention_d7.value.cohort_size, 2); assert.equal(k.retention_d7.value.retained, 1);
  assert.equal(k.retention_d30.value.cohort_size, 2); assert.equal(k.retention_d30.value.retained, 1, 'B was active on 09-10 + 30 = 10-10');
  assert.equal(k.retention_d90.state, 'NOT_YET_OBSERVABLE'); assert.equal(k.retention_d90.value, null);
  assert.equal(k.recurring_actors_30d.value, 1); assert.equal(k.active_orgs_30d.value, 1);
  assert.equal(k.churned_orgs_30d.value.churned, 1, 't2 was active before the window and silent since'); assert.equal(k.churned_orgs_30d.value.base, 2);
  assert.equal(k.mau.state, 'REAL_VERIFIED'); const early = await kpis(w.db, w.clock, { asOf: '2026-08-20' }); assert.equal(early.mau.state, 'PARTIAL_COVERAGE');
});

test('a cohort day whose day+N is still today (an incomplete day) is not counted', async () => {
  const w = await world({ now: '2026-10-23T10:00:00Z' }); await w.tenant('t1');
  await act(w, '2026-10-01', 't1', 'api_key_client', 'X'); await act(w, '2026-10-16', 't1', 'api_key_client', 'Y'); await act(w, '2026-10-16', 't1', 'api_key_client', 'Z');   // Y, Z first seen 10-16: D7 = 10-23 = today, incomplete
  const k = await kpis(w.db, w.clock); assert.equal(k.retention_d7.state, 'NOT_YET_OBSERVABLE');
});

test('Premium adoption is usage, not payment, and a tenant filter never leaks another tenant', async () => {
  const w = await world({ now: '2026-10-23T10:00:00Z' }); await w.tenant('t1'); await w.tenant('t2');
  await act(w, '2026-10-22', 't1', 'api_key_client', 'P', 1); await act(w, '2026-10-22', 't1', 'api_key_client', 'N', 0); await act(w, '2026-10-22', 't2', 'api_key_client', 'Q', 1);
  const all = await kpis(w.db, w.clock), t1 = await kpis(w.db, w.clock, { tenantId: 't1' });
  assert.equal(all.premium_actors_30d.value, 2); assert.equal(all.premium_adoption_rate.value.rate, 2 / 3); assert.equal(all.paid_customers.state, 'NOT_APPLICABLE');
  assert.equal(t1.premium_actors_30d.value, 1); assert.equal(t1.mau.value.total, 2); assert.equal(t1.active_orgs_30d.value, 1); assert.equal(t1.requests_by_channel.value.rest.requests, 2);
  assert.equal(t1.funnel.value.REGISTERED.count, 1); assert.equal(t1.funnel.value.PREMIUM_USER.count, 0, 'first_premium_day is only set by real premium requests');
});

test('latency percentiles need volume; billed is exactly zero and theoretical is labelled not revenue', async () => {
  const w = await world({ now: '2026-10-23T10:00:00Z' }); await w.tenant('t1');
  await act(w, '2026-10-22', 't1', 'api_key_client', 'A'); let k = await kpis(w.db, w.clock); assert.equal(k.latency_ms.state, 'NOT_YET_OBSERVABLE');
  await w.db.prepare("UPDATE analytics_daily SET requests = 200, b2 = 200, units = 7, theoretical_micros = 70000").run(); k = await kpis(w.db, w.clock);
  assert.deepEqual([k.latency_ms.value.p50, k.latency_ms.value.p99], [25, 25]); assert.equal(k.latency_ms.accuracy, 'ESTIMATED'); assert.equal(k.billed_micros.value, 0); assert.equal(k.theoretical_value_micros.note, 'not revenue');
});

test('addDays crosses month and leap boundaries', () => { assert.equal(addDays('2026-10-31', 1), '2026-11-01'); assert.equal(addDays('2028-03-01', -1), '2028-02-29'); });
