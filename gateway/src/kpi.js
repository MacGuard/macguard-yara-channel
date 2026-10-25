// KPI engine over the incremental aggregates. Every value says what it is (metric_id -> kpi_catalog), how sure we are (accuracy), what state the data is in, and for which window.
// Rules: no data is NO_DATA (never zero); an immature cohort is NOT_YET_OBSERVABLE (never an invented period); a window that starts before telemetry did is PARTIAL_COVERAGE.
import { KPI_IDS } from './kpi_catalog.js';
import { quantile } from './analytics.js';
import { iso } from './util.js';

export const addDays = (d, n) => { const t = new Date(d + 'T00:00:00Z'); t.setUTCDate(t.getUTCDate() + n); return t.toISOString().slice(0, 10); };
const KINDS = ['authenticated_service', 'api_key_client', 'device_identity'];

export async function kpis(db, clock, { asOf = null, tenantId = null, mode = 'FREE_LAUNCH' } = {}) {
  const today = clock().toISOString().slice(0, 10), asOfDay = asOf ?? today, updated = iso(clock());
  const tq = tenantId ? ' AND tenant_id = ?' : '', ta = tenantId ? [tenantId] : [];
  const all = (sql, ...a) => db.prepare(sql).bind(...a).all().then((r) => r.results);
  const one = (sql, ...a) => db.prepare(sql).bind(...a).first();
  const start = (await one('SELECT MIN(day) d FROM analytics_daily WHERE tenant_id <> \'-\'' + tq, ...ta))?.d ?? null;       // first day with any telemetry (for this scope)
  const out = {};
  const put = (id, value, { state = 'REAL_VERIFIED', accuracy, window = null, note = null } = {}) => {
    if (!KPI_IDS.has(id)) throw new Error('metric without a catalog entry: ' + id);
    out[id] = { metric_id: id, value, state, window, as_of: asOfDay, last_updated: updated, ...(accuracy ? { accuracy } : {}), ...(note ? { note } : {}) };
  };
  const cover = (from) => (start === null ? 'NO_DATA' : from < start ? 'PARTIAL_COVERAGE' : 'REAL_VERIFIED');
  const win = (days) => ({ from: addDays(asOfDay, -(days - 1)), to: asOfDay });

  // ---- activity -----------------------------------------------------------------------------------------------------------------------------------------
  const active = async (from, to) => {
    const rows = await all(`SELECT actor_kind k, COUNT(DISTINCT actor_hash) n FROM activity_daily WHERE day BETWEEN ? AND ?${tq} GROUP BY actor_kind`, from, to, ...ta);
    const by = Object.fromEntries(KINDS.map((k) => [k, 0])); for (const r of rows) by[r.k] = r.n;
    return { by_kind: by, total: Object.values(by).reduce((a, b) => a + b, 0) };
  };
  for (const [id, days] of [['dau', 1], ['wau', 7], ['mau', 30]]) { const w = win(days); put(id, start === null ? null : await active(w.from, w.to), { state: cover(w.from), accuracy: 'EXACT', window: w }); }
  put('active_humans', null, { state: 'NOT_INSTRUMENTED', accuracy: 'UNKNOWN' });
  const w30 = win(30), w60 = win(60);
  put('active_orgs_30d', start === null ? null : (await one(`SELECT COUNT(DISTINCT tenant_id) n FROM activity_daily WHERE day BETWEEN ? AND ?${tq}`, w30.from, w30.to, ...ta)).n, { state: cover(w30.from), accuracy: 'EXACT', window: w30 });
  const rec = await one(`SELECT COUNT(*) n FROM (SELECT actor_hash FROM activity_daily WHERE day BETWEEN ? AND ?${tq} GROUP BY tenant_id, actor_kind, actor_hash HAVING COUNT(*) >= 2)`, w30.from, w30.to, ...ta);
  put('recurring_actors_30d', start === null ? null : rec.n, { state: cover(w30.from), accuracy: 'EXACT', window: w30 });

  // ---- cohorts ------------------------------------------------------------------------------------------------------------------------------------------
  // Cohort = actors whose first day is `c`. Retained at Dn = active exactly on c+n. A cohort counts only if c+n is a COMPLETE day (< today) and c is after the first telemetry day.
  const lastComplete = addDays(today, -1) < asOfDay ? addDays(today, -1) : asOfDay;
  for (const n of [7, 30, 90]) {
    const maxCohort = addDays(lastComplete, -n), minCohort = start === null ? null : addDays(start, 1);
    if (start === null || maxCohort < minCohort) { put(`retention_d${n}`, null, { state: start === null ? 'NO_DATA' : 'NOT_YET_OBSERVABLE', accuracy: 'EXACT', note: start === null ? undefined : `first eligible cohort day ${minCohort} needs day+${n} (${addDays(minCohort, n)}) to be complete` }); continue; }
    const r = await one(`SELECT COUNT(*) size, SUM(EXISTS (SELECT 1 FROM activity_daily a WHERE a.tenant_id = f.tenant_id AND a.actor_kind = f.actor_kind AND a.actor_hash = f.actor_hash AND a.day = date(f.first_day, '+${n} days'))) kept
      FROM actor_first_seen f WHERE f.first_day BETWEEN ? AND ?${tq.replace('tenant_id', 'f.tenant_id')}`, minCohort, maxCohort, ...ta);
    const later = r.size ? null : await one(`SELECT 1 x FROM actor_first_seen WHERE first_day > ?${tq} LIMIT 1`, maxCohort, ...ta);       // actors exist, but all too recent to have a day+n yet
    put(`retention_d${n}`, r.size ? { cohort_size: r.size, retained: r.kept ?? 0, rate: (r.kept ?? 0) / r.size, cohort_days: { from: minCohort, to: maxCohort } } : null,
      { state: r.size ? 'REAL_VERIFIED' : later ? 'NOT_YET_OBSERVABLE' : 'NO_DATA', accuracy: 'EXACT', window: { from: minCohort, to: maxCohort } });
  }
  { // monthly retention: previous calendar month -> as-of month
    const m = asOfDay.slice(0, 7), pm = addDays(m + '-01', -1).slice(0, 7), pFrom = pm + '-01', pTo = addDays(m + '-01', -1);
    if (start === null || start > pFrom) put('monthly_retention', null, { state: start === null ? 'NO_DATA' : 'NOT_YET_OBSERVABLE', accuracy: 'EXACT', note: 'the previous calendar month is not fully covered by telemetry' });
    else {
      const r = await one(`SELECT COUNT(*) base, SUM(EXISTS (SELECT 1 FROM activity_daily b WHERE b.tenant_id = a.tenant_id AND b.actor_kind = a.actor_kind AND b.actor_hash = a.actor_hash AND b.day BETWEEN ? AND ?)) kept
        FROM (SELECT DISTINCT tenant_id, actor_kind, actor_hash FROM activity_daily WHERE day BETWEEN ? AND ?${tq}) a`, m + '-01', asOfDay, pFrom, pTo, ...ta);
      put('monthly_retention', r.base ? { base: r.base, retained: r.kept ?? 0, rate: (r.kept ?? 0) / r.base, previous_month: pm, month: m } : null, { state: r.base ? 'REAL_VERIFIED' : 'NO_DATA', accuracy: 'EXACT', window: { from: pFrom, to: asOfDay } });
    }
  }
  { // churn / reactivation at tenant level (inactivity, not cancellation)
    const before = addDays(w30.from, -1);
    const ever = await one(`SELECT COUNT(*) n FROM (SELECT tenant_id FROM activity_daily WHERE day <= ?${tq} GROUP BY tenant_id)`, before, ...ta);
    const silent = await one(`SELECT COUNT(*) n FROM (SELECT tenant_id FROM activity_daily WHERE day <= ?${tq} GROUP BY tenant_id) e WHERE NOT EXISTS (SELECT 1 FROM activity_daily x WHERE x.tenant_id = e.tenant_id AND x.day BETWEEN ? AND ?)`, before, ...ta, w30.from, w30.to);
    put('churned_orgs_30d', ever.n ? { churned: silent.n, base: ever.n } : null, { state: ever.n ? cover(w60.from) : (start === null ? 'NO_DATA' : 'NOT_YET_OBSERVABLE'), accuracy: 'EXACT', window: w30 });
    const prevTo = before, prevFrom = addDays(w30.from, -30);
    const re = await one(`SELECT COUNT(*) n FROM (SELECT DISTINCT tenant_id FROM activity_daily WHERE day BETWEEN ? AND ?${tq}) c
      WHERE EXISTS (SELECT 1 FROM activity_daily e WHERE e.tenant_id = c.tenant_id AND e.day < ?) AND NOT EXISTS (SELECT 1 FROM activity_daily p WHERE p.tenant_id = c.tenant_id AND p.day BETWEEN ? AND ?)`, w30.from, w30.to, ...ta, prevFrom, prevFrom, prevTo);
    put('reactivated_orgs_30d', start === null ? null : re.n, { state: cover(prevFrom), accuracy: 'EXACT', window: { from: prevFrom, to: asOfDay } });
  }
  { // time to first use
    const rows = await all(`SELECT t.created_at c, f.first_day d FROM tenant_first_seen f JOIN tenants t ON t.id = f.tenant_id WHERE substr(t.created_at,1,10) >= COALESCE(?, '9999') ${tenantId ? 'AND t.id = ?' : ''}`, start, ...ta);
    const days = rows.map((r) => Math.round((Date.parse(r.d + 'T00:00:00Z') - Date.parse(r.c.slice(0, 10) + 'T00:00:00Z')) / 86400000)).sort((a, b) => a - b);
    put('time_to_first_use_days', days.length ? { median: days.length % 2 ? days[(days.length - 1) / 2] : (days[days.length / 2 - 1] + days[days.length / 2]) / 2, tenants: days.length } : null, { state: days.length ? 'REAL_VERIFIED' : (start === null ? 'NO_DATA' : 'NOT_YET_OBSERVABLE'), accuracy: 'EXACT' });
  }

  // ---- premium adoption (usage, never payment) ------------------------------------------------------------------------------------------------------------
  const pa = start === null ? null : (await one(`SELECT COUNT(DISTINCT actor_hash) n FROM activity_daily WHERE premium = 1 AND day BETWEEN ? AND ?${tq}`, w30.from, w30.to, ...ta)).n;
  const po = start === null ? null : (await one(`SELECT COUNT(DISTINCT tenant_id) n FROM activity_daily WHERE premium = 1 AND day BETWEEN ? AND ?${tq}`, w30.from, w30.to, ...ta)).n;
  put('premium_actors_30d', pa, { state: cover(w30.from), accuracy: 'EXACT', window: w30 }); put('premium_orgs_30d', po, { state: cover(w30.from), accuracy: 'EXACT', window: w30 });
  const mauTotal = out.mau.value?.total ?? 0;
  put('premium_adoption_rate', start === null || !mauTotal ? null : { premium_actors: pa, active_actors: mauTotal, rate: pa / mauTotal }, { state: start === null || !mauTotal ? 'NO_DATA' : cover(w30.from), accuracy: 'EXACT', window: w30 });
  if (mode === 'FREE_LAUNCH') put('paid_customers', null, { state: 'NOT_APPLICABLE', accuracy: 'EXACT', note: 'FREE_LAUNCH: nothing is billed' });
  else put('paid_customers', (await one(`SELECT COUNT(*) n FROM tenants WHERE plan <> 'community' AND status = 'active'${tenantId ? ' AND id = ?' : ''}`, ...ta)).n, { accuracy: 'EXACT' });

  // ---- consumption ----------------------------------------------------------------------------------------------------------------------------------------
  const w = win(30);
  const rows = await all(`SELECT channel, status_class, SUM(requests) r, SUM(units) u, SUM(billable_micros) bm, SUM(theoretical_micros) tm, SUM(b0) b0, SUM(b1) b1, SUM(b2) b2, SUM(b3) b3, SUM(b4) b4, SUM(b5) b5, SUM(b6) b6, SUM(b7) b7, SUM(b8) b8, SUM(b9) b9
    FROM analytics_daily WHERE day BETWEEN ? AND ? AND tenant_id <> '-'${tq} GROUP BY channel, status_class`, w.from, w.to, ...ta);
  const st = start === null ? 'NO_DATA' : cover(w.from), has = rows.length > 0;
  const byCh = {}; let total = 0, bad = 0, units = 0, bm = 0, tm = 0; const hist = new Array(10).fill(0);
  for (const r of rows) { byCh[r.channel] ??= { requests: 0, errors_5xx_or_tool: 0, client_errors_4xx: 0 }; byCh[r.channel].requests += r.r; total += r.r; units += r.u; bm += r.bm; tm += r.tm;
    if (r.status_class === '5xx' || r.status_class === 'tool_error') { byCh[r.channel].errors_5xx_or_tool += r.r; bad += r.r; } if (r.status_class === '4xx') byCh[r.channel].client_errors_4xx += r.r;
    for (let i = 0; i < 10; i++) hist[i] += r['b' + i]; }
  put('requests_by_channel', has ? byCh : null, { state: has ? st : (start === null ? 'NO_DATA' : 'NO_DATA'), accuracy: 'EXACT', window: w });
  put('error_rate', has ? { errors: bad, requests: total, rate: bad / total } : null, { state: has ? st : 'NO_DATA', accuracy: 'EXACT', window: w });
  put('latency_ms', total >= 100 ? { p50: quantile(hist, 0.5), p95: quantile(hist, 0.95), p99: quantile(hist, 0.99), samples: total } : null, { state: !has ? 'NO_DATA' : total >= 100 ? st : 'NOT_YET_OBSERVABLE', accuracy: 'ESTIMATED', window: w, note: total >= 100 ? 'upper edge of the histogram bucket' : 'fewer than 100 requests' });
  put('units_consumed', has ? units : null, { state: has ? st : 'NO_DATA', accuracy: 'RECONCILED', window: w });
  put('theoretical_value_micros', has ? tm : null, { state: has ? st : 'NO_DATA', accuracy: 'ESTIMATED', window: w, note: 'not revenue' });
  put('billed_micros', has ? bm : null, { state: has ? st : 'NO_DATA', accuracy: 'EXACT', window: w });

  // ---- funnel (tenants) ---------------------------------------------------------------------------------------------------------------------------------
  const registered = (await one(`SELECT COUNT(*) n FROM tenants${tenantId ? ' WHERE id = ?' : ''}`, ...ta)).n;
  const activated = start === null ? null : (await one(`SELECT COUNT(*) n FROM tenant_first_seen${tenantId ? ' WHERE tenant_id = ?' : ''}`, ...ta)).n;
  const repeat = start === null ? null : (await one(`SELECT COUNT(*) n FROM (SELECT tenant_id FROM activity_daily WHERE 1=1${tq} GROUP BY tenant_id HAVING COUNT(DISTINCT day) >= 2)`, ...ta)).n;
  const premium = start === null ? null : (await one(`SELECT COUNT(*) n FROM tenant_first_seen WHERE first_premium_day IS NOT NULL${tenantId ? ' AND tenant_id = ?' : ''}`, ...ta)).n;
  const NA = mode === 'FREE_LAUNCH' ? 'NOT_APPLICABLE' : 'NOT_INSTRUMENTED';
  put('funnel', { VISITOR: { state: 'NOT_INSTRUMENTED', count: null }, REGISTERED: { state: 'REAL_VERIFIED', count: registered }, ACTIVATED: { state: activated === null ? 'NO_DATA' : cover(start), count: activated },
    REPEAT_USER: { state: repeat === null ? 'NO_DATA' : cover(start), count: repeat }, PREMIUM_USER: { state: premium === null ? 'NO_DATA' : cover(start), count: premium },
    TRIAL_REQUESTED: { state: NA, count: null }, TRIAL_ACTIVE: { state: NA, count: null }, PAYMENT_INTENT: { state: NA, count: null }, PAID_ACTIVE: { state: NA, count: null }, CANCELLED: { state: NA, count: null }, CHURNED: { state: 'REAL_VERIFIED', count: out.churned_orgs_30d.value?.churned ?? null, note: 'inactive 30 days, not a cancellation' } },
    { state: 'PARTIAL_COVERAGE', accuracy: 'PARTIAL' });
  return out;
}
