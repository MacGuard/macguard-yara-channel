// Alert rules over the analytics data. They only EVALUATE and return normalised alert objects (contracts/v1/alert.schema.json); nothing is sent anywhere: delivery belongs to an
// incident/escalation engine (GuardOps) that is not part of this gateway. A rule without enough data says INSUFFICIENT_DATA instead of staying silent or firing on noise.
import { downloadSummary } from './gh_collector.js';
import { quantile } from './analytics.js';
import { costSummary } from './cost.js';
import { iso } from './util.js';
import { addDays } from './kpi.js';

export const DEFAULTS = { collector_min_runs: 6, collector_min_ok_ratio: 0.8, collector_stale_seconds: 3 * 3600, collector_failures: 3, error_rate: 0.05, min_requests: 100, p95_ms: 1000, anomaly_sigma: 3, anomaly_min_days: 7, anomaly_min_abs: 20, cost_tolerance: 0.1 };
const SEV = { critical: 4, high: 3, medium: 2, low: 1 };

export async function evaluateAlerts(db, clock, opts = {}) {
  const T = { ...DEFAULTS, ...opts }, now = clock(), today = now.toISOString().slice(0, 10), at = iso(now), out = [];
  const rule = (rule_id, category, severity, state, value, threshold, message, dedupe = rule_id) => out.push({ schema: 'macguard.alert/1', rule_id, category, severity, state, value, threshold, message, dedupe_key: dedupe, evaluated_at: at, source: { kind: 'gateway', id: 'analytics' } });

  const gh = await downloadSummary(db, clock, { windowDays: 30 });
  if (gh.last_status === 'never_run') rule('github.collector_stale', 'availability', 'medium', 'INSUFFICIENT_DATA', null, T.collector_stale_seconds, 'The GitHub collector has never run.');
  else rule('github.collector_stale', 'availability', 'high', gh.staleness_seconds > T.collector_stale_seconds ? 'FIRING' : 'OK', gh.staleness_seconds, T.collector_stale_seconds, `Last successful GitHub sync was ${gh.staleness_seconds}s ago.`);
  rule('github.collector_failing', 'availability', 'high', gh.last_status === 'never_run' ? 'INSUFFICIENT_DATA' : gh.consecutive_failures >= T.collector_failures ? 'FIRING' : 'OK', gh.consecutive_failures, T.collector_failures, `${gh.consecutive_failures} consecutive collector failures.`);

  // Reliability over the last 24 h: an intermittent failure (shared egress addresses hitting GitHub's per-IP limit) never reaches three CONSECUTIVE failures but still thins the observations.
  const runs = (await db.prepare("SELECT status FROM gh_sync_log WHERE observed_at > ?").bind(iso(new Date(now.getTime() - 86400000))).all()).results, okRuns = runs.filter((r) => r.status === 'ok').length;
  rule('github.collector_reliability', 'availability', 'medium', runs.length < T.collector_min_runs ? 'INSUFFICIENT_DATA' : okRuns / runs.length < T.collector_min_ok_ratio ? 'FIRING' : 'OK', runs.length ? +(okRuns / runs.length).toFixed(3) : null, T.collector_min_ok_ratio,
    `${okRuns} of ${runs.length} collector runs in the last 24 h succeeded. A gap delays an observation but never loses a download: the counters are cumulative.`);

  // A rejected token fails EVERY run until someone replaces it: it deserves its own alert instead of hiding in the failure ratio.
  rule('github.token_rejected', 'security', 'high', gh.last_status === 'never_run' ? 'INSUFFICIENT_DATA' : (await db.prepare('SELECT last_status s FROM gh_sync WHERE id = 1').first())?.s === 'github_unauthorized' ? 'FIRING' : 'OK', null, null, 'GitHub answered 401: the GITHUB_TOKEN secret is invalid, expired or revoked. Replace it (wrangler secret put GITHUB_TOKEN).');

  // Download anomaly: today's OBSERVED increase against the mean + k*sigma of the previous days. Needs a baseline of real days; never fires on a cold start.
  const daily = (await db.prepare("SELECT substr(o.observed_at,1,10) d, SUM(o.download_count - o.prev_count) n FROM gh_observations o JOIN gh_assets a ON a.asset_id = o.asset_id WHERE o.kind = 'delta' AND a.kind = 'bundle' AND substr(o.observed_at,1,10) >= ? GROUP BY d").bind(addDays(today, -30)).all()).results;
  const byDay = new Map(daily.map((r) => [r.d, r.n])), firstDay = gh.collector_first_success_at?.slice(0, 10);
  const base = []; if (firstDay) for (let d = addDays(today, -1), i = 0; i < 30 && d >= firstDay; d = addDays(d, -1), i++) base.push(byDay.get(d) ?? 0);
  if (base.length < T.anomaly_min_days) rule('downloads.anomaly', 'traffic', 'medium', 'INSUFFICIENT_DATA', null, null, `Only ${base.length} complete observed days; ${T.anomaly_min_days} are needed for a baseline.`);
  else { const mean = base.reduce((a, b) => a + b, 0) / base.length, sd = Math.sqrt(base.reduce((a, b) => a + (b - mean) ** 2, 0) / base.length), v = byDay.get(today) ?? 0, limit = mean + T.anomaly_sigma * sd;
    rule('downloads.anomaly', 'traffic', 'medium', v > limit && v >= T.anomaly_min_abs ? 'FIRING' : 'OK', v, +limit.toFixed(2), `Observed bundle downloads today: ${v} (baseline mean ${mean.toFixed(1)}, sd ${sd.toFixed(1)}).`); }

  // API health over the last 24h (today and yesterday's rows are day-granular, so this is the UTC day pair, stated in the message).
  const rows = (await db.prepare('SELECT status_class sc, SUM(requests) r, SUM(b0) b0, SUM(b1) b1, SUM(b2) b2, SUM(b3) b3, SUM(b4) b4, SUM(b5) b5, SUM(b6) b6, SUM(b7) b7, SUM(b8) b8, SUM(b9) b9 FROM analytics_daily WHERE day >= ? GROUP BY status_class').bind(addDays(today, -1)).all()).results;
  const total = rows.reduce((a, r) => a + r.r, 0), bad = rows.filter((r) => r.sc === '5xx' || r.sc === 'tool_error').reduce((a, r) => a + r.r, 0), hist = new Array(10).fill(0); for (const r of rows) for (let i = 0; i < 10; i++) hist[i] += r['b' + i];
  if (total < T.min_requests) { rule('api.error_rate', 'availability', 'high', 'INSUFFICIENT_DATA', total, T.min_requests, `Fewer than ${T.min_requests} requests in the last two UTC days.`); rule('api.latency_p95', 'performance', 'medium', 'INSUFFICIENT_DATA', total, T.min_requests, 'Not enough requests.'); }
  else { rule('api.error_rate', 'availability', 'high', bad / total > T.error_rate ? 'FIRING' : 'OK', +(bad / total).toFixed(4), T.error_rate, `${bad} of ${total} requests failed server-side or as tool errors (today + yesterday, UTC).`);
    const p95 = quantile(hist, 0.95); rule('api.latency_p95', 'performance', 'medium', p95 > T.p95_ms ? 'FIRING' : 'OK', p95, T.p95_ms, `Estimated p95 (histogram upper bound) ${p95} ms.`); }

  // Telemetry integrity: the billing ledger is authoritative; analytics must never see FEWER metered units than the ledger for the same UTC day.
  const led = (await db.prepare("SELECT COALESCE(SUM(units),0) u FROM usage_events WHERE substr(created_at,1,10) = ? AND request_status IN ('processed','completed')").bind(today).first()).u;
  const ana = (await db.prepare('SELECT COALESCE(SUM(units),0) u FROM analytics_daily WHERE day = ? AND channel IN (\'rest\',\'mcp\')').bind(today).first()).u;
  rule('telemetry.undercount', 'telemetry', 'high', led === 0 && ana === 0 ? 'INSUFFICIENT_DATA' : ana < led ? 'FIRING' : 'OK', ana, led, `Analytics saw ${ana} metered units today, the ledger ${led}. Telemetry is best-effort: a shortfall means lost writes, and the ledger is the source for billing.`);

  // Costs: any month with both an invoice and an estimate that disagree beyond tolerance.
  const month = today.slice(0, 7), prev = addDays(month + '-01', -1).slice(0, 7);
  for (const period of [prev, month]) { const s = await costSummary(db, { period, tolerance: T.cost_tolerance }); const mism = s.lines.filter((l) => l.reconciliation.status === 'MISMATCH'), comp = s.lines.filter((l) => l.reconciliation.status !== 'UNKNOWN');
    rule(`cost.reconciliation.${period}`, 'cost', 'medium', !comp.length ? 'INSUFFICIENT_DATA' : mism.length ? 'FIRING' : 'OK', mism.length, 0, mism.length ? `${mism.map((l) => l.provider + '/' + l.service).join(', ')} differ from the invoice by more than ${T.cost_tolerance * 100}%.` : 'Estimates agree with invoices.', `cost.reconciliation.${period}`); }
  return { evaluated_at: at, thresholds: T, alerts: out.sort((a, b) => (a.state === 'FIRING' ? 0 : 1) - (b.state === 'FIRING' ? 0 : 1) || SEV[b.severity] - SEV[a.severity]), firing: out.filter((a) => a.state === 'FIRING').length, delivery: 'none: alerts are evaluated, never sent, from this service' };
}
