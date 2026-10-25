// Dashboard and report model. A panel is DATA, not pixels: {id,title,type,state,source,accuracy,data,empty_reason,limitations}. Flutter, GuardOps or the offline HTML renderer all consume the
// same JSON. Missing data is an explicit state (NO_DATA, NOT_APPLICABLE, ...) with a reason, never a zero. Sandbox/synthetic data is never mixed into these (production tables only).
import { kpis } from './kpi.js';
import { downloadSummary, observedWindows } from './gh_collector.js';
import { costSummary, unitCosts } from './cost.js';
import { crmSummary } from './crm.js';
import { evaluateAlerts } from './alerts.js';
import { iso, HttpError } from './util.js';

export const DASHBOARDS = ['overview', 'downloads', 'api', 'premium', 'cost', 'crm', 'comparison', 'retention', 'pipeline', 'signatures', 'cas_backups'];
export const panel = (id, title, type, state, source, data, { accuracy = null, reason = null, limitations = null } = {}) => ({ id, title, type, state, source, accuracy, data: state === 'NO_DATA' || state === 'NOT_INSTRUMENTED' || state === 'NOT_APPLICABLE' || state === 'NOT_YET_OBSERVABLE' ? null : data, empty_reason: reason, limitations });
const fromKpi = (k, id, title, type, source, shape = (v) => v) => panel(id, title, type, k.state, source, k.value === null ? null : shape(k.value), { accuracy: k.accuracy, reason: k.note ?? (k.value === null ? k.state.toLowerCase().replace(/_/g, ' ') : null) });

export async function dashboard(db, clock, id, { tenantId = null, period = null, mode = 'FREE_LAUNCH', dataClass = 'real', extraPanels = [] } = {}) {
  if (!DASHBOARDS.includes(id)) throw new HttpError(404, 'not_found', 'Unknown dashboard.');
  const now = clock(), month = period ?? now.toISOString().slice(0, 7), k = await kpis(db, clock, { tenantId, mode }), panels = [];
  if (id === 'overview') {
    const gh = tenantId ? null : await downloadSummary(db, clock, { windowDays: 30 }), al = tenantId ? null : await evaluateAlerts(db, clock);
    panels.push(fromKpi(k.dau, 'dau', 'Active API clients today (keys, not people)', 'value', 'activity_daily', (v) => v), fromKpi(k.mau, 'mau', 'Active API clients, 30 days', 'value', 'activity_daily'), fromKpi(k.active_orgs_30d, 'orgs', 'Active organisations, 30 days', 'value', 'activity_daily'),
      fromKpi(k.requests_by_channel, 'requests', 'Requests by channel, 30 days', 'bar', 'analytics_daily'), fromKpi(k.premium_actors_30d, 'premium', 'Premium clients (free during FREE_LAUNCH), 30 days', 'value', 'activity_daily'),
      fromKpi(k.billed_micros, 'billed', 'Revenue actually billed (micro-units)', 'value', 'analytics_daily'));
    panels.push(gh ? panel('downloads30', 'YARA bundle downloads observed, 30 days', 'value', gh.last_status === 'never_run' ? 'NO_DATA' : gh.coverage_of_window < 1 ? 'PARTIAL_COVERAGE' : 'REAL_VERIFIED', 'github_release_download_count', { observed: gh.totals.bundle_downloads_observed_in_window, coverage: gh.coverage_of_window }, { accuracy: gh.accuracy.observed, reason: gh.last_status === 'never_run' ? 'the collector has not run' : null, limitations: gh.limitations })
      : panel('downloads30', 'YARA bundle downloads', 'value', 'NOT_APPLICABLE', 'github', null, { reason: 'public releases are not tenant data' }));
    if (al) panels.push(panel('alerts', 'Alerts firing', 'list', 'REAL_VERIFIED', 'alerts', al.alerts.filter((a) => a.state === 'FIRING'), { reason: al.firing ? null : `none firing; ${al.alerts.filter((a) => a.state === 'INSUFFICIENT_DATA').length} of ${al.alerts.length} rules cannot be judged yet (insufficient data)` }));
  }
  if (id === 'downloads') {
    if (tenantId) panels.push(panel('gh', 'GitHub downloads', 'table', 'NOT_APPLICABLE', 'github', null, { reason: 'public releases are not tenant data' }));
    else { const gh = await downloadSummary(db, clock, { windowDays: 30 }), none = gh.last_status === 'never_run';
      panels.push(panel('collector', 'Collector health', 'value', none ? 'NO_DATA' : gh.consecutive_failures ? 'QUERY_ERROR' : 'REAL_VERIFIED', 'gh_sync', { last_success_at: gh.last_success_at, staleness_seconds: gh.staleness_seconds, coverage_of_window: gh.coverage_of_window, consecutive_failures: gh.consecutive_failures, ...(await collectorReliability(db, clock)) }, { reason: none ? 'the collector has not run' : null }),
        panel('releases', 'Releases: bundle downloads (cumulative vs observed)', 'table', none ? 'NO_DATA' : 'REAL_VERIFIED', 'gh_assets, gh_observations', gh.releases, { accuracy: gh.accuracy.observed, reason: none ? 'the collector has not run' : null, limitations: gh.limitations }),
        ...(await communityWindowPanels(db, clock)),
        panel('kinds', 'Assets by kind (never summed as bundle downloads)', 'bar', none ? 'NO_DATA' : 'REAL_VERIFIED', 'gh_assets', gh.by_asset_kind, { accuracy: 'EXACT' })); }
    const c = (await db.prepare("SELECT release_tag, asset_name, actor_kind, SUM(redirected) n FROM community_requests_daily c WHERE day >= ? AND NOT EXISTS (SELECT 1 FROM telemetry_exclusions x WHERE x.source = 'community_requests_daily' AND x.row_key = c.day || '|' || c.release_tag || '|' || c.asset_name || '|' || c.actor_kind) GROUP BY release_tag, asset_name, actor_kind ORDER BY n DESC LIMIT 50").bind(iso(new Date(now.getTime() - 30 * 864e5)).slice(0, 10)).all()).results;
    panels.push(panel('redirects', 'Community redirects issued via the gateway route (NOT completed downloads), 30 days', 'table', c.length ? 'REAL_VERIFIED' : 'NO_DATA', 'community_requests_daily', c, { accuracy: 'EXACT', reason: c.length ? null : 'no redirect has been issued through the gateway', limitations: 'The public URLs on GitHub bypass this route; GitHub and gateway figures are separate and are not added together.' }));
    const dl = await db.prepare(`SELECT state, COUNT(*) n FROM downloads${tenantId ? ' WHERE tenant_id = ?' : ''} GROUP BY state`).bind(...(tenantId ? [tenantId] : [])).all().then((r) => r.results);
    panels.push(panel('premium_downloads', 'Premium downloads by state', 'bar', dl.length ? 'REAL_VERIFIED' : 'NO_DATA', 'downloads', dl, { accuracy: 'EXACT', reason: dl.length ? null : 'no Premium download recorded', limitations: 'COMPLETED only when the delivered byte ranges cover the whole file.' }));
  }
  if (id === 'api') {
    panels.push(fromKpi(k.requests_by_channel, 'requests', 'Requests by channel, 30 days', 'bar', 'analytics_daily'), fromKpi(k.error_rate, 'errors', 'Server-side error rate, 30 days', 'value', 'analytics_daily'), fromKpi(k.latency_ms, 'latency', 'Latency p50/p95/p99 (estimated)', 'value', 'analytics_daily buckets'), fromKpi(k.units_consumed, 'units', 'Metered units consumed', 'value', 'analytics_daily'));
    const top = (await db.prepare(`SELECT operation, channel, SUM(requests) requests, SUM(CASE WHEN status_class IN ('5xx','tool_error') THEN requests ELSE 0 END) errors FROM analytics_daily WHERE day >= ? AND tenant_id <> '-'${tenantId ? ' AND tenant_id = ?' : ''} GROUP BY operation, channel ORDER BY requests DESC LIMIT 20`).bind(iso(new Date(now.getTime() - 30 * 864e5)).slice(0, 10), ...(tenantId ? [tenantId] : [])).all()).results;
    panels.push(panel('top_ops', 'Most used operations / MCP tools, 30 days', 'table', top.length ? 'REAL_VERIFIED' : 'NO_DATA', 'analytics_daily', top, { accuracy: 'EXACT', reason: top.length ? null : 'no requests recorded' }));
  }
  if (id === 'premium') panels.push(fromKpi(k.premium_actors_30d, 'actors', 'Premium clients, 30 days (usage, not payment)', 'value', 'activity_daily'), fromKpi(k.premium_orgs_30d, 'orgs', 'Premium organisations, 30 days', 'value', 'activity_daily'), fromKpi(k.premium_adoption_rate, 'rate', 'Premium share of active clients', 'value', 'activity_daily'),
    fromKpi(k.paid_customers, 'paid', 'Paying customers', 'value', 'tenants'), fromKpi(k.funnel, 'funnel', 'Conversion funnel (tenants)', 'table', 'tenants, activity', (v) => Object.entries(v).map(([state, x]) => ({ state, ...x }))),
    fromKpi(k.retention_d30, 'ret30', 'D30 retention', 'value', 'actor_first_seen'), fromKpi(k.monthly_retention, 'retm', 'Monthly retention', 'value', 'activity_daily'), fromKpi(k.recurring_actors_30d, 'recurring', 'Recurring clients, 30 days', 'value', 'activity_daily'), ...(await premiumUsagePanels(db, tenantId)));
  if (id === 'cost') {
    const s = await costSummary(db, { period: month, tenantId }), u = await unitCosts(db, month);
    panels.push(panel('lines', `Costs ${month} by provider/service`, 'table', s.state, 'cost_entries', s.lines, { accuracy: 'RECONCILED', reason: s.state === 'NO_DATA' ? 'no invoice imported and no rate configured' : null, limitations: s.note }),
      panel('totals', 'Totals by currency', 'value', s.state, 'cost_entries', s.totals_by_currency, { accuracy: 'EXACT' }), panel('unit', 'Unit cost per 1000 requests', 'value', u.unit_costs[0].value === null ? 'NO_DATA' : 'REAL_VERIFIED', 'cost_entries, analytics_daily', u.unit_costs, { accuracy: u.unit_costs[0].accuracy ?? null, reason: u.unit_costs[0].reason ?? null }),
      fromKpi(k.theoretical_value_micros, 'theoretical', 'Theoretical value at example prices (NOT revenue)', 'value', 'analytics_daily'), fromKpi(k.billed_micros, 'billed', 'Billed (real revenue)', 'value', 'analytics_daily'));
    panels.push(panel('stripe', 'Stripe sandbox', 'value', 'NOT_INSTRUMENTED', 'stripe', null, { reason: 'sandbox credentials are not configured; no Stripe data is shown or simulated' }));
  }
  if (id === 'crm') {
    if (tenantId) panels.push(panel('crm', 'CRM', 'table', 'NOT_APPLICABLE', 'leads', null, { reason: 'the CRM is platform-level' }));
    else { const c = await crmSummary(db); panels.push(panel('pipeline', 'Pipeline by current state', 'bar', c.state, 'leads', c.current, { accuracy: 'EXACT', reason: c.state === 'NO_DATA' ? 'no lead has been recorded' : null, limitations: c.note }), panel('reached', 'Leads that ever reached each state', 'bar', c.state, 'lead_events', c.ever_reached, { accuracy: 'EXACT' }), panel('win', 'Win rate (WON / (WON + LOST))', 'value', c.win_rate === null ? 'NO_DATA' : 'REAL_VERIFIED', 'lead_events', c.win_rate, { accuracy: 'EXACT' })); }
  }
  if (id === 'comparison') panels.push(...(await comparisonPanels(db, clock, k, tenantId)));
  if (id === 'retention') panels.push(fromKpi(k.retention_d30, 'd30', 'D30 retention (keys first seen 30+ days ago still active)', 'value', 'actor_first_seen'), fromKpi(k.monthly_retention, 'monthly', 'Monthly retention', 'value', 'activity_daily'),
    fromKpi(k.recurring_actors_30d, 'recurring', 'Recurring clients, 30 days (keys, not people)', 'value', 'activity_daily'), fromKpi(k.mau, 'mau', 'Active API clients, 30 days', 'value', 'activity_daily'),
    panel('policy', 'Analytics retention policy', 'value', 'REAL_VERIFIED', 'owner decision 2026-10-23', { analytics_days: 365, never_touched: ['ledger', 'audit', 'costs', 'policy'] }, { accuracy: 'EXACT' }));
  if (id === 'pipeline') panels.push(...(tenantId ? [panel('pipeline', 'Intelligence pipeline', 'table', 'NOT_APPLICABLE', 'intel_sources', null, { reason: 'the source pipeline is platform-level' })] : await pipelinePanels(db)));
  if (id === 'signatures') panels.push(...(await signaturePanels(db, tenantId)));
  if (id === 'cas_backups') panels.push(panel('cas', 'Content-addressed archive (CAS)', 'value', 'NOT_INSTRUMENTED', 'feat/backup-archive (local tooling)', null, { reason: 'the CAS lives in the local archive tooling and has never been written to a real store; the gateway has no view of it' }),
    ...(extraPanels.length ? extraPanels : [panel('backups', 'D1 backups', 'value', 'NOT_INSTRUMENTED', 'tools/backup_flow.mjs status.json', null, { reason: 'backups run on the owner machine, outside the Worker: render this dashboard offline with --backup-root to include them' })]));
  const cls = (p) => (p.state === 'NO_DATA' || p.state === 'NOT_INSTRUMENTED' || p.state === 'NOT_APPLICABLE' || p.state === 'NOT_YET_OBSERVABLE' ? 'absent' : dataClass);
  return { schema: 'macguard.dashboard/1', id, scope: tenantId ? { tenant_id: tenantId } : { platform: true }, mode, data_class: dataClass, generated_at: iso(now), panels: panels.map((p) => ({ ...p, data_class: cls(p) })) };
}

// ---- reports: a period + a set of dashboards, rendered as JSON, CSV or HTML. Every section repeats its source, accuracy and limitations. ---------------------------------------------------
const PLAN = { daily: ['downloads', 'api'], weekly: ['overview', 'premium'], monthly: ['cost', 'premium', 'crm'] };
export async function report(db, clock, kind, opts = {}) {
  if (!PLAN[kind]) throw new HttpError(400, 'invalid_input', 'kind must be daily, weekly or monthly.');
  const now = clock(), day = now.toISOString().slice(0, 10), periodOf = { daily: { from: day, to: day }, weekly: { from: new Date(now.getTime() - 6 * 864e5).toISOString().slice(0, 10), to: day }, monthly: { month: day.slice(0, 7) } }[kind];
  const sections = []; for (const id of PLAN[kind]) sections.push(await dashboard(db, clock, id, opts));
  return { schema: 'macguard.report/1', kind, period: periodOf, generated_at: iso(now), scope: opts.tenantId ? { tenant_id: opts.tenantId } : { platform: true }, note: 'Figures are as of generation time; windows inside each panel are stated in its title/source.', sections };
}
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const flat = (v, p = '') => (v !== null && typeof v === 'object' ? Object.entries(v).flatMap(([k, x]) => flat(x, p ? `${p}.${k}` : k)) : [[p, v]]);
const csvCell = (v) => { let s = String(v ?? ''); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };       // leading =,+,-,@ neutralised (CSV injection)
export function toCsv(rep) {
  const lines = [['dashboard', 'panel', 'state', 'accuracy', 'source', 'key', 'value'].join(',')];
  for (const s of rep.sections ?? [rep]) for (const p of s.panels) { const kv = p.data === null || p.data === undefined ? [['', '']] : flat(p.data); for (const [k, v] of kv) lines.push([s.id, p.id, p.state, p.accuracy, p.source, k, v].map(csvCell).join(',')); }
  return lines.join('\n') + '\n';
}
export function toHtml(rep) {
  const sections = rep.sections ?? [rep], title = rep.kind ? `MacGuard ${rep.kind} report` : `MacGuard dashboard: ${rep.id}`;
  const body = sections.map((s) => `<section><h2>${esc(s.id)}</h2>${s.panels.map((p) => `<article class="p ${esc(p.state)}"><h3>${esc(p.title)}</h3><p class="m"><b>${esc(p.state)}</b> · ${esc(p.source)}${p.accuracy ? ' · ' + esc(p.accuracy) : ''}</p>${p.data === null || p.data === undefined ? `<p class="e">${esc(p.empty_reason ?? 'no data')}</p>` : `<table>${flat(p.data).map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`).join('')}</table>`}${p.limitations ? `<p class="l">${esc(p.limitations)}</p>` : ''}</article>`).join('')}</section>`).join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><style>:root{--bg:#fff;--fg:#1a1a1a;--mu:#666;--bd:#ddd;--gr:#e6e6e6}@media(prefers-color-scheme:dark){:root{--bg:#161616;--fg:#eee;--mu:#aaa;--bd:#333;--gr:#2a2a2a}}body{background:var(--bg);color:var(--fg);font:15px/1.4 system-ui;margin:16px;max-width:1000px}.p{border:1px solid var(--bd);border-radius:8px;padding:10px 14px;margin:10px 0}.p.NO_DATA,.p.NOT_APPLICABLE,.p.NOT_INSTRUMENTED,.p.NOT_YET_OBSERVABLE{background:var(--gr)}.m,.l,.e{color:var(--mu);margin:.2em 0}table{border-collapse:collapse;width:100%}th,td{text-align:left;border-top:1px solid var(--bd);padding:3px 6px;word-break:break-word}th{font-weight:500;color:var(--mu)}</style></head><body><h1>${esc(title)}</h1><p class="m">Generated ${esc(rep.generated_at)} · ${esc(JSON.stringify(rep.scope))}${rep.period ? ' · ' + esc(JSON.stringify(rep.period)) : ''}</p>${body}</body></html>`;
}

// Community side: what GitHub's public counters show for the BUNDLE, in windows, with the coverage of each window stated.
async function communityWindowPanels(db, clock) {
  const w = await observedWindows(db, clock), none = w.first_observation_at === null;
  return [panel('observed_windows', 'Bundle downloads observed: day / week / month / observed year', 'table', none ? 'NO_DATA' : w.windows.year_observed.coverage < 1 ? 'PARTIAL_COVERAGE' : 'REAL_VERIFIED', 'gh_observations (same asset_id only)',
      Object.entries(w.windows).map(([window, x]) => ({ window, observed: x.observed, coverage: x.coverage, state: x.state })), { accuracy: 'PARTIAL', reason: none ? 'the collector has not run' : null,
      limitations: 'Counts requests GitHub served for the bundle asset, not people. A window is only as complete as the collector coverage shown; uncovered time is unknown, not zero. The year is the observed year: history before the first observation does not exist.' }),
    panel('trend', 'Bundle downloads observed per day, last 30 days', 'graph', none ? 'NO_DATA' : 'PARTIAL_COVERAGE', 'gh_observations', w.series, { accuracy: 'PARTIAL', reason: none ? 'the collector has not run' : null, limitations: 'null = before the first observation (unknown). Granularity is the collector cadence.' })];
}
// Comparison: two products, two different counters. The panels carry the definition of each side so they are never read as the same unit.
async function comparisonPanels(db, clock, k, tenantId) {
  const w = tenantId ? null : await observedWindows(db, clock), gh = tenantId ? null : await downloadSummary(db, clock, { windowDays: 30 });
  const prem = (await db.prepare(`SELECT COUNT(*) FILTER (WHERE state = 'completed') completed, COUNT(*) total FROM downloads${tenantId ? ' WHERE tenant_id = ?' : ''}`).bind(...(tenantId ? [tenantId] : [])).first());
  const bytes = (await db.prepare(`SELECT COALESCE(SUM(bytes),0) b FROM analytics_daily WHERE channel = 'download' AND tenant_id <> '-'${tenantId ? ' AND tenant_id = ?' : ''}`).bind(...(tenantId ? [tenantId] : [])).first()).b;
  const community = tenantId ? panel('community', 'Community (free, public)', 'table', 'NOT_APPLICABLE', 'github', null, { reason: 'public releases are not tenant data' })
    : panel('community', 'Community (free, permanent): bundle requests served by GitHub', 'value', gh.last_status === 'never_run' ? 'NO_DATA' : 'PARTIAL_COVERAGE', 'github_release_download_count',
      { cumulative_bundle_requests: gh.totals.bundle_downloads_cumulative, observed_last_30_days: w.windows.month.observed, window_coverage: w.windows.month.coverage, unit: 'requests served by GitHub for the bundle asset' }, { accuracy: 'PARTIAL', reason: gh.last_status === 'never_run' ? 'the collector has not run' : null });
  const premium = panel('premium', 'Intelligence Premium (free during FREE_LAUNCH): authenticated downloads', 'value', prem.total ? 'REAL_VERIFIED' : 'NO_DATA', 'downloads', { authorised: prem.total, completed: prem.completed, bytes_transferred: bytes, unit: 'authorised transfers by identified API keys; completed = every byte of the file delivered' }, { accuracy: 'EXACT', reason: prem.total ? null : 'no Premium download recorded yet' });
  const keys = k.premium_actors_30d, rec = k.recurring_actors_30d;
  return [community, premium,
    panel('definitions', 'Why the two figures are not added or ranked', 'list', 'REAL_VERIFIED', 'definitions', ['Community counts anonymous requests served by GitHub (no identity, includes our own and CI downloads, may include partial transfers).', 'Premium counts authorised downloads by identified keys and distinguishes started, partial and completed.', 'Neither counts people.'], { accuracy: null }),
    fromKpi(keys, 'premium_clients', 'Premium clients active (usage, not payment), 30 days', 'value', 'activity_daily'), fromKpi(rec, 'premium_recurring', 'Recurring clients, 30 days', 'value', 'activity_daily'), fromKpi(k.billed_micros, 'billed', 'Billed (real revenue) — zero in FREE_LAUNCH', 'value', 'analytics_daily'),
    fromKpi(k.theoretical_value_micros, 'theoretical', 'Theoretical value of the consumption at example prices (not revenue)', 'value', 'analytics_daily')];
}

async function premiumUsagePanels(db, tenantId) {
  const t = tenantId ? ' AND tenant_id = ?' : '', a = tenantId ? [tenantId] : [];
  const x = await db.prepare(`SELECT COALESCE(SUM(CASE WHEN channel = 'download' THEN bytes ELSE 0 END),0) bytes, COALESCE(SUM(CASE WHEN channel IN ('rest','mcp') THEN requests ELSE 0 END),0) req, COALESCE(SUM(theoretical_micros),0) theo, COALESCE(SUM(billable_micros),0) billed, COALESCE(SUM(CASE WHEN channel IN ('rest','mcp') THEN units ELSE 0 END),0) units FROM analytics_daily WHERE tenant_id <> '-'${t}`).bind(...a).first();
  const keys = (await db.prepare(`SELECT COUNT(*) n FROM (SELECT DISTINCT actor_hash FROM activity_daily WHERE 1=1${t})`).bind(...a).first()).n, has = x.req > 0 || x.bytes > 0;
  return [panel('bytes', 'Bytes transferred in authenticated downloads (all time kept)', 'value', has ? 'REAL_VERIFIED' : 'NO_DATA', 'analytics_daily', x.bytes, { accuracy: 'EXACT', reason: has ? null : 'no traffic yet' }),
    panel('keys_seen', 'Distinct API keys that ever made a request (keys, not people)', 'value', keys ? 'REAL_VERIFIED' : 'NO_DATA', 'activity_daily', keys, { accuracy: 'EXACT' }),
    panel('cost_per_op', 'Theoretical value per metered unit, in micro-units (NOT a price, NOT revenue)', 'value', x.units > 0 ? 'REAL_VERIFIED' : 'NO_DATA', 'analytics_daily', x.units > 0 ? { theoretical_micros_per_unit: Math.round(x.theo / x.units), units: x.units, billed_micros: x.billed } : null, { accuracy: 'ESTIMATED', reason: x.units > 0 ? null : 'no metered units yet', limitations: 'Example price list; the platform cost per operation comes from cost intelligence, not from this figure.' })];
}

// How dependable the collector has been in the last 24 h and whether it uses a GitHub token (a token lifts the per-IP limit that shared Cloudflare egress addresses hit).
async function collectorReliability(db, clock) {
  const runs = (await db.prepare('SELECT status FROM gh_sync_log WHERE observed_at > ?').bind(iso(new Date(clock().getTime() - 86400000))).all()).results, ok = runs.filter((r) => r.status === 'ok').length;
  const a = await db.prepare('SELECT authenticated a FROM gh_sync WHERE id = 1').first();
  return { runs_24h: runs.length, ok_runs_24h: ok, success_ratio_24h: runs.length ? +(ok / runs.length).toFixed(3) : null, authenticated: !!a?.a, last_failure_causes: [...new Set(runs.filter((r) => r.status !== 'ok').map((r) => r.status))] };
}

// Intelligence pipeline: what each source is, how many records it holds and how far it got in the licence gate. Real rows only; counts are not an indication that anything is published.
async function pipelinePanels(db) {
  const src = (await db.prepare('SELECT status, COUNT(*) n FROM intel_sources GROUP BY status').all()).results, rec = (await db.prepare('SELECT kind, source_id, COUNT(*) n, MAX(expires_at) latest_expiry FROM intel_records GROUP BY kind, source_id ORDER BY kind, source_id').all()).results;
  const rel = (await db.prepare("SELECT edition, status, COUNT(*) n, MAX(published_at) last_published_at FROM releases GROUP BY edition, status").all()).results;
  const premium = rel.filter((r) => r.edition === 'premium' && r.status === 'published').reduce((a, r) => a + r.n, 0);
  return [panel('sources', 'Sources by licence status', 'bar', src.length ? 'REAL_VERIFIED' : 'NO_DATA', 'intel_sources', src, { accuracy: 'EXACT', reason: src.length ? null : 'no source registered in the gateway database' }),
    panel('records', 'Records held per kind and source', 'table', rec.length ? 'REAL_VERIFIED' : 'NO_DATA', 'intel_records', rec, { accuracy: 'EXACT', reason: rec.length ? null : 'no intelligence record has been ingested into the gateway', limitations: 'Local pipelines (feeds, validation, licence matrix) live outside the gateway until a source is approved and published.' }),
    panel('releases', 'Releases by edition and status', 'table', rel.length ? 'REAL_VERIFIED' : 'NO_DATA', 'releases', rel, { accuracy: 'EXACT', reason: rel.length ? null : 'no release row exists' }),
    panel('premium_published', 'Premium bundles actually published', 'value', premium ? 'REAL_VERIFIED' : 'NO_DATA', 'releases', premium, { accuracy: 'EXACT', reason: premium ? null : 'no Premium bundle has been published: Premium is not operational until a real authorised publication and a complete verified download' })];
}
// Signatures and transparency: what the gateway can show is the integrity material recorded per release. Detached signatures and a transparency log are not instrumented yet and say so.
async function signaturePanels(db, tenantId) {
  const rel = (await db.prepare("SELECT id, edition, status, published_at, size, sha256 IS NOT NULL has_sha256, manifest_sha256 IS NOT NULL has_manifest, rules_root IS NOT NULL has_rules_root FROM releases ORDER BY published_at DESC LIMIT 50").all()).results;
  const complete = rel.filter((r) => r.has_sha256 && r.has_manifest && r.has_rules_root).length;
  return [panel('integrity', 'Releases with file hash, manifest hash and rules root recorded', 'table', rel.length ? 'REAL_VERIFIED' : 'NO_DATA', 'releases', { total: rel.length, complete, releases: rel }, { accuracy: 'EXACT', reason: rel.length ? null : 'no release row exists' }),
    panel('signature', 'Detached release signatures verified', 'value', 'NOT_INSTRUMENTED', 'release signing (PRE-07)', null, { reason: 'signing and verification are planned but not built; no signature is stored or shown' }),
    panel('transparency', 'Transparency log checkpoints', 'value', 'NOT_INSTRUMENTED', 'transparency log (PRE-07)', null, { reason: 'no transparency log exists yet' })];
}
