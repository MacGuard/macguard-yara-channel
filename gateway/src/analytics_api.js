// Administrator analytics API (/admin/v1/analytics/*). The caller is already authenticated (admin key + TOTP). There is ONE administrator role today (platform admin); finer RBAC
// (analyst, read-only) needs a role column on `admins` and is PLANNED. Tenants never reach these routes: they read their own numbers through GET /v1/account/analytics.
import { kpis } from './kpi.js';
import { KPI_CATALOG } from './kpi_catalog.js';
import { dashboard, report, toCsv, toHtml, DASHBOARDS } from './dashboards.js';
import { evaluateAlerts } from './alerts.js';
import { downloadSummary, sync as syncGithub } from './gh_collector.js';
import { importCsv, setRate, estimate, costSummary, unitCosts } from './cost.js';
import { createLead, moveLead, listLeads, crmSummary, STATES } from './crm.js';
import { audit } from './audit.js';
import { loadActive } from './policy.js';
import { HttpError, jsonResponse, readBounded, sha256Hex } from './util.js';

const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/, DAY = /^\d{4}-\d\d-\d\d$/, MONTH = /^\d{4}-(0[1-9]|1[0-2])$/;
const bad = (m) => new HttpError(400, 'invalid_input', m);
function q(url, name, re, fallback = null) { const v = url.searchParams.get(name); if (v === null || v === '') return fallback; if (!re.test(v)) throw bad(`Invalid ${name}.`); return v; }
function fmt(url) { const f = url.searchParams.get('format') ?? 'json'; if (!['json', 'csv', 'html'].includes(f)) throw bad('format must be json, csv or html.'); return f; }
const file = (body, type, name) => new Response(body, { status: 200, headers: { 'content-type': type, 'content-disposition': `attachment; filename="${name}"`, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' } });
function out(url, obj, name) {
  const f = fmt(url); if (f === 'json') return jsonResponse(200, obj);
  const rep = obj.sections ? obj : { id: obj.id, generated_at: obj.generated_at, scope: obj.scope, panels: obj.panels }; if (!rep.panels && !rep.sections) throw bad(`${f} is available for dashboards and reports only.`);
  return f === 'csv' ? file(toCsv(rep), 'text/csv; charset=utf-8', name + '.csv') : file(toHtml(rep), 'text/html; charset=utf-8', name + '.html');
}
const readText = (request, max = 1_000_000) => readBounded(request, max);
async function readBody(request) { try { return JSON.parse(await readText(request, 20_000)); } catch (e) { if (e instanceof HttpError) throw e; throw bad('Send a JSON object.'); } }

export async function adminAnalytics(request, env, db, clock, path, url, admin) {
  const m = request.method, p = path.slice('/admin/v1/analytics'.length) || '/', tenant = q(url, 'tenant', ID);
  if (tenant && !(await db.prepare('SELECT 1 x FROM tenants WHERE id = ?').bind(tenant).first())) throw new HttpError(404, 'not_found', 'Unknown tenant.');
  const mode = (await loadActive(db)).doc.mode;
  if (url.searchParams.has('format') && !/^\/(dashboards|reports|usage)\b/.test(p)) throw bad('format is available for dashboards, reports and usage only.');
  if (m === 'GET') {
    if (p === '/kpi-catalog') return jsonResponse(200, { schema: 'macguard.kpi-catalog/1', metrics: KPI_CATALOG });
    if (p === '/kpis') return jsonResponse(200, { scope: tenant ? { tenant_id: tenant } : { platform: true }, mode, kpis: await kpis(db, clock, { tenantId: tenant, asOf: q(url, 'as_of', DAY), mode }) });
    let r; if ((r = /^\/dashboards\/([a-z]+)$/.exec(p))) { if (!DASHBOARDS.includes(r[1])) throw new HttpError(404, 'not_found', 'Unknown dashboard.'); return out(url, await dashboard(db, clock, r[1], { tenantId: tenant, period: q(url, 'period', MONTH), mode }), 'dashboard-' + r[1]); }
    if ((r = /^\/reports\/([a-z]+)$/.exec(p))) return out(url, await report(db, clock, r[1], { tenantId: tenant, period: q(url, 'period', MONTH), mode }), 'report-' + r[1]);
    if (p === '/alerts') return jsonResponse(200, await evaluateAlerts(db, clock));
    if (p === '/downloads') return jsonResponse(200, await downloadSummary(db, clock, { windowDays: Math.min(Number(q(url, 'window_days', /^\d{1,3}$/, '30')) || 30, 365) }));
    if (p === '/usage') return usage(url, db, tenant);
    if (p === '/costs') return jsonResponse(200, await costSummary(db, { period: q(url, 'period', MONTH) ?? clock().toISOString().slice(0, 7), tenantId: tenant }));
    if (p === '/costs/unit') return jsonResponse(200, await unitCosts(db, q(url, 'period', MONTH) ?? clock().toISOString().slice(0, 7)));
    if (p === '/exclusions') return jsonResponse(200, { exclusions: (await db.prepare('SELECT source, row_key, row_digest, reason, marked_by, marked_at FROM telemetry_exclusions ORDER BY marked_at').all()).results });
    if (p === '/crm/summary') return jsonResponse(200, await crmSummary(db));
    if (p === '/crm/leads') { const st = q(url, 'state', /^[A-Z_]+$/); if (st && !STATES.includes(st)) throw bad('Unknown state.'); return jsonResponse(200, await listLeads(db, { state: st, limit: q(url, 'limit', /^\d{1,3}$/, '50'), cursor: q(url, 'after', /^ld_[0-9a-f]{16}$/) })); }
  }
  if (m === 'POST') {
    if (p === '/github/sync') { const res = await syncGithub(db, clock, (u, o) => (env.fetchImpl ?? fetch)(u, o), { repo: env.COMMUNITY_REPO || 'MacGuard/macguard-yara-channel', token: env.GITHUB_TOKEN || null }); await audit(db, clock, null, 'analytics.github_sync', { admin_id: admin.id, ok: res.ok, status: res.status }); return jsonResponse(res.ok ? 200 : 502, res); }
    if (p === '/costs/import') { const provider = q(url, 'provider', /^[a-z_]{2,20}$/), kind = q(url, 'kind', /^(confirmed|estimated)$/, 'confirmed'); if (!provider) throw bad('provider is required.');
      const res = await importCsv(db, clock, await readText(request), { provider, kind, batch: q(url, 'batch', ID) }); await audit(db, clock, null, 'analytics.cost_import', { admin_id: admin.id, provider, kind, imported: res.imported, rejected: res.rejected }); return jsonResponse(res.rejected ? 422 : 201, res); }
    if (p === '/costs/estimate') { const period = q(url, 'period', MONTH); if (!period) throw bad('period is required.'); const res = await estimate(db, clock, period); await audit(db, clock, null, 'analytics.cost_estimate', { admin_id: admin.id, period }); return jsonResponse(200, res); }
    if (p === '/exclusions') {                       // identify (never delete) rows that are known test traffic; the row must exist and its digest is stored, so the mark is verifiable
      const b = await readBody(request); if (b.source !== 'community_requests_daily' || !/^\d{4}-\d\d-\d\d\|[A-Za-z0-9._-]{1,140}\|[A-Za-z0-9._-]{1,140}\|[a-z_]{1,40}$/.test(b.row_key ?? '') || !b.reason || String(b.reason).length > 300) throw bad('source, row_key (day|release_tag|asset_name|actor_kind) and reason are required.');
      const [day, tag, asset, kind] = b.row_key.split('|'), row = await db.prepare('SELECT * FROM community_requests_daily WHERE day = ? AND release_tag = ? AND asset_name = ? AND actor_kind = ?').bind(day, tag, asset, kind).first();
      if (!row) throw new HttpError(404, 'not_found', 'No such telemetry row.');
      const digest = await sha256Hex(JSON.stringify([row.day, row.release_tag, row.asset_name, row.actor_kind, row.redirected]));
      const r = await db.prepare('INSERT OR IGNORE INTO telemetry_exclusions(source,row_key,row_digest,reason,marked_by,marked_at) VALUES (?,?,?,?,?,?)').bind(b.source, b.row_key, digest, String(b.reason), admin.id, clock().toISOString().replace(/\.\d{3}Z$/, 'Z')).run();
      await audit(db, clock, null, 'analytics.exclusion_marked', { admin_id: admin.id, source: b.source, row_key: b.row_key, digest }); return jsonResponse(r.meta.changes ? 201 : 200, { marked: !!r.meta.changes, row_digest: digest });
    }
    if (p === '/crm/leads') { const b = await readBody(request); return jsonResponse(201, await createLead(db, clock, admin, b)); }
    let r; if ((r = /^\/crm\/leads\/(ld_[0-9a-f]{16})\/state$/.exec(p))) { const b = await readBody(request); return jsonResponse(200, await moveLead(db, clock, admin, r[1], b.state)); }
  }
  if (m === 'PUT' && p === '/costs/rates') { const b = await readBody(request); await setRate(db, clock, b); await audit(db, clock, null, 'analytics.cost_rate', { admin_id: admin.id, provider: b.provider, service: b.service }); return jsonResponse(200, { ok: true }); }
  throw new HttpError(404, 'not_found', 'Not found.');
}

// Keyset pagination over the aggregate's primary key: stable under concurrent writes, no OFFSET scans.
async function usage(url, db, tenant) {
  const from = q(url, 'from', DAY, '0000-01-01'), to = q(url, 'to', DAY, '9999-12-31'); if (from > to) throw bad('from must not be after to.');
  if (url.searchParams.has('from') && url.searchParams.has('to') && (Date.parse(to) - Date.parse(from)) / 864e5 > 366) throw bad('The range is limited to 366 days.');
  const limit = Math.min(Math.max(Number(q(url, 'limit', /^\d{1,3}$/, '100')), 1), 500), channel = q(url, 'channel', /^(rest|mcp|x402|download)$/), op = q(url, 'operation', /^[a-z0-9_.]{1,60}$/);
  const after = q(url, 'after', /^[A-Za-z0-9._:|-]{1,400}$/), c = after ? after.split('|') : null; if (c && c.length !== 7) throw bad('Invalid after.');
  const rows = (await db.prepare(`SELECT day, tenant_id, channel, product, operation, status_class, commercial_mode, requests, units, bytes, duration_ms_sum, billable_micros, theoretical_micros FROM analytics_daily
    WHERE day BETWEEN ? AND ? AND (? IS NULL OR tenant_id = ?) AND (? IS NULL OR channel = ?) AND (? IS NULL OR operation = ?)
    ${c ? 'AND (day, tenant_id, channel, product, operation, status_class, commercial_mode) > (?,?,?,?,?,?,?)' : ''} ORDER BY day, tenant_id, channel, product, operation, status_class, commercial_mode LIMIT ?`)
    .bind(from, to, tenant, tenant, channel, channel, op, op, ...(c ?? []), limit + 1).all()).results;
  const page = rows.slice(0, limit), k = (r) => [r.day, r.tenant_id, r.channel, r.product, r.operation, r.status_class, r.commercial_mode].join('|');
  const body = { source: 'analytics_daily', accuracy: 'EXACT', note: 'best-effort telemetry; usage_events is the billing source', rows: page, next: rows.length > limit ? k(page[limit - 1]) : null, state: page.length || c ? 'REAL_VERIFIED' : 'NO_DATA' };
  if (fmt(url) === 'csv') { const cols = ['day', 'tenant_id', 'channel', 'product', 'operation', 'status_class', 'commercial_mode', 'requests', 'units', 'bytes', 'duration_ms_sum', 'billable_micros', 'theoretical_micros'];
    return file([cols.join(','), ...page.map((r) => cols.map((x) => r[x]).join(','))].join('\n') + '\n', 'text/csv; charset=utf-8', 'usage.csv'); }
  return jsonResponse(200, body);
}
