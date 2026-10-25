import test from 'node:test';
import assert from 'node:assert/strict';
import { apiWorld } from './apiworld.js';
import { fromBase32, totp, stepOf } from '../src/totp.js';
import { createAdmin } from '../src/admin.js';

const SECRET = { KEY_PEPPER: 'k'.repeat(40), ANALYTICS_PEPPER: 'a'.repeat(40), COMMUNITY_DOWNLOAD_BASE: 'https://dl.example.test/base', COMMUNITY_DEFAULT_ASSET: 'bundle.tar.gz' };
async function setup() {
  const w = await apiWorld({ envExtra: SECRET }); await w.tenant('t1'); await w.tenant('t2');
  const adm = await createAdmin(w.env.DB, w.env, w.clock, { name: 'root' }), seed = fromBase32(adm.totp_seed_base32);
  const hdr = async () => { w.clock.advance(60000); return { authorization: `Bearer ${adm.key}`, 'x-mfa-code': await totp(seed, stepOf(w.clock().getTime())) }; };
  const A = async (path, o = {}) => w.call(path, { ...o, headers: { ...(await hdr()), ...(o.headers ?? {}) } });
  return { w, A };
}

test('analytics admin routes need the administrator key AND a fresh MFA code; tenant keys cannot reach them', async () => {
  const { w, A } = await setup(); const key = (await w.key('t1')).key;
  assert.equal((await w.call('/admin/v1/analytics/kpis')).status, 401); assert.equal((await w.call('/admin/v1/analytics/kpis', { key })).status, 401);
  assert.equal((await A('/admin/v1/analytics/kpis')).status, 200); assert.equal((await A('/admin/v1/analytics/nope')).status, 404);
});
test('KPIs, catalog, dashboards in three formats, reports and alerts are served; bad filters are rejected, never ignored', async () => {
  const { w, A } = await setup(); const key = (await w.key('t1')).key; await w.call('/v1/intelligence/hash/' + 'a'.repeat(64), { key });
  const k = await A('/admin/v1/analytics/kpis'); assert.equal(k.json.mode, 'FREE_LAUNCH'); assert.equal(k.json.kpis.active_humans.state, 'NOT_INSTRUMENTED'); assert.equal(k.json.kpis.mau.value.total, 1);
  assert.ok((await A('/admin/v1/analytics/kpi-catalog')).json.metrics.length > 20);
  const csv = await A('/admin/v1/analytics/dashboards/api?format=csv'); assert.match(csv.res.headers.get('content-type'), /text\/csv/); assert.match(csv.text, /^dashboard,panel,state/);
  const html = await A('/admin/v1/analytics/dashboards/api?format=html'); assert.match(html.text, /<!doctype html>/); assert.equal((await A('/admin/v1/analytics/reports/weekly')).json.schema, 'macguard.report/1');
  assert.ok(Array.isArray((await A('/admin/v1/analytics/alerts')).json.alerts));
  for (const bad of ['?tenant=ghost', '?tenant=../x', '?format=xml', '?as_of=yesterday']) assert.ok([400, 404].includes((await A('/admin/v1/analytics/kpis' + bad)).status), bad);
  assert.equal((await A('/admin/v1/analytics/dashboards/api?tenant=t2')).json.panels.find((p) => p.id === 'requests').state, 'NO_DATA', 't2 has no traffic: not zero, not t1\'s');
});
test('usage listing paginates by keyset without gaps or repeats, filters, and exports CSV', async () => {
  const { w, A } = await setup(); const key = (await w.key('t1')).key;
  for (const op of ['/v1/intelligence/hash/' + 'a'.repeat(64), '/v1/intelligence/cve/CVE-2026-0001', '/v1/account/usage', '/v1/account/entitlements']) await w.call(op, { key });
  const all = (await A('/admin/v1/analytics/usage?limit=500')).json.rows, seen = []; let after = null;
  for (let i = 0; i < 10; i++) { const r = (await A('/admin/v1/analytics/usage?limit=2' + (after ? '&after=' + encodeURIComponent(after) : ''))).json; seen.push(...r.rows); after = r.next; if (!after) break; }
  assert.equal(seen.length, all.length); assert.deepEqual(seen.map((r) => r.operation), all.map((r) => r.operation)); assert.ok(all.length >= 3);
  assert.ok((await A('/admin/v1/analytics/usage?operation=account.usage')).json.rows.every((r) => r.operation === 'account.usage'));
  assert.equal((await A('/admin/v1/analytics/usage?tenant=t2')).json.state, 'NO_DATA');
  assert.match((await A('/admin/v1/analytics/usage?format=csv')).text, /^day,tenant_id,channel/); assert.equal((await A('/admin/v1/analytics/usage?from=2026-02-01&to=2026-01-01')).status, 400);
  assert.equal((await A('/admin/v1/analytics/usage?from=2024-01-01&to=2026-01-01')).status, 400, 'range limited to 366 days'); assert.equal((await A('/admin/v1/analytics/usage?after=a|b')).status, 400);
});
test('costs and CRM through the API: import, rates, estimate, summary, audit trail, state machine', async () => {
  const { w, A } = await setup();
  const imp = await A('/admin/v1/analytics/costs/import?provider=cloudflare', { method: 'POST', body: 'period,service,amount,currency\n2026-10,workers,5.00,USD\n' }); assert.equal(imp.status, 201); assert.equal(imp.json.imported, 1);
  assert.equal((await A('/admin/v1/analytics/costs/import?provider=cloudflare', { method: 'POST', body: 'period,service,amount,currency\n2026-10,workers,abc,USD\n' })).status, 422);
  assert.equal((await A('/admin/v1/analytics/costs/import?provider=cloudflare', { method: 'POST', body: 'x'.repeat(1_000_001) })).status, 413);
  assert.equal((await A('/admin/v1/analytics/costs/rates', { method: 'PUT', json: { provider: 'cloudflare', service: 'workers', usage_unit: 'request', micros_per_unit: 300, currency: 'USD', source_url: 'https://example.test/p' } })).status, 200);
  assert.equal((await A('/admin/v1/analytics/costs/estimate?period=2026-10', { method: 'POST' })).json.estimated.length, 1);
  const s = await A('/admin/v1/analytics/costs?period=2026-10'); assert.equal(s.json.lines[0].confirmed_micros, 5000000); assert.equal(s.json.lines[0].reconciliation.status, 'MISMATCH');
  const l = await A('/admin/v1/analytics/crm/leads', { method: 'POST', json: { org_name: 'Acme' } }); assert.equal(l.status, 201);
  assert.equal((await A(`/admin/v1/analytics/crm/leads/${l.json.lead_id}/state`, { method: 'POST', json: { state: 'WON' } })).status, 409);
  assert.equal((await A(`/admin/v1/analytics/crm/leads/${l.json.lead_id}/state`, { method: 'POST', json: { state: 'CONTACTED' } })).status, 200); assert.equal((await A('/admin/v1/analytics/crm/summary')).json.total, 1);
  const acts = (await w.env.DB.prepare("SELECT action FROM audit WHERE action LIKE 'analytics.%' OR action LIKE 'crm.%'").all()).results.map((r) => r.action); for (const a of ['analytics.cost_import', 'analytics.cost_rate', 'analytics.cost_estimate', 'crm.lead_created', 'crm.lead_moved']) assert.ok(acts.includes(a), a);
});
test('a tenant reads only its own analytics, and the tenant id cannot be chosen by the caller', async () => {
  const { w } = await setup(); const k1 = (await w.key('t1')).key, k2 = (await w.key('t2')).key;
  for (let i = 0; i < 3; i++) await w.call('/v1/intelligence/hash/' + 'a'.repeat(64), { key: k1 }); await w.call('/v1/intelligence/hash/' + 'a'.repeat(64), { key: k2 });
  const a1 = await w.call('/v1/account/analytics', { key: k1 }), a2 = await w.call('/v1/account/analytics?tenant=t1', { key: k2 });
  assert.equal(a1.status, 200); assert.equal(a1.json.tenant_id, 't1'); assert.equal(a2.json.tenant_id, 't2', 'the query string is ignored'); assert.ok(a1.json.kpis.requests_by_channel.value.rest.requests >= 3); assert.ok(a2.json.kpis.requests_by_channel.value.rest.requests < a1.json.kpis.requests_by_channel.value.rest.requests);
  assert.ok(!JSON.stringify(a1.json).includes('t2')); assert.equal((await w.call('/v1/account/analytics')).status, 401);
});

test('an administrator can force a GitHub sync; failures are reported (502) and audited, never thrown', async () => {
  const { w, A } = await setup(); const rel = [{ id: 1, tag_name: 'rules-20261021-1', draft: false, prerelease: false, assets: [{ id: 10, name: 'rules-release.tar.gz', size: 5, download_count: 7, content_type: 'application/gzip' }] }];
  w.env.fetchImpl = async () => new Response(JSON.stringify(rel), { status: 200, headers: { 'content-type': 'application/json' } });
  const ok = await A('/admin/v1/analytics/github/sync', { method: 'POST' }); assert.equal(ok.status, 200); assert.equal(ok.json.ok, true);
  assert.equal((await A('/admin/v1/analytics/downloads')).json.totals.bundle_downloads_cumulative, 7);
  w.env.fetchImpl = async () => { throw new Error('network down'); }; assert.equal((await A('/admin/v1/analytics/github/sync', { method: 'POST' })).status, 502);
  assert.equal((await w.call('/admin/v1/analytics/github/sync', { method: 'POST' })).status, 401);
  assert.ok((await w.env.DB.prepare("SELECT COUNT(*) n FROM audit WHERE action = 'analytics.github_sync'").first()).n === 2);
});

test('known test traffic is identified, not deleted: unauthenticated rows never reach commercial KPIs and marked redirect rows leave the dashboard', async () => {
  const { w, A } = await setup();
  for (let i = 0; i < 3; i++) await w.call('/v1/intelligence/hash/' + 'a'.repeat(64));                              // unauthenticated probes: recorded under the pseudo-tenant '-'
  await w.call('/v1/community/releases/rules-20261021-1/download');
  assert.ok((await w.env.DB.prepare("SELECT COUNT(*) n FROM analytics_daily WHERE tenant_id = '-'").first()).n >= 1, 'the probe rows exist (nothing deleted)');
  const k = (await A('/admin/v1/analytics/kpis')).json.kpis; assert.equal(k.requests_by_channel.state, 'NO_DATA', 'unauthenticated probes are not commercial traffic'); assert.equal(k.requests_by_channel.value, null); assert.equal(k.dau.state, 'NO_DATA');
  const before = (await A('/admin/v1/analytics/dashboards/downloads')).json.panels.find((p) => p.id === 'redirects'); assert.equal(before.data[0].n, 1);
  const day = w.clock().toISOString().slice(0, 10), key = `${day}|rules-20261021-1|bundle.tar.gz|anonymous_request`;
  assert.equal((await A('/admin/v1/analytics/exclusions', { method: 'POST', json: { source: 'community_requests_daily', row_key: key, reason: 'deployment verification probe' } })).status, 201);
  assert.equal((await A('/admin/v1/analytics/exclusions', { method: 'POST', json: { source: 'community_requests_daily', row_key: key, reason: 'again' } })).status, 200, 'idempotent');
  assert.equal((await A('/admin/v1/analytics/exclusions', { method: 'POST', json: { source: 'community_requests_daily', row_key: `${day}|nope|nope|anonymous_request`, reason: 'x' } })).status, 404, 'only an existing row can be marked');
  assert.equal((await A('/admin/v1/analytics/exclusions', { method: 'POST', json: { source: 'analytics_daily', row_key: key, reason: 'x' } })).status, 400);
  const after = (await A('/admin/v1/analytics/dashboards/downloads')).json.panels.find((p) => p.id === 'redirects'); assert.equal(after.state, 'NO_DATA');
  assert.equal((await w.env.DB.prepare('SELECT COUNT(*) n FROM community_requests_daily').first()).n, 1, 'the row itself is still there');
  const list = (await A('/admin/v1/analytics/exclusions')).json.exclusions; assert.equal(list.length, 1); assert.match(list[0].row_digest, /^[0-9a-f]{64}$/); assert.equal(list[0].reason, 'deployment verification probe');
});
