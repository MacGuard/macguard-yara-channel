import test from 'node:test';
import assert from 'node:assert/strict';
import { RULES, PUBLIC_PATHS, expression, matches, payload } from '../hardening/rules.js';

const H = 'api.mac-guard.com', R = (method, path, host = H) => ({ method, path, host });
const hit = (req) => RULES.filter((r) => matches(r, req, H)).map((r) => r.id);

test('no rule ever touches a Community or health request, whatever the method', () => {
  for (const method of ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'OPTIONS']) for (const path of ['/v1/community/releases', '/v1/community/releases/latest', '/v1/community/releases/rules-20261021-1/download', '/v1/community/releases/rules-20261021-1/manifest', '/v1/health'])
    assert.deepEqual(hit(R(method, path)).filter((id) => id !== 'unexpected-methods'), [], `${method} ${path}`);
  for (const r of RULES) for (const p of PUBLIC_PATHS) if (r.match.path_prefix?.some((x) => p.startsWith(x) && x !== '/')) assert.ok(r.match.path_not_prefix?.includes(p), `${r.id} covers ${p} only if it explicitly excludes it`);
});
test('legitimate traffic is left alone and abusive shapes are caught', () => {
  assert.deepEqual(hit(R('GET', '/admin/v1/analytics/kpis')), ['admin-rate']); assert.deepEqual(hit(R('POST', '/admin/v1/analytics/costs/import')), ['admin-rate']); assert.deepEqual(hit(R('PUT', '/admin/v1/analytics/costs/rates')), ['admin-rate']);
  assert.deepEqual(hit(R('DELETE', '/admin/v1/policy')), ['admin-methods', 'admin-rate']); assert.deepEqual(hit(R('PATCH', '/admin/v1/policy')), ['admin-methods', 'admin-rate']);
  assert.deepEqual(hit(R('POST', '/mcp')), ['mcp-rate']); assert.deepEqual(hit(R('GET', '/mcp')), ['mcp-method', 'mcp-rate']);
  assert.deepEqual(hit(R('POST', '/stripe/webhook')), ['webhook-rate']); assert.deepEqual(hit(R('GET', '/stripe/webhook')), ['webhook-method', 'webhook-rate']);
  assert.deepEqual(hit(R('GET', '/v1/intelligence/hash/' + 'a'.repeat(64))), ['api-rate']); assert.deepEqual(hit(R('GET', '/v1/premium/releases')), ['api-rate']);
  assert.deepEqual(hit(R('TRACE', '/anything')), ['unexpected-methods']);
  assert.deepEqual(hit(R('GET', '/anything', 'other.example.com')), [], 'rules are scoped to the gateway host: Quarantine and Pages hosts are untouched');
});
test('rendered expressions are scoped by host, parse as balanced, and carry the same structure as the data', () => {
  for (const r of RULES) { const e = expression(r, H); assert.ok(e.startsWith(`http.host eq "${H}"`), r.id); assert.equal([...e].filter((c) => c === '(').length, [...e].filter((c) => c === ')').length, r.id); assert.ok(!/[;`$]/.test(e), 'no injection characters'); }
  assert.equal(expression(RULES.find((r) => r.id === 'api-rate'), H), 'http.host eq "api.mac-guard.com" and (starts_with(http.request.uri.path, "/v1/")) and not starts_with(http.request.uri.path, "/v1/community/") and not starts_with(http.request.uri.path, "/v1/health")');
  assert.equal(expression(RULES.find((r) => r.id === 'admin-methods'), H), 'http.host eq "api.mac-guard.com" and (starts_with(http.request.uri.path, "/admin/")) and not http.request.method in {"GET" "POST" "PUT"}');
});
test('the payload is explicitly not applied and every rate rule has a bounded, per-IP characteristic', () => {
  const p = payload(H); assert.equal(p.applied, false); assert.match(p.note, /Not applied/);
  assert.equal(p.phases.http_ratelimit.length, 4); for (const r of p.phases.http_ratelimit) { assert.deepEqual(r.ratelimit.characteristics, ['ip.src']); assert.ok(r.ratelimit.requests >= 20 && r.ratelimit.period === 60 && r.ratelimit.mitigation_timeout <= 600); }
  assert.equal(new Set(RULES.map((r) => r.id)).size, RULES.length);
});

import { routes } from '../tools/route_inventory.mjs';
import { accessApplication } from '../hardening/rules.js';
const sampleOf = (p) => p.replace(/\{[^}]+\}/g, 'x');
test('regression before any rule is applied: every documented route is reachable with its documented method; only rate rules (never method blocks) touch legitimate calls; Community and health are untouched', () => {
  const METHOD_RULES = new Set(['admin-methods', 'webhook-method', 'mcp-method', 'unexpected-methods']);
  for (const r of routes().filter((x) => !(x.method === 'GET' && x.path === '/mcp'))) {       // GET /mcp is listed only to document that the Worker answers 405; the edge rule blocking it earlier is intended
    const hits = RULES.filter((x) => matches(x, { method: r.method, path: sampleOf(r.path), host: 'api.mac-guard.com' }, 'api.mac-guard.com')).map((x) => x.id);
    assert.deepEqual(hits.filter((id) => METHOD_RULES.has(id)), [], `${r.method} ${r.path} would be blocked by a method rule`);
    if (['community', 'health'].includes(r.area)) assert.deepEqual(hits, [], `${r.method} ${r.path}`);
    if (r.area.startsWith('admin')) assert.ok(hits.includes('admin-rate') && hits.length === 1, `${r.path}: ${hits}`);
    if (['intel', 'premium', 'download', 'account'].includes(r.area)) assert.deepEqual(hits, ['api-rate'], `${r.method} ${r.path}: ${hits}`);
    if (r.area === 'mcp') assert.deepEqual(hits, ['mcp-rate'], `${r.method} ${r.path}`); }
});
test('the Access application covers only /admin, keeps webhook and public routes out, and carries no real identity', () => {
  const a = accessApplication('api.mac-guard.com'); assert.equal(a.applied, false); assert.equal(a.app.domain, 'api.mac-guard.com/admin'); assert.ok(a.never_behind_access.includes('/stripe/webhook') && a.never_behind_access.includes('/v1/'));
  assert.ok(JSON.stringify(a).includes('OWNER_EMAIL_PLACEHOLDER') && !/@[a-z0-9-]+\./i.test(JSON.stringify(a)), 'a placeholder, not an address'); assert.equal(a.app.same_site_cookie_attribute, 'strict');
});
