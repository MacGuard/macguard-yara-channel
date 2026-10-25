// Generates docs/analytics/ROUTE-INVENTORY.md: every route of the gateway with its target hostname, owner service, authentication, permission, dependencies, DNS/migration impact, risk, smoke test and
// rollback, plus the edge rules that touch it. Operation routes come from the code (OPS); the others are listed here and a test calls each of them so the list cannot drift. `--check` compares with the file.
import { readFileSync, writeFileSync } from 'node:fs';
import { OPS } from '../src/plans.js';
import { RULES, matches } from '../hardening/rules.js';

export const TARGET = 'api.mac-guard.com', WORKER = 'macguard-gateway';
// Areas carry the columns that are the same for all their routes.
export const AREAS = {
  health: { what: 'liveness', auth: 'none', perm: '-', deps: 'none', risk: 'none', smoke: 'GET /v1/health -> 200 over TLS', rollback: 'redeploy previous version' },
  community: { what: 'Community index and redirect helpers', auth: 'none (optional key only to label the caller kind)', perm: '-', deps: 'GitHub Releases (public), D1 for best-effort counts only', risk: 'must never fail because telemetry or D1 is down; must not be rate limited', smoke: 'GET /v1/community/releases/<tag>/download -> 302 to the public asset; 400 on a bad tag', rollback: 'redeploy previous version; the public GitHub URLs never depended on it' },
  intel: { what: 'Intelligence REST (hash, CVE, IOC, enrich)', auth: 'API key (Bearer mgk_)', perm: 'scope intel.query / intel.enrich', deps: 'D1 (records, quotas, ledger)', risk: 'licence gate must hold; quotas atomic', smoke: 'GET /v1/intelligence/hash/<sha256> without key -> 401', rollback: 'redeploy previous version' },
  premium: { what: 'Premium catalogue and authorised download', auth: 'API key', perm: 'scope premium.read / premium.download', deps: 'D1 + private R2 bucket (binding PREMIUM)', risk: 'R2 private; one-time bound token; licence gate', smoke: 'GET /v1/premium/releases without key -> 401', rollback: 'redeploy previous version' },
  download: { what: 'Signed download transfer (Range)', auth: 'API key + one-time token bound to the key', perm: 'scope premium.download', deps: 'D1 + R2', risk: 'token reuse/sharing; partial transfers', smoke: 'GET /v1/dl/<token> without key -> 401', rollback: 'redeploy previous version' },
  account: { what: 'Tenant self-service (usage, entitlements, analytics, commercial terms, checkout)', auth: 'API key', perm: 'scope account.read / account.billing', deps: 'D1; Stripe only for checkout (not configured)', risk: 'tenant id only from the key', smoke: 'GET /v1/account/usage without key -> 401', rollback: 'redeploy previous version' },
  mcp: { what: 'MCP server (stateless, revision 2026-07-28)', auth: 'API key', perm: 'scope mcp + the operation scope', deps: 'same pipeline as REST', risk: 'body size, Origin check', smoke: 'GET /mcp -> 405; POST without key -> 400/401', rollback: 'redeploy previous version' },
  webhook: { what: 'Stripe webhook', auth: 'Stripe signature over the raw body', perm: '-', deps: 'D1 (event-id dedupe); STRIPE_WEBHOOK_SECRETS (not configured)', risk: 'replay, forged events, oversize bodies', smoke: 'POST /stripe/webhook unsigned -> 400/503', rollback: 'redeploy previous version; remove the webhook endpoint in Stripe' },
  x402: { what: 'x402 pay-per-request (experimental, OFF)', auth: 'payment proof', perm: '-', deps: 'facilitator (none)', risk: 'must stay disabled', smoke: 'GET /x402/anything -> 404', rollback: 'n/a' },
  'admin-policy': { what: 'Commercial policy: propose, approve, apply, rollback', auth: 'administrator key + TOTP (+ two approvals for charging modes)', perm: 'administrator', deps: 'D1', risk: 'changing the commercial mode; Cloudflare Access recommended in front', smoke: 'GET /admin/v1/policy without credentials -> 401', rollback: 'POST /admin/v1/policy/rollback' },
  'admin-analytics': { what: 'Analytics API, dashboards, reports, costs, CRM, exclusions, forced GitHub sync', auth: 'administrator key + TOTP', perm: 'administrator', deps: 'D1; GitHub API for the sync', risk: 'cost/CRM data is commercially sensitive', smoke: 'GET /admin/v1/analytics/kpis without credentials -> 401', rollback: 'redeploy previous version' },
  'admin-tenants': { what: 'Tenants and API-key lifecycle', auth: 'administrator key + TOTP', perm: 'administrator', deps: 'D1 (KEY_PEPPER secret)', risk: 'a new key is shown once; audit chain', smoke: 'GET /admin/v1/tenants without credentials -> 401', rollback: 'revoke the key / suspend the tenant' },
};
const area = (op, o) => (op.startsWith('community.') ? 'community' : op.startsWith('intel.') ? 'intel' : op === 'premium.download' ? 'premium' : op.startsWith('premium.') ? 'premium' : 'account');
export const STATIC = [
  ['GET', '/v1/health', 'health'], ['POST', '/mcp', 'mcp'], ['GET', '/mcp', 'mcp'], ['POST', '/stripe/webhook', 'webhook'], ['GET', '/x402/{any}', 'x402'], ['GET', '/v1/dl/{token}', 'download'],
  ['GET', '/v1/account/commercial', 'account'], ['POST', '/v1/account/commercial/accept', 'account'], ['POST', '/v1/account/checkout', 'account'],
  ['GET', '/admin/v1/policy', 'admin-policy'], ['POST', '/admin/v1/policy/proposals', 'admin-policy'], ['POST', '/admin/v1/policy/proposals/{id}/approve', 'admin-policy'], ['POST', '/admin/v1/policy/proposals/{id}/apply', 'admin-policy'], ['POST', '/admin/v1/policy/rollback', 'admin-policy'],
  ['GET', '/admin/v1/analytics/kpis', 'admin-analytics'], ['GET', '/admin/v1/analytics/kpi-catalog', 'admin-analytics'], ['GET', '/admin/v1/analytics/dashboards/{id}', 'admin-analytics'], ['GET', '/admin/v1/analytics/reports/{kind}', 'admin-analytics'], ['GET', '/admin/v1/analytics/alerts', 'admin-analytics'],
  ['GET', '/admin/v1/analytics/downloads', 'admin-analytics'], ['GET', '/admin/v1/analytics/usage', 'admin-analytics'], ['GET', '/admin/v1/analytics/costs', 'admin-analytics'], ['GET', '/admin/v1/analytics/costs/unit', 'admin-analytics'], ['GET', '/admin/v1/analytics/crm/summary', 'admin-analytics'], ['GET', '/admin/v1/analytics/crm/leads', 'admin-analytics'], ['GET', '/admin/v1/analytics/exclusions', 'admin-analytics'],
  ['POST', '/admin/v1/analytics/costs/import', 'admin-analytics'], ['PUT', '/admin/v1/analytics/costs/rates', 'admin-analytics'], ['POST', '/admin/v1/analytics/costs/estimate', 'admin-analytics'], ['POST', '/admin/v1/analytics/crm/leads', 'admin-analytics'], ['POST', '/admin/v1/analytics/crm/leads/{id}/state', 'admin-analytics'], ['POST', '/admin/v1/analytics/exclusions', 'admin-analytics'], ['POST', '/admin/v1/analytics/github/sync', 'admin-analytics'],
  ['GET', '/admin/v1/tenants', 'admin-tenants'], ['POST', '/admin/v1/tenants', 'admin-tenants'], ['GET', '/admin/v1/tenants/{id}', 'admin-tenants'], ['POST', '/admin/v1/tenants/{id}/status', 'admin-tenants'], ['POST', '/admin/v1/tenants/{id}/keys', 'admin-tenants'], ['POST', '/admin/v1/tenants/{id}/keys/{key}/revoke', 'admin-tenants'], ['POST', '/admin/v1/tenants/{id}/keys/{key}/rotate', 'admin-tenants'],
];
export function routes() {
  const rows = [...STATIC.map(([m, p, a]) => ({ method: m, path: p, area: a, source: 'router' }))];
  for (const [op, o] of Object.entries(OPS)) { const [m, p] = o.route.split(' '); rows.push({ method: m, path: p, area: area(op, o), source: 'OPS ' + op, auth: o.auth === false ? 'none' : undefined, scope: o.scope }); }
  return rows;
}
const sample = (p) => p.replace(/\{[^}]+\}/g, 'x');
export function render() {
  const lines = ['# Route inventory (generated by `gateway/tools/route_inventory.mjs`; do not edit by hand)', '',
    `Target for every route below: **${TARGET}**, served by the single Worker \`${WORKER}\` (a modular backend, not one service per hostname). Current host: \`quarantine-api.mac-guard.com\` (see DOMAIN-ARCHITECTURE.md). Quarantine routes are NOT in this table: they belong to the Quarantine Worker and keep \`panel.\` / \`quarantine-api.\`. DNS: one new record for \`api\` at cutover (Custom Domain), nothing else. D1 migrations: \`0001\` and \`0002\` before the code that needs them.`, '',
    '| Method | Path | Area | Auth | Permission | Edge rules that touch it |', '|---|---|---|---|---|---|'];
  for (const r of routes()) { const a = AREAS[r.area], hit = RULES.filter((x) => matches(x, { method: r.method, path: sample(r.path), host: TARGET }, TARGET)).map((x) => x.id).join(', ') || '—';
    lines.push(`| ${r.method} | \`${r.path}\` | ${r.area} | ${r.auth ?? a.auth} | ${r.scope ?? a.perm} | ${hit} |`); }
  lines.push('', '## Per area: function, dependencies, risk, smoke test, rollback', '', '| Area | Function | Dependencies | Risk | Smoke test | Rollback |', '|---|---|---|---|---|---|');
  for (const [k, a] of Object.entries(AREAS)) lines.push(`| ${k} | ${a.what} | ${a.deps} | ${a.risk} | ${a.smoke} | ${a.rollback} |`);
  return lines.join('\n') + '\n';
}
if (process.argv[1] && process.argv[1].endsWith('route_inventory.mjs')) {
  const file = new URL('../../docs/analytics/ROUTE-INVENTORY.md', import.meta.url), text = render();
  if (process.argv.includes('--check')) { if (readFileSync(file, 'utf8') !== text) { console.error('ROUTE-INVENTORY.md is out of date'); process.exit(1); } console.log('ROUTE-INVENTORY.md is current'); } else { writeFileSync(file, text); console.log('written'); }
}
