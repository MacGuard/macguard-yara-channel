// Plans, operations and PRICING. This file is the single source of truth for REST, MCP and the OpenAPI document (a test compares them), so a tool cannot exist that the REST
// pipeline would not authorise in the same way.
// Prices, their approval and the commercial mode live in the versioned policy document (policy.js), NOT in code: changing them needs no deployment.
export const PLANS = Object.freeze({
  community: { features: [], quotas: { minute: 30, day: 2000, month: 20000, downloads_month: 0, bytes_month: 0 }, default_budget_micros: 0 },
  intelligence: { features: ['premium', 'intel', 'intel.enrich', 'mcp'], quotas: { minute: 60, day: 5000, month: 100000, downloads_month: 30, bytes_month: 2 * 1024 ** 3 }, default_budget_micros: 0 },
  business: { features: ['premium', 'intel', 'intel.enrich', 'mcp'], quotas: { minute: 300, day: 50000, month: 1000000, downloads_month: 300, bytes_month: 20 * 1024 ** 3 }, default_budget_micros: 0 },
});

// class: free (no auth needed or no cost), included (in the subscription, counts against quotas), metered (also costs money per unit against the tenant's budget)
export const OPS = Object.freeze({
  'community.releases.list': { class: 'free', auth: false, route: 'GET /v1/community/releases', title: 'List Community releases', tool: null },
  'community.releases.latest': { class: 'free', auth: false, route: 'GET /v1/community/releases/latest', title: 'Latest Community release', tool: null },
  'community.releases.download': { class: 'free', auth: false, route: 'GET /v1/community/releases/{id}/download', title: 'Redirect to a Community release asset (default: the bundle)', tool: null },
  'community.releases.manifest': { class: 'free', auth: false, route: 'GET /v1/community/releases/{id}/manifest', title: 'Redirect to the signed manifest of a Community release', tool: null },
  'premium.releases.list': { class: 'included', scope: 'premium.read', feature: 'premium', route: 'GET /v1/premium/releases', title: 'List Premium releases', tool: 'macguard_list_premium_releases' },
  'premium.releases.latest': { class: 'included', scope: 'premium.read', feature: 'premium', route: 'GET /v1/premium/releases/latest', title: 'Latest Premium release', tool: 'macguard_latest_premium_release' },
  'premium.download': { class: 'included', scope: 'premium.download', feature: 'premium', route: 'GET /v1/premium/releases/{id}/download', title: 'Authorise a Premium download', tool: 'macguard_authorize_download' },
  'intel.hash': { class: 'included', scope: 'intel.query', feature: 'intel', route: 'GET /v1/intelligence/hash/{sha256}', title: 'Look up a file hash', tool: 'macguard_lookup_hash' },
  'intel.cve': { class: 'included', scope: 'intel.query', feature: 'intel', route: 'GET /v1/intelligence/cve/{id}', title: 'Look up a CVE (KEV, EPSS, EUVD where licensed)', tool: 'macguard_lookup_cve' },
  'intel.ioc.search': { class: 'included', scope: 'intel.query', feature: 'intel', route: 'POST /v1/intelligence/ioc/search', title: 'Search indicators', tool: 'macguard_search_iocs' },
  'intel.enrich': { class: 'metered', scope: 'intel.enrich', feature: 'intel.enrich', unit: 'indicator', route: 'POST /v1/intelligence/enrich', title: 'Enrich and correlate indicators', tool: 'macguard_enrich_indicators' },
  'usage.estimate': { class: 'free', auth: true, scope: 'usage.estimate', route: 'POST /v1/usage/estimate', title: 'Estimate the cost of planned operations', tool: 'macguard_estimate_cost' },
  'account.usage': { class: 'free', auth: true, scope: 'account.read', route: 'GET /v1/account/usage', title: 'Usage and spend this month', tool: 'macguard_account_usage' },
  'account.analytics': { class: 'free', auth: true, scope: 'account.read', route: 'GET /v1/account/analytics', title: 'Your own usage analytics (30 days)', tool: null },
  'account.entitlements': { class: 'free', auth: true, scope: 'account.read', route: 'GET /v1/account/entitlements', title: 'Plan, features, quotas and key scopes', tool: null },
});
export const ALL_SCOPES = Object.freeze([...new Set(Object.values(OPS).map((o) => o.scope).filter(Boolean)), 'mcp', 'account.billing']);
export const unitsFor = (op, args) => (op === 'intel.enrich' ? Math.max(1, args?.indicators?.length ?? 1) : 1);
