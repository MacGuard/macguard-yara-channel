// Cloudflare edge hardening for the commercial gateway, as DATA. `expression()` renders each rule for the Rulesets API and `matches()` evaluates the very same data, so a test can prove which
// requests a rule touches (and that no Community path is ever blocked or limited). Nothing here is applied: tools/gen_hardening.mjs only writes the payload; applying it is a remote change that
// needs the owner's authorisation. Plan limits (number of rate-limiting rules, periods) must be checked against the account's plan before applying.
export const PUBLIC_PATHS = ['/v1/community/', '/v1/health'];                      // never blocked, challenged or rate limited by these rules
const MAX_ADMIN_METHODS = ['GET', 'POST', 'PUT'];

export const RULES = [
  { id: 'admin-methods', phase: 'http_request_firewall_custom', action: 'block', description: 'Administrator routes accept GET, POST and PUT only', match: { path_prefix: ['/admin/'], method_not_in: MAX_ADMIN_METHODS } },
  { id: 'webhook-method', phase: 'http_request_firewall_custom', action: 'block', description: 'The Stripe webhook is POST only', match: { path_prefix: ['/stripe/webhook'], method_not_in: ['POST'] } },
  { id: 'mcp-method', phase: 'http_request_firewall_custom', action: 'block', description: '/mcp is POST only (the Worker also answers 405)', match: { path_prefix: ['/mcp'], method_not_in: ['POST'] } },
  { id: 'unexpected-methods', phase: 'http_request_firewall_custom', action: 'block', description: 'TRACE, CONNECT and similar are never needed on the API', match: { path_prefix: ['/'], method_in: ['TRACE', 'CONNECT', 'TRACK'] } },
  { id: 'admin-rate', phase: 'http_ratelimit', action: 'block', description: 'Administrator routes: 20 requests per minute per IP, blocked for 10 minutes (stops key/TOTP guessing)', match: { path_prefix: ['/admin/'] }, rate: { requests: 20, period: 60, mitigation_timeout: 600, characteristics: ['ip.src'] } },
  { id: 'webhook-rate', phase: 'http_ratelimit', action: 'block', description: 'Stripe webhook: 120 requests per minute per IP (signature verification is the real control)', match: { path_prefix: ['/stripe/webhook'] }, rate: { requests: 120, period: 60, mitigation_timeout: 60, characteristics: ['ip.src'] } },
  { id: 'mcp-rate', phase: 'http_ratelimit', action: 'block', description: 'MCP: 300 requests per minute per IP (per-key quotas apply on top)', match: { path_prefix: ['/mcp'] }, rate: { requests: 300, period: 60, mitigation_timeout: 60, characteristics: ['ip.src'] } },
  { id: 'api-rate', phase: 'http_ratelimit', action: 'block', description: 'Authenticated REST (/v1/ except the public paths): 600 requests per minute per IP', match: { path_prefix: ['/v1/'], path_not_prefix: PUBLIC_PATHS }, rate: { requests: 600, period: 60, mitigation_timeout: 60, characteristics: ['ip.src'] } },
];

const q = (s) => JSON.stringify(s);
export function expression(rule, host) {
  const m = rule.match, parts = [];
  if (host) parts.push(`http.host eq ${q(host)}`);
  if (m.path_prefix) parts.push('(' + m.path_prefix.map((p) => `starts_with(http.request.uri.path, ${q(p)})`).join(' or ') + ')');
  if (m.path_not_prefix) for (const p of m.path_not_prefix) parts.push(`not starts_with(http.request.uri.path, ${q(p)})`);
  if (m.method_in) parts.push(`http.request.method in {${m.method_in.map(q).join(' ')}}`);
  if (m.method_not_in) parts.push(`not http.request.method in {${m.method_not_in.map(q).join(' ')}}`);
  return parts.join(' and ');
}
export function matches(rule, req, host) {
  const m = rule.match, p = req.path, meth = req.method.toUpperCase();
  if (host && req.host !== host) return false;
  if (m.path_prefix && !m.path_prefix.some((x) => p.startsWith(x))) return false;
  if (m.path_not_prefix && m.path_not_prefix.some((x) => p.startsWith(x))) return false;
  if (m.method_in && !m.method_in.includes(meth)) return false;
  if (m.method_not_in && m.method_not_in.includes(meth)) return false;
  return true;
}
// Cloudflare Access in front of the administrator routes: a second, independent gate (identity provider + MFA) before the application's own key + TOTP. PREPARED ONLY; the allowed identity is a placeholder the
// owner fills in. Webhook and public routes are never behind Access (Stripe and API clients cannot log in interactively).
export function accessApplication(host) {
  return { applied: false, note: 'Prepared payload for POST /accounts/{account_id}/access/apps. Replace OWNER_EMAIL_PLACEHOLDER. Not applied.', app: { name: 'macguard-gateway admin', type: 'self_hosted', domain: `${host}/admin`, session_duration: '12h', allowed_idps: [], auto_redirect_to_identity: false, http_only_cookie_attribute: true, same_site_cookie_attribute: 'strict' },
    policies: [{ name: 'owner only', decision: 'allow', include: [{ email: { email: 'OWNER_EMAIL_PLACEHOLDER' } }], require: [], exclude: [] }], never_behind_access: ['/stripe/webhook', '/mcp', '/v1/', '/x402/'] };
}
export function payload(host) {
  const by = (phase) => RULES.filter((r) => r.phase === phase).map((r) => ({ ref: r.id, description: r.description, expression: expression(r, host), action: r.action, ...(r.rate ? { ratelimit: r.rate } : {}), enabled: true }));
  return { host, access: accessApplication(host), applied: false, note: 'Prepared payload. Not applied. Confirm the account plan allows this many rate-limiting rules and these periods before applying.', phases: { http_request_firewall_custom: by('http_request_firewall_custom'), http_ratelimit: by('http_ratelimit') } };
}
