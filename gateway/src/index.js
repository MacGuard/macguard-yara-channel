// MacGuard gateway Worker (Premium, API, MCP). NOT DEPLOYED. The Community channel does not depend on it in any way: its files, signatures and logs are served from where they
// always were; /v1/community/* is only an index over them.
import { OPS } from './plans.js';
import { buildContext } from './context.js';
import { execute } from './ops.js';
import { effective, loadActive, policyHistory, propose, approve, applyProposal, rollback, acceptTerms, productOf } from './policy.js';
import { authenticateAdmin } from './admin.js';
import { entitlementsFor, requireCapability } from './entitlements.js';
import { serveDownload } from './downloads.js';
import { StripeApi, handleEvent, reportUsage, sweepPastDue, verifyWebhook } from './stripe.js';
import { handleMcp } from './mcp.js';
import { handleX402 } from './x402.js';
import { HttpError, errorResponse, jsonResponse, randomHex, readBounded } from './util.js';
import { audit } from './audit.js';
import { track, trackCommunity } from './analytics.js';
import { authenticate } from './auth.js';
import { sync as syncGithub } from './gh_collector.js';
import { adminAnalytics } from './analytics_api.js';
import { pruneAnalytics } from './retention.js';
import { adminTenants } from './admin_tenants.js';
import { flush as flushGuardops, enqueueMetrics } from './guardops.js';
import { emit } from './events.js';

const MAX_BODY = 64 * 1024, MAX_WEBHOOK_BODY = 256 * 1024;
const compile = (route) => { const [method, path] = route.split(' '); const names = []; const re = new RegExp('^' + path.replace(/\{(\w+)\}/g, (_, n) => { names.push(n); return '([^/]+)'; }) + '$'); return { method, re, names }; };
const TABLE = Object.entries(OPS).map(([op, o]) => ({ op, ...compile(o.route) }));
async function readJson(request) {
  const len = Number(request.headers.get('content-length') || 0); if (len > MAX_BODY) throw new HttpError(413, 'too_large', 'The request body is too large.');
  if (!/^application\/json\b/i.test(request.headers.get('content-type') || '')) throw new HttpError(415, 'unsupported_media_type', 'Send application/json.');
  const text = await readBounded(request, MAX_BODY);
  try { const v = JSON.parse(text); if (v === null || typeof v !== 'object' || Array.isArray(v)) throw 0; return v; } catch { throw new HttpError(400, 'invalid_json', 'The body is not a JSON object.'); }
}

export function createHandler({ clock = () => new Date(), stripe = (env) => new StripeApi({ apiKey: env.STRIPE_API_KEY, fetchImpl: env.fetchImpl }), facilitator = null } = {}) {
  const need = (ctx, scope) => { if (!ctx.scopes.has(scope)) throw new HttpError(403, 'insufficient_scope', `This key lacks the scope ${scope}.`, { required_scope: scope }); };

  return async function handle(request, env, ectx = { waitUntil: () => {} }) {
    const requestId = 'req_' + randomHex(8), url = new URL(request.url), path = url.pathname, db = env.DB;
    const defer = (p) => ectx.waitUntil(p);
    try {
      // Hostname gate. ALLOWED_HOSTS (comma list) restricts which hostnames this Worker answers on, so a Custom Domain attached by mistake can never expose the gateway under another service's name;
      // ADMIN_HOSTS (optional) further restricts /admin to specific hostnames (for example a hostname behind Cloudflare Access). Unset = no restriction (local tests, workers.dev).
      const hostIn = (list) => String(list).split(',').map((h) => h.trim().toLowerCase()).filter(Boolean).includes(url.hostname.toLowerCase());
      if ((env.ALLOWED_HOSTS && !hostIn(env.ALLOWED_HOSTS)) || (env.ADMIN_HOSTS && path.startsWith('/admin/') && !hostIn(env.ADMIN_HOSTS))) throw new HttpError(404, 'not_found', 'Not found.');
      const res = await route(request, env, db, path, url, requestId, defer);
      res.headers.set('x-request-id', requestId);
      return res;
    } catch (e) {
      if (!(e instanceof HttpError)) console.error(JSON.stringify({ request_id: requestId, error: String(e?.message ?? e).slice(0, 200) }));     // internal detail goes to the log, never to the client
      return errorResponse(e, requestId);
    } finally {
      if (env.__guardopsDirty) { env.__guardopsDirty = false; defer(flushGuardops(env, db, clock)); }                    // an operational event was queued during this request (answer or error): deliver it after the response
    }
  };

  async function route(request, env, db, path, url, requestId, defer) {
    if (path === '/v1/health') return jsonResponse(200, { ok: true });
    if (path === '/mcp') return handleMcp(request, env, db, clock, defer);
    if (path.startsWith('/x402/')) return handleX402(request, env, db, clock, facilitator ?? { verify: async () => ({ isValid: false }), settle: async () => null });
    if (path === '/stripe/webhook' && request.method === 'POST') {
      const raw = await readBounded(request, MAX_WEBHOOK_BODY); const secrets = (env.STRIPE_WEBHOOK_SECRETS || '').split(',').map((s) => s.trim()).filter(Boolean);
      if (!secrets.length) throw new HttpError(503, 'billing_unavailable', 'Billing is not configured.');
      const ev = await verifyWebhook(raw, request.headers.get('stripe-signature'), secrets, clock().getTime());
      return jsonResponse(200, { received: true, ...(await handleEvent(env, db, clock, stripe(env), ev)) });
    }
    if (path.startsWith('/admin/v1/')) return admin(request, env, db, path);
    if (path === '/v1/account/commercial' && request.method === 'GET') return commercial(request, env, db);
    if (path === '/v1/account/commercial/accept' && request.method === 'POST') {
      const ctx = await buildContext(request, env, db, clock); need(ctx, 'account.billing'); const b = await readJson(request);
      const a = await acceptTerms(db, clock, ctx, ctx.policy.doc, { pricing_version: b.pricing_version, terms_version: b.terms_version });
      return jsonResponse(200, { accepted: true, pricing_version: a.pricing_version, accepted_at: a.accepted_at, effect: 'applies to use from this moment on; earlier use is never charged' });
    }
    if (path === '/v1/account/checkout' && request.method === 'POST') {
      const ctx = await buildContext(request, env, db, clock); need(ctx, 'account.billing'); const b = await readJson(request);
      if (!ctx.policy.doc.billing.allow_checkout) throw new HttpError(409, 'checkout_disabled', 'Paid plans are not open yet.');
      const priceId = JSON.parse(env.PRICE_IDS || '{}')[b.plan]; if (!priceId) throw new HttpError(400, 'invalid_plan', 'Unknown plan.');
      const s = await stripe(env).createCheckoutSession({ tenantId: ctx.tenant.id, priceId, successUrl: env.CHECKOUT_SUCCESS_URL, cancelUrl: env.CHECKOUT_CANCEL_URL }, `checkout:${ctx.tenant.id}:${b.plan}:${clock().toISOString().slice(0, 10)}`);
      await audit(db, clock, ctx.tenant.id, 'checkout.created', { plan: b.plan }); return jsonResponse(200, { checkout_url: s.url });
    }
    const dl = /^\/v1\/dl\/(dlt_[A-Za-z0-9_-]{43})$/.exec(path);
    if (dl && request.method === 'GET') {
      const ctx = await buildContext(request, env, db, clock), eff = effective(ctx.policy.doc, ctx.tenant, 'premium', clock().getTime(), ctx.acceptance);
      need(ctx, 'premium.download'); requireCapability(await entitlementsFor(db, ctx, eff, clock().getTime(), 'rules.premium.download'), 'rules.premium.download');     // checked again at transfer time: a token minted before a downgrade or revocation is useless
      ctx.track = (extra) => track(env, db, clock, { tenantId: ctx.tenant.id, keyId: ctx.key.id, actorKind: ctx.key.actorKind, commercialMode: eff.mode, ...extra });
      return serveDownload(env, db, clock, ctx, eff, request, dl[1], defer);
    }
    for (const r of TABLE) {
      if (r.method !== request.method) continue; const m = r.re.exec(path); if (!m) continue;
      const params = Object.fromEntries(r.names.map((n, i) => [n, decodeURIComponent(m[i + 1])]));
      if (r.op.startsWith('community.')) return community(r.op, params, request, env, db, url, defer);
      const t0 = Date.now(); let ctx = null;
      const rec = (extra) => ({ tenantId: ctx?.tenant.id ?? '-', keyId: ctx?.key.id, actorKind: ctx?.key.actorKind, channel: 'rest', product: productOf(r.op), operation: r.op, durationMs: Date.now() - t0, commercialMode: ctx?.policy.doc.mode, ...extra });
      try {
        ctx = await buildContext(request, env, db, clock);
        const args = r.op === 'premium.download' ? { release_id: params.id } : r.op === 'intel.hash' ? { hash: params.sha256 } : r.op === 'intel.cve' ? { id: params.id }
          : ['intel.ioc.search', 'intel.enrich', 'usage.estimate'].includes(r.op) ? await readJson(request) : {};
        const out = await execute({ env, db, clock }, ctx, r.op, args, { idemKey: request.headers.get('idempotency-key'), requestId });
        defer(track(env, db, clock, rec({ httpStatus: 200, commercialMode: out.eff.mode, units: out.units, billable: out.billable, theoretical: out.theoretical, replayed: out.replayed })));
        return jsonResponse(200, out.result, { 'x-commercial-mode': out.eff.mode, 'x-access-mode': out.accessMode, ...(out.usage_event_id ? { 'x-usage-event-id': out.usage_event_id } : {}), ...(out.replayed ? { 'x-idempotent-replayed': 'true' } : {}) });
      } catch (e) { if (e instanceof HttpError) defer(track(env, db, clock, rec({ httpStatus: e.status }))); throw e; }
    }
    throw new HttpError(404, 'not_found', 'Not found.');
  }

  // Community: an index over the existing public site. If it is unreachable the index fails; the files, signatures and logs themselves are untouched and keep being served as before.
  async function community(op, params, request, env, db, url, defer) {
    if (op === 'community.releases.download' || op === 'community.releases.manifest') {
      // A redirect to the public asset. Telemetry is best-effort and never gates it. A redirect is a REQUEST that was AUTHORISED to leave for GitHub: completion happens on
      // GitHub's side and is not observable here, so nothing in this route can ever be reported as a completed download.
      // The public location and the default asset name are CONFIGURATION (wrangler vars): this code never names the Community data paths.
      const base = (env.COMMUNITY_DOWNLOAD_BASE || '').replace(/\/$/, ''), tag = params.id, asset = op === 'community.releases.manifest' ? 'manifest.json' : (url.searchParams.get('asset') || env.COMMUNITY_DEFAULT_ASSET || '');
      if (!/^https:\/\/[A-Za-z0-9.-]+(\/[A-Za-z0-9._-]+)*$/.test(base) || !asset) throw new HttpError(503, 'origin_unavailable', 'The Community download location is not configured.');
      if (!/^rules-\d{8}-\d+$/.test(tag) || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(asset)) throw new HttpError(400, 'invalid_input', 'Unknown release or asset name.');
      if (db) defer((async () => {
        try { let kind = 'anonymous_request'; if (request.headers.get('authorization')) { try { kind = (await authenticate(request, env, db, clock)).key.actorKind; } catch { /* an invalid key is just anonymous here */ } } await trackCommunity(db, clock, { tag, asset, actorKind: kind }, env); } catch { /* telemetry never matters here */ }
      })());
      return new Response(null, { status: 302, headers: { location: `${base}/${tag}/${asset}`, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' } });
    }
    const origin = (env.COMMUNITY_ORIGIN || '').replace(/\/$/, ''); if (!origin) throw new HttpError(503, 'origin_unavailable', 'The Community index is not configured.');
    let r; try { r = await (env.fetchImpl ?? fetch)(`${origin}/${op === 'community.releases.latest' ? 'latest.json' : 'releases.json'}`, { signal: AbortSignal.timeout(8000) }); } catch { throw new HttpError(502, 'origin_unavailable', 'The Community site could not be reached.'); }
    if (!r.ok) throw new HttpError(502, 'origin_unavailable', 'The Community site returned an error.');
    return new Response(await r.text(), { status: 200, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'public, max-age=300', 'x-content-type-options': 'nosniff' } });
  }

  async function commercial(request, env, db) {
    const ctx = await buildContext(request, env, db, clock); need(ctx, 'account.read'); const d = ctx.policy.doc, now = clock().getTime();
    const eff = (p) => effective(d, ctx.tenant, p, now, ctx.acceptance);
    return jsonResponse(200, { policy_version: ctx.policy.version, modes: { premium: eff('premium').mode, api: eff('api').mode }, community: 'FREE_FOREVER',
      upcoming_change: d.scheduled ? { mode: d.scheduled.mode, effective_from: d.scheduled.effective_from, notice_days: d.billing.notice_days } : null,
      pricing: { version: d.billing.pricing.version, approved: d.billing.pricing.approved, currency: d.billing.pricing.currency, unit_micros: d.billing.pricing.unit_micros, note: d.billing.pricing.approved ? undefined : 'example prices, not an offer' },
      terms_version: d.billing.terms_version, terms_accepted: eff('api').accepted, charging_now: eff('api').charging, checkout_open: d.billing.allow_checkout,
      guarantees: ['nothing is charged before you accept the pricing and terms', 'use before your acceptance is never charged', 'Community stays free'] });
  }

  async function admin(request, env, db, path) {
    const a = await authenticateAdmin(request, env, db, clock);
    if (path === '/admin/v1/policy' && request.method === 'GET') { const act = await loadActive(db); return jsonResponse(200, { version: act.version, policy: act.doc, history: await policyHistory(db) }); }
    if (path === '/admin/v1/policy/proposals' && request.method === 'POST') { const b = await readJson(request); return jsonResponse(201, await propose(db, clock, a, b.policy, String(b.reason ?? '').slice(0, 300))); }
    const m = /^\/admin\/v1\/policy\/proposals\/(pp_[0-9a-f]{20})\/(approve|apply)$/.exec(path);
    if (m && request.method === 'POST') return jsonResponse(200, m[2] === 'approve' ? await approve(db, clock, a, m[1]) : await applyProposal(db, clock, a, m[1]));
    if (path === '/admin/v1/policy/rollback' && request.method === 'POST') { const b = await readJson(request); return jsonResponse(200, await rollback(db, clock, a, String(b.reason ?? 'rollback').slice(0, 300))); }
    if (path === '/admin/v1/tenants' || path.startsWith('/admin/v1/tenants/')) return adminTenants(request, env, db, clock, path, new URL(request.url), a);
    if (path.startsWith('/admin/v1/analytics')) return adminAnalytics(request, env, db, clock, path, new URL(request.url), a);
    throw new HttpError(404, 'not_found', 'Not found.');
  }
}

const handler = createHandler();
export default {
  fetch: (request, env, ctx) => handler(request, env, ctx),
  async scheduled(event, env, ctx) {                                           // cron: expire grace periods and report charged usage (a no-op while billing is not live)
    ctx.waitUntil((async () => { const clock = () => new Date(); await sweepPastDue(env.DB, clock, Number(env.GRACE_DAYS) || 3); await reportUsage(env, env.DB, clock, new StripeApi({ apiKey: env.STRIPE_API_KEY })); })());
    if (new Date(event?.scheduledTime ?? Date.now()).getUTCHours() === 3) ctx.waitUntil(pruneAnalytics(env.DB, () => new Date()).catch(() => null));       // once a day (the 03:xx run): analytics older than a year
    ctx.waitUntil((async () => {                                                                  // read-only collector; records its own failures and never throws
      const clock = () => new Date(), r = await syncGithub(env.DB, clock, (u, o) => fetch(u, o), { repo: env.COMMUNITY_REPO || 'MacGuard/macguard-yara-channel', token: env.GITHUB_TOKEN || null });
      if (!r.ok) { const n = (await env.DB.prepare('SELECT consecutive_failures n FROM gh_sync WHERE id = 1').first().catch(() => null))?.n ?? 0; if (n === 3 || (n > 3 && n % 6 === 0)) await emit(env, clock, 'gateway.incident', { component: 'github-collector', code: r.status }); }       // report a streak, not every blip
      if (new Date(event?.scheduledTime ?? Date.now()).getUTCHours() === 6) await enqueueMetrics(env, env.DB, clock);
      await flushGuardops(env, env.DB, clock);
    })());
  },
};
