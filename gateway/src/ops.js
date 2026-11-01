// The single implementation of every operation. REST routes and MCP tools both call execute(); neither has its own copy of a permission, quota or price check.
import { OPS, PLANS } from './plans.js';
import * as intel from './intel.js';
import { authorizeDownload, listReleases } from './downloads.js';
import { authorize, effectiveFor, monthUsage, run, usageEventId } from './pipeline.js';
import { effective, productOf } from './policy.js';
import { PUBLIC, accessMode, entitlementsFor, loadGrants, principalOf, redactIntel, resolve, snapshot } from './entitlements.js';
import { emit } from './events.js';
import { kpis } from './kpi.js';
import { HttpError, windows } from './util.js';

const HASH = { type: 'string', pattern: '^([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$' };
const IND = { type: 'string', minLength: 1, maxLength: 2048 };
export const INPUT = Object.freeze({
  'premium.releases.list': { type: 'object', properties: {}, additionalProperties: false },
  'premium.releases.latest': { type: 'object', properties: {}, additionalProperties: false },
  'premium.download': { type: 'object', properties: { release_id: { type: 'string', pattern: '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' } }, required: ['release_id'], additionalProperties: false },
  'intel.hash': { type: 'object', properties: { hash: HASH }, required: ['hash'], additionalProperties: false },
  'intel.cve': { type: 'object', properties: { id: { type: 'string', pattern: '^[Cc][Vv][Ee]-\\d{4}-\\d{4,7}$' } }, required: ['id'], additionalProperties: false },
  'intel.ioc.search': { type: 'object', properties: { value: IND, values: { type: 'array', items: IND, minItems: 1, maxItems: 50 }, type: { type: 'string', enum: ['sha256', 'sha1', 'md5', 'ipv4', 'domain', 'url'] } }, additionalProperties: false },
  'intel.enrich': { type: 'object', properties: { indicators: { type: 'array', items: IND, minItems: 1, maxItems: 50 } }, required: ['indicators'], additionalProperties: false },
  'usage.estimate': { type: 'object', properties: { operations: { type: 'array', minItems: 1, maxItems: 50, items: { type: 'object', properties: { operation: { type: 'string', enum: Object.keys(OPS) }, count: { type: 'integer', minimum: 1, maximum: 1000000 } }, required: ['operation'], additionalProperties: false } } }, required: ['operations'], additionalProperties: false },
  'account.usage': { type: 'object', properties: {}, additionalProperties: false },
  'account.entitlements': { type: 'object', properties: {}, additionalProperties: false },
  'account.analytics': { type: 'object', properties: {}, additionalProperties: false },
});

const H = {
  'premium.releases.list': async ({ db }) => ({ releases: await listReleases(db, 'premium') }),
  'premium.releases.latest': async ({ db }) => { const r = (await listReleases(db, 'premium'))[0]; if (!r) throw new HttpError(404, 'not_found', 'No Premium release is published yet.'); return r; },
  'premium.download': async ({ db, clock, ctx, args, env }) => {
    const d = await authorizeDownload(db, clock, ctx, null, args.release_id, Number(env.DOWNLOAD_TTL_SECONDS) || undefined);
    await emit(env, clock, 'download.authorized', { tenant_id: ctx.tenant.id, api_key_id: ctx.key.id, release_id: args.release_id });
    const { token, url_path, ...rest } = d; return { ...rest, url: `${env.PUBLIC_BASE}${url_path}`, note: 'Present your API key together with this URL; it works only for the key that asked for it.' };
  },
  'intel.hash': ({ db, clock, args }) => intel.hash(db, clock, args.hash),
  'intel.cve': ({ db, clock, args }) => intel.cve(db, clock, args.id),
  'intel.ioc.search': ({ db, clock, args }) => intel.iocSearch(db, clock, args),
  'intel.enrich': ({ db, clock, args }) => intel.enrich(db, clock, args),
  // Asking for a price is not executing: nothing is metered, charged or reserved.
  'usage.estimate': async ({ ctx, eff, args }) => {
    const lines = args.operations.map((o) => {
      const spec = OPS[o.operation], n = o.count ?? 1, unit = eff.pricing.unit_micros[o.operation] ?? 0, theo = ctx.policy.doc.theoretical_prices_micros?.[o.operation] ?? unit;
      return { operation: o.operation, count: n, class: spec.class, would_be_charged_micros: eff.charging && spec.class === 'metered' ? unit * n : 0, theoretical_micros: theo * n };
    });
    return { commercial_mode: eff.mode, charging_now: eff.charging, currency: eff.currency, pricing_version: eff.pricing.version, prices_approved: eff.pricing.approved, lines,
      total_would_be_charged_micros: lines.reduce((a, l) => a + l.would_be_charged_micros, 0), total_theoretical_micros: lines.reduce((a, l) => a + l.theoretical_micros, 0), note: 'estimate only; nothing was executed or reserved' };
  },
  'account.usage': ({ db, ctx, clock }) => monthUsage(db, ctx, clock),
  // Own-tenant analytics only: the tenant id comes from the authenticated key, never from the request.
  'account.analytics': async ({ db, ctx, clock, eff }) => { const k = await kpis(db, clock, { tenantId: ctx.tenant.id, mode: eff.mode }); return { tenant_id: ctx.tenant.id, commercial_mode: eff.mode, kpis: Object.fromEntries(['mau', 'premium_actors_30d', 'requests_by_channel', 'error_rate', 'latency_ms', 'units_consumed', 'billed_micros'].map((id) => [id, k[id]])) }; },
  'account.entitlements': async ({ db, ctx, eff, clock }) => ({ ...entitlementsView(ctx, eff, await loadGrants(db, ctx.tenant.id), clock().getTime()), tenant: { id: ctx.tenant.id, plan: ctx.tenant.plan }, key_id: ctx.key.id, scopes: [...ctx.scopes].sort(), commercial_mode: eff.mode, mode_source: eff.source, features: [...eff.features].sort(), quotas: eff.quotas,
    charging: eff.charging, terms_accepted: eff.accepted, policy_version: ctx.policy.version, plans_available: Object.keys(PLANS), month: windows(clock()).month }),
};

// The capability records of GET /v1/account/entitlements (contract macguard.entitlements/1), next to the existing plan/features/quotas fields.
// A capability that gates operations is listed only if authorize() would let at least one of those operations through for THIS key, each resolved with its OWN
// product policy (premium routes use the premium product, intel routes the api product): what the endpoint advertises is what the routes enforce.
// Public capabilities are always listed (they describe the public portal, not the licensed API lookup, which keeps its own commercial gate).
const CAP_OPS = Object.entries(OPS).reduce((m, [op, s]) => (s.capability && !PUBLIC.includes(s.capability) ? { ...m, [s.capability]: [...(m[s.capability] || []), op] } : m), {});
function effectiveEntitlements(ctx, grants, nowMs, base) {
  const caps = new Set(base.caps), via = { ...base.via }, preview = new Set(base.preview);
  for (const [c, ops] of Object.entries(CAP_OPS)) {
    let hit = null;
    for (const op of ops) {
      const e = effectiveFor(ctx, op, nowMs), ent = resolve(principalOf(ctx, e, grants), nowMs);
      try { authorize(ctx, op, e, ent); hit = ent; break; } catch (err) { if (!(err instanceof HttpError)) throw err; }
    }
    if (hit) { caps.add(c); via[c] = hit.via[c]; if (hit.preview.has(c)) preview.add(c); else preview.delete(c); } else { caps.delete(c); delete via[c]; preview.delete(c); }
  }
  return { ...base, caps, via, preview };
}
const entitlementsView = (ctx, eff, grants, nowMs) => { const s = snapshot(ctx, eff, effectiveEntitlements(ctx, grants, nowMs, resolve(principalOf(ctx, eff, grants), nowMs)), grants, nowMs); return { entitlements: s, capabilities: s.capabilities, access_mode: s.access_mode, preview: s.preview_capabilities.length > 0 }; };
const INTEL_READS = new Set(['intel.hash', 'intel.cve', 'intel.ioc.search']);

export async function execute(deps, ctx, opName, args, { idemKey = null, requestId }) {
  const { env, db, clock } = deps, spec = OPS[opName];
  if (!spec || !H[opName]) throw new HttpError(404, 'unknown_operation', 'No such operation.');
  const schema = INPUT[opName]; const { validate } = await import('./schema.js'); const errs = validate(schema, args ?? {});
  if (errs.length) throw new HttpError(400, 'invalid_input', errs.slice(0, 3).join('; '));
  if (opName === 'intel.ioc.search' && !('value' in args) && !('values' in args)) throw new HttpError(400, 'invalid_input', 'Send "value" or "values".');
  const nowMs = clock().getTime();
  // CVE data is licensed per product: an indicator search or enrichment that asks for a CVE must pass the SAME gate as the dedicated CVE route (intel.cve),
  // otherwise an IOC grant would expose CVE records the CVE endpoint refuses (Codex entitlements-final-20261101, HIGH).
  const cveIn = opName === 'intel.ioc.search' ? [args.value, ...(args.values || [])] : opName === 'intel.enrich' ? args.indicators : [];
  if (cveIn.some((v) => intel.typeOf(v) === 'cve')) { const e = effectiveFor(ctx, 'intel.cve', nowMs); authorize(ctx, 'intel.cve', e, await entitlementsFor(db, ctx, e, nowMs, OPS['intel.cve'].capability)); }
  const pre = effective(ctx.policy.doc, ctx.tenant, productOf(opName), nowMs, ctx.acceptance);
  let key = idemKey;
  if (opName === 'premium.download') { key = key ?? `dl:${args.release_id}:${clock().toISOString().slice(0, 10)}`; ctx = { ...ctx, usageEventId: await usageEventId(ctx.tenant.id, key) }; }
  const call = (a, eff) => H[opName]({ ...deps, ctx, eff, args: a });
  let out = await run(env, db, clock, ctx, opName, args ?? {}, call, { idemKey: key, requestId, cacheResult: opName !== 'premium.download', extraQuota: (eff) => (opName === 'premium.download' ? [['downloads', eff.quotas.downloads_month, 1]] : []) });
  // An authorisation must be fresh: a repeat of the same logical request (same release, same day) is not counted again, but gets a new short-lived token instead of an old, maybe expired, one.
  if (out.replayed && opName === 'premium.download') out = { ...out, result: await call(args, pre) };
  // Correlation fields leave the server only with intel.correlation.read, resolved NOW (also for an idempotent replay of an older answer).
  if (INTEL_READS.has(opName)) out = { ...out, result: redactIntel(out.result, await entitlementsFor(db, ctx, pre, clock().getTime(), 'intel.correlation.read')) };
  return { ...out, eff: pre, accessMode: accessMode(ctx.policy.doc, pre.mode) };
}
