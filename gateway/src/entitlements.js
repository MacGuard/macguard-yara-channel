// Entitlements: WHAT a principal may do, as capabilities, decoupled from prices. Contract: contracts/v1/entitlements.schema.json (macguard.entitlements/1).
// It EXTENDS the existing model instead of replacing it: plans and the commercial policy (plans.js, policy.js effective()) still decide which features a tenant has; this module turns
// them into capabilities, adds explicit grants (with expiry and revocation) and the access mode, and is the ONLY place an operation's capability is decided. Everything here is
// server-side: identity comes from the verified key (auth.js) and the access mode from the versioned, approved policy document. No request header, query or body takes part.
//
// Access mode (implementation of the gate, independent of the commercial mode):
//   OPEN_PREMIUM_PREVIEW  premium capabilities are granted to every principal while the content is free (marked as preview); research.poc.metadata.read is NEVER part of it.
//   ENFORCED              only what plans, the commercial policy and explicit grants give.
//   anything else         fails CLOSED for premium capabilities and OPEN only for the public ones.
// When the policy does not set it, it follows the commercial mode: FREE_LAUNCH -> OPEN_PREMIUM_PREVIEW (today's behaviour), any charging mode -> ENFORCED. A policy cannot pair the
// preview with a charging mode (validatePolicy), so the preview can never become a permanent bypass once commerce starts.
import { HttpError, iso } from './util.js';

export const SCHEMA = 'macguard.entitlements/1';
export const CAPABILITIES = Object.freeze(['catalog.public.read', 'vulnerability.public.read', 'yara.community.download', 'rules.premium.read', 'rules.premium.download', 'ioc.premium.read',
  'intel.correlation.read', 'intel.advanced.export', 'research.poc.metadata.read']);
export const PUBLIC = Object.freeze(['catalog.public.read', 'vulnerability.public.read', 'yara.community.download']);
export const PREMIUM = Object.freeze(['rules.premium.read', 'rules.premium.download', 'ioc.premium.read', 'intel.correlation.read', 'intel.advanced.export']);
export const EXPLICIT_ONLY = Object.freeze(['research.poc.metadata.read']);          // only an explicit, reviewed grant: no plan, mode or preview ever gives it
export const ACCESS_MODES = Object.freeze(['OPEN_PREMIUM_PREVIEW', 'ENFORCED']);
export const SOURCES = Object.freeze(['manual', 'subscription', 'preview']);

// Existing features (plans.js / policy launch|freemium) -> capabilities. Prices never appear here.
const FROM_FEATURE = Object.freeze({ premium: ['rules.premium.read', 'rules.premium.download'], intel: ['ioc.premium.read'], 'intel.enrich': ['intel.correlation.read'] });
// Capabilities a paid plan adds beyond its features (only for a subscribed tenant).
const PLAN_EXTRA = Object.freeze({ community: [], intelligence: [], business: ['intel.advanced.export'] });

// The access mode of a policy document for a given effective commercial mode. Unknown values do not fall back to anything permissive.
export function accessMode(doc, commercialMode) {
  const e = doc?.entitlements;
  if (e === undefined || e === null) return commercialMode === 'FREE_LAUNCH' ? 'OPEN_PREMIUM_PREVIEW' : 'ENFORCED';
  if (!e || typeof e !== 'object' || !ACCESS_MODES.includes(e.access_mode)) return 'INVALID';
  // The preview only exists where the EFFECTIVE commercial mode of this tenant/product is FREE_LAUNCH (an override or product mode that charges enforces).
  return e.access_mode === 'OPEN_PREMIUM_PREVIEW' && commercialMode !== 'FREE_LAUNCH' ? 'ENFORCED' : e.access_mode;
}
// Policy validation for the `entitlements` block (called from policy.js validatePolicy).
export function validateEntitlementsBlock(d) {
  if (d.entitlements === undefined || d.entitlements === null) return [];
  const e = d.entitlements, errs = [];
  if (typeof e !== 'object' || Array.isArray(e) || Object.keys(e).some((k) => !['access_mode', 'note'].includes(k)) || !ACCESS_MODES.includes(e.access_mode)) return [`entitlements.access_mode must be one of ${ACCESS_MODES}`];
  if (e.access_mode === 'OPEN_PREMIUM_PREVIEW') {
    const charging = [d.mode, d.scheduled?.mode, ...Object.values(d.products || {}).map((p) => p?.mode), ...(d.overrides || []).map((o) => o?.mode)].some((m) => m && m !== 'FREE_LAUNCH');
    if (charging || d.billing?.live === true) errs.push('entitlements.access_mode OPEN_PREMIUM_PREVIEW cannot be combined with a charging mode or live billing: set ENFORCED first');
  }
  return errs;
}

// A grant applies only with valid timestamps: an unparseable granted_at/revoked_at/expires_at (e.g. '' written by other tooling) fails CLOSED. Only null means "no expiry / not revoked".
const ts = (v) => (typeof v === 'string' ? Date.parse(v) : NaN);
const active = (g, nowMs) => ts(g.granted_at) <= nowMs && (g.revoked_at == null || ts(g.revoked_at) > nowMs) && (g.expires_at == null || ts(g.expires_at) > nowMs);

// principal: { anonymous?, user?: {id}, organizations?: [{id}], plan, subscribed, features: Set|[], accessMode, grants: [{subject:{kind,id}, capability, granted_at, expires_at, revoked_at, source}] }
// A user inherits the grants of the organizations it belongs to (membership is resolved by the caller from verified data, never from the request).
export function resolve(principal, nowMs) {
  const caps = new Set(PUBLIC), via = {}, preview = new Set(), mode = principal.accessMode;
  for (const c of PUBLIC) via[c] = 'public';
  if (mode === 'INVALID') return { caps, via, preview, accessMode: mode };                    // fail closed: public capabilities only
  if (!principal.anonymous) {
    for (const f of principal.features || []) for (const c of FROM_FEATURE[f] || []) if (!caps.has(c)) { caps.add(c); via[c] = `feature:${f}`; }
    if (principal.subscribed) for (const c of PLAN_EXTRA[principal.plan] || []) if (!caps.has(c)) { caps.add(c); via[c] = `plan:${principal.plan}`; }
    const subjects = new Set([...(principal.user ? [`user:${principal.user.id}`] : []), ...(principal.organizations || []).map((o) => `organization:${o.id}`)]);
    for (const g of principal.grants || []) {
      if (!subjects.has(`${g.subject?.kind}:${g.subject?.id}`) || !CAPABILITIES.includes(g.capability) || !active(g, nowMs)) continue;
      if (!caps.has(g.capability)) { caps.add(g.capability); via[g.capability] = `grant:${g.source}`; }
    }
  }
  if (mode === 'OPEN_PREMIUM_PREVIEW') for (const c of PREMIUM) if (!caps.has(c)) { caps.add(c); via[c] = 'preview'; preview.add(c); }
  return { caps, via, preview, accessMode: mode };
}
export const can = (principal, capability, nowMs) => CAPABILITIES.includes(capability) && resolve(principal, nowMs).caps.has(capability);

// ---- gateway glue ------------------------------------------------------------------------------------------------------------------------
// Explicit grants of the authenticated organization (tenant). Read only when a capability is not already given by plan, policy or preview: one D1 read, not one per request.
export async function loadGrants(db, tenantId) {
  if (!db || !tenantId) return [];
  const rows = (await db.prepare("SELECT subject_kind, subject_id, capability, granted_at, expires_at, revoked_at, source FROM entitlement_grants WHERE subject_kind = 'organization' AND subject_id = ?").bind(tenantId).all()).results;
  return rows.map((r) => ({ subject: { kind: r.subject_kind, id: r.subject_id }, capability: r.capability, granted_at: r.granted_at, expires_at: r.expires_at, revoked_at: r.revoked_at, source: r.source }));
}
export const principalOf = (ctx, eff, grants = []) => ({ anonymous: !ctx?.tenant, organizations: ctx?.tenant ? [{ id: ctx.tenant.id }] : [], plan: ctx?.tenant?.plan ?? 'community', subscribed: !!eff?.subscribed,
  features: [...(eff?.features || [])], accessMode: accessMode(ctx?.policy?.doc, eff?.mode), grants });

// Resolve for a request; loads explicit grants only if `need` is not granted without them.
export async function entitlementsFor(db, ctx, eff, nowMs, need = null) {
  let r = resolve(principalOf(ctx, eff), nowMs);
  if ((!need || !r.caps.has(need)) && ctx?.tenant && db) r = resolve(principalOf(ctx, eff, await loadGrants(db, ctx.tenant.id)), nowMs);
  return r;
}
export function requireCapability(ent, capability, extra = {}) {
  if (!ent.caps.has(capability)) throw new HttpError(403, 'not_entitled', 'Your current access does not include this operation.', { required_capability: capability, access_mode: ent.accessMode, ...extra });
}

// Fields that are correlation (relations between indicators, malware, CVEs, techniques). Removed on the SERVER when intel.correlation.read is missing: never sent to be hidden by the UI.
const CORRELATION_KEYS = ['malware', 'attack', 'cve', 'cves', 'related', 'relations'];
export function redactIntel(result, ent) {
  if (ent.caps.has('intel.correlation.read') || result === null || typeof result !== 'object') return result;
  const strip = (r) => (r && Array.isArray(r.records) ? { ...r, records: r.records.map((x) => ({ ...x, data: Object.fromEntries(Object.entries(x.data || {}).filter(([k]) => !CORRELATION_KEYS.includes(k))) })) } : r);
  const out = Array.isArray(result.results) ? { ...result, results: result.results.map(strip) } : strip(result);
  if (Array.isArray(out.results)) out.results = out.results.map(({ relations, ...r }) => r);
  return { ...out, redacted: ['correlation'] };
}

// The snapshot a client sees (GET /v1/account/entitlements), in contract form (macguard.entitlements/1). granted_at = when it was resolved; expires_at = the earliest expiry of a
// grant that some capability depends on (null when nothing expires); revoked_at is null for a live snapshot (revoked grants appear in `grants` with their own revoked_at).
export function snapshot(ctx, eff, ent, grants = [], nowMs = Date.now()) {
  const mine = grants.filter((x) => x.subject.kind === 'organization' && x.subject.id === ctx.tenant.id);
  const deps = mine.filter((x) => ent.via[x.capability] === `grant:${x.source}` && active(x, nowMs) && x.expires_at).map((x) => x.expires_at).sort();
  return { schema: SCHEMA, subject: { kind: 'organization', id: ctx.tenant.id }, plan: ctx.tenant.plan, access_mode: ent.accessMode, capabilities: [...ent.caps].sort(), preview_capabilities: [...ent.preview].sort(),
    source: ent.preview.size ? 'preview' : (Object.values(ent.via).some((v) => v.startsWith('grant:')) ? 'manual' : 'subscription'), version: ctx.policy?.version ?? null,
    granted_at: iso(new Date(nowMs)), expires_at: deps[0] ?? null, revoked_at: null,
    // the CURRENT grants only (history stays in D1): revoked or expired rows are left out, newest first, within the contract's 200-entry limit
    grants: mine.filter((x) => active(x, nowMs)).sort((p, q) => String(q.granted_at).localeCompare(String(p.granted_at))).slice(0, 200).map((x) => ({ capability: x.capability, source: x.source, granted_at: x.granted_at, expires_at: x.expires_at ?? null, revoked_at: x.revoked_at ?? null })) };
}

// Explicit grants (admin tooling): append-style, revocation keeps the row.
export async function grant(db, clock, { subjectKind = 'organization', subjectId, capability, expiresAt = null, source = 'manual', reason, grantedBy }) {
  if (!['organization', 'user'].includes(subjectKind) || !subjectId) throw new HttpError(400, 'invalid_subject', 'A grant needs an organization or user subject.');
  if (!CAPABILITIES.includes(capability)) throw new HttpError(400, 'invalid_capability', 'Unknown capability.');
  if (!['manual', 'subscription'].includes(source)) throw new HttpError(400, 'invalid_source', 'A stored grant is manual or subscription; preview is never stored.');
  if (!reason || !grantedBy) throw new HttpError(400, 'invalid_grant', 'A grant needs a reason and who granted it.');
  const now = iso(clock());
  // null = no expiry; anything else must be a real future UTC timestamp (an empty or malformed value must never become permanent access)
  if (expiresAt !== null && (typeof expiresAt !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/.test(expiresAt) || !Number.isFinite(Date.parse(expiresAt)) || Date.parse(expiresAt) <= Date.parse(now)))
    throw new HttpError(400, 'invalid_expiry', 'expires_at must be null or a future UTC timestamp.');
  await db.prepare('INSERT INTO entitlement_grants(subject_kind,subject_id,capability,granted_at,expires_at,revoked_at,source,reason,granted_by) VALUES (?,?,?,?,?,NULL,?,?,?)')
    .bind(subjectKind, subjectId, capability, now, expiresAt, source, String(reason).slice(0, 300), grantedBy).run();
  return { granted_at: now };
}
export async function revoke(db, clock, { subjectKind = 'organization', subjectId, capability }) {
  const r = await db.prepare('UPDATE entitlement_grants SET revoked_at = ? WHERE subject_kind = ? AND subject_id = ? AND capability = ? AND revoked_at IS NULL').bind(iso(clock()), subjectKind, subjectId, capability).run();
  return r.meta.changes;
}
