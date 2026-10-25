// Commercial policy: modes, exceptions, offers, transitions. Pure functions (validate, effective, requiredApprovals) + the D1 store (immutable versions, one pointer, CAS).
import { PLANS } from './plans.js';
import { audit } from './audit.js';
import { HttpError, SECRET_KEYS, canonical, iso, sha256Hex } from './util.js';

export const MODES = ['FREE_LAUNCH', 'FREEMIUM', 'PAID'];
const RANK = { FREE_LAUNCH: 0, FREEMIUM: 1, PAID: 2 };
export const PRODUCTS = ['premium', 'api'];
export const FEATURES = ['premium', 'intel', 'intel.enrich', 'mcp'];
const QUOTA_KEYS = ['minute', 'day', 'month', 'downloads_month', 'bytes_month'];
const SECRET_VALUE = /(sk_(live|test)_|rk_(live|test)_|whsec_|mgk_[0-9a-f]{16}_|mga_|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY)/;
export const productOf = (op) => (op.startsWith('premium.') ? 'premium' : 'api');

const isoOrNull = (v) => v === null || (typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(v) && !Number.isNaN(Date.parse(v)));
const isInt = (n) => Number.isInteger(n) && n >= 0;
function walk(o, path, errs) {
  if (typeof o === 'number' && !Number.isInteger(o)) errs.push(`${path}: floats are not allowed (money is integer micro-units)`);
  if (typeof o === 'string' && SECRET_VALUE.test(o)) errs.push(`${path}: looks like a secret; commercial settings never hold credentials`);
  if (o && typeof o === 'object') for (const [k, v] of Object.entries(o)) { if (!path.endsWith('_comment') && SECRET_KEYS.test(k) && !/^theoretical|pricing|unit_micros/.test(k)) errs.push(`${path}.${k}: a key named like a secret does not belong in the policy`); walk(v, `${path}.${k}`, errs); }
}
export function validatePolicy(d) {
  const e = [];
  if (!d || d.schema !== 'macguard.commercial-policy/1') return ['unknown schema'];
  walk(d, 'policy', e);
  if (!MODES.includes(d.mode)) e.push('mode must be FREE_LAUNCH, FREEMIUM or PAID');
  for (const p of PRODUCTS) if (!(p in (d.products || {})) || ![null, ...MODES].includes(d.products[p].mode)) e.push(`products.${p}.mode must be null or a mode`);
  for (const g of ['launch', 'freemium']) {
    const x = d[g]; if (!x || !Array.isArray(x.features) || x.features.some((f) => !FEATURES.includes(f))) { e.push(`${g}.features must be a subset of ${FEATURES}`); continue; }
    for (const k of QUOTA_KEYS) if (!isInt(x.quotas?.[k])) e.push(`${g}.quotas.${k} must be a non-negative integer`);
  }
  if (!isInt(d.freemium?.metered_free_units_month)) e.push('freemium.metered_free_units_month must be a non-negative integer');
  for (const o of d.overrides || []) { if (!o.tenant_id || !MODES.includes(o.mode) || ![null, ...PRODUCTS].includes(o.product) || !isoOrNull(o.until ?? null) || !o.reason) e.push(`override ${JSON.stringify(o.tenant_id)} is malformed (tenant_id, mode, product, until, reason)`); }
  for (const o of d.offers || []) { if (!o.id || !Array.isArray(o.products) || o.products.some((p) => !PRODUCTS.includes(p)) || !isoOrNull(o.free_until) || o.free_until === null || ![null, undefined].includes(o.tenant_id) && typeof o.tenant_id !== 'string') e.push(`offer ${o.id} is malformed`); }
  const b = d.billing || {};
  if (typeof b.live !== 'boolean' || typeof b.allow_checkout !== 'boolean' || !isInt(b.notice_days) || !['freemium', 'community'].includes(b.on_unaccepted)) e.push('billing: live, allow_checkout (booleans), notice_days (integer) and on_unaccepted (freemium|community) are required');
  const pr = b.pricing; if (!pr || typeof pr.version !== 'string' || typeof pr.approved !== 'boolean' || !/^[A-Z]{3}$/.test(pr.currency || '') || Object.values(pr.unit_micros || {}).some((v) => !isInt(v))) e.push('billing.pricing: version, approved, currency and integer unit_micros are required');
  if (typeof b.terms_version !== 'string') e.push('billing.terms_version is required');
  if (Object.values(d.theoretical_prices_micros || {}).some((v) => !isInt(v))) e.push('theoretical_prices_micros must hold non-negative integers');
  if (d.scheduled !== null && d.scheduled !== undefined) { const s = d.scheduled; if (!MODES.includes(s.mode) || !isoOrNull(s.effective_from) || !s.effective_from) e.push('scheduled needs mode and effective_from'); }
  return e;
}

// How many distinct administrators must approve going from `prev` to `next`.
export function requiredApprovals(prev, next, kind = 'change') {
  if (kind === 'rollback') return 1;
  if (next.billing.live && !prev.billing.live) return 2;
  if (next.billing.pricing.approved && !prev.billing.pricing.approved) return 2;
  if (next.billing.pricing.version !== prev.billing.pricing.version) return 2;
  if (next.scheduled && RANK[next.scheduled.mode] > RANK[prev.mode]) return 2;
  if (RANK[next.mode] > RANK[prev.mode]) return 2;
  return 1;
}
// Rules of a change. A MORE charging mode can never take effect immediately: it must be scheduled at least notice_days ahead. Nothing may start charging without notice.
export function checkTransition(prev, next, nowMs, kind = 'change') {
  const errs = validatePolicy(next); if (errs.length) return errs;
  if (kind === 'rollback') {
    if (next.mode !== 'FREE_LAUNCH' || next.scheduled || next.billing.live) errs.push('a rollback must land on FREE_LAUNCH with nothing scheduled and billing.live false');
    return errs;
  }
  if (RANK[next.mode] > RANK[prev.mode]) errs.push(`mode ${prev.mode} -> ${next.mode} cannot be immediate: schedule it with notice`);
  if (next.scheduled) {
    const min = nowMs + next.billing.notice_days * 86400000;
    if (RANK[next.scheduled.mode] > RANK[prev.mode] && Date.parse(next.scheduled.effective_from) < min) errs.push(`a scheduled increase needs at least ${next.billing.notice_days} days of notice`);
  }
  if (next.billing.live && !prev.billing.live && !next.scheduled && next.mode === 'FREE_LAUNCH') { /* live flag with no charging mode is harmless: charging also needs a charging mode */ }
  for (const o of next.overrides) if (RANK[o.mode] > RANK[prev.mode] && !(prev.overrides || []).some((x) => canonical(x) === canonical(o)) && !o.until) errs.push(`override for ${o.tenant_id} raises charging without an end date: use a scheduled change`);
  return errs;
}

// The policy that applies to one tenant for one product at one instant. Deterministic and side-effect free: every Worker computes the same answer from the same version.
export function effective(doc, tenant, product, nowMs, acceptance = null) {
  let mode = doc.mode, source = 'global';
  if (doc.scheduled && Date.parse(doc.scheduled.effective_from) <= nowMs) { mode = doc.scheduled.mode; source = 'scheduled'; }
  const pm = doc.products?.[product]?.mode; if (pm) { mode = pm; source = 'product'; }
  const offer = (doc.offers || []).find((o) => (o.tenant_id == null || o.tenant_id === tenant.id) && o.products.includes(product) && Date.parse(o.free_until) > nowMs);
  if (offer && RANK[mode] > 0) { mode = 'FREE_LAUNCH'; source = `offer:${offer.id}`; }
  const ov = (doc.overrides || []).find((o) => o.tenant_id === tenant.id && (o.product == null || o.product === product) && (!o.until || Date.parse(o.until) > nowMs));
  if (ov) { mode = ov.mode; source = 'override'; }
  const subscribed = tenant.plan !== 'community', b = doc.billing;
  const accepted = !!acceptance && acceptance.pricing_version === b.pricing.version && Date.parse(acceptance.accepted_at) <= nowMs;
  let grant = mode === 'FREE_LAUNCH' ? doc.launch : mode === 'FREEMIUM' ? doc.freemium : null;
  if (mode === 'PAID' && subscribed && !accepted) grant = b.on_unaccepted === 'freemium' ? doc.freemium : null;     // terms not accepted yet: no charge, only the free allowance
  const paid = subscribed ? PLANS[tenant.plan] : null;
  const features = new Set([...(paid?.features || []), ...(grant?.features || [])]);
  const srcs = [paid?.quotas, grant?.quotas].filter(Boolean);       // the mode's own limits apply as written: a launch limit can be stricter than any plan; community limits only when nothing else grants access
  const quotas = srcs.length ? Object.fromEntries(QUOTA_KEYS.map((k) => [k, Math.max(...srcs.map((x) => x[k]))])) : { ...PLANS.community.quotas };
  const charging = mode !== 'FREE_LAUNCH' && subscribed && accepted && b.live === true && b.pricing.approved === true;
  return { mode, source, features, quotas, charging, accepted, subscribed, chargeFromMs: accepted ? Date.parse(acceptance.accepted_at) : null,
    meteredFreeUnits: mode === 'FREE_LAUNCH' ? Infinity : mode === 'FREEMIUM' ? doc.freemium.metered_free_units_month : 0, pricing: b.pricing, currency: b.pricing.currency };
}

// ---- store -------------------------------------------------------------------------------------------------------------------------
const cache = new Map();                                       // content hash -> parsed doc (a stored version is immutable, so an entry can never go stale)
export async function loadActive(db) {
  const row = await db.prepare('SELECT v.* FROM policy_pointer p JOIN policy_versions v ON v.version = p.version WHERE p.id = 1').first();
  if (!row) throw new Error('no commercial policy is installed');
  let doc = cache.get(row.doc_sha256);                          // keyed by CONTENT hash: a version number alone is not an identity across databases
  if (!doc) { if ((await sha256Hex(row.doc)) !== row.doc_sha256) throw new Error('the commercial policy failed its integrity check'); doc = JSON.parse(row.doc); cache.set(row.doc_sha256, doc); }
  return { version: row.version, doc, sha256: row.doc_sha256 };
}
async function insertVersion(db, clock, base, doc, by, reason, kind) {
  const text = canonical(doc), v = base.version + 1;
  await db.prepare('INSERT INTO policy_versions(version,doc,doc_sha256,prev_sha256,created_by,created_at,reason,kind) VALUES (?,?,?,?,?,?,?,?)').bind(v, text, await sha256Hex(text), base.sha256, by, iso(clock()), reason, kind).run();
  const r = await db.prepare('UPDATE policy_pointer SET version = ? WHERE id = 1 AND version = ?').bind(v, base.version).run();
  if (r.meta.changes !== 1) throw new HttpError(409, 'policy_conflict', 'The policy changed while this change was being applied.');
  return v;
}
export async function seedPolicy(db, clock, doc, by = 'seed') {
  const errs = validatePolicy(doc); if (errs.length) throw new Error('invalid seed policy: ' + errs.join('; '));
  if (await db.prepare('SELECT 1 AS x FROM policy_pointer').first()) throw new Error('a policy is already installed');
  const text = canonical(doc); const h = await sha256Hex(text);
  await db.prepare('INSERT INTO policy_versions(version,doc,doc_sha256,prev_sha256,created_by,created_at,reason,kind) VALUES (1,?,?,?,?,?,?,?)').bind(text, h, '0'.repeat(64), by, iso(clock()), 'initial policy', 'seed').run();
  await db.prepare('INSERT INTO policy_pointer(id, version) VALUES (1, 1)').run();
}
export async function propose(db, clock, admin, doc, reason) {
  const base = await loadActive(db), errs = checkTransition(base.doc, doc, clock().getTime());
  if (errs.length) throw new HttpError(422, 'policy_rejected', errs.join('; '));
  const id = 'pp_' + (await sha256Hex(canonical(doc) + base.version + admin.id + iso(clock()))).slice(0, 20);
  await db.prepare('INSERT INTO policy_proposals(id,base_version,doc,reason,proposed_by,created_at,status) VALUES (?,?,?,?,?,?,?)').bind(id, base.version, canonical(doc), reason, admin.id, iso(clock()), 'open').run();
  await db.prepare('INSERT INTO policy_approvals(proposal_id,admin_id,at) VALUES (?,?,?)').bind(id, admin.id, iso(clock())).run();
  await audit(db, clock, null, 'policy.proposed', { proposal: id, by: admin.id, base_version: base.version, needs: requiredApprovals(base.doc, doc) });
  return { id, base_version: base.version, approvals_required: requiredApprovals(base.doc, doc) };
}
export async function approve(db, clock, admin, id) {
  const p = await db.prepare("SELECT * FROM policy_proposals WHERE id = ? AND status = 'open'").bind(id).first();
  if (!p) throw new HttpError(404, 'not_found', 'No open proposal with that id.');
  await db.prepare('INSERT OR IGNORE INTO policy_approvals(proposal_id,admin_id,at) VALUES (?,?,?)').bind(id, admin.id, iso(clock())).run();
  await audit(db, clock, null, 'policy.approved', { proposal: id, by: admin.id });
  return { approvals: (await db.prepare('SELECT COUNT(*) AS n FROM policy_approvals WHERE proposal_id = ?').bind(id).first()).n };
}
export async function applyProposal(db, clock, admin, id) {
  const p = await db.prepare("SELECT * FROM policy_proposals WHERE id = ? AND status = 'open'").bind(id).first();
  if (!p) throw new HttpError(404, 'not_found', 'No open proposal with that id.');
  const base = await loadActive(db);
  if (p.base_version !== base.version) { await db.prepare("UPDATE policy_proposals SET status = 'stale' WHERE id = ?").bind(id).run(); throw new HttpError(409, 'policy_conflict', 'The policy changed after this proposal was made: propose again.'); }
  const doc = JSON.parse(p.doc), errs = checkTransition(base.doc, doc, clock().getTime()); if (errs.length) throw new HttpError(422, 'policy_rejected', errs.join('; '));
  const need = requiredApprovals(base.doc, doc), have = (await db.prepare('SELECT COUNT(*) AS n FROM policy_approvals WHERE proposal_id = ?').bind(id).first()).n;
  if (have < need) throw new HttpError(403, 'approvals_missing', `This change needs ${need} distinct administrators; it has ${have}.`);
  const v = await insertVersion(db, clock, base, doc, admin.id, p.reason, 'change');
  await db.prepare("UPDATE policy_proposals SET status = 'applied' WHERE id = ?").bind(id).run();
  await audit(db, clock, null, 'policy.applied', { proposal: id, by: admin.id, version: v, mode: doc.mode, scheduled: doc.scheduled });
  return { version: v };
}
// Emergency reversal: one administrator with MFA, immediate, always lands on FREE_LAUNCH with charging off. Charges already recorded stay recorded; nothing new is charged.
export async function rollback(db, clock, admin, reason) {
  const base = await loadActive(db), doc = JSON.parse(JSON.stringify(base.doc));
  doc.mode = 'FREE_LAUNCH'; doc.scheduled = null; doc.billing.live = false; doc.billing.allow_checkout = false; doc.products = { premium: { mode: null }, api: { mode: null } }; doc.overrides = doc.overrides.filter((o) => o.mode === 'FREE_LAUNCH');
  const v = await insertVersion(db, clock, base, doc, admin.id, reason, 'rollback');
  await audit(db, clock, null, 'policy.rollback', { by: admin.id, version: v, from_version: base.version, reason });
  return { version: v };
}
export async function policyHistory(db) {
  const rows = (await db.prepare('SELECT version, doc_sha256, prev_sha256, created_by, created_at, reason, kind FROM policy_versions ORDER BY version').all()).results;
  let prev = '0'.repeat(64), ok = true; for (const r of rows) { if (r.prev_sha256 !== prev) ok = false; prev = r.doc_sha256; }
  return { chain_ok: ok, versions: rows };
}
export async function acceptanceOf(db, tenantId, pricingVersion) {
  return db.prepare('SELECT * FROM terms_acceptances WHERE tenant_id = ? AND pricing_version = ?').bind(tenantId, pricingVersion).first();
}
export async function acceptTerms(db, clock, ctx, doc, { pricing_version, terms_version }) {
  if (pricing_version !== doc.billing.pricing.version || terms_version !== doc.billing.terms_version) throw new HttpError(409, 'terms_mismatch', 'These are not the current pricing and terms versions.', { pricing_version: doc.billing.pricing.version, terms_version: doc.billing.terms_version });
  await db.prepare('INSERT OR IGNORE INTO terms_acceptances(tenant_id,pricing_version,terms_version,accepted_at,accepted_by_key) VALUES (?,?,?,?,?)').bind(ctx.tenant.id, pricing_version, terms_version, iso(clock()), ctx.key.id).run();
  await audit(db, clock, ctx.tenant.id, 'terms.accepted', { pricing_version, terms_version, key_id: ctx.key.id });
  return acceptanceOf(db, ctx.tenant.id, pricing_version);
}
