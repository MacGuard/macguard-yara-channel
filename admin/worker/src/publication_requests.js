// Publication requests: the DESIRED state of a resource, applied either by the daily run (SCHEDULED, the default) or by an extraordinary run (EXPEDITED). Both run in GitHub Actions through the same
// factory; nothing in this file publishes anything and the panel never writes the effective state of a rule: it syncs it from a verified release. See docs/design/EXPEDITED-PUBLICATION.md.
// The Worker holds no general GitHub credential: an expedited run is asked for through `dispatch(request_id)`, a function that can only start ONE fixed workflow with ONE validated input.
import { sha256Hex, canonical } from './core.js';
import { can } from './rbac.js';
import { appendAudit } from './store.js';

export const STATES = ['PENDING', 'AWAITING_APPROVAL', 'AUTHORIZED', 'QUEUED', 'RUNNING', 'VALIDATING', 'SIGNING', 'PUBLISHING', 'VERIFYING', 'APPLIED', 'SYNC_PENDING', 'BLOCKED', 'FAILED', 'CANCELLED'];
export const CLOSED = ['APPLIED', 'FAILED', 'CANCELLED'];
export const TRANSITIONS = {
  PENDING: ['RUNNING', 'APPLIED', 'FAILED', 'CANCELLED', 'BLOCKED'], AWAITING_APPROVAL: ['AUTHORIZED', 'CANCELLED', 'BLOCKED'], AUTHORIZED: ['QUEUED', 'BLOCKED', 'CANCELLED'], QUEUED: ['RUNNING', 'FAILED', 'BLOCKED', 'CANCELLED'],
  RUNNING: ['VALIDATING', 'FAILED', 'BLOCKED'], VALIDATING: ['SIGNING', 'FAILED', 'BLOCKED'], SIGNING: ['PUBLISHING', 'FAILED'], PUBLISHING: ['VERIFYING', 'FAILED'], VERIFYING: ['APPLIED', 'SYNC_PENDING', 'FAILED'],
  SYNC_PENDING: ['APPLIED'], BLOCKED: ['QUEUED', 'CANCELLED', 'FAILED'], APPLIED: [], FAILED: [], CANCELLED: [],
};
/** What each action is, and what the engine can really do today. Only resources whose family has a real publication pipeline are eligible; everything else answers `not_eligible`. */
export const ACTIONS = {
  PUBLISH: { critical: false, security: false }, QUARANTINE: { critical: true, security: true }, WITHDRAW: { critical: true, security: true }, REVOKE: { critical: true, security: true }, REPLACE: { critical: true, security: true },
  ADD_IOC: { critical: false, security: false }, RETIRE_IOC: { critical: false, security: false }, SOURCE_CHANGE: { critical: false, security: false }, PACKAGE_PROFILE: { critical: false, security: false },
};
export const ELIGIBLE = { yara_rule: ['PUBLISH'], policy: ['WITHDRAW', 'REVOKE'] };   // grows only when a family gets signed packages and a distribution policy
export const DESIRED = { PUBLISH: 'RELEASED', WITHDRAW: 'WITHDRAWN', REVOKE: 'REVOKED' };
export const LIMITS = { openExpeditedStandard: 3, authorizationTtlS: 24 * 3600, stalledS: 3 * 3600, dailyMinutes: 120, reasonExpedite: 20 };
const REQID = /^[A-Za-z0-9_-]{16,80}$/, RES = /^[A-Za-z0-9][A-Za-z0-9:._-]{2,199}$/, UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const visible = (s) => String(s).replace(/[\s\p{Cf}]/gu, '').length;
const bad = (status, error, extra = {}) => ({ status, body: { error, ...extra } });
const addS = (iso, s) => new Date(Date.parse(iso) + s * 1000).toISOString();
const J = (v) => JSON.stringify(v ?? null);

export function validateCreate(b) {
  if (!b || typeof b !== 'object' || Array.isArray(b)) return { error: 'JSON body required' };
  const mode = b.mode === undefined ? 'SCHEDULED' : b.mode; if (!['SCHEDULED', 'EXPEDITED'].includes(mode)) return { error: 'mode must be SCHEDULED or EXPEDITED' };
  if (!Object.hasOwn(ACTIONS, b.action)) return { error: `action must be one of ${Object.keys(ACTIONS).join(', ')}` };
  if (typeof b.resource_kind !== 'string' || !['yara_rule', 'policy', 'intel_record', 'source', 'package'].includes(b.resource_kind)) return { error: 'unknown resource_kind' };
  if (typeof b.resource_id !== 'string' || !RES.test(b.resource_id)) return { error: 'resource_id is required' };
  if (!Number.isInteger(b.resource_version) || b.resource_version < 1) return { error: 'resource_version (the exact version you saw) is required' };
  if (typeof b.request_id !== 'string' || !REQID.test(b.request_id)) return { error: 'request_id (16-80 url-safe characters) is required: it makes the request idempotent' };
  const min = mode === 'EXPEDITED' ? LIMITS.reasonExpedite : 5; if (typeof b.reason !== 'string' || visible(b.reason) < min || b.reason.length > 2000) return { error: `a reason of ${min} to 2000 visible characters is required` };
  if (mode === 'EXPEDITED' && b.confirm !== b.resource_id) return { error: 'confirm must equal the resource_id: an expedited publication is confirmed by typing the identifier', code: 'confirm_required' };
  return { value: { mode, action: b.action, resource_kind: b.resource_kind, resource_id: b.resource_id, resource_version: b.resource_version, request_id: b.request_id, reason: b.reason.trim(), expect_effective_state: typeof b.expect_effective_state === 'string' ? b.expect_effective_state.slice(0, 40) : null } };
}
const view = (r) => r && { ...r, requested_roles: JSON.parse(r.requested_roles), evidence: JSON.parse(r.evidence || '{}'), over_budget: !!r.over_budget };
export const get = async (db, id) => view(await db.prepare('SELECT * FROM publication_requests WHERE id = ?').bind(id).first());

async function event(db, id, from, to, actor, detail, now) { await db.prepare('INSERT INTO publication_request_events (request_id, at, from_state, to_state, actor, detail) VALUES (?,?,?,?,?,?)').bind(id, now, from, to, actor, J(detail)).run(); }
/** One compare-and-set transition: the row, its event and the audit entry. A concurrent change makes it fail and change nothing. */
async function move(db, row, to, set, actor, detail, now, audit) {
  const fail = (status, error, extra = {}) => ({ ok: false, status, body: { error, ...extra } });
  if (!TRANSITIONS[row.state].includes(to)) return fail(409, `a request in state ${row.state} cannot become ${to}`, { state: row.state });
  const cols = Object.keys(set), r = await db.prepare(`UPDATE publication_requests SET state = ?, version = version + 1, updated_at = ?${cols.map((c) => `, ${c} = ?`).join('')} WHERE id = ? AND version = ? AND state = ?`).bind(to, now, ...cols.map((c) => set[c]), row.id, row.version, row.state).run();
  if (!r.meta || r.meta.changes !== 1) return fail(409, 'the request changed while it was being processed; nothing was changed', { retry: true });
  await event(db, row.id, row.state, to, actor, detail, now); if (audit) await appendAudit(db, { actor, role: audit.role || 'SYSTEM', action: `publication.${to.toLowerCase()}`, target: row.id, detail: { mode: row.mode, resource: `${row.resource_kind}:${row.resource_id}`, version: row.resource_version, ...detail } }, now);
  return { ok: true, row: await get(db, row.id) };
}
const authSha = async (r) => sha256Hex(new TextEncoder().encode(canonical({ id: r.id, request_id: r.request_id, action: r.action, resource_kind: r.resource_kind, resource_id: r.resource_id, resource_version: r.resource_version, desired_state: r.desired_state, requested_by_id: r.requested_by_id })));

/** What the engine knows about the resource right now: its effective state and version, or why nothing can be done. */
async function inspectResource(db, v) {
  if (v.resource_kind === 'yara_rule') { const c = await db.prepare('SELECT id, state, version, sha256 FROM candidates WHERE id = ? AND archived_at IS NULL').bind(v.resource_id).first(); return c ? { effective: c.state, version: c.version } : null; }
  if (v.resource_kind === 'policy') { try { const p = await db.prepare('SELECT id, status, withdrawal, kind, version FROM policies WHERE id = ?').bind(v.resource_id).first(); return p ? { effective: `${p.status}/${p.withdrawal}`, version: p.version } : null; } catch (e) { if (/no such table/i.test(String(e))) return null; throw e; } }
  return null;
}
const preconditionError = (v, info) => {
  if (v.action === 'PUBLISH' && info.effective !== 'APPROVED_PENDING_VALIDATION') return `a rule can be published only from APPROVED_PENDING_VALIDATION; it is ${info.effective}`;
  if ((v.action === 'WITHDRAW' || v.action === 'REVOKE') && !/^ACTIVE\//.test(info.effective)) return `the policy is ${info.effective}`;
  return null;
};

/** actor: { login, id, role, roles }. deps: { uuid, dispatch?, env }. Never starts anything for SCHEDULED; for EXPEDITED it authorises (or asks for a second identity) and then requests ONE run. */
export async function create(db, body, actor, now, deps = {}) {
  const x = validateCreate(body); if (x.error) return bad(400, x.error, x.code ? { code: x.code } : {}); const v = x.value, info = ACTIONS[v.action], roles = actor.roles || [actor.role];
  if (v.mode === 'EXPEDITED') {
    if (!can(roles, 'publication.expedite')) return bad(403, v.mode === 'EXPEDITED' && can(roles, 'publication.expedite.propose') ? 'you may propose an expedited publication, but only a PUBLISHER, SECURITY_ADMIN or ADMIN may request it' : 'the permission publication.expedite is required', { code: 'forbidden', permission: 'publication.expedite' });
    if (roles.includes('SECURITY_ADMIN') && !roles.includes('ADMIN') && !roles.includes('PUBLISHER') && !info.security) return bad(403, 'a SECURITY_ADMIN requests an expedited run only for security actions (quarantine, withdrawal, revocation, signature replacement)', { code: 'forbidden' });
  } else if (!can(roles, 'publication.expedite.propose')) return bad(403, 'the permission publication.expedite.propose is required', { code: 'forbidden', permission: 'publication.expedite.propose' });
  if (!(ELIGIBLE[v.resource_kind] || []).includes(v.action)) return bad(409, `${v.action} on ${v.resource_kind} cannot be published by the engine yet: that family has no signed packages and no distribution policy`, { code: 'not_eligible' });
  const prior = await db.prepare('SELECT * FROM publication_requests WHERE request_id = ?').bind(v.request_id).first();
  if (prior) return prior.requested_by_id === actor.id && prior.resource_id === v.resource_id && prior.action === v.action ? { status: 200, body: { replay: true, request: view(prior) } } : bad(409, 'request id reused for a different request');
  const res = await inspectResource(db, v); if (!res) return bad(404, 'the resource does not exist in this panel');
  if (res.version !== v.resource_version) return bad(409, 'the resource changed since you saw it', { code: 'stale', version: res.version });
  if (v.expect_effective_state && v.expect_effective_state !== res.effective) return bad(409, 'its effective state changed since you saw it', { code: 'stale', effective: res.effective });
  const pre = preconditionError(v, res); if (pre) return bad(409, pre, { code: 'precondition' });
  if (v.resource_kind === 'yara_rule' && v.action === 'PUBLISH') { const ap = await db.prepare("SELECT actor_id FROM decisions WHERE candidate_id = ? AND to_state = 'APPROVED_PENDING_VALIDATION' ORDER BY id DESC LIMIT 1").bind(v.resource_id).first(); if (ap && ap.actor_id === actor.id && v.mode === 'EXPEDITED') return bad(403, 'the person who approved a rule cannot also request its extraordinary publication', { code: 'same_identity' }); }
  const desired = DESIRED[v.action], dedupe = `${v.resource_kind}:${v.resource_id}:${v.resource_version}:${v.action}`;
  const open = await db.prepare("SELECT id, mode, action, state FROM publication_requests WHERE resource_kind = ? AND resource_id = ? AND state NOT IN ('APPLIED','FAILED','CANCELLED')").bind(v.resource_kind, v.resource_id).all();
  for (const o of open.results) { if (o.action === v.action) { const same = await db.prepare('SELECT * FROM publication_requests WHERE id = ?').bind(o.id).first(); return { status: 200, body: { duplicate: true, request: view(same), note: 'an equivalent request is already open; nothing was added' } }; } }
  if (open.results.length) return bad(409, 'another open request asks for a different change to this resource: cancel it or wait for it before asking for this one', { code: 'conflicting_request', conflicts: open.results.map((o) => o.id) });
  let over = 0;
  if (v.mode === 'EXPEDITED' && !info.critical) {
    const n = (await db.prepare("SELECT COUNT(*) AS n FROM publication_requests WHERE mode = 'EXPEDITED' AND state NOT IN ('APPLIED','FAILED','CANCELLED') AND criticality = 'STANDARD'").first()).n; if (n >= LIMITS.openExpeditedStandard) return bad(409, `${n} non-critical expedited runs are already open: wait for one to finish (a critical change is never held back by this limit)`, { code: 'too_many_open' });
    const spent = (await db.prepare('SELECT COALESCE(SUM(cost_minutes), 0) AS m FROM publication_requests WHERE substr(updated_at, 1, 10) = ?').bind(now.slice(0, 10)).first()).m, budget = Number(deps.env && deps.env.EXPEDITE_MINUTES_PER_DAY) || LIMITS.dailyMinutes;
    if (spent >= budget) return bad(409, `the day's budget of expedited minutes (${budget}) is used up: the change is kept for the next daily run, or use the emergency procedure`, { code: 'budget_exhausted', spent, budget });
  } else if (v.mode === 'EXPEDITED') { const spent = (await db.prepare('SELECT COALESCE(SUM(cost_minutes), 0) AS m FROM publication_requests WHERE substr(updated_at, 1, 10) = ?').bind(now.slice(0, 10)).first()).m; if (spent >= (Number(deps.env && deps.env.EXPEDITE_MINUTES_PER_DAY) || LIMITS.dailyMinutes)) over = 1; }   // a critical change is never blocked by budget: it is flagged for review
  const id = deps.uuid(), state = v.mode === 'SCHEDULED' ? 'PENDING' : 'AWAITING_APPROVAL';
  try {
    await db.prepare('INSERT INTO publication_requests (id, request_id, mode, action, criticality, resource_kind, resource_id, resource_version, desired_state, effective_state_at_request, reason, dedupe_key, state, over_budget, requested_by, requested_by_id, requested_roles, requested_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
      .bind(id, v.request_id, v.mode, v.action, info.critical ? 'CRITICAL' : 'STANDARD', v.resource_kind, v.resource_id, v.resource_version, desired, res.effective, v.reason, dedupe, state, over, actor.login, actor.id, J(roles), now, now).run();
  } catch (e) { return bad(409, /UNIQUE/.test(String(e)) ? 'an equivalent request is already open' : 'the request could not be recorded; nothing was changed'); }
  await event(db, id, null, state, actor.login, { mode: v.mode, action: v.action, reason: v.reason, over_budget: !!over }, now);
  await appendAudit(db, { actor: actor.login, role: actor.role, action: `publication.${v.mode === 'EXPEDITED' ? 'expedite_requested' : 'scheduled'}`, target: id, detail: { resource: `${v.resource_kind}:${v.resource_id}`, version: v.resource_version, action: v.action, desired_state: desired, criticality: info.critical ? 'CRITICAL' : 'STANDARD', reason: v.reason, request_id: v.request_id, actor_id: actor.id, over_budget: !!over } }, now);
  let row = await get(db, id);
  if (v.mode === 'EXPEDITED' && !info.critical) { const a = await authorise(db, row, actor, now); if (!a.ok) return out(a); return dispatch(db, a.row.id, actor, now, deps); }
  return { status: 200, body: { request: row, next: v.mode === 'SCHEDULED' ? 'the next daily run will apply it' : 'a second identity must authorise it (POST /api/approvals with op publication.expedite)' } };
}

/** Authorisation is bound to this request, resource, version and action, expires, and is used once. */
export async function authorise(db, row, by, now) {
  const sha = await authSha(row); return move(db, row, 'AUTHORIZED', { authorized_by: by.login, authorized_by_id: by.id, authorized_at: now, authorization_sha256: sha, authorization_expires_at: addS(now, LIMITS.authorizationTtlS) }, by.login, { authorized_by_id: by.id, authorization_sha256: sha }, now, { role: by.role });
}
const out = (m, extra = {}) => (m.ok ? { status: 200, body: { request: m.row, ...extra } } : { status: m.status, body: m.body });
/** Called when the approval of a critical request is granted (or its emergency path executed). */
/** A second, different identity authorises a CRITICAL expedited change; then ONE run is asked for. */
export async function approve(db, id, v, actor, now, deps = {}) {
  const row = await get(db, id); if (!row) return bad(404, 'not found'); const roles = actor.roles || [actor.role];
  if (!can(roles, 'publication.expedite.approve')) return bad(403, 'the permission publication.expedite.approve is required', { code: 'forbidden' });
  if (row.mode !== 'EXPEDITED' || row.state !== 'AWAITING_APPROVAL') return bad(409, `a request in state ${row.state} cannot be approved`, { state: row.state });
  if (actor.id === row.requested_by_id) return bad(403, 'the identity that asked cannot authorise the run: another identity must', { code: 'same_identity' });
  if (!v || typeof v.reason !== 'string' || visible(v.reason) < 5) return bad(400, 'a reason of at least 5 visible characters is required');
  if (!Number.isInteger(v.expect_version) || v.expect_version !== row.version) return bad(409, 'the request changed since you saw it', { code: 'stale', version: row.version });
  const a = await authorise(db, row, actor, now); if (!a.ok) return out(a); await appendAudit(db, { actor: actor.login, role: actor.role, action: 'publication.approved', target: row.id, detail: { reason: v.reason.trim(), approver_id: actor.id, requested_by_id: row.requested_by_id } }, now);
  return dispatch(db, row.id, actor, now, deps);
}
/** The emergency path for when no second identity exists: long reason, a short delay, execution by the requester, review afterwards by a third identity. It is not a permanent bypass: every use is flagged. */
export const EMERGENCY_DELAY_S = 30 * 60;
async function note(db, row, patch, actor, now, detail) { const ev = { ...row.evidence, ...patch }; const r = await db.prepare('UPDATE publication_requests SET evidence = ?, version = version + 1, updated_at = ? WHERE id = ? AND version = ?').bind(J(ev), now, row.id, row.version).run(); if (!r.meta || r.meta.changes !== 1) return false; await event(db, row.id, row.state, row.state, actor, detail, now); return true; }
export async function emergency(db, id, v, actor, now) {
  const row = await get(db, id); if (!row) return bad(404, 'not found'); const roles = actor.roles || [actor.role];
  if (!can(roles, 'publication.expedite.breakglass')) return bad(403, 'the permission publication.expedite.breakglass is required', { code: 'forbidden' });
  if (row.mode !== 'EXPEDITED' || row.state !== 'AWAITING_APPROVAL' || row.requested_by_id !== actor.id) return bad(409, 'only the requester of a request waiting for approval may start the emergency path');
  if (!v || typeof v.reason !== 'string' || visible(v.reason) < 40 || v.no_second_approver !== true) return bad(400, 'the emergency path needs a reason of at least 40 visible characters and no_second_approver: true (it is only for when a second identity is not available)');
  if (row.evidence.emergency) return bad(409, 'the emergency path was already started');
  const nb = addS(now, EMERGENCY_DELAY_S); if (!(await note(db, row, { emergency: { requested_at: now, reason: v.reason.trim(), not_before: nb } }, actor.login, now, { emergency_requested: true, not_before: nb }))) return bad(409, 'the request changed; nothing was changed');
  await appendAudit(db, { actor: actor.login, role: actor.role, action: 'publication.emergency_requested', target: row.id, detail: { not_before: nb, reason: v.reason.trim(), actor_id: actor.id } }, now); return { status: 200, body: { request: await get(db, id), not_before: nb } };
}
export async function executeEmergency(db, id, actor, now, deps = {}) {
  const row = await get(db, id); if (!row) return bad(404, 'not found'); const em = row.evidence.emergency;
  if (!em || row.state !== 'AWAITING_APPROVAL' || row.requested_by_id !== actor.id) return bad(409, 'there is no emergency to execute for you');
  if (now < em.not_before) return bad(409, 'the delay of the emergency path has not elapsed', { code: 'delay', not_before: em.not_before });
  const a = await authorise(db, row, actor, now); if (!a.ok) return out(a); const cur = await get(db, id); await note(db, cur, { emergency: { ...em, executed_at: now, review_required: true } }, actor.login, now, { emergency_executed: true });
  await appendAudit(db, { actor: actor.login, role: actor.role, action: 'publication.emergency_executed', target: id, detail: { actor_id: actor.id, review_required: true } }, now); return dispatch(db, id, actor, now, deps);
}
export async function review(db, id, v, actor, now) {
  const row = await get(db, id); if (!row) return bad(404, 'not found'); const em = row.evidence.emergency, roles = actor.roles || [actor.role];
  if (!can(roles, 'approvals.review')) return bad(403, 'the permission approvals.review is required', { code: 'forbidden' });
  if (!em || !em.executed_at) return bad(409, 'only an executed emergency is reviewed'); if (em.review) return bad(409, 'already reviewed');
  if (actor.id === row.requested_by_id || actor.id === row.authorized_by_id) return bad(403, 'the reviewer must be a different identity from who asked and who executed', { code: 'same_identity' });
  if (!v || !['APPROPRIATE', 'INAPPROPRIATE'].includes(v.outcome) || typeof v.reason !== 'string' || visible(v.reason) < 5) return bad(400, 'outcome (APPROPRIATE or INAPPROPRIATE) and a reason are required');
  if (!(await note(db, row, { emergency: { ...em, review: { by_id: actor.id, by: actor.login, at: now, outcome: v.outcome, reason: v.reason.trim() } } }, actor.login, now, { emergency_review: v.outcome }))) return bad(409, 'the request changed; nothing was changed');
  await appendAudit(db, { actor: actor.login, role: actor.role, action: 'publication.emergency_reviewed', target: id, detail: { outcome: v.outcome, reason: v.reason.trim(), reviewer_id: actor.id } }, now); return { status: 200, body: { request: await get(db, id) } };
}
/** Asks for ONE run of the fixed expedited workflow. Without a configured dispatcher the request is BLOCKED and says so; it never pretends. */
export async function dispatch(db, id, actor, now, deps = {}) {
  const row = await get(db, id); if (!row) return bad(404, 'not found');
  if (row.mode !== 'EXPEDITED') return bad(409, 'a scheduled request is applied by the daily run, never dispatched');
  if (!['AUTHORIZED', 'BLOCKED'].includes(row.state)) return bad(409, `a request in state ${row.state} is not dispatched`, { state: row.state });
  if (!row.authorization_sha256 || row.authorization_sha256 !== await authSha(row)) return bad(409, 'the authorisation does not match this request');
  if (row.authorization_expires_at && row.authorization_expires_at <= now) return bad(409, 'the authorisation has expired: ask again', { code: 'authorization_expired' });
  const q = await move(db, row, 'QUEUED', { dispatched_at: now, state_reason: null }, actor.login, { dispatching: true }, now, { role: actor.role }); if (!q.ok) return out(q);
  const block = async (cause, message) => { const b = await move(db, q.row, 'BLOCKED', { state_reason: cause }, 'system', { cause, ...(message ? { message } : {}) }, now, { role: 'SYSTEM' }); return b.ok ? b.row : q.row; };
  if (!deps.dispatch) return { status: 200, body: { request: await block('dispatcher_not_configured'), blocked: 'dispatcher_not_configured', note: 'authorised, but this panel has no credential to request a GitHub Actions run; the daily run will still apply it' } };
  try { const r = await deps.dispatch({ request_id: q.row.id }); if (r && r.ok === false) throw new Error(r.error || 'dispatch refused'); }
  catch (e) { return { status: 200, body: { request: await block('github_unavailable', String(e.message).slice(0, 120)), blocked: 'github_unavailable', note: 'GitHub Actions did not accept the run; the authorisation is kept and the daily run will still apply it' } }; }
  return { status: 200, body: { request: q.row } };
}
export async function cancel(db, id, v, actor, now) {
  const row = await get(db, id); if (!row) return bad(404, 'not found'); const roles = actor.roles || [actor.role];
  if (row.requested_by_id !== actor.id && !can(roles, 'publication.expedite.approve')) return bad(403, 'only the requester or an approver may cancel');
  if (!v || typeof v.reason !== 'string' || visible(v.reason) < 5) return bad(400, 'a reason of at least 5 visible characters is required');
  return out(await move(db, row, 'CANCELLED', { state_reason: 'cancelled_by_person' }, actor.login, { reason: v.reason.trim(), by_id: actor.id }, now, { role: actor.role }));
}
export async function list(db, { state, mode } = {}) {
  const where = [], args = []; if (state && STATES.includes(state)) { where.push('state = ?'); args.push(state); } if (mode && ['SCHEDULED', 'EXPEDITED'].includes(mode)) { where.push('mode = ?'); args.push(mode); }
  return { schema: 1, items: (await db.prepare(`SELECT * FROM publication_requests ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY requested_at DESC, id LIMIT 200`).bind(...args).all()).results.map(view) };
}
export async function events(db, id) { return (await db.prepare('SELECT seq, at, from_state, to_state, actor, detail FROM publication_request_events WHERE request_id = ? ORDER BY seq').bind(id).all()).results.map((e) => ({ ...e, detail: JSON.parse(e.detail) })); }

// ---- what the GitHub Actions workflows may do (OIDC identity checked by the caller) ----------------------------------------------------------------------------------------------------------------
/** The expedited workflow reads its own request, and only while it is authorised, queued or running and the authorisation is valid and unexpired. */
export async function forWorkflow(db, id, now) {
  if (!UUID.test(id) && !/^[0-9a-f-]{8,64}$/.test(id)) return bad(400, 'invalid id'); const row = await get(db, id); if (!row || row.mode !== 'EXPEDITED') return bad(404, 'not found');
  if (!['QUEUED', 'RUNNING', 'VALIDATING', 'SIGNING', 'PUBLISHING', 'VERIFYING'].includes(row.state)) return bad(409, `the request is ${row.state}`, { state: row.state });
  if (!row.authorization_sha256 || row.authorization_sha256 !== await authSha(row) || (row.authorization_expires_at && row.authorization_expires_at <= now)) return bad(409, 'the authorisation is not valid', { code: 'authorization_invalid' });
  return { status: 200, body: { schema: 1, id: row.id, action: row.action, resource_kind: row.resource_kind, resource_id: row.resource_id, resource_version: row.resource_version, desired_state: row.desired_state, criticality: row.criticality, authorization_sha256: row.authorization_sha256, state: row.state } };
}
const PROGRESS = ['RUNNING', 'VALIDATING', 'SIGNING', 'PUBLISHING', 'VERIFYING'];
/** report: { state, run_id?, run_url?, commit_sha?, release_tag?, hashes?, minutes?, failure_reason?, blocked_reason? }. APPLIED needs the release to be verified by the caller (`deps.verifyRelease`) and then synced (`deps.sync`). */
export async function report(db, id, rep, now, deps = {}) {
  const row = await get(db, id); if (!row || row.mode !== 'EXPEDITED') return bad(404, 'not found');
  if (!rep || typeof rep !== 'object' || ![...PROGRESS, 'APPLIED', 'FAILED', 'BLOCKED'].includes(rep.state)) return bad(400, 'state must be one of RUNNING, VALIDATING, SIGNING, PUBLISHING, VERIFYING, APPLIED, FAILED, BLOCKED');
  const meta = {}; if (rep.run_id !== undefined) { if (!/^\d{1,20}$/.test(String(rep.run_id))) return bad(400, 'run_id must be numeric'); meta.run_id = String(rep.run_id); }
  if (rep.run_url !== undefined) { if (!/^https:\/\/github\.com\/[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+\/actions\/runs\/\d+$/.test(String(rep.run_url))) return bad(400, 'run_url must be a GitHub Actions run URL'); meta.run_url = rep.run_url; }
  if (rep.commit_sha !== undefined) { if (!/^[0-9a-f]{40}$/.test(String(rep.commit_sha))) return bad(400, 'commit_sha must be 40 hex characters'); meta.commit_sha = rep.commit_sha; }
  if (rep.minutes !== undefined) { if (typeof rep.minutes !== 'number' || rep.minutes < 0 || rep.minutes > 600) return bad(400, 'minutes must be a number between 0 and 600'); meta.cost_minutes = rep.minutes; }
  const actor = `workflow:publish-expedited.yml`;
  if (rep.state === 'FAILED') return unwrap(await move(db, row, 'FAILED', { ...meta, state_reason: String(rep.failure_reason || 'failed').slice(0, 200) }, actor, { failure_reason: String(rep.failure_reason || '').slice(0, 200), previous_effective_state_kept: true }, now, { role: 'PIPELINE' }));
  if (rep.state === 'BLOCKED') return unwrap(await move(db, row, 'BLOCKED', { ...meta, state_reason: String(rep.blocked_reason || 'blocked').slice(0, 200) }, actor, { blocked_reason: String(rep.blocked_reason || '').slice(0, 200) }, now, { role: 'PIPELINE' }));
  if (rep.state === 'APPLIED') {
    if (row.state !== 'VERIFYING') return bad(409, `the request is ${row.state}: it must be VERIFYING before it can be applied`);
    if (!/^[A-Za-z0-9._-]{3,80}$/.test(String(rep.release_tag || '')) || !meta.commit_sha && !row.commit_sha || !meta.run_id && !row.run_id) return bad(400, 'APPLIED needs release_tag, commit_sha and run_id');
    const ok = deps.verifyRelease ? await deps.verifyRelease(rep.release_tag, row) : false; if (!ok) return unwrap(await move(db, row, 'FAILED', { ...meta, state_reason: 'release_not_verifiable' }, actor, { failure_reason: 'the release is not active and verifiable', release_tag: rep.release_tag }, now, { role: 'PIPELINE' }));
    const base = { ...meta, release_tag: rep.release_tag, evidence: J({ hashes: rep.hashes || null, release_tag: rep.release_tag }) };
    try { if (deps.sync) await deps.sync(row, rep.release_tag); } catch (e) { return unwrap(await move(db, row, 'SYNC_PENDING', { ...base, state_reason: 'sync_failed' }, actor, { cause: 'sync_failed', message: String(e.message).slice(0, 120), republish: false }, now, { role: 'PIPELINE' })); }
    return unwrap(await move(db, row, 'APPLIED', { ...base, applied_at: now, state_reason: null }, actor, { release_tag: rep.release_tag, commit_sha: meta.commit_sha || row.commit_sha, run_id: meta.run_id || row.run_id, hashes: rep.hashes || null }, now, { role: 'PIPELINE' }));
  }
  const i = PROGRESS.indexOf(rep.state), cur = PROGRESS.indexOf(row.state);
  if (row.state === 'QUEUED' ? rep.state !== 'RUNNING' : i !== cur + 1) return bad(409, `the request is ${row.state}: the next step is ${row.state === 'QUEUED' ? 'RUNNING' : PROGRESS[cur + 1] || 'APPLIED'}`);
  return unwrap(await move(db, row, rep.state, meta, actor, { reported: rep.state }, now, null));
}
const unwrap = (m) => out(m);

// ---- the daily run -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
/** What the daily run must apply: scheduled requests still PENDING (an expedited request already applied is not here). */
export async function pendingScheduled(db) { return (await db.prepare("SELECT id, action, resource_kind, resource_id, resource_version, desired_state, criticality, requested_at FROM publication_requests WHERE mode = 'SCHEDULED' AND state = 'PENDING' ORDER BY requested_at, id LIMIT 500").all()).results; }
/** The daily run reports what it applied. A request already closed (e.g. applied by an expedited run) is skipped, never applied twice. */
export async function dailyApplied(db, ids, run, now) {
  const res = { applied: [], skipped: [] };
  for (const id of ids) { const row = await get(db, id); if (!row || row.mode !== 'SCHEDULED' || row.state !== 'PENDING') { res.skipped.push(id); continue; }
    const m = await move(db, row, 'APPLIED', { run_id: run.run_id ? String(run.run_id) : null, release_tag: run.release_tag || null, applied_at: now }, 'workflow:daily.yml', { run_id: run.run_id || null, release_tag: run.release_tag || null }, now, { role: 'PIPELINE' }); (m.ok ? res.applied : res.skipped).push(id); }
  return res;
}
/** Retries what must not be republished (SYNC_PENDING) and frees what stalled; safe to run repeatedly. */
export async function reconcile(db, now, deps = {}) {
  const res = { synced: [], stalled: [] };
  for (const r of (await db.prepare("SELECT * FROM publication_requests WHERE state = 'SYNC_PENDING'").all()).results) { const row = view(r); try { if (deps.sync) await deps.sync(row, row.release_tag); const m = await move(db, row, 'APPLIED', { applied_at: now, state_reason: null }, 'system', { reconciled: true, republished: false }, now, { role: 'SYSTEM' }); if (m.ok) res.synced.push(row.id); } catch { /* it stays SYNC_PENDING and is retried */ } }
  for (const r of (await db.prepare("SELECT * FROM publication_requests WHERE state IN ('QUEUED','RUNNING','VALIDATING','SIGNING','PUBLISHING','VERIFYING') AND updated_at < ?").bind(addS(now, -LIMITS.stalledS)).all()).results) { const row = view(r); const m = await move(db, row, 'FAILED', { state_reason: 'stalled' }, 'system', { failure_reason: 'no progress reported; the previous effective state is kept', republished: false }, now, { role: 'SYSTEM' }); if (m.ok) res.stalled.push(row.id); }
  return res;
}

/** The only way this Worker asks GitHub for a run: a fixed workflow, a fixed ref, one UUID input, a credential that can do nothing else. */
export function makeDispatcher(env, deps) {
  if (!env.GITHUB_DISPATCH_TOKEN || !env.REPO) return null;
  return async ({ request_id }) => {
    if (!UUID.test(request_id) && !/^[0-9a-f-]{8,64}$/.test(request_id)) throw new Error('invalid request id');
    const r = await deps.fetch(`https://api.github.com/repos/${env.REPO}/actions/workflows/publish-expedited.yml/dispatches`, { method: 'POST', headers: { Authorization: `Bearer ${env.GITHUB_DISPATCH_TOKEN}`, Accept: 'application/vnd.github+json', 'Content-Type': 'application/json', 'User-Agent': 'macguard-panel' }, body: JSON.stringify({ ref: 'main', inputs: { request_id } }), redirect: 'manual' });
    if (r.status !== 204) throw new Error(`GitHub answered ${r.status}`); return { ok: true };
  };
}
