// Publication requests: the DESIRED state of a resource, applied either by the daily run (SCHEDULED, the default) or by an extraordinary run (EXPEDITED). Both run in GitHub Actions through the same
// factory; nothing in this file publishes anything and the panel never writes the effective state of a rule: it syncs it from a verified release. See docs/design/EXPEDITED-PUBLICATION.md.
// The Worker holds no general GitHub credential: an expedited run is asked for through `dispatch(request_id)`, a function that can only start ONE fixed workflow with ONE validated input.
import { sha256Hex, canonical, chainHash } from './core.js';
import { can } from './rbac.js';
import { markReleased } from './store.js';
import { chainHead } from './anchor.js';
import { reconcilePolicies, listsScope } from './policies.js';

export const STATES = ['PENDING', 'AWAITING_APPROVAL', 'AUTHORIZED', 'QUEUED', 'RUNNING', 'VALIDATING', 'SIGNING', 'PUBLISHING', 'VERIFYING', 'APPLIED', 'SYNC_PENDING', 'BLOCKED', 'FAILED', 'CANCELLED'];
export const CLOSED = ['APPLIED', 'FAILED', 'CANCELLED'];
export const TRANSITIONS = {
  PENDING: ['RUNNING', 'APPLIED', 'FAILED', 'CANCELLED', 'BLOCKED'], AWAITING_APPROVAL: ['AUTHORIZED', 'PENDING', 'CANCELLED', 'BLOCKED'], AUTHORIZED: ['QUEUED', 'BLOCKED', 'CANCELLED'], QUEUED: ['RUNNING', 'FAILED', 'BLOCKED', 'CANCELLED'],
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

// Every change is ONE transaction (D1 batch): the guarded row write, its append-only event and its audit entries commit together or not at all (review F1).
const eventStmt = (db, id, from, to, actor, detail, now) => db.prepare('INSERT INTO publication_request_events (request_id, at, from_state, to_state, actor, detail) VALUES (?,?,?,?,?,?)').bind(id, now, from, to, actor, J(detail));
const GUARD = "SELECT CASE WHEN changes() = 1 THEN 1 ELSE json('not-json') END";   // aborts the batch when the guarded statement before it changed no row
/** Audit inserts chained from the current head; a concurrent writer that takes the link makes the batch fail (UNIQUE prev_hash) and the caller retries. */
async function auditStmts(db, entries, now) {
  let prev = await chainHead(db); const out = [];
  for (const a of entries) {
    const e = { at: now, actor: a.actor, role: a.role, action: a.action, target: a.target, detail: J(a.detail) }, hash = await chainHash(prev, e);
    out.push(db.prepare('INSERT INTO audit (at, actor, role, action, target, detail, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?)').bind(e.at, e.actor, e.role, e.action, e.target, e.detail, prev, hash)); prev = hash;
  }
  return out;
}
/** Runs `build()` as one batch; retried only while the failure is audit-chain contention and `stillValid()` says the guarded row did not change. */
async function commit(db, build, stillValid) {
  for (let attempt = 0; ; attempt++) {
    try { await db.batch(await build()); return { ok: true }; }
    catch (e) { if (!(await stillValid())) return { ok: false, conflict: true }; if (attempt >= 2 || !/UNIQUE|constraint/i.test(String(e))) throw e; }
  }
}
const conflictOut = (status = 409) => ({ ok: false, status, body: { error: 'the request changed while it was being processed; nothing was changed', retry: true } });
/** One compare-and-set transition: the row, its event and the audit entries (`extra.audits`), atomically. A concurrent change makes it fail and change nothing. */
async function move(db, row, to, set, actor, detail, now, audit, extra = {}) {
  const fail = (status, error, x = {}) => ({ ok: false, status, body: { error, ...x } });
  if (!TRANSITIONS[row.state].includes(to)) return fail(409, `a request in state ${row.state} cannot become ${to}`, { state: row.state });
  const cols = Object.keys(set), audits = [...(audit ? [{ actor, role: audit.role || 'SYSTEM', action: `publication.${to.toLowerCase()}`, target: row.id, detail: { mode: row.mode, resource: `${row.resource_kind}:${row.resource_id}`, version: row.resource_version, ...detail } }] : []), ...(extra.audits || [])];
  const c = await commit(db, async () => [
    db.prepare(`UPDATE publication_requests SET state = ?, version = version + 1, updated_at = ?${cols.map((k) => `, ${k} = ?`).join('')} WHERE id = ? AND version = ? AND state = ?`).bind(to, now, ...cols.map((k) => set[k]), row.id, row.version, row.state),
    db.prepare(GUARD), eventStmt(db, row.id, row.state, to, actor, detail, now), ...(await auditStmts(db, audits, now))], async () => { const cur = await get(db, row.id); return !!cur && cur.version === row.version && cur.state === row.state; });
  if (!c.ok) return conflictOut();
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
  if (v.mode === 'EXPEDITED' || info.critical) {   // a critical change needs the request permission and a second identity in EVERY mode: the daily run must never be a way around it
    if (!can(roles, 'publication.expedite')) return bad(403, can(roles, 'publication.expedite.propose') ? (v.mode === 'EXPEDITED' ? 'you may propose an expedited publication, but only a PUBLISHER, SECURITY_ADMIN or ADMIN may request it' : 'a critical change (quarantine, withdrawal, revocation, replacement) is requested by a PUBLISHER, SECURITY_ADMIN or ADMIN and authorised by a second identity') : 'the permission publication.expedite is required', { code: 'forbidden', permission: 'publication.expedite' });
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
  const id = deps.uuid(), state = v.mode === 'SCHEDULED' && !info.critical ? 'PENDING' : 'AWAITING_APPROVAL';
  const taken = async () => !!(await db.prepare("SELECT 1 AS x FROM publication_requests WHERE request_id = ? OR (dedupe_key = ? AND state NOT IN ('APPLIED','FAILED','CANCELLED')) LIMIT 1").bind(v.request_id, dedupe).first());
  const c = await commit(db, async () => [
    db.prepare('INSERT INTO publication_requests (id, request_id, mode, action, criticality, resource_kind, resource_id, resource_version, desired_state, effective_state_at_request, reason, dedupe_key, state, over_budget, requested_by, requested_by_id, requested_roles, requested_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
      .bind(id, v.request_id, v.mode, v.action, info.critical ? 'CRITICAL' : 'STANDARD', v.resource_kind, v.resource_id, v.resource_version, desired, res.effective, v.reason, dedupe, state, over, actor.login, actor.id, J(roles), now, now),
    eventStmt(db, id, null, state, actor.login, { mode: v.mode, action: v.action, reason: v.reason, over_budget: !!over }, now),
    ...(await auditStmts(db, [{ actor: actor.login, role: actor.role, action: `publication.${v.mode === 'EXPEDITED' ? 'expedite_requested' : 'scheduled'}`, target: id, detail: { resource: `${v.resource_kind}:${v.resource_id}`, version: v.resource_version, action: v.action, desired_state: desired, criticality: info.critical ? 'CRITICAL' : 'STANDARD', reason: v.reason, request_id: v.request_id, actor_id: actor.id, over_budget: !!over } }], now))],
  async () => !(await taken())).catch(() => ({ ok: false }));
  if (!c.ok) return bad(409, (await taken()) ? 'an equivalent request is already open' : 'the request could not be recorded; nothing was changed');
  let row = await get(db, id);
  if (v.mode === 'EXPEDITED' && !info.critical) { const a = await authorise(db, row, actor, now); if (!a.ok) return out(a); return dispatch(db, a.row.id, actor, now, deps); }
  return { status: 200, body: { request: row, next: v.mode === 'SCHEDULED' && !info.critical ? 'the next daily run will apply it' : 'a second identity must authorise it (POST /api/publication-requests/<id>/approve); a scheduled critical change then waits for the daily run' } };
}

/** Authorisation is bound to this request, resource, version and action, expires, and is used once. */
export async function authorise(db, row, by, now, extra = {}) {
  const sha = await authSha(row); return move(db, row, 'AUTHORIZED', { authorized_by: by.login, authorized_by_id: by.id, authorized_at: now, authorization_sha256: sha, authorization_expires_at: addS(now, LIMITS.authorizationTtlS), ...(extra.set || {}) }, by.login, { authorized_by_id: by.id, authorization_sha256: sha, ...(extra.detail || {}) }, now, { role: by.role }, extra);
}
const out = (m, extra = {}) => (m.ok ? { status: 200, body: { request: m.row, ...extra } } : { status: m.status, body: m.body });
/** Called when the approval of a critical request is granted (or its emergency path executed). */
/** A scheduled critical change, once a second identity authorised it, becomes PENDING for the daily run (bound to this request like any authorisation). */
async function schedule(db, row, by, now, extra = {}) { const sha = await authSha(row); return move(db, row, 'PENDING', { authorized_by: by.login, authorized_by_id: by.id, authorized_at: now, authorization_sha256: sha, authorization_expires_at: addS(now, 7 * 24 * 3600) }, by.login, { authorized_by_id: by.id, authorization_sha256: sha, scheduled: true }, now, { role: by.role }, extra); }
/** A second, different identity authorises a CRITICAL change; an expedited one then asks for ONE run, a scheduled one waits for the daily run. */
export async function approve(db, id, v, actor, now, deps = {}) {
  const row = await get(db, id); if (!row) return bad(404, 'not found'); const roles = actor.roles || [actor.role];
  if (!can(roles, 'publication.expedite.approve')) return bad(403, 'the permission publication.expedite.approve is required', { code: 'forbidden' });
  if (row.state !== 'AWAITING_APPROVAL') return bad(409, `a request in state ${row.state} cannot be approved`, { state: row.state });
  if (actor.id === row.requested_by_id) return bad(403, 'the identity that asked cannot authorise the run: another identity must', { code: 'same_identity' });
  if (!v || typeof v.reason !== 'string' || visible(v.reason) < 5) return bad(400, 'a reason of at least 5 visible characters is required');
  if (!Number.isInteger(v.expect_version) || v.expect_version !== row.version) return bad(409, 'the request changed since you saw it', { code: 'stale', version: row.version });
  const approved = { audits: [{ actor: actor.login, role: actor.role, action: 'publication.approved', target: row.id, detail: { reason: v.reason.trim(), approver_id: actor.id, requested_by_id: row.requested_by_id } }] };
  const a = row.mode === 'SCHEDULED' ? await schedule(db, row, actor, now, approved) : await authorise(db, row, actor, now, approved); if (!a.ok) return out(a);
  return row.mode === 'SCHEDULED' ? { status: 200, body: { request: a.row, next: 'authorised: the next daily run will apply it' } } : dispatch(db, row.id, actor, now, deps);
}
/** The emergency path for when no second identity exists: long reason, a short delay, execution by the requester, review afterwards by a third identity. It is not a permanent bypass: every use is flagged. */
export const EMERGENCY_DELAY_S = 30 * 60;
/** Evidence-only change of an open request, with its event and audit entries, atomically. */
async function note(db, row, patch, actor, now, detail, audits = []) {
  const ev = { ...row.evidence, ...patch };
  const c = await commit(db, async () => [db.prepare('UPDATE publication_requests SET evidence = ?, version = version + 1, updated_at = ? WHERE id = ? AND version = ?').bind(J(ev), now, row.id, row.version), db.prepare(GUARD),
    eventStmt(db, row.id, row.state, row.state, actor, detail, now), ...(await auditStmts(db, audits, now))], async () => { const cur = await get(db, row.id); return !!cur && cur.version === row.version; });
  return c.ok;
}
/** The post-execution review of an emergency: its own append-only record (one per request), writable after the request closed (review F4). */
export const reviewOf = async (db, id) => db.prepare('SELECT request_id, at, by_login, by_id, outcome, reason FROM publication_request_reviews WHERE request_id = ?').bind(id).first();
export async function emergency(db, id, v, actor, now) {
  const row = await get(db, id); if (!row) return bad(404, 'not found'); const roles = actor.roles || [actor.role];
  if (!can(roles, 'publication.expedite.breakglass')) return bad(403, 'the permission publication.expedite.breakglass is required', { code: 'forbidden' });
  if (row.mode !== 'EXPEDITED' || row.state !== 'AWAITING_APPROVAL' || row.requested_by_id !== actor.id) return bad(409, 'only the requester of a request waiting for approval may start the emergency path');
  if (!v || typeof v.reason !== 'string' || visible(v.reason) < 40 || v.no_second_approver !== true) return bad(400, 'the emergency path needs a reason of at least 40 visible characters and no_second_approver: true (it is only for when a second identity is not available)');
  if (row.evidence.emergency) return bad(409, 'the emergency path was already started');
  const nb = addS(now, EMERGENCY_DELAY_S);
  if (!(await note(db, row, { emergency: { requested_at: now, reason: v.reason.trim(), not_before: nb } }, actor.login, now, { emergency_requested: true, not_before: nb }, [{ actor: actor.login, role: actor.role, action: 'publication.emergency_requested', target: row.id, detail: { not_before: nb, reason: v.reason.trim(), actor_id: actor.id } }]))) return bad(409, 'the request changed; nothing was changed');
  return { status: 200, body: { request: await get(db, id), not_before: nb } };
}
export async function executeEmergency(db, id, actor, now, deps = {}) {
  const row = await get(db, id); if (!row) return bad(404, 'not found'); const em = row.evidence.emergency;
  if (!em || row.state !== 'AWAITING_APPROVAL' || row.requested_by_id !== actor.id) return bad(409, 'there is no emergency to execute for you');
  if (now < em.not_before) return bad(409, 'the delay of the emergency path has not elapsed', { code: 'delay', not_before: em.not_before });
  const a = await authorise(db, row, actor, now, { set: { evidence: J({ ...row.evidence, emergency: { ...em, executed_at: now, review_required: true } }) }, detail: { emergency_executed: true },
    audits: [{ actor: actor.login, role: actor.role, action: 'publication.emergency_executed', target: id, detail: { actor_id: actor.id, review_required: true } }] }); if (!a.ok) return out(a);
  return dispatch(db, id, actor, now, deps);
}
export async function review(db, id, v, actor, now) {
  const row = await get(db, id); if (!row) return bad(404, 'not found'); const em = row.evidence.emergency, roles = actor.roles || [actor.role];
  if (!can(roles, 'approvals.review')) return bad(403, 'the permission approvals.review is required', { code: 'forbidden' });
  if (!em || !em.executed_at) return bad(409, 'only an executed emergency is reviewed'); if (em.review || await reviewOf(db, id)) return bad(409, 'already reviewed');
  if (actor.id === row.requested_by_id || actor.id === row.authorized_by_id) return bad(403, 'the reviewer must be a different identity from who asked and who executed', { code: 'same_identity' });
  if (!v || !['APPROPRIATE', 'INAPPROPRIATE'].includes(v.outcome) || typeof v.reason !== 'string' || visible(v.reason) < 5) return bad(400, 'outcome (APPROPRIATE or INAPPROPRIATE) and a reason are required');
  // the request row is never touched (a closed request is final): the review is its own append-only record, with its event and audit entry, in one transaction
  const c = await commit(db, async () => [db.prepare('INSERT INTO publication_request_reviews (request_id, at, by_login, by_id, outcome, reason) VALUES (?,?,?,?,?,?)').bind(id, now, actor.login, actor.id, v.outcome, v.reason.trim()),
    eventStmt(db, id, row.state, row.state, actor.login, { emergency_review: v.outcome }, now),
    ...(await auditStmts(db, [{ actor: actor.login, role: actor.role, action: 'publication.emergency_reviewed', target: id, detail: { outcome: v.outcome, reason: v.reason.trim(), reviewer_id: actor.id } }], now))], async () => !(await reviewOf(db, id))).catch(() => ({ ok: false }));
  if (!c.ok) return bad(409, (await reviewOf(db, id)) ? 'already reviewed' : 'the review could not be recorded; nothing was changed');
  return { status: 200, body: { request: await get(db, id), review: await reviewOf(db, id) } };
}
/** Asks for ONE run of the fixed expedited workflow. Without a configured dispatcher the request is BLOCKED and says so; it never pretends. */
export async function dispatch(db, id, actor, now, deps = {}) {
  const row = await get(db, id); if (!row) return bad(404, 'not found');
  if (row.mode !== 'EXPEDITED') return bad(409, 'a scheduled request is applied by the daily run, never dispatched');
  if (!['AUTHORIZED', 'BLOCKED'].includes(row.state)) return bad(409, `a request in state ${row.state} is not dispatched`, { state: row.state });
  if (!row.authorization_sha256 || row.authorization_sha256 !== await authSha(row)) return bad(409, 'the authorisation does not match this request');
  if (row.authorization_expires_at && row.authorization_expires_at <= now) return bad(409, 'the authorisation has expired: ask again', { code: 'authorization_expired' });
  // a new dispatch is a new execution: the run that claims it next (F6) is bound afresh
  const q = await move(db, row, 'QUEUED', { dispatched_at: now, state_reason: null, run_id: null, run_url: null, evidence: J({ ...row.evidence, claim: null }) }, actor.login, { dispatching: true }, now, { role: actor.role }); if (!q.ok) return out(q);
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
// deps.run: { run_id, run_attempt } from the signed OIDC token of the caller (never from the body). The first RUNNING report CLAIMS the request for that run and
// attempt; every later report must come from the same execution (review F6).
export async function report(db, id, rep, now, deps = {}) {
  const row = await get(db, id); if (!row || row.mode !== 'EXPEDITED') return bad(404, 'not found');
  if (!rep || typeof rep !== 'object' || ![...PROGRESS, 'APPLIED', 'FAILED', 'BLOCKED'].includes(rep.state)) return bad(400, 'state must be one of RUNNING, VALIDATING, SIGNING, PUBLISHING, VERIFYING, APPLIED, FAILED, BLOCKED');
  const run = deps.run && /^\d{1,20}$/.test(String(deps.run.run_id || '')) ? { run_id: String(deps.run.run_id), run_attempt: Number(deps.run.run_attempt) || null } : null;
  if (!run) return bad(403, 'a report must come from an identified workflow run (run_id in its OIDC token)', { code: 'run_identity_required' });
  const meta = { run_id: run.run_id }; if (rep.run_id !== undefined) { if (!/^\d{1,20}$/.test(String(rep.run_id))) return bad(400, 'run_id must be numeric'); if (String(rep.run_id) !== run.run_id) return bad(400, 'run_id must be the run of the token that signs the report'); }
  if (rep.run_url !== undefined) { if (!/^https:\/\/github\.com\/[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+\/actions\/runs\/\d+$/.test(String(rep.run_url)) || !String(rep.run_url).endsWith(`/actions/runs/${run.run_id}`)) return bad(400, 'run_url must be the GitHub Actions URL of the reporting run'); meta.run_url = rep.run_url; }
  const claim = row.evidence.claim || null;
  if (!claim) { if (row.state !== 'QUEUED' || rep.state !== 'RUNNING') return bad(403, 'this request has not been claimed by a run: the run that executes it reports RUNNING first', { code: 'not_claimed' }); }
  else if (claim.run_id !== run.run_id || (claim.run_attempt ?? null) !== run.run_attempt) return bad(403, 'this request belongs to another workflow execution', { code: 'other_execution' });
  if (rep.commit_sha !== undefined) { if (!/^[0-9a-f]{40}$/.test(String(rep.commit_sha))) return bad(400, 'commit_sha must be 40 hex characters'); meta.commit_sha = rep.commit_sha; }
  if (rep.minutes !== undefined) { if (typeof rep.minutes !== 'number' || rep.minutes < 0 || rep.minutes > 600) return bad(400, 'minutes must be a number between 0 and 600'); meta.cost_minutes = rep.minutes; }
  const actor = `workflow:publish-expedited.yml`;
  if (rep.state === 'FAILED') return unwrap(await move(db, row, 'FAILED', { ...meta, state_reason: String(rep.failure_reason || 'failed').slice(0, 200) }, actor, { failure_reason: String(rep.failure_reason || '').slice(0, 200), previous_effective_state_kept: true }, now, { role: 'PIPELINE' }));
  if (rep.state === 'BLOCKED') return unwrap(await move(db, row, 'BLOCKED', { ...meta, state_reason: String(rep.blocked_reason || 'blocked').slice(0, 200) }, actor, { blocked_reason: String(rep.blocked_reason || '').slice(0, 200) }, now, { role: 'PIPELINE' }));
  if (rep.state === 'APPLIED') {
    if (row.state !== 'VERIFYING') return bad(409, `the request is ${row.state}: it must be VERIFYING before it can be applied`);
    if (!/^[A-Za-z0-9._-]{3,80}$/.test(String(rep.release_tag || '')) || !meta.commit_sha && !row.commit_sha || !meta.run_id && !row.run_id) return bad(400, 'APPLIED needs release_tag, commit_sha and run_id');
    // verifyRelease answers the verified release only if it contains THIS exact change (F3); sync then derives the effective state from it, and APPLIED needs both
    const ok = deps.verifyRelease ? await deps.verifyRelease(rep.release_tag, row) : false; if (!ok) return unwrap(await move(db, row, 'FAILED', { ...meta, state_reason: 'release_not_verifiable' }, actor, { failure_reason: 'the release is not public and verifiable, or it does not contain the requested change', release_tag: rep.release_tag }, now, { role: 'PIPELINE' }));
    const base = { ...meta, release_tag: rep.release_tag, evidence: J({ ...row.evidence, hashes: rep.hashes || null, release_tag: rep.release_tag }) };   // what was recorded before (emergency, claim) is kept (F4)
    if (!deps.sync) return bad(500, 'no effective-state sync is configured: nothing was changed');
    try { await deps.sync(row, rep.release_tag, ok); } catch (e) { return unwrap(await move(db, row, 'SYNC_PENDING', { ...base, state_reason: 'sync_failed' }, actor, { cause: 'sync_failed', message: String(e.message).slice(0, 120), republish: false }, now, { role: 'PIPELINE' })); }
    return unwrap(await move(db, row, 'APPLIED', { ...base, applied_at: now, state_reason: null }, actor, { release_tag: rep.release_tag, commit_sha: meta.commit_sha || row.commit_sha, run_id: meta.run_id || row.run_id, hashes: rep.hashes || null }, now, { role: 'PIPELINE' }));
  }
  const i = PROGRESS.indexOf(rep.state), cur = PROGRESS.indexOf(row.state);
  if (row.state === 'QUEUED' ? rep.state !== 'RUNNING' : i !== cur + 1) return bad(409, `the request is ${row.state}: the next step is ${row.state === 'QUEUED' ? 'RUNNING' : PROGRESS[cur + 1] || 'APPLIED'}`);
  if (!claim) meta.evidence = J({ ...row.evidence, claim: { run_id: run.run_id, run_attempt: run.run_attempt, at: now } });
  return unwrap(await move(db, row, rep.state, meta, actor, { reported: rep.state, ...(claim ? {} : { claimed_by_run: run.run_id, run_attempt: run.run_attempt }) }, now, null));
}

// ---- evidence of the exact change in a verified release (F2, F3) ---------------------------------------------------------------------------------------------------------------------------------
/** Does this verified release (`pub`, from fetchPublication) carry the exact change of the request? A rule: its exact path with its exact SHA-256.
 *  A withdrawal or revocation of a policy: a release published after the policy's baseline that no longer lists its scope. Anything else: no. */
export async function covers(db, row, pub) {
  if (!pub || !pub.ok) return false;
  if (row.resource_kind === 'yara_rule' && row.action === 'PUBLISH') { const c = await db.prepare('SELECT path, sha256 FROM candidates WHERE id = ?').bind(row.resource_id).first(); const m = c && pub.files.get(c.path); return !!(m && m.sha256 === c.sha256); }
  if (row.resource_kind === 'policy' && ['WITHDRAW', 'REVOKE'].includes(row.action)) {
    const p = await db.prepare('SELECT * FROM policies WHERE id = ?').bind(row.resource_id).first(); if (!p) return false; const at = pub.release && pub.release.published_at ? Date.parse(pub.release.published_at) : NaN;
    return Number.isFinite(at) && at > Date.parse(p.baseline_published_at) && pub.tag !== p.baseline_tag && !listsScope(pub, p);
  }
  return false;
}
/** Derives the effective state from the verified release with the panel's own sync (the same as the publish callback), then answers whether THIS resource reached the requested state. */
export async function syncFromRelease(db, row, pub, ctx, actor, now) {
  if (row.resource_kind === 'yara_rule') { await markReleased(db, pub, ctx, actor, now, { always: false }); const c = await db.prepare('SELECT state FROM candidates WHERE id = ?').bind(row.resource_id).first(); return !!c && c.state === 'RELEASED'; }
  if (row.resource_kind === 'policy') { await reconcilePolicies(db, pub, ctx, actor, now); const p = await db.prepare('SELECT withdrawal FROM policies WHERE id = ?').bind(row.resource_id).first(); return !!p && p.withdrawal === 'CONFIRMED'; }
  return false;
}
const unwrap = (m) => out(m);

// ---- the daily run -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
/** What the daily run must apply: scheduled requests still PENDING (an expedited request already applied is not here). */
export async function pendingScheduled(db, now = new Date().toISOString()) { return (await db.prepare("SELECT id, action, resource_kind, resource_id, resource_version, desired_state, criticality, requested_at FROM publication_requests WHERE mode = 'SCHEDULED' AND state = 'PENDING' AND (criticality = 'STANDARD' OR (authorized_by_id IS NOT NULL AND authorized_by_id != requested_by_id AND authorization_sha256 IS NOT NULL AND authorization_expires_at > ?)) ORDER BY requested_at, id LIMIT 500").bind(now).all()).results; }
/** The daily run reports what it applied. A request already closed (e.g. applied by an expedited run) is skipped, never applied twice. */
/** run: { run_id (from the signed token), release_tag }. deps.evidence(row) answers whether the verified release carries THIS exact change and the effective state was synced from it
 *  (F2): without that a request stays PENDING for a later run, it is never closed on the word of the caller. */
export async function dailyApplied(db, ids, run, now, deps = {}) {
  const res = { applied: [], skipped: [] };
  const okRun = /^\d{1,20}$/.test(String(run.run_id || '')) && /^[A-Za-z0-9._-]{3,80}$/.test(String(run.release_tag || '')) && typeof deps.evidence === 'function';
  for (const id of ids) { const row = await get(db, id); if (!okRun || !row || row.mode !== 'SCHEDULED' || row.state !== 'PENDING' || (row.criticality === 'CRITICAL' && (!row.authorized_by_id || row.authorized_by_id === row.requested_by_id || row.authorization_sha256 !== await authSha(row)))) { res.skipped.push(id); continue; }
    if (!(await deps.evidence(row))) { res.skipped.push(id); continue; }
    const m = await move(db, row, 'APPLIED', { run_id: String(run.run_id), release_tag: run.release_tag, applied_at: now }, 'workflow:daily.yml', { run_id: String(run.run_id), release_tag: run.release_tag, evidence: 'exact change listed in the verified release; effective state synced' }, now, { role: 'PIPELINE' }); (m.ok ? res.applied : res.skipped).push(id); }
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
