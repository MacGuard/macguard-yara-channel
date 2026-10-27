// Second-identity approvals. Some operations may not be done by one person: granting a privileged role while two administrators exist, authorising a real recovery, turning a preventive suspension into a
// definitive revocation. Each one is a row that records WHAT was asked (frozen), by WHOM, and who approved it: always a different GitHub identity (the database refuses equal ids), whatever roles the two hold.
// The emergency path (BREAKGLASS) exists for the day no second approver is available: long reason, a delay before it can run, and a review afterwards by someone who neither asked nor executed it.
// Every transition writes its audit entry in the same batch, so there is no approval without a trace and no trace without an approval.
import { chainHash, sha256Hex, canonical } from './core.js';
import { can, OP_PERMISSIONS } from './rbac.js';

export const TTL_S = { 'role.grant': 72 * 3600, 'restore.real': 24 * 3600, 'policy.revoke_confirm': 72 * 3600 };
export const BREAKGLASS_DELAY_S = 6 * 3600, REVIEW_WITHIN_S = 7 * 24 * 3600;
export const PRIVILEGED_ROLES = ['PUBLISHER', 'SECURITY_ADMIN', 'ADMIN'];
export const PROTECTED_PROCEDURES = ['d1_only', 'full_service', 'compromise'];
const REQID = /^[A-Za-z0-9_-]{16,80}$/, UUIDISH = /^[0-9a-f-]{8,64}$/, ID = /^[0-9a-f-]{8,64}$/;
const visible = (s) => String(s).replace(/[\s\p{Cf}]/gu, '').length;
const reasonOk = (r, min = 5) => typeof r === 'string' && visible(r) >= min && r.length <= 2000;
const J = (v) => JSON.stringify(v ?? null);
const GUARD = "SELECT CASE WHEN changes() = 1 THEN 1 ELSE json('not-json') END";
const addS = (iso, s) => new Date(Date.parse(iso) + s * 1000).toISOString();
const bad = (m, status = 400) => ({ ok: false, status, error: m });

/** What an operation asks for, normalised; anything outside the schema is refused. */
export function validateParams(op, p) {
  if (!p || typeof p !== 'object' || Array.isArray(p)) return bad('params must be an object');
  const only = (keys) => Object.keys(p).every((k) => keys.includes(k)) ? null : bad(`unknown field in params (allowed: ${keys.join(', ')})`);
  if (op === 'role.grant') {
    const e = only(['user_id', 'login', 'role']); if (e) return e;
    if (!Number.isInteger(p.user_id) || p.user_id < 1 || !/^[A-Za-z0-9-]{1,39}$/.test(p.login || '') || !PRIVILEGED_ROLES.includes(p.role)) return bad('role.grant needs user_id, login and a privileged role (PUBLISHER, SECURITY_ADMIN or ADMIN)');
    return { ok: true, value: { user_id: p.user_id, login: p.login.toLowerCase(), role: p.role } };
  }
  if (op === 'restore.real') {
    const e = only(['procedure', 'run', 'target', 'backup', 'rollback_plan']); if (e) return e;
    if (!PROTECTED_PROCEDURES.includes(p.procedure)) return bad('procedure must be a protected recovery procedure');
    if (!/^[A-Za-z0-9-]{8,64}$/.test(p.run || '')) return bad('run (the assistant run id) is required: the authorisation is bound to that run');
    if (!/^[A-Za-z0-9_.:-]{3,80}$/.test(p.target || '')) return bad('target (the exact destination) is required');
    const b = p.backup; if (!b || typeof b !== 'object' || !/^\d{8}T\d{6}Z$/.test(b.stamp || '') || !['b2', 'scaleway', 'r2', 'local'].includes(b.provider)) return bad('backup {stamp, provider} is required: the chosen backup, exactly');
    if (!reasonOk(p.rollback_plan, 20) || p.rollback_plan.length > 400) return bad('rollback_plan (20 to 400 visible characters) is required');
    return { ok: true, value: { procedure: p.procedure, run: p.run, target: p.target, backup: { stamp: b.stamp, provider: b.provider }, rollback_plan: p.rollback_plan.trim() } };
  }
  if (op === 'policy.revoke_confirm') {
    const e = only(['policy_id']); if (e) return e;
    if (!UUIDISH.test(p.policy_id || '')) return bad('policy_id required');
    return { ok: true, value: { policy_id: p.policy_id } };
  }
  return bad('unknown operation');
}

export function validateCreate(body, roles) {
  if (!body || typeof body !== 'object') return bad('JSON body required');
  const ops = OP_PERMISSIONS[body.op]; if (!ops) return bad('unknown operation');
  const mode = body.mode === 'BREAKGLASS' ? 'BREAKGLASS' : body.mode === undefined || body.mode === 'DUAL' ? 'DUAL' : null; if (!mode) return bad('mode must be DUAL or BREAKGLASS');
  if (!can(roles, ops.request)) return bad(`the permission ${ops.request} is required`, 403);
  if (mode === 'BREAKGLASS' && (!ops.breakglass || !can(roles, ops.breakglass))) return bad(ops.breakglass ? `the permission ${ops.breakglass} is required for the emergency path` : 'this operation has no emergency path', 403);
  const v = validateParams(body.op, body.params); if (!v.ok) return v;
  if (!reasonOk(body.reason, mode === 'BREAKGLASS' ? 40 : 5)) return bad(mode === 'BREAKGLASS' ? 'an emergency approval needs a reason of at least 40 visible characters saying why no second approver is available' : 'a reason of 5 to 2000 visible characters is required');
  if (mode === 'BREAKGLASS' && body.no_second_approver !== true) return bad('no_second_approver: true is required: the emergency path is only for when a second approver is not available');
  if (typeof body.request_id !== 'string' || !REQID.test(body.request_id)) return bad('request_id (16-80 url-safe chars) required: it makes the request idempotent');
  return { ok: true, value: { op: body.op, params: v.value, reason: body.reason.trim(), request_id: body.request_id, mode } };
}
export function validateStep(body, { reason = false, outcome = false } = {}) {
  if (!body || typeof body !== 'object') return bad('JSON body required');
  if (typeof body.request_id !== 'string' || !REQID.test(body.request_id)) return bad('request_id (16-80 url-safe chars) required');
  if (!Number.isInteger(body.expect_version)) return bad('expect_version (the version you saw) required');
  if (reason && !reasonOk(body.reason)) return bad('a reason of 5 to 2000 visible characters is required');
  if (outcome && !['APPROPRIATE', 'INAPPROPRIATE'].includes(body.outcome)) return bad('outcome must be APPROPRIATE or INAPPROPRIATE');
  return { ok: true, value: { request_id: body.request_id, expect_version: body.expect_version, reason: typeof body.reason === 'string' ? body.reason.trim() : '', outcome: body.outcome } };
}

async function auditStmt(db, { actor, role, action, target, detail }, at) {
  const last = await db.prepare('SELECT hash FROM audit ORDER BY seq DESC LIMIT 1').first(), prev = last ? last.hash : '0'.repeat(64);
  const e = { at, actor, role, action, target, detail: J(detail) };
  return db.prepare('INSERT INTO audit (at, actor, role, action, target, detail, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?)').bind(e.at, e.actor, e.role, e.action, e.target, e.detail, prev, await chainHash(prev, e));
}
const view = (r) => r && { ...r, params: JSON.parse(r.params), requested_roles: JSON.parse(r.requested_roles), approved_roles: r.approved_roles ? JSON.parse(r.approved_roles) : null };
const get = async (db, id) => view(await db.prepare('SELECT * FROM approvals WHERE id = ?').bind(id).first());
const effective = (r, now) => (['REQUESTED', 'APPROVED'].includes(r.state) && r.expires_at <= now ? 'EXPIRED' : r.state);   // an overdue request reads as expired even before anything rewrote it
const out = (r, now) => r && { ...r, state: effective(r, now) };

export async function list(db, { state, op } = {}, now) {
  const where = [], args = []; if (state && ['REQUESTED', 'APPROVED', 'EXECUTED', 'CANCELLED', 'EXPIRED'].includes(state)) { where.push('state = ?'); args.push(state); } if (op && OP_PERMISSIONS[op]) { where.push('op = ?'); args.push(op); }
  const rows = (await db.prepare(`SELECT * FROM approvals ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY requested_at DESC, id LIMIT 200`).bind(...args).all()).results.map(view);
  return { schema: 1, items: rows.map((r) => out(r, now)) };
}
export async function getOne(db, id, now) { return out(await get(db, id), now); }

/** Replays answer from the first outcome; a request id reused for another operation is refused. */
export async function create(db, v, actor, now, newId) {
  const prior = await db.prepare('SELECT * FROM approvals WHERE request_id = ?').bind(v.request_id).first();
  if (prior) return prior.requested_by_id === actor.id && prior.op === v.op ? { status: 200, replay: true, approval: out(view(prior), now) } : { status: 409, error: 'request id reused for a different request' };
  const id = newId(), params = canonical(v.params), sha = await sha256Hex(new TextEncoder().encode(`${v.op}\n${params}`));
  const open = await db.prepare("SELECT id FROM approvals WHERE op = ? AND params_sha256 = ? AND state IN ('REQUESTED','APPROVED') AND expires_at > ?").bind(v.op, sha, now).first();
  if (open) return { status: 409, error: 'an identical request is already open', approval_id: open.id };
  const notBefore = v.mode === 'BREAKGLASS' ? addS(now, BREAKGLASS_DELAY_S) : null, expires = addS(now, TTL_S[v.op] + (v.mode === 'BREAKGLASS' ? BREAKGLASS_DELAY_S : 0));
  try {
    await db.batch([db.prepare('INSERT INTO approvals (id, op, params, params_sha256, mode, state, reason, requested_by, requested_by_id, requested_roles, requested_at, expires_at, not_before, request_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
      .bind(id, v.op, params, sha, v.mode, 'REQUESTED', v.reason, actor.login, actor.id, J(actor.roles || [actor.role]), now, expires, notBefore, v.request_id),
      await auditStmt(db, { actor: actor.login, role: actor.role, action: v.mode === 'BREAKGLASS' ? 'approval.breakglass_requested' : 'approval.requested', target: id, detail: { op: v.op, params_sha256: sha, mode: v.mode, request_id: v.request_id, actor_id: actor.id, roles: actor.roles || [actor.role], not_before: notBefore, expires_at: expires } }, now)]);
  } catch { return { status: 409, error: 'the request could not be recorded; nothing was changed' }; }
  return { status: 200, approval: out(await get(db, id), now) };
}

async function step(db, row, set, auditArgs, now) {
  const cols = Object.keys(set), stmts = [db.prepare(`UPDATE approvals SET ${cols.map((c) => `${c} = ?`).join(', ')}, version = version + 1 WHERE id = ? AND version = ? AND state = ?`).bind(...cols.map((c) => set[c]), row.id, row.version, row.state), db.prepare(GUARD), await auditStmt(db, auditArgs, now)];
  try { await db.batch(stmts); } catch { return { status: 409, error: 'the approval changed while the request was being applied; nothing was changed', retry: true }; }
  return null;
}
const stale = (row, v) => (row.version !== v.expect_version ? { status: 409, error: 'the approval changed since you saw it', version: row.version } : null);

/** A second identity approves. The approver must hold the operation's approve permission and must not be the requester (by account id, whatever roles either holds). */
export async function approve(db, id, v, actor, now) {
  const row = await get(db, id); if (!row) return { status: 404, error: 'not found' };
  const ops = OP_PERMISSIONS[row.op]; if (!can(actor.roles || actor.role, ops.approve)) return { status: 403, error: `the permission ${ops.approve} is required` };
  const e = effective(row, now); if (e === 'EXPIRED') return { status: 409, error: 'this request has expired', state: 'EXPIRED' };
  if (row.state !== 'REQUESTED' || row.mode !== 'DUAL') return { status: 409, error: row.mode === 'BREAKGLASS' ? 'an emergency approval is executed, not approved' : `an approval in state ${row.state} cannot be approved`, state: row.state };
  if (actor.id === row.requested_by_id) return { status: 403, error: 'the approver must be a different identity from the requester', code: 'same_identity' };
  const s = stale(row, v); if (s) return s;
  const r = await step(db, row, { state: 'APPROVED', approved_by: actor.login, approved_by_id: actor.id, approved_roles: J(actor.roles || [actor.role]), approved_at: now, approval_reason: v.reason }, { actor: actor.login, role: actor.role, action: 'approval.approved', target: id, detail: { op: row.op, params_sha256: row.params_sha256, request_id: v.request_id, approver_id: actor.id, requester_id: row.requested_by_id, roles: actor.roles || [actor.role], reason: v.reason } }, now);
  return r || { status: 200, approval: out(await get(db, id), now) };
}

/** Marks the approval executed after its effect was applied. For DUAL it follows approve; for BREAKGLASS it is the only step and only after the delay, by the requester. */
export async function markExecuted(db, id, actor, now, extra = {}) {
  const row = await get(db, id); if (!row) return { status: 404, error: 'not found' };
  const r = await step(db, row, { state: 'EXECUTED', executed_by: actor.login, executed_by_id: actor.id, executed_at: now }, { actor: actor.login, role: actor.role, action: row.mode === 'BREAKGLASS' ? 'approval.breakglass_executed' : 'approval.executed', target: id, detail: { op: row.op, params_sha256: row.params_sha256, mode: row.mode, executor_id: actor.id, ...extra } }, now);
  return r || { status: 200, approval: out(await get(db, id), now) };
}
/** The state in which the effect may be applied, or a refusal. */
export async function readyToExecute(db, id, actor, now) {
  const row = await get(db, id); if (!row) return { status: 404, error: 'not found' };
  if (effective(row, now) === 'EXPIRED') return { status: 409, error: 'this request has expired', state: 'EXPIRED' };
  if (row.mode === 'BREAKGLASS') {
    if (row.state !== 'REQUESTED') return { status: 409, error: `an emergency approval in state ${row.state} cannot be executed`, state: row.state };
    if (actor.id !== row.requested_by_id) return { status: 403, error: 'only the person who requested an emergency approval may execute it' };
    if (!can(actor.roles || actor.role, OP_PERMISSIONS[row.op].breakglass || '')) return { status: 403, error: 'the emergency permission is required' };
    if (now < row.not_before) return { status: 409, error: 'the delay of the emergency path has not elapsed', not_before: row.not_before, code: 'delay' };
  } else if (row.state !== 'APPROVED') return { status: 409, error: `an approval in state ${row.state} cannot be executed`, state: row.state };
  return { status: 200, row };
}

export async function cancel(db, id, v, actor, now) {
  const row = await get(db, id); if (!row) return { status: 404, error: 'not found' };
  if (!['REQUESTED', 'APPROVED'].includes(row.state)) return { status: 409, error: `an approval in state ${row.state} cannot be cancelled`, state: row.state };
  if (actor.id !== row.requested_by_id && !can(actor.roles || actor.role, OP_PERMISSIONS[row.op].approve)) return { status: 403, error: 'only the requester or an approver may cancel' };
  const s = stale(row, v); if (s) return s;
  const r = await step(db, row, { state: 'CANCELLED' }, { actor: actor.login, role: actor.role, action: 'approval.cancelled', target: id, detail: { op: row.op, params_sha256: row.params_sha256, request_id: v.request_id, reason: v.reason, actor_id: actor.id } }, now);
  return r || { status: 200, approval: out(await get(db, id), now) };
}

/** After an emergency execution somebody who neither asked nor executed it says whether it was appropriate. */
export async function review(db, id, v, actor, now) {
  const row = await get(db, id); if (!row) return { status: 404, error: 'not found' };
  if (row.mode !== 'BREAKGLASS' || row.state !== 'EXECUTED') return { status: 409, error: 'only an executed emergency approval is reviewed', state: row.state };
  if (row.reviewed_at) return { status: 409, error: 'already reviewed' };
  if (actor.id === row.requested_by_id || actor.id === row.executed_by_id) return { status: 403, error: 'the reviewer must be a different identity from who requested and executed it', code: 'same_identity' };
  const s = stale(row, v); if (s) return s;
  const r = await step(db, row, { reviewed_by: actor.login, reviewed_by_id: actor.id, reviewed_at: now, review_outcome: v.outcome }, { actor: actor.login, role: actor.role, action: 'approval.reviewed', target: id, detail: { op: row.op, outcome: v.outcome, note: v.reason, request_id: v.request_id, reviewer_id: actor.id, executor_id: row.executed_by_id } }, now);
  return r || { status: 200, approval: out(await get(db, id), now) };
}

/** A real recovery event may only be recorded under an authorisation of THIS procedure and THIS run, still valid, from two identities (or an executed, delayed emergency one). */
export async function authorisationFor(db, id, { procedure, run }, now) {
  if (typeof id !== 'string' || !ID.test(id)) return { ok: false, error: 'authorization_id required: a real recovery needs an authorisation by two identities' };
  const row = await get(db, id); if (!row || row.op !== 'restore.real') return { ok: false, error: 'unknown authorisation' };
  if (effective(row, now) === 'EXPIRED') return { ok: false, error: 'the authorisation has expired' };
  const usable = (row.mode === 'DUAL' && row.state === 'APPROVED') || (row.mode === 'BREAKGLASS' && row.state === 'EXECUTED');
  if (!usable) return { ok: false, error: `the authorisation is ${row.state}${row.mode === 'BREAKGLASS' ? ' (an emergency authorisation must be executed after its delay)' : ''}` };
  if (row.params.procedure !== procedure || row.params.run !== run) return { ok: false, error: 'the authorisation is for another procedure or another run' };
  return { ok: true, approval: row };
}
