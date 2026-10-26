// Persistent administrative policy: withdrawal of a published rule, its lift state machine and its confirmation by evidence.
// Design: docs/audit/quarantine-decision-memory-and-withdrawal-spec.md. Nothing here edits a release or a candidate other than through the guarded batches below;
// the only way a withdrawal becomes CONFIRMED is a later public release whose manifest the Worker itself fetched and verified (src/publication.js).
import { canonical, chainHash, sha256hex, GENESIS } from './core.js';
import { can } from './rbac.js';
import { fetchPublication } from './publication.js';

// ---- constants of the state machine (the DB repeats the ones it can: migrations/0003_policies.sql) ----
export const BREAKGLASS_DELAY_S = 6 * 3600;        // between asking for the emergency lift and being allowed to apply it: time for a second administrator to appear or to veto
export const BREAKGLASS_WINDOW_S = 24 * 3600;      // after the delay the request stays executable this long, then it expires by itself
export const DUAL_WINDOW_S = 72 * 3600;            // a second authorization must arrive within this time
export const REVIEW_WITHIN_S = 7 * 24 * 3600;      // an emergency lift must be reviewed by ANOTHER administrator within this time
export const CRITICALITIES = ['STANDARD', 'CRITICAL'];
export const SCOPES = ['path', 'content'];

const J = (v) => JSON.stringify(v ?? null);
const parse = (s, d) => { try { return JSON.parse(s); } catch { return d; } };
/** The three READ hooks that existing routes call (rule sheet, Published, approval) run before migration 0003 has been applied when the Worker is deployed first:
 *  a database without the policy tables has no policies, so they answer as if there were none. Anything else is still an error. */
const noTable = (e) => /no such table/i.test(String((e && e.message) || e));
async function rowsOrNone(query) { try { return (await query()).results; } catch (e) { if (noTable(e)) return []; throw e; } }
const addS = (iso, s) => new Date(Date.parse(iso) + s * 1000).toISOString();
const asciiLower = (s) => String(s).replace(/[A-Z]/g, (c) => c.toLowerCase());
const GUARD = "SELECT CASE WHEN changes() = 1 THEN 1 ELSE json('not-json') END";   // aborts the whole batch when the statement before it changed a row count other than one

// ---- identity ---------------------------------------------------------------------------------
/** The persistent identity of a rule file is (source, normalized path). Separators are unified, `.` and empty segments are dropped, `..` is refused (null). Case is
 *  folded only inside the scope key, so `Rules/A.yar` and `rules/a.yar` can never be two different prohibitions. scripts/policy_snapshot.py repeats this function. */
export function normalizePath(p) {
  if (typeof p !== 'string' || !p || p.length > 400) return null;
  const parts = p.replace(/\\/g, '/').normalize('NFC').split('/').filter((s) => s !== '' && s !== '.');
  if (!parts.length || parts.some((s) => s === '..')) return null;
  return parts.join('/');
}
export function scopeKey(scope, { source, path, sha256 }) {
  if (scope === 'content') return `content:${sha256}`;
  const n = normalizePath(path); return n === null ? null : `path:${asciiLower(source)}:${asciiLower(n)}`;
}
/** Does policy `p` (row or snapshot entry) prohibit this classified file? Exactly the rule decide.py applies. */
export function policyMatches(p, file) {
  if (p.scope === 'content') return p.sha256 === file.sha256;
  return p.scope_key === scopeKey('path', file);
}

// ---- validation (role first: a non-admin learns nothing about the shape of the request) -----------
const REQID = /^[A-Za-z0-9_-]{16,80}$/, UUIDISH = /^[0-9a-f-]{8,64}$/;
const visible = (s) => s.replace(/[\s\p{Cf}]/gu, '').length;
const reasonOk = (r, min = 5) => typeof r === 'string' && visible(r) >= min && r.length <= 2000;
const bad = (m) => ({ ok: false, status: 400, error: m });
const needs = (role, perm) => (can(role, perm) ? null : { ok: false, status: 403, error: `the permission ${perm} is required` });   // `role`: a role name or the person's roles
export function validateWithdrawalRequest(b, role) {
  const no = needs(role, 'publication.withdraw.request'); if (no) return no;
  return validateWithdrawalShape(b, role);
}
function validateWithdrawalShape(b, role) {
  if (!b || typeof b !== 'object') return bad('JSON body required');
  if (typeof b.candidate_id !== 'string' || !UUIDISH.test(b.candidate_id)) return bad('candidate_id required');
  if (!SCOPES.includes(b.scope)) return bad('scope must be "path" or "content" (explicit: there is no default)');
  if (!CRITICALITIES.includes(b.criticality)) return bad('criticality must be "STANDARD" or "CRITICAL" (explicit: it decides who may lift the block)');
  if (role !== undefined && (b.criticality === 'CRITICAL' || b.scope === 'content')) { const deny = needs(role, 'security.suspend'); if (deny) return deny; }   // a critical or content-wide block is a preventive SUSPENSION (effective at once); it becomes a definitive revocation only through an independent approval
  if (!reasonOk(b.reason)) return bad('a reason of 5 to 2000 visible characters is required');
  if (typeof b.request_id !== 'string' || !REQID.test(b.request_id)) return bad('request_id (16-80 url-safe chars) required: it makes the request idempotent');
  if (!Number.isInteger(b.expect_version)) return bad('expect_version (the version you saw) required');
  if (!Number.isInteger(b.confirm_collateral) || b.confirm_collateral < 0) return bad('confirm_collateral must equal the number of dependent rules that leave with this one');
  return { ok: true, value: { candidate_id: b.candidate_id, scope: b.scope, criticality: b.criticality, reason: b.reason.trim(), request_id: b.request_id, expect_version: b.expect_version, confirm_collateral: b.confirm_collateral } };
}
/** A preventive suspension ordered for a security incident (SECURITY_ADMIN or ADMIN): always critical, effective at once, with a real justification. Making it definitive is a separate, independently approved step. */
export function validateSuspensionRequest(b, role) {
  const no = needs(role, 'security.suspend'); if (no) return no;
  if (!b || typeof b !== 'object') return bad('JSON body required');
  if (!reasonOk(b.reason, 20)) return bad('a suspension needs a justification of at least 20 visible characters');
  return validateWithdrawalShape({ ...b, criticality: 'CRITICAL' });
}
export function validateLiftRequest(b, role) {
  const no = needs(role, 'publication.lift.request'); if (no) return no;
  if (!b || typeof b !== 'object') return bad('JSON body required');
  if (!['DIRECT', 'DUAL', 'BREAKGLASS'].includes(b.kind)) return bad('kind must be DIRECT, DUAL or BREAKGLASS');
  if (!reasonOk(b.reason, b.kind === 'BREAKGLASS' ? 20 : 5)) return bad(b.kind === 'BREAKGLASS' ? 'an emergency lift needs a reason of at least 20 visible characters saying why a second administrator is not available' : 'a reason of 5 to 2000 visible characters is required');
  if (b.kind === 'BREAKGLASS' && b.no_second_admin !== true) return bad('no_second_admin: true is required: the emergency path is only for when two administrators are not available');
  if (typeof b.request_id !== 'string' || !REQID.test(b.request_id)) return bad('request_id (16-80 url-safe chars) required');
  if (!Number.isInteger(b.expect_version)) return bad('expect_version (the policy version you saw) required');
  return { ok: true, value: { kind: b.kind, reason: b.reason.trim(), request_id: b.request_id, expect_version: b.expect_version } };
}
export function validateLiftStep(b, role, { reason = false, outcome = false, perm = 'publication.lift.authorize' } = {}) {
  const no = needs(role, perm); if (no) return no;
  if (!b || typeof b !== 'object') return bad('JSON body required');
  if (typeof b.request_id !== 'string' || !REQID.test(b.request_id)) return bad('request_id (16-80 url-safe chars) required');
  if (!Number.isInteger(b.expect_version)) return bad('expect_version (the version of the lift you saw) required');
  if (reason && !reasonOk(b.reason)) return bad('a reason of 5 to 2000 visible characters is required');
  if (outcome && !['APPROPRIATE', 'INAPPROPRIATE'].includes(b.outcome)) return bad('outcome must be APPROPRIATE or INAPPROPRIATE');
  return { ok: true, value: { request_id: b.request_id, expect_version: b.expect_version, reason: typeof b.reason === 'string' ? b.reason.trim() : '', outcome: b.outcome } };
}

// ---- plumbing --------------------------------------------------------------------------------------
async function auditStmt(db, { actor, role, action, target, detail }, at) {
  const last = await db.prepare('SELECT hash FROM audit ORDER BY seq DESC LIMIT 1').first(), prev = last ? last.hash : GENESIS;
  const e = { at, actor, role, action, target, detail: J(detail) };
  return db.prepare('INSERT INTO audit (at, actor, role, action, target, detail, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?)').bind(e.at, e.actor, e.role, e.action, e.target, e.detail, prev, await chainHash(prev, e));
}
/** A history row, written only if the statement right before it changed a row (so a lost race leaves no event). */
const eventStmt = (db, p, o) => db.prepare('INSERT INTO policy_events (policy_id, policy_version, event, actor, actor_id, role, reason, release_tag, evidence, request_id, at) SELECT ?,?,?,?,?,?,?,?,?,?,? WHERE changes() = 1')
  .bind(p.id, o.version, o.event, o.actor, o.actor_id ?? null, o.role, o.reason, o.release_tag ?? null, J(o.evidence ?? {}), o.request_id, o.at);
/** Read, decide and write in one atomic batch; when the batch is refused (somebody else moved a row first, or the audit link was taken) read everything again. */
async function attempt(build) {
  for (let i = 0; i < 3; i++) {
    const plan = await build(); if (plan.done) return plan.done;
    try { await plan.db.batch(plan.stmts); } catch { if (i === 2) return { status: 409, error: 'the data changed while the request was being applied; nothing was changed', retry: true }; continue; }
    return typeof plan.ok === 'function' ? plan.ok() : plan.ok;
  }
}
const view = (r) => (r ? { ...r } : r);
const lastOf = async (db, table, id) => view(await db.prepare(`SELECT * FROM ${table} WHERE id = ?`).bind(id).first());

// ---- collateral ---------------------------------------------------------------------------------
/** Published rules (RELEASED and listed in the manifest) that need the withdrawn path, directly or transitively: decide.py drops them from the next release too. */
export async function collateralOf(db, cand, pub) {
  const rows = (await db.prepare("SELECT id, path, depends_on FROM candidates WHERE archived_at IS NULL AND state = 'RELEASED' AND id != ?").bind(cand.id).all()).results
    .filter((r) => pub.files.has(r.path)).map((r) => ({ id: r.id, path: r.path, deps: parse(r.depends_on, []) }));
  const gone = new Set([cand.path]), out = new Map();
  for (let grew = true; grew;) { grew = false; for (const r of rows) if (!out.has(r.id) && r.deps.some((d) => gone.has(d))) { out.set(r.id, { id: r.id, path: r.path }); gone.add(r.path); grew = true; } }
  return [...out.values()].sort((a, b) => (a.path < b.path ? -1 : 1));
}

// ---- request a withdrawal ----------------------------------------------------------------------------
async function precheck(db, env, deps, req) {
  const c = await db.prepare('SELECT * FROM candidates WHERE id = ?').bind(req.candidate_id).first();
  if (!c || c.archived_at) return { fail: { status: 404, error: 'not found' } };
  if (c.state !== 'RELEASED') return { fail: { status: 409, error: `only a RELEASED rule can be withdrawn (this one is ${c.state}); use reject for a rule that is not published`, code: 'not_released' } };
  const path = normalizePath(c.path), key = path === null ? null : scopeKey(req.scope, { source: c.source, path: c.path, sha256: c.sha256 });
  if (!key) return { fail: { status: 409, error: 'the rule has no normalizable path', code: 'bad_path' } };
  const pub = await fetchPublication(env, deps, null);   // the Worker reads the latest public release itself; the request's word is never evidence
  if (!pub.ok) return { fail: { status: pub.status, error: `${pub.error}; nothing was changed` } };
  const m = pub.files.get(c.path);
  if (!m || m.sha256 !== c.sha256) return { fail: { status: 409, error: 'the latest public release does not list this exact path and content: there is nothing to withdraw (use reject)', code: 'not_in_current_release' } };
  if (!pub.release.published_at) return { fail: { status: 502, error: 'the latest release has no verifiable publication time; nothing was changed' } };
  return { c, path, key, pub, collateral: await collateralOf(db, c, pub) };
}
export async function previewWithdrawal(db, env, deps, { candidate_id, scope }) {
  if (!SCOPES.includes(scope)) return { status: 400, error: 'scope must be "path" or "content"' };
  const p = await precheck(db, env, deps, { candidate_id, scope }); if (p.fail) return p.fail;
  const active = await db.prepare("SELECT id FROM policies WHERE scope_key = ? AND status = 'ACTIVE'").bind(p.key).first();
  return { status: 200, scope_key: p.key, version: p.c.version, already_active: active ? active.id : null, collateral: p.collateral, baseline: { tag: p.pub.tag, published_at: p.pub.release.published_at, manifest_sha256: p.pub.manifest_sha256, rules_root: p.pub.rules_root } };
}
export async function requestWithdrawal(db, env, deps, req, actor, now) {
  return attempt(async () => {
    const prior = await db.prepare('SELECT * FROM policies WHERE request_id = ?').bind(req.request_id).first();
    if (prior) return { done: prior.candidate_id === req.candidate_id && prior.scope === req.scope ? { status: 200, replay: true, policy: view(prior) } : { status: 409, error: 'request id reused for a different request' } };
    const p = await precheck(db, env, deps, req); if (p.fail) return { done: p.fail };
    const { c, key, pub, collateral } = p;
    if (c.version !== req.expect_version) return { done: { status: 409, error: `changed since you loaded it (version ${c.version}, you saw ${req.expect_version})` } };
    const dup = await db.prepare("SELECT id FROM policies WHERE scope_key = ? AND status = 'ACTIVE'").bind(key).first();
    if (dup) return { done: { status: 409, error: 'a prohibition for this scope is already in force', code: 'already_active', policy_id: dup.id } };
    if (req.confirm_collateral !== collateral.length) return { done: { status: 409, error: `confirm_collateral must equal ${collateral.length}: that many dependent rules leave with this one`, code: 'collateral_mismatch', collateral } };
    const id = deps.uuid(), base = { tag: pub.tag, published_at: pub.release.published_at, manifest_sha256: pub.manifest_sha256, rules_root: pub.rules_root, evidence: pub.release.evidence };
    const stmts = [
      db.prepare("UPDATE candidates SET version = version + 1, updated_at = ? WHERE id = ? AND version = ? AND state = 'RELEASED' AND archived_at IS NULL").bind(now, c.id, c.version),
      db.prepare('INSERT INTO policies (id, scope, scope_key, source, path, sha256, candidate_id, criticality, kind, author, author_id, author_role, reason, created_at, request_id, baseline_tag, baseline_published_at, baseline_manifest_sha256, baseline_rules_root, updated_at) SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,? WHERE changes() = 1')
        .bind(id, req.scope, key, c.source, p.path, c.sha256, c.id, req.criticality, req.criticality === 'CRITICAL' || req.scope === 'content' ? 'SUSPENSION' : 'WITHDRAWAL', actor.login, actor.id, actor.role, req.reason, now, req.request_id, pub.tag, pub.release.published_at, pub.manifest_sha256, pub.rules_root, now),
      eventStmt(db, { id }, { version: 1, event: 'WITHDRAWAL_REQUESTED', actor: actor.login, actor_id: actor.id, role: actor.role, reason: req.reason, release_tag: pub.tag, evidence: { baseline: base, collateral: collateral.length, criticality: req.criticality, kind: req.criticality === 'CRITICAL' || req.scope === 'content' ? 'SUSPENSION' : 'WITHDRAWAL' }, request_id: req.request_id, at: now }),
      db.prepare(GUARD),
      await auditStmt(db, { actor: actor.login, role: actor.role, action: 'policy.withdrawal_requested', target: id, detail: { request_id: req.request_id, policy_id: id, policy_version: 1, scope: req.scope, scope_key: key, criticality: req.criticality, kind: req.criticality === 'CRITICAL' || req.scope === 'content' ? 'SUSPENSION' : 'WITHDRAWAL', source: c.source, path: p.path, sha256: c.sha256, candidate_id: c.id,
        candidate_version_before: c.version, candidate_version_after: c.version + 1, reason: req.reason, baseline: base, collateral, confirm_collateral: req.confirm_collateral } }, now)];
    return { db, stmts, ok: async () => ({ status: 200, policy: view(await db.prepare('SELECT * FROM policies WHERE id = ?').bind(id).first()) ?? { id }, collateral, baseline: base }) };
  });
}

// ---- lifting a policy: DIRECT / DUAL / BREAKGLASS --------------------------------------------------
/** The statements that turn an authorized lift into a LIFTED policy (and the candidate back to PENDING when it is still RELEASED). The lift row must already be APPLIED
 *  earlier in the same batch: the trigger policies_lift_needs_recorded_authorization refuses a LIFTED policy otherwise. */
async function liftStatements(db, p, lift, via, actor, reason, requestId, now) {
  const c = await db.prepare('SELECT id, sha256, state, version, archived_at FROM candidates WHERE id = ?').bind(p.candidate_id).first();
  const stmts = [
    db.prepare("UPDATE policies SET status = 'LIFTED', withdrawal = CASE withdrawal WHEN 'REQUESTED' THEN 'CANCELLED' ELSE withdrawal END, lifted_by = ?, lifted_by_id = ?, lifted_reason = ?, lifted_at = ?, lifted_via = ?, lift_id = ?, version = version + 1, updated_at = ? WHERE id = ? AND version = ? AND status = 'ACTIVE'")
      .bind(actor.login, actor.id, reason, now, via, lift.id, now, p.id, p.version), db.prepare(GUARD)];
  let candidate = null;
  if (c && !c.archived_at && c.state === 'RELEASED') {
    stmts.push(db.prepare("UPDATE candidates SET state = 'PENDING', version = version + 1, updated_at = ? WHERE id = ? AND version = ? AND state = 'RELEASED'").bind(now, c.id, c.version),
      db.prepare("INSERT INTO decisions (candidate_id, sha256, action, from_state, to_state, candidate_version, actor, actor_id, role, reason, batch_id, request_id, at) SELECT ?,?,?,?,?,?,?,?,?,?,?,?,? WHERE changes() = 1")
        .bind(c.id, c.sha256, 'lift_policy', 'RELEASED', 'PENDING', c.version + 1, actor.login, actor.id, actor.role, reason, null, requestId, now), db.prepare(GUARD));
    candidate = { id: c.id, from: 'RELEASED', to: 'PENDING' };
  }
  return { stmts, candidate };
}
const effective = (l, now) => (l.state === 'REQUESTED' && l.expires_at <= now ? 'EXPIRED' : l.state);

/** Persist the expiry of lifts nobody applied in time. Reads treat them as expired already, and the DB refuses to apply a lift at or after expires_at, so this only writes the record. */
export async function expireDue(db, now) {
  const due = (await db.prepare("SELECT * FROM policy_lifts WHERE state = 'REQUESTED' AND expires_at <= ? ORDER BY expires_at LIMIT 20").bind(now).all()).results, done = [];
  for (const l of due) {
    const p = await db.prepare('SELECT id, version FROM policies WHERE id = ?').bind(l.policy_id).first();
    try {
      await db.batch([
        db.prepare("UPDATE policy_lifts SET state = 'EXPIRED', closed_by = 'system', closed_reason = 'expired without being applied', closed_at = ?, version = version + 1, updated_at = ? WHERE id = ? AND version = ? AND state = 'REQUESTED' AND expires_at <= ?").bind(now, now, l.id, l.version, now),
        eventStmt(db, { id: l.policy_id }, { version: p ? p.version : 0, event: 'LIFT_EXPIRED', actor: 'system', role: 'SYSTEM', reason: 'expired without being applied', evidence: { lift_id: l.id, kind: l.kind, expires_at: l.expires_at }, request_id: l.id, at: now }), db.prepare(GUARD),
        await auditStmt(db, { actor: 'system', role: 'SYSTEM', action: l.kind === 'BREAKGLASS' ? 'breakglass.expired' : 'policy.lift_expired', target: l.policy_id, detail: { lift_id: l.id, kind: l.kind, requested_by: l.requested_by, expires_at: l.expires_at } }, now)]);
      done.push(l.id);
    } catch { /* somebody else closed it first */ }
  }
  return done;
}
const replayOf = async (db, policyId, event, requestId) => db.prepare('SELECT 1 AS x FROM policy_events WHERE policy_id = ? AND event = ? AND request_id = ?').bind(policyId, event, requestId).first();

export async function requestLift(db, policyId, req, actor, now) {
  await expireDue(db, now);
  return attempt(async () => {
    const prior = await db.prepare('SELECT * FROM policy_lifts WHERE request_id = ?').bind(req.request_id).first();
    if (prior) return { done: prior.policy_id === policyId && prior.kind === req.kind ? { status: 200, replay: true, lift: view(prior) } : { status: 409, error: 'request id reused for a different request' } };
    const p = await lastOf(db, 'policies', policyId); if (!p) return { done: { status: 404, error: 'not found' } };
    if (p.status !== 'ACTIVE') return { done: { status: 409, error: 'this policy is not in force', code: 'not_active' } };
    if (p.version !== req.expect_version) return { done: { status: 409, error: `changed since you loaded it (version ${p.version}, you saw ${req.expect_version})` } };
    if (req.kind === 'DIRECT' && p.criticality !== 'STANDARD') return { done: { status: 409, error: 'a CRITICAL block cannot be lifted by one administrator: ask for a second, independent authorization (DUAL)', code: 'critical_needs_second_authorization' } };
    if (req.kind === 'BREAKGLASS' && p.criticality !== 'CRITICAL') return { done: { status: 409, error: 'the emergency path is for CRITICAL blocks only', code: 'not_critical' } };
    const open = await db.prepare("SELECT id FROM policy_lifts WHERE policy_id = ? AND state = 'REQUESTED'").bind(policyId).first();
    if (open) return { done: { status: 409, error: 'a lift of this policy is already waiting', code: 'lift_already_requested', lift_id: open.id } };
    if (req.kind === 'BREAKGLASS') {
      const overdue = await db.prepare("SELECT id FROM policy_lifts WHERE kind = 'BREAKGLASS' AND state = 'APPLIED' AND reviewed_at IS NULL AND review_due_at < ? LIMIT 1").bind(now).first();
      if (overdue) return { done: { status: 409, error: 'a previous emergency lift has not been reviewed by another administrator in time: review it first', code: 'review_overdue', lift_id: overdue.id } };
    }
    const id = `${req.kind === 'DIRECT' ? 'd' : req.kind === 'DUAL' ? 'u' : 'b'}-${await sha256hex(req.request_id)}`.slice(0, 40);
    const notBefore = req.kind === 'BREAKGLASS' ? addS(now, BREAKGLASS_DELAY_S) : now, expires = req.kind === 'BREAKGLASS' ? addS(notBefore, BREAKGLASS_WINDOW_S) : addS(now, DUAL_WINDOW_S);
    const lift = { id, kind: req.kind };
    const loud = req.kind === 'BREAKGLASS';
    if (req.kind === 'DIRECT') {
      const { stmts: lifting, candidate } = await liftStatements(db, p, lift, 'DIRECT', actor, req.reason, req.request_id, now);
      const stmts = [db.prepare("INSERT INTO policy_lifts (id, policy_id, kind, state, requested_by, requested_by_id, requested_role, reason, requested_at, request_id, not_before, expires_at, applied_at, updated_at) SELECT ?,?,'DIRECT','APPLIED',?,?,?,?,?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM policies WHERE id = ? AND version = ? AND status = 'ACTIVE')")
        .bind(id, policyId, actor.login, actor.id, actor.role, req.reason, now, req.request_id, now, expires, now, now, policyId, p.version), db.prepare(GUARD), ...lifting,
        eventStmt(db, p, { version: p.version + 1, event: 'LIFTED', actor: actor.login, actor_id: actor.id, role: actor.role, reason: req.reason, evidence: { via: 'DIRECT', lift_id: id, candidate }, request_id: req.request_id, at: now }),
        await auditStmt(db, { actor: actor.login, role: actor.role, action: 'policy.lifted', target: policyId, detail: { request_id: req.request_id, policy_id: policyId, version_from: p.version, version_to: p.version + 1, via: 'DIRECT', lift_id: id, reason: req.reason, withdrawal_at_lift: p.withdrawal, candidate } }, now)];
      return { db, stmts, ok: { status: 200, lifted: true, via: 'DIRECT', policy: { id: policyId, status: 'LIFTED' }, candidate } };
    }
    const stmts = [db.prepare("INSERT INTO policy_lifts (id, policy_id, kind, state, requested_by, requested_by_id, requested_role, reason, requested_at, request_id, not_before, expires_at, updated_at) SELECT ?,?,?,'REQUESTED',?,?,?,?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM policies WHERE id = ? AND version = ? AND status = 'ACTIVE')")
      .bind(id, policyId, req.kind, actor.login, actor.id, actor.role, req.reason, now, req.request_id, notBefore, expires, now, policyId, p.version), db.prepare(GUARD),
      eventStmt(db, p, { version: p.version, event: loud ? 'BREAKGLASS_REQUESTED' : 'LIFT_REQUESTED', actor: actor.login, actor_id: actor.id, role: actor.role, reason: req.reason, evidence: { lift_id: id, not_before: notBefore, expires_at: expires }, request_id: req.request_id, at: now }),
      await auditStmt(db, { actor: actor.login, role: actor.role, action: loud ? 'breakglass.requested' : 'policy.lift_requested', target: policyId, detail: { request_id: req.request_id, policy_id: policyId, policy_version: p.version, lift_id: id, kind: req.kind, reason: req.reason, not_before: notBefore, expires_at: expires, criticality: p.criticality,
        ...(loud ? { warning: 'EMERGENCY LIFT REQUESTED WITHOUT A SECOND ADMINISTRATOR: it can be vetoed until it is applied and must be reviewed by another administrator', review_within_s: REVIEW_WITHIN_S } : {}) } }, now)];
    return { db, stmts, ok: async () => ({ status: 200, lift: view(await db.prepare('SELECT * FROM policy_lifts WHERE id = ?').bind(id).first()) ?? { id, kind: req.kind, not_before: notBefore, expires_at: expires } }) };
  });
}
/** A DIFFERENT administrator (other login and other GitHub account id) authorizes a DUAL lift: the policy is lifted in the same batch. */
export async function authorizeLift(db, liftId, req, actor, now) {
  await expireDue(db, now);
  return attempt(async () => {
    const l = await lastOf(db, 'policy_lifts', liftId); if (!l) return { done: { status: 404, error: 'not found' } };
    if (l.kind !== 'DUAL') return { done: { status: 409, error: 'only a two-person lift is authorized by a second administrator', code: 'wrong_kind' } };
    if (await replayOf(db, l.policy_id, 'LIFTED', req.request_id)) return { done: { status: 200, replay: true, lift: l } };
    if (l.state !== 'REQUESTED' || l.expires_at <= now) return { done: { status: 409, error: l.state === 'REQUESTED' || l.state === 'EXPIRED' ? 'this lift request has expired' : `this lift is ${l.state}`, code: l.state !== 'APPLIED' && l.state !== 'CANCELLED' ? 'expired' : 'not_open' } };
    if (actor.id === l.requested_by_id || asciiLower(actor.login) === asciiLower(l.requested_by)) return { done: { status: 403, error: 'the second authorization must come from a different administrator than the one who asked for the lift', code: 'second_authorizer_must_differ' } };
    if (l.version !== req.expect_version) return { done: { status: 409, error: `changed since you loaded it (version ${l.version}, you saw ${req.expect_version})` } };
    const p = await lastOf(db, 'policies', l.policy_id); if (!p || p.status !== 'ACTIVE') return { done: { status: 409, error: 'this policy is not in force', code: 'not_active' } };
    const { stmts: lifting, candidate } = await liftStatements(db, p, l, 'DUAL', actor, req.reason, req.request_id, now);
    const stmts = [db.prepare("UPDATE policy_lifts SET state = 'APPLIED', authorized_by = ?, authorized_by_id = ?, authorized_reason = ?, authorized_at = ?, applied_at = ?, version = version + 1, updated_at = ? WHERE id = ? AND version = ? AND state = 'REQUESTED' AND expires_at > ?")
      .bind(actor.login, actor.id, req.reason, now, now, now, l.id, l.version, now), db.prepare(GUARD), ...lifting,
      eventStmt(db, p, { version: p.version + 1, event: 'LIFTED', actor: actor.login, actor_id: actor.id, role: actor.role, reason: req.reason, evidence: { via: 'DUAL', lift_id: l.id, requested_by: l.requested_by, requested_by_id: l.requested_by_id, candidate }, request_id: req.request_id, at: now }),
      await auditStmt(db, { actor: actor.login, role: actor.role, action: 'policy.lifted', target: p.id, detail: { request_id: req.request_id, policy_id: p.id, version_from: p.version, version_to: p.version + 1, via: 'DUAL', lift_id: l.id, requested_by: l.requested_by, authorized_by: actor.login, reason_requested: l.reason, reason: req.reason, withdrawal_at_lift: p.withdrawal, candidate } }, now)];
    return { db, stmts, ok: { status: 200, lifted: true, via: 'DUAL', policy: { id: p.id, status: 'LIFTED' }, candidate } };
  });
}
/** The emergency lift: only its requester applies it, only after the mandatory delay and before it expires; it is then loudly audited and owes a review by ANOTHER administrator. */
export async function executeBreakglass(db, liftId, req, actor, now) {
  await expireDue(db, now);
  return attempt(async () => {
    const l = await lastOf(db, 'policy_lifts', liftId); if (!l) return { done: { status: 404, error: 'not found' } };
    if (l.kind !== 'BREAKGLASS') return { done: { status: 409, error: 'this is not an emergency lift', code: 'wrong_kind' } };
    if (await replayOf(db, l.policy_id, 'BREAKGLASS_EXECUTED', req.request_id)) return { done: { status: 200, replay: true, lift: l } };
    if (l.state !== 'REQUESTED' || l.expires_at <= now) return { done: { status: 409, error: l.state === 'REQUESTED' || l.state === 'EXPIRED' ? 'this emergency request has expired' : `this lift is ${l.state}`, code: l.state !== 'APPLIED' && l.state !== 'CANCELLED' ? 'expired' : 'not_open' } };
    if (actor.id !== l.requested_by_id) return { done: { status: 403, error: 'only the administrator who asked for the emergency lift can apply it', code: 'not_requester' } };
    if (l.not_before > now) return { done: { status: 409, error: 'the mandatory delay has not elapsed', code: 'delay_not_elapsed', not_before: l.not_before } };
    if (l.version !== req.expect_version) return { done: { status: 409, error: `changed since you loaded it (version ${l.version}, you saw ${req.expect_version})` } };
    const p = await lastOf(db, 'policies', l.policy_id); if (!p || p.status !== 'ACTIVE') return { done: { status: 409, error: 'this policy is not in force', code: 'not_active' } };
    const due = addS(now, REVIEW_WITHIN_S), { stmts: lifting, candidate } = await liftStatements(db, p, l, 'BREAKGLASS', actor, l.reason, req.request_id, now);
    const stmts = [db.prepare("UPDATE policy_lifts SET state = 'APPLIED', applied_at = ?, review_due_at = ?, version = version + 1, updated_at = ? WHERE id = ? AND version = ? AND state = 'REQUESTED' AND not_before <= ? AND expires_at > ?")
      .bind(now, due, now, l.id, l.version, now, now), db.prepare(GUARD), ...lifting,
      eventStmt(db, p, { version: p.version + 1, event: 'BREAKGLASS_EXECUTED', actor: actor.login, actor_id: actor.id, role: actor.role, reason: l.reason, evidence: { lift_id: l.id, requested_at: l.requested_at, review_due_at: due, candidate }, request_id: req.request_id, at: now }),
      await auditStmt(db, { actor: actor.login, role: actor.role, action: 'breakglass.executed', target: p.id, detail: { request_id: req.request_id, policy_id: p.id, version_from: p.version, version_to: p.version + 1, lift_id: l.id, reason: l.reason, requested_at: l.requested_at, not_before: l.not_before, review_due_at: due, candidate,
        warning: 'EMERGENCY LIFT APPLIED WITH A SINGLE ADMINISTRATOR: another administrator must review it', second_authorization: false } }, now)];
    return { db, stmts, ok: { status: 200, lifted: true, via: 'BREAKGLASS', review_due_at: due, policy: { id: p.id, status: 'LIFTED' }, candidate } };
  });
}
/** Withdraw a waiting lift request. The requester may; so may ANY other administrator (a veto during the break-glass delay). */
export async function cancelLift(db, liftId, req, actor, now) {
  await expireDue(db, now);
  return attempt(async () => {
    const l = await lastOf(db, 'policy_lifts', liftId); if (!l) return { done: { status: 404, error: 'not found' } };
    if (await replayOf(db, l.policy_id, 'LIFT_CANCELLED', req.request_id)) return { done: { status: 200, replay: true, lift: l } };
    if (l.state !== 'REQUESTED') return { done: { status: 409, error: `this lift is ${l.state}`, code: 'not_open' } };
    if (l.version !== req.expect_version) return { done: { status: 409, error: `changed since you loaded it (version ${l.version}, you saw ${req.expect_version})` } };
    const p = await lastOf(db, 'policies', l.policy_id);
    const stmts = [db.prepare("UPDATE policy_lifts SET state = 'CANCELLED', closed_by = ?, closed_by_id = ?, closed_reason = ?, closed_at = ?, version = version + 1, updated_at = ? WHERE id = ? AND version = ? AND state = 'REQUESTED'").bind(actor.login, actor.id, req.reason, now, now, l.id, l.version),
      eventStmt(db, p || { id: l.policy_id }, { version: p ? p.version : 0, event: 'LIFT_CANCELLED', actor: actor.login, actor_id: actor.id, role: actor.role, reason: req.reason, evidence: { lift_id: l.id, kind: l.kind, veto: actor.id !== l.requested_by_id }, request_id: req.request_id, at: now }), db.prepare(GUARD),
      await auditStmt(db, { actor: actor.login, role: actor.role, action: l.kind === 'BREAKGLASS' ? 'breakglass.cancelled' : 'policy.lift_cancelled', target: l.policy_id, detail: { request_id: req.request_id, lift_id: l.id, kind: l.kind, requested_by: l.requested_by, reason: req.reason, veto: actor.id !== l.requested_by_id } }, now)];
    return { db, stmts, ok: { status: 200, cancelled: true, lift_id: l.id } };
  });
}
/** The post-hoc review that an emergency lift owes: by an administrator other than the one who used it. */
export async function reviewBreakglass(db, liftId, req, actor, now) {
  return attempt(async () => {
    const l = await lastOf(db, 'policy_lifts', liftId); if (!l) return { done: { status: 404, error: 'not found' } };
    if (l.kind !== 'BREAKGLASS' || l.state !== 'APPLIED') return { done: { status: 409, error: 'only an applied emergency lift is reviewed', code: 'not_reviewable' } };
    if (l.reviewed_at) return { done: l.review_outcome === req.outcome && await replayOf(db, l.policy_id, 'BREAKGLASS_REVIEWED', req.request_id) ? { status: 200, replay: true, lift: l } : { status: 409, error: 'already reviewed', code: 'already_reviewed' } };
    if (actor.id === l.requested_by_id || asciiLower(actor.login) === asciiLower(l.requested_by)) return { done: { status: 403, error: 'the review must come from a different administrator than the one who used the emergency lift', code: 'reviewer_must_differ' } };
    if (l.version !== req.expect_version) return { done: { status: 409, error: `changed since you loaded it (version ${l.version}, you saw ${req.expect_version})` } };
    const p = await lastOf(db, 'policies', l.policy_id);
    const stmts = [db.prepare("UPDATE policy_lifts SET reviewed_by = ?, reviewed_by_id = ?, reviewed_at = ?, review_outcome = ?, review_note = ?, version = version + 1, updated_at = ? WHERE id = ? AND version = ? AND state = 'APPLIED' AND reviewed_at IS NULL").bind(actor.login, actor.id, now, req.outcome, req.reason, now, l.id, l.version),
      eventStmt(db, p || { id: l.policy_id }, { version: p ? p.version : 0, event: 'BREAKGLASS_REVIEWED', actor: actor.login, actor_id: actor.id, role: actor.role, reason: req.reason, evidence: { lift_id: l.id, outcome: req.outcome, used_by: l.requested_by }, request_id: req.request_id, at: now }), db.prepare(GUARD),
      await auditStmt(db, { actor: actor.login, role: actor.role, action: 'breakglass.reviewed', target: l.policy_id, detail: { request_id: req.request_id, lift_id: l.id, outcome: req.outcome, note: req.reason, used_by: l.requested_by, applied_at: l.applied_at, overdue: l.review_due_at < now } }, now)];
    return { db, stmts, ok: { status: 200, reviewed: true, outcome: req.outcome } };
  });
}

// ---- confirmation by evidence -------------------------------------------------------------------------
const listsScope = (pub, p) => {
  if (p.scope === 'content') return [...pub.files.values()].some((f) => f.sha256 === p.sha256);
  const want = p.scope_key.split(':').slice(2).join(':');   // path:<source>:<path>  ->  <path>; the source is not in the manifest key, so ANY entry at the path counts
  return [...pub.files.keys()].some((k) => asciiLower(normalizePath(k) ?? k) === want);
};
/** Called with a release the Worker itself fetched and verified (`pub`). A withdrawal is CONFIRMED only when a release published strictly after the baseline has no entry for its scope.
 *  A release that lists the scope while the policy is in force is recorded as a conflict and changes nothing. With no policy in force this writes nothing at all. */
export async function reconcilePolicies(db, pub, ctx, actor, now) {
  await expireDue(db, now);
  for (let attemptNo = 0; attemptNo < 3; attemptNo++) {
    const active = (await db.prepare("SELECT * FROM policies WHERE status = 'ACTIVE' ORDER BY id").all()).results;
    if (!active.length) return { recorded: false, confirmed: [], still_listed: [], conflicts: [] };
    const pubAt = pub.release.published_at ? Date.parse(pub.release.published_at) : NaN;
    const confirmed = [], stillListed = [], conflicts = [], notEligible = [];
    for (const p of active) {
      const newer = Number.isFinite(pubAt) && pubAt > Date.parse(p.baseline_published_at) && pub.tag !== p.baseline_tag, listed = listsScope(pub, p);
      if (newer && listed) { conflicts.push({ policy_id: p.id, reason: p.withdrawal === 'REQUESTED' ? 'listed_after_request' : 'published_despite_policy' }); if (p.withdrawal === 'REQUESTED') stillListed.push({ policy_id: p.id, scope: p.scope, path: p.path }); }
      else if (p.withdrawal === 'REQUESTED' && !newer) notEligible.push({ policy_id: p.id, reason: Number.isFinite(pubAt) ? 'release_not_newer_than_baseline' : 'release_has_no_publication_time' });
      else if (p.withdrawal === 'REQUESTED' && newer && !listed) confirmed.push(p);
    }
    if (!confirmed.length && !stillListed.length && !conflicts.length) return { recorded: false, confirmed: [], still_listed: [], conflicts: [], not_eligible: notEligible };
    const stmts = [];
    for (const p of confirmed) stmts.push(
      db.prepare("UPDATE policies SET withdrawal = 'CONFIRMED', confirmed_tag = ?, confirmed_published_at = ?, confirmed_manifest_sha256 = ?, confirmed_rules_root = ?, confirmed_at = ?, version = version + 1, updated_at = ? WHERE id = ? AND version = ? AND status = 'ACTIVE' AND withdrawal = 'REQUESTED'")
        .bind(pub.tag, pub.release.published_at, pub.manifest_sha256, pub.rules_root, now, now, p.id, p.version),
      eventStmt(db, p, { version: p.version + 1, event: 'WITHDRAWAL_CONFIRMED', actor, role: ctx.role || 'PIPELINE', reason: 'absent from a later verified public release', release_tag: pub.tag, evidence: { manifest_sha256: pub.manifest_sha256, rules_root: pub.rules_root, published_at: pub.release.published_at, evidence: pub.release.evidence, trigger: ctx.trigger }, request_id: pub.tag, at: now }), db.prepare(GUARD));
    stmts.push(await auditStmt(db, { actor, role: ctx.role || 'PIPELINE', action: 'policy.reconciled', target: pub.tag, detail: { tag: pub.tag, trigger: ctx.trigger, receipt: confirmed.length ? 'first' : 'idempotent_retry', release: pub.release, manifest_sha256: pub.manifest_sha256, rules_root: pub.rules_root, manifest_files: pub.files.size,
      confirmed: confirmed.map((p) => ({ policy_id: p.id, version_from: p.version, version_to: p.version + 1, scope: p.scope, path: p.path, sha256: p.sha256 })), still_listed: stillListed, conflicts, not_eligible: notEligible, run_url: ctx.run_url || null, token_run_id: ctx.token_run_id ?? null, run_attempt: ctx.run_attempt ?? null } }, now));
    try { await db.batch(stmts); } catch (e) { if (attemptNo === 2) throw e; continue; }   // a lift or another callback moved a policy first: read again
    return { recorded: true, confirmed: confirmed.map((p) => p.id), still_listed: stillListed, conflicts };
  }
}
/** ADMIN fallback when the publish callback was lost: the Worker reads the latest public release by itself; the caller supplies no tag and no hash. */
export async function reconcileNow(db, env, deps, actor, now) {
  const pub = await fetchPublication(env, deps, null); if (!pub.ok) return { status: pub.status, error: `${pub.error}; nothing was changed` };
  return { status: 200, tag: pub.tag, ...(await reconcilePolicies(db, pub, { trigger: 'reconcile', role: actor.role }, actor.login, now)) };
}

// ---- reads -----------------------------------------------------------------------------------------
const pol = (r) => ({ ...r });
const withLiftState = (l, now) => ({ ...l, effective_state: effective(l, now), review_overdue: l.kind === 'BREAKGLASS' && l.state === 'APPLIED' && !l.reviewed_at && l.review_due_at < now });
export async function listPolicies(db, { status } = {}, now) {
  const policies = (await db.prepare(`SELECT * FROM policies ${status === 'ACTIVE' || status === 'LIFTED' ? 'WHERE status = ?' : ''} ORDER BY created_at DESC, id LIMIT 200`).bind(...(status === 'ACTIVE' || status === 'LIFTED' ? [status] : [])).all()).results.map(pol);
  const lifts = (await db.prepare("SELECT * FROM policy_lifts WHERE state = 'REQUESTED' OR (kind = 'BREAKGLASS' AND reviewed_at IS NULL) ORDER BY requested_at DESC LIMIT 200").all()).results.map((l) => withLiftState(l, now));
  return { policies, lifts, review_overdue: lifts.filter((l) => l.review_overdue).map((l) => l.id) };
}
export async function getPolicy(db, id, now) {
  const p = await lastOf(db, 'policies', id); if (!p) return null;
  return { policy: p, events: (await db.prepare('SELECT * FROM policy_events WHERE policy_id = ? ORDER BY id').bind(id).all()).results.map((e) => ({ ...e, evidence: parse(e.evidence, {}) })),
    lifts: (await db.prepare('SELECT * FROM policy_lifts WHERE policy_id = ? ORDER BY requested_at DESC').bind(id).all()).results.map((l) => withLiftState(l, now)) };
}
/** What the rule sheet shows: pending / confirmed / lifted, derived from the policy rows (never a free-hand flag). */
export async function candidateView(db, c, now) {
  const keys = [scopeKey('content', c), scopeKey('path', c)].filter(Boolean);
  const rows = await rowsOrNone(() => db.prepare(`SELECT * FROM policies WHERE candidate_id = ? OR scope_key IN (${keys.map(() => '?').join(',') || "''"}) ORDER BY created_at DESC, id LIMIT 20`).bind(c.id, ...keys).all());
  const live = rows.find((p) => p.status === 'ACTIVE') || null, last = live || rows[0] || null;
  const publication = live ? (live.withdrawal === 'CONFIRMED' ? 'withdrawn' : 'withdrawal_pending') : last ? 'lifted' : c.state === 'RELEASED' ? 'published' : null;
  const lifts = last ? (await db.prepare('SELECT * FROM policy_lifts WHERE policy_id = ? ORDER BY requested_at DESC LIMIT 10').bind(last.id).all()).results.map((l) => withLiftState(l, now)) : [];
  return { publication, policy: last ? pol(last) : null, lifts, policies: rows.length };
}
/** Marks, for the Published inventory, the files that carry a policy. */
export async function annotateItems(db, items) {
  const rows = await rowsOrNone(() => db.prepare('SELECT id, scope, scope_key, sha256, status, withdrawal, criticality FROM policies ORDER BY created_at DESC, id LIMIT 500').all());
  if (!rows.length) return items;
  return items.map((it) => {
    const keys = new Set([`content:${it.sha256}`, scopeKey('path', { source: it.source || '', path: it.path })]);
    const hit = (p) => keys.has(p.scope_key) || (p.scope === 'path' && !it.source && p.scope_key.endsWith(`:${asciiLower(normalizePath(it.path) ?? it.path)}`));
    const p = rows.find((r) => r.status === 'ACTIVE' && hit(r)) || rows.find(hit);
    return p ? { ...it, policy: { id: p.id, status: p.status, withdrawal: p.withdrawal, criticality: p.criticality, publication: p.status === 'LIFTED' ? 'lifted' : p.withdrawal === 'CONFIRMED' ? 'withdrawn' : 'withdrawal_pending' } } : it;
  });
}
/** Approving a candidate that an ACTIVE policy covers would be meaningless (decide.py blocks it): refuse it up front. */
export async function blockedByPolicy(db, ids) {
  const active = await rowsOrNone(() => db.prepare("SELECT id, scope, scope_key, sha256 FROM policies WHERE status = 'ACTIVE'").all()); if (!active.length) return [];
  const out = [];
  for (let i = 0; i < ids.length; i += 50) {
    const part = ids.slice(i, i + 50);
    for (const c of (await db.prepare(`SELECT id, source, path, sha256 FROM candidates WHERE id IN (${part.map(() => '?').join(',')})`).bind(...part).all()).results) {
      const p = active.find((a) => policyMatches(a, c)); if (p) out.push({ id: c.id, code: 'blocked_by_policy', policy_id: p.id, error: `an administrative prohibition is in force (${p.id}): lift it first` });
    }
  }
  return out;
}

// ---- the pipeline's view ---------------------------------------------------------------------------------
/** Hashes of every rejected candidate, archived or not: a rejection must not vanish because a row was archived. */
export async function rejectedHashes(db) { return (await db.prepare("SELECT DISTINCT sha256 FROM candidates WHERE state = 'REJECTED' ORDER BY sha256").all()).results.map((r) => r.sha256); }
/** The active policy set as the pipeline consumes it, with canonical digests (sorted, no reasons, no people). `policy_set_sha256` covers exactly `policies`. */
export async function snapshot(db, now) {
  const policies = (await db.prepare("SELECT id, version, scope, scope_key, source, path, sha256, criticality, withdrawal, created_at FROM policies WHERE status = 'ACTIVE' ORDER BY id").all()).results.map(pol);
  const lifted = (await db.prepare("SELECT id, version, lifted_via FROM policies WHERE status = 'LIFTED' ORDER BY id").all()).results.map(pol);
  const rejected = await rejectedHashes(db), head = await db.prepare('SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1').first();
  const maxDecision = (await db.prepare('SELECT COALESCE(MAX(id), 0) AS n FROM decisions').first()).n;
  const overdue = (await db.prepare("SELECT COUNT(*) AS n FROM policy_lifts WHERE kind = 'BREAKGLASS' AND state = 'APPLIED' AND reviewed_at IS NULL AND review_due_at < ?").bind(now).first()).n;
  return { schema: 1, generated_at: now, audit_head: head ? { seq: head.seq, hash: head.hash } : { seq: 0, hash: GENESIS }, decisions_max_id: maxDecision, policies, lifted, rejected,
    policy_set_sha256: await sha256hex(canonical(policies)), rejected_sha256: await sha256hex(canonical(rejected)), breakglass_reviews_overdue: overdue };
}

/** The effect of an approved `policy.revoke_confirm`: a SUSPENSION that is still in force becomes a definitive REVOCATION (version +1, event, audit). A policy that is no longer a suspension in force is never changed. */
export async function confirmRevocation(db, policyId, approval, actor, now) {
  return attempt(async () => {
    const p = await db.prepare('SELECT * FROM policies WHERE id = ?').bind(policyId).first();
    if (!p) return { done: { status: 404, error: 'policy not found' } };
    if (p.kind === 'REVOCATION') return { done: { status: 200, replay: true, policy: view(p) } };
    if (p.kind !== 'SUSPENSION' || p.status !== 'ACTIVE') return { done: { status: 409, error: 'only a suspension that is still in force can become a definitive revocation', kind: p.kind, status_now: p.status } };
    return { db, stmts: [
      db.prepare("UPDATE policies SET kind = 'REVOCATION', version = version + 1, updated_at = ? WHERE id = ? AND version = ? AND kind = 'SUSPENSION' AND status = 'ACTIVE'").bind(now, p.id, p.version), db.prepare(GUARD),
      eventStmt(db, p, { version: p.version + 1, event: 'REVOCATION_CONFIRMED', actor: actor.login, actor_id: actor.id, role: actor.role, reason: approval.approval_reason || approval.reason, evidence: { approval_id: approval.id, requested_by_id: approval.requested_by_id, approved_by_id: approval.approved_by_id }, request_id: `rev-${approval.id}`, at: now }),
      db.prepare(GUARD), await auditStmt(db, { actor: actor.login, role: actor.role, action: 'policy.revocation_confirmed', target: p.id, detail: { policy_id: p.id, version_from: p.version, version_to: p.version + 1, approval_id: approval.id, requested_by_id: approval.requested_by_id, approved_by_id: approval.approved_by_id } }, now)],
      ok: async () => ({ status: 200, policy: view(await db.prepare('SELECT * FROM policies WHERE id = ?').bind(p.id).first()) }) };
  });
}
