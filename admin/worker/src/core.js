// Pure logic of the quarantine service: roles, state machine, validation, audit chain. No I/O in this file.
export const STATES = ['PENDING', 'UNDER_REVIEW', 'APPROVED_PENDING_VALIDATION', 'REJECTED', 'RELEASED'];
export const ROLES = ['VIEWER', 'REVIEWER', 'ADMIN'];
const RANK = { VIEWER: 1, REVIEWER: 2, ADMIN: 3 };
export const MAX_BATCH = 500;

export function atLeast(role, needed) { return (RANK[role] || 0) >= RANK[needed]; }

/** GitHub repository permission -> role. Read access is public on a public repo, so it grants nothing by itself. */
export function roleFromRepoPermission(permission) {
  switch (permission) { case 'admin': return 'ADMIN'; case 'maintain': case 'write': return 'REVIEWER'; default: return null; }
}
export function highestRole(...roles) { return roles.filter(Boolean).sort((a, b) => RANK[b] - RANK[a])[0] || null; }

// Allowed human transitions. APPROVED -> RELEASED and APPROVED -> PENDING are done by the pipeline, never by a person.
const HUMAN = {
  approve: { from: ['PENDING', 'UNDER_REVIEW'], to: 'APPROVED_PENDING_VALIDATION' },
  reject: { from: ['PENDING', 'UNDER_REVIEW', 'APPROVED_PENDING_VALIDATION'], to: 'REJECTED' },
  review: { from: ['PENDING'], to: 'UNDER_REVIEW' },
  // keep it in quarantine on purpose: also takes back an approval that has not been released yet
  hold: { from: ['PENDING', 'UNDER_REVIEW', 'APPROVED_PENDING_VALIDATION'], to: 'UNDER_REVIEW' },
  release_review: { from: ['UNDER_REVIEW'], to: 'PENDING' },
};
/** Findings a person's judgement may waive. Everything else (truncation, corruption, compile errors, a dynamic failure, a changed licence, a blocked module,
 *  a missing engine, a hash rejected before) is a technical control that no approval can skip, so such a candidate is not approvable. Mirrors WAIVABLE in
 *  scripts/decide.py, which enforces it again when the pipeline applies decisions; a test keeps the two lists identical. */
export const WAIVABLE = new Set(['costly-regex', 'filesize-loop', 'many-loops', 'unknown-module', 'include', 'license-unchecked', 'matches-benign-corpus', 'dependency-not-validated']);
export const blockingReasons = (reasons) => (Array.isArray(reasons) ? reasons : []).filter((code) => !WAIVABLE.has(code));
/** Dependencies between candidates. A rule file may need other rule files (`depends_on`, paths). decide.py puts a file in the release only if it has no
 *  technical finding, is approved when it has judgement findings, and everything it needs is in the release too; the panel computes the same thing so that a
 *  reviewer sees, before approving, whether an approval will take effect. `rows` are the candidates of the panel: { id, path, state, reasons: [codes],
 *  depends_on: [paths], detected_at }. A needed path that is not a candidate in the panel is not in quarantine and is taken to be in the validated set. */
const HELD = new Set(['APPROVED_PENDING_VALIDATION', 'RELEASED']);   // approved, or already released
const needsOwnApproval = (r) => r.reasons.length === 0 || r.reasons.some((c) => c !== 'dependency-not-validated');   // a file held only by its dependencies needs no approval of its own
const permanentlyBlocked = (r) => r.state === 'REJECTED' || blockingReasons(r.reasons).length > 0;
/** A file the pipeline holds back for `dependency-not-validated` whose visible dependencies are all approved already, while it also needs files that are not
 *  in the panel: what holds it back is outside the panel (a rejected or retired file never reaches it), so no approval here can release it. Returns that path. */
function outsideBlock(r, byPath) {
  const deps = r.depends_on || []; if (!r.reasons.includes('dependency-not-validated')) return null;
  const outside = deps.filter((d) => !byPath.has(d)); if (!outside.length) return null;
  return deps.filter((d) => byPath.has(d)).every((d) => HELD.has(byPath.get(d).state)) ? outside[0] : null;
}
function latestByPath(rows) { const m = new Map(); for (const r of rows) { const k = m.get(r.path); if (!k || String(r.detected_at) > String(k.detected_at)) m.set(r.path, r); } return m; }
/** The ids that would be in the release if exactly `approved` ids (plus the states already HELD) were approved. */
function includedIds(rows, byPath, approved) {
  const memo = new Map();
  const inc = (r, seen) => {
    if (memo.has(r.id)) return memo.get(r.id);
    if (seen.has(r.id)) return true;                         // a cycle does not exclude by itself, as in decide.py
    if (permanentlyBlocked(r) || outsideBlock(r, byPath) || (needsOwnApproval(r) && !approved.has(r.id))) { memo.set(r.id, false); return false; }
    const next = new Set(seen).add(r.id); let ok = true;
    for (const d of r.depends_on || []) { const dr = byPath.get(d); if (dr && !inc(dr, next)) { ok = false; break; } }
    memo.set(r.id, ok); return ok;
  };
  return new Set(rows.filter((r) => inc(r, new Set())).map((r) => r.id));
}
export function dependencyEffect(rows, id, together = []) {
  const byPath = latestByPath(rows), target = rows.find((r) => r.id === id); if (!target) return null;
  const base = new Set(rows.filter((r) => HELD.has(r.state)).map((r) => r.id)), hyp = new Set([...base, id, ...together]);
  const incBase = includedIds(rows, byPath, base), incHyp = includedIds(rows, byPath, hyp);
  const chainBlocked = (r, seen = new Set()) => { if (seen.has(r.id)) return null; if (permanentlyBlocked(r)) return r.path; const out = outsideBlock(r, byPath); if (out) return out; const next = new Set(seen).add(r.id);
    for (const d of r.depends_on || []) { const dr = byPath.get(d); const b = dr && chainBlocked(dr, next); if (b) return b; } return null; };
  const closure = (r, acc = new Map()) => { for (const d of r.depends_on || []) { const dr = byPath.get(d); if (dr && !acc.has(dr.id)) { acc.set(dr.id, dr); closure(dr, acc); } } return acc; };
  const needs = [...closure(target).values(), target].filter((r) => !incHyp.has(r.id) && !chainBlocked(r) && needsOwnApproval(r) && !hyp.has(r.id)).map((r) => r.path);
  const required = (target.depends_on || []).map((p) => {
    const r = byPath.get(p); if (!r) return { path: p, id: null, in_panel: false, state: null, reasons: [], blocking: [], approvable: null, status: 'not_in_quarantine', needs_approval_of: [] };
    const sub = [...closure(r).values(), r].filter((q) => !incHyp.has(q.id) && !chainBlocked(q) && needsOwnApproval(q) && !hyp.has(q.id)).map((q) => q.path);
    const status = incHyp.has(r.id) ? (HELD.has(r.state) ? 'approved' : needsOwnApproval(r) ? 'together' : 'validated') : chainBlocked(r) ? 'blocked' : 'needs_approval';
    return { path: p, id: r.id, in_panel: true, state: r.state, reasons: r.reasons, blocking: blockingReasons(r.reasons), approvable: !permanentlyBlocked(r), status, blocked_by: status === 'blocked' ? chainBlocked(r) : null, needs_approval_of: sub };
  });
  const own = blockingReasons(target.reasons), blockedBy = chainBlocked(target);
  const effect = own.length || target.state === 'REJECTED' ? 'not_approvable' : incHyp.has(id) ? 'effective' : blockedBy ? 'ineffective' : 'conditional';
  const returning = rows.filter((r) => r.id !== id && incHyp.has(r.id) && !incBase.has(r.id) && r.state !== 'REJECTED');
  return { effect, required, needs_approval_of: effect === 'conditional' ? needs.filter((p) => p !== target.path) : [], blocked_by: effect === 'ineffective' ? blockedBy : null,
    dependents: rows.filter((r) => (r.depends_on || []).includes(target.path)).map((r) => ({ id: r.id, path: r.path, state: r.state, reasons: r.reasons, own_blockers: r.reasons.filter((c) => c !== 'dependency-not-validated'), returns: returning.some((q) => q.id === r.id) })),
    would_return: returning.map((r) => ({ id: r.id, path: r.path })) };
}
export function humanTransition(action, fromState) {
  const t = HUMAN[action];
  if (!t) return { ok: false, error: 'unknown action' };
  if (!t.from.includes(fromState)) return { ok: false, error: `cannot ${action} a candidate that is ${fromState}` };
  return { ok: true, to: t.to };
}
export function pipelineTransition(event, fromState) {
  if (event === 'revalidation_failed' && fromState === 'APPROVED_PENDING_VALIDATION') return { ok: true, to: 'PENDING' };
  if (event === 'revalidation_failed' && fromState === 'RELEASED') return { ok: true, to: 'PENDING' };
  return { ok: false, error: `${event} does not apply to ${fromState}` };
}

// ---- publication evidence ---------------------------------------------------------------------
// A candidate becomes RELEASED only when the public release itself shows its exact (path, SHA-256) in the manifest of a non-draft release. Passing the
// checks, being approved by a person, or being named in a request is never enough. A person can never produce this transition: it has no human action.
export const RELEASE_TAG = /^rules-\d{8}-\d+$/;
const enc = new TextEncoder();
const hex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('');
const sha = async (bytes) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
const cat = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; };
export const sha256Hex = async (bytes) => hex(await sha(bytes));
/** The rules root of scripts/tlog.py: RFC 6962 Merkle tree over `path\0sha256` leaves sorted by path. */
export async function rulesRoot(files) {
  const sorted = [...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const mth = async (ls) => { const n = ls.length; if (n === 0) return sha(new Uint8Array(0)); if (n === 1) return ls[0]; let k = 1; while (k * 2 < n) k *= 2; return sha(cat(Uint8Array.of(1), await mth(ls.slice(0, k)), await mth(ls.slice(k)))); };
  return hex(await mth(await Promise.all(sorted.map((f) => sha(cat(Uint8Array.of(0), enc.encode(`${f.path}\0${f.sha256}`)))))));
}
/** A release manifest as evidence: well formed, unique printable paths, and a `rules_root` that really is the root of its own file list. */
export async function verifyManifest(bytes) {
  let m; try { m = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { return { ok: false, error: 'the manifest is not valid JSON' }; }
  if (!m || !Array.isArray(m.files) || m.files.length === 0 || m.files.length > 20000) return { ok: false, error: 'the manifest has no usable file list' };
  const files = new Map();
  for (const f of m.files) {
    if (!f || typeof f.path !== 'string' || !/^[\x21-\x7e]+(?: [\x21-\x7e]+)*$/.test(f.path) || !/^[0-9a-f]{64}$/.test(f.sha256 || '')) return { ok: false, error: 'the manifest lists an entry that is not a printable path with a SHA-256' };
    if (files.has(f.path)) return { ok: false, error: 'the manifest lists a path twice' };
    files.set(f.path, { sha256: f.sha256, bytes: Number.isInteger(f.bytes) ? f.bytes : null });
  }
  const root = await rulesRoot(m.files);
  if (m.rules_root !== root) return { ok: false, error: 'the manifest rules_root does not match its own file list' };
  return { ok: true, files, rules_root: root };
}
/** What happens to a candidate whose exact content the verified manifest lists. A rejected one is never moved: that would be a release in spite of a human rejection, so it is reported. */
export function releaseTransition(fromState) {
  if (fromState === 'RELEASED') return { ok: false, already: true };
  if (fromState === 'REJECTED') return { ok: false, conflict: 'published_despite_rejection' };
  if (fromState === 'APPROVED_PENDING_VALIDATION') return { ok: true, to: 'RELEASED', basis: 'human_approval_and_pipeline_checks' };
  if (fromState === 'PENDING' || fromState === 'UNDER_REVIEW') return { ok: true, to: 'RELEASED', basis: 'pipeline_checks_only' };
  return { ok: false, conflict: 'unknown_state' };
}

export function validateDecisionRequest(body, role) {
  const err = (m) => ({ ok: false, status: 400, error: m });
  if (!atLeast(role, 'REVIEWER')) return { ok: false, status: 403, error: 'reviewer role required' };
  if (!body || typeof body !== 'object') return err('JSON body required');
  const { action, ids, reason, request_id, confirm_count, expect } = body;
  if (!['approve', 'reject', 'hold', 'review', 'release_review'].includes(action)) return err('unknown action');
  if (!Array.isArray(ids) || ids.length === 0) return err('ids must be a non-empty list');
  if (new Set(ids).size !== ids.length) return err('duplicate ids');
  if (ids.length > MAX_BATCH) return err(`at most ${MAX_BATCH} candidates per request`);
  if (!ids.every((i) => typeof i === 'string' && /^[0-9a-f-]{8,64}$/.test(i))) return err('malformed id');
  if (typeof request_id !== 'string' || !/^[A-Za-z0-9_-]{16,80}$/.test(request_id)) return err('request_id (16-80 url-safe chars) required: it makes the request idempotent');
  if (['approve', 'reject', 'hold'].includes(action) && (typeof reason !== 'string' || reason.replace(/[\s\p{Cf}]/gu, '').length < 5 || reason.length > 2000)) return err('a reason of 5 to 2000 visible characters is required');
  if (ids.length > 1 && confirm_count !== ids.length) return err(`confirm_count must equal the exact number of affected candidates (${ids.length})`);
  if (!expect || typeof expect !== 'object' || !ids.every((i) => Number.isInteger(expect[i]))) return err('expect must give the version you saw for every id (concurrency check)');
  return { ok: true, value: { action, ids, reason: (reason || '').trim(), request_id, expect } };
}

export function validateSubmission(item) {
  if (!item || typeof item !== 'object') return 'item must be an object';
  if (!/^[0-9a-f]{64}$/.test(item.sha256 || '')) return 'sha256 must be 64 hex characters';
  if (typeof item.path !== 'string' || !item.path || item.path.length > 400 || !/^[A-Za-z0-9._\-/]+$/.test(item.path) || item.path.split('/').some((s) => s === '' || s === '.' || s === '..')) return 'unsafe path';
  if (typeof item.source !== 'string' || item.source.length > 80) return 'source required';
  if (!Array.isArray(item.reasons) || item.reasons.some((r) => typeof r !== 'string')) return 'reasons must be codes';
  if (item.content_b64 !== undefined && (typeof item.content_b64 !== 'string' || item.content_b64.length > 1_400_000)) return 'content too large (1 MB max)';
  if (item.commit !== undefined && (typeof item.commit !== 'string' || item.commit.length > 80)) return 'commit must be a short string';
  if (item.metrics !== undefined && (typeof item.metrics !== 'object' || item.metrics === null || JSON.stringify(item.metrics).length > 4000)) return 'metrics must be a small object';
  return null;
}
/** The reviewer must see exactly the bytes the hash names: the content is decoded and hashed here, before anything is stored. */
export async function blobError(item) {
  if (item.content_b64 === undefined) return null;
  let bytes; try { bytes = Uint8Array.from(atob(item.content_b64), (c) => c.charCodeAt(0)); } catch { return 'content_b64 is not valid base64'; }
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return [...d].map((b) => b.toString(16).padStart(2, '0')).join('') === item.sha256 ? null : 'content does not match its sha256';
}

// ---- audit chain ------------------------------------------------------------------------------
export function canonical(obj) {
  if (Array.isArray(obj)) return '[' + obj.map(canonical).join(',') + ']';
  if (obj && typeof obj === 'object') return '{' + Object.keys(obj).sort().map((k) => JSON.stringify(k) + ':' + canonical(obj[k])).join(',') + '}';
  return JSON.stringify(obj);
}
export async function sha256hex(text) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
export const GENESIS = '0'.repeat(64);
export async function chainHash(prevHash, entry) { return sha256hex(prevHash + canonical(entry)); }
export async function verifyChain(rows) {
  let prev = GENESIS;
  for (const r of rows) {
    if (r.prev_hash !== prev) return { ok: false, at: r.seq, error: 'chain link broken (entry removed or reordered)' };
    const expect = await chainHash(prev, { at: r.at, actor: r.actor, role: r.role, action: r.action, target: r.target, detail: r.detail });
    if (expect !== r.hash) return { ok: false, at: r.seq, error: 'entry content was altered' };
    prev = r.hash;
  }
  return { ok: true, entries: rows.length, head: prev };
}

/** What may appear on the public site: counts only. No names, rules, hashes or identities. */
export function publicStats(counts) {
  const n = (k) => Number(counts[k] || 0);
  return { schema: 1, pending_review: n('PENDING') + n('UNDER_REVIEW'), approved_waiting_validation: n('APPROVED_PENDING_VALIDATION'), rejected: n('REJECTED'), released_after_review: n('RELEASED_REVIEWED') };
}
