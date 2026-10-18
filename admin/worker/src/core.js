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
  release_review: { from: ['UNDER_REVIEW'], to: 'PENDING' },
};
export function humanTransition(action, fromState) {
  const t = HUMAN[action];
  if (!t) return { ok: false, error: 'unknown action' };
  if (!t.from.includes(fromState)) return { ok: false, error: `cannot ${action} a candidate that is ${fromState}` };
  return { ok: true, to: t.to };
}
export function pipelineTransition(event, fromState) {
  if (event === 'released' && fromState === 'APPROVED_PENDING_VALIDATION') return { ok: true, to: 'RELEASED' };
  if (event === 'revalidation_failed' && fromState === 'APPROVED_PENDING_VALIDATION') return { ok: true, to: 'PENDING' };
  if (event === 'revalidation_failed' && fromState === 'RELEASED') return { ok: true, to: 'PENDING' };
  return { ok: false, error: `${event} does not apply to ${fromState}` };
}

export function validateDecisionRequest(body, role) {
  const err = (m) => ({ ok: false, status: 400, error: m });
  if (!atLeast(role, 'REVIEWER')) return { ok: false, status: 403, error: 'reviewer role required' };
  if (!body || typeof body !== 'object') return err('JSON body required');
  const { action, ids, reason, request_id, confirm_count, expect } = body;
  if (!['approve', 'reject', 'review', 'release_review'].includes(action)) return err('unknown action');
  if (!Array.isArray(ids) || ids.length === 0) return err('ids must be a non-empty list');
  if (new Set(ids).size !== ids.length) return err('duplicate ids');
  if (ids.length > MAX_BATCH) return err(`at most ${MAX_BATCH} candidates per request`);
  if (!ids.every((i) => typeof i === 'string' && /^[0-9a-f-]{8,64}$/.test(i))) return err('malformed id');
  if (typeof request_id !== 'string' || !/^[A-Za-z0-9_-]{16,80}$/.test(request_id)) return err('request_id (16-80 url-safe chars) required: it makes the request idempotent');
  if ((action === 'approve' || action === 'reject') && (typeof reason !== 'string' || reason.trim().length < 5 || reason.length > 2000)) return err('a reason of 5 to 2000 characters is required');
  if (ids.length > 1 && confirm_count !== ids.length) return err(`confirm_count must equal the exact number of affected candidates (${ids.length})`);
  if (!expect || typeof expect !== 'object' || !ids.every((i) => Number.isInteger(expect[i]))) return err('expect must give the version you saw for every id (concurrency check)');
  return { ok: true, value: { action, ids, reason: (reason || '').trim(), request_id, expect } };
}

export function validateSubmission(item) {
  if (!item || typeof item !== 'object') return 'item must be an object';
  if (!/^[0-9a-f]{64}$/.test(item.sha256 || '')) return 'sha256 must be 64 hex characters';
  if (typeof item.path !== 'string' || !item.path || item.path.length > 400 || item.path.includes('..') || item.path.startsWith('/')) return 'unsafe path';
  if (typeof item.source !== 'string' || item.source.length > 80) return 'source required';
  if (!Array.isArray(item.reasons) || item.reasons.some((r) => typeof r !== 'string')) return 'reasons must be codes';
  if (item.content_b64 !== undefined && (typeof item.content_b64 !== 'string' || item.content_b64.length > 1_400_000)) return 'content too large (1 MB max)';
  return null;
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
  return { schema: 1, pending_review: n('PENDING') + n('UNDER_REVIEW'), approved_waiting_validation: n('APPROVED_PENDING_VALIDATION'), rejected: n('REJECTED'), released_after_review: n('RELEASED') };
}
