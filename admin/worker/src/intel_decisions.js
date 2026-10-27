// Human decisions about promoted intelligence records of every family: hold, quarantine, reject, approve. Same shape as the YARA decisions (reason required, idempotent request id, a batch
// is all-or-nothing, the audit chain records it) but stored in the INTEL database, as an append-only overlay on the imported state. "Approve" means approved for the NEXT publication: this
// panel never publishes a non-YARA record; PUBLISHED is only ever set by the pipeline that signs a release. A record that cannot be approved says why, from the evidence.
import { approvability, FAMILIES, overlayMissing } from './intel_data.js';
import { appendAudit } from './store.js';

export const ACTIONS = { hold: 'RETENIDA', quarantine: 'QUARANTINED', reject: 'REJECTED', approve: 'APPROVED' };
const ID = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,199}$/, REQID = /^[A-Za-z0-9_-]{16,80}$/;
const visible = (s) => String(s).replace(/[\s\p{Cf}]/gu, '').length;
const bad = (status, error, extra = {}) => ({ status, body: { error, ...extra } });
export const MAX_BATCH = 50;
/** The RBAC permission an action needs. Unknown actions have none (default deny). */
export const permissionForAction = (a) => (a === 'approve' ? 'intel.approve' : ['hold', 'quarantine', 'reject'].includes(a) ? 'intel.decide' : null);

export function validate(b) {
  if (!b || typeof b !== 'object' || Array.isArray(b)) return { error: 'JSON body required' };
  if (!Object.hasOwn(ACTIONS, b.action)) return { error: `action must be one of ${Object.keys(ACTIONS).join(', ')}` };
  if (!Array.isArray(b.ids) || !b.ids.length || b.ids.length > MAX_BATCH || new Set(b.ids).size !== b.ids.length || !b.ids.every((x) => typeof x === 'string' && ID.test(x))) return { error: `ids must be 1 to ${MAX_BATCH} distinct record ids` };
  if (typeof b.reason !== 'string' || visible(b.reason) < 5 || b.reason.length > 2000) return { error: 'a reason of 5 to 2000 visible characters is required' };
  if (typeof b.request_id !== 'string' || !REQID.test(b.request_id)) return { error: 'request_id (16-80 url-safe characters) is required: it makes the request idempotent' };
  if (b.expect !== undefined && (!b.expect || typeof b.expect !== 'object' || Array.isArray(b.expect))) return { error: 'expect must map record id to the state you saw' };
  return { value: { action: b.action, ids: b.ids, reason: b.reason.trim(), request_id: b.request_id, expect: b.expect || null } };
}

/** intel: the INTEL database; panel: the panel database (audit). All-or-nothing: one blocked record changes nothing. */
export async function decide(ctx, body, actor, now, mayRead = () => true) {
  try { return await decideInner(ctx, body, actor, now, mayRead); } catch (e) { if (overlayMissing(e)) return { status: 503, body: { error: 'migration INTEL 0002 has not been applied to the intelligence database yet; nothing was changed', code: 'migration_pending' } }; throw e; }
}
async function decideInner({ intel, panel }, body, actor, now, mayRead) {
  const v = validate(body); if (v.error) return bad(400, v.error); const { action, ids, reason, request_id, expect } = v.value, to = ACTIONS[action];
  const done = (await intel.prepare('SELECT record_id, to_state, family, reason, actor, actor_id, audited FROM intel_decisions WHERE request_id = ? ORDER BY id').bind(request_id).all()).results;
  if (done.length && done.some((x) => !x.audited) && done[0].actor_id === actor.id) {   // recovery: the decision was recorded but its audit entry was not (a failure in between); the same request finishes the job, once
    const fams = {}; for (const x of done) fams[x.family] = (fams[x.family] || 0) + 1;
    try { await appendAudit(panel, { actor: actor.login, role: actor.role, action: 'intel.decision', target: done.length === 1 ? done[0].record_id : `${done.length} records`, detail: { request_id, decision: action, to_state: done[0].to_state, count: done.length, ids: done.slice(0, MAX_BATCH).map((x) => x.record_id), families: fams, actor_id: actor.id, reason: done[0].reason, recovered: true } }, now);
      await intel.prepare('UPDATE intel_decisions SET audited = 1 WHERE request_id = ?').bind(request_id).run(); } catch { return { status: 500, body: { error: 'the audit entry could still not be written; the decision stays flagged as unaudited', request_id } }; }
  }
  if (done.length) return done.map((x) => x.record_id).sort().join() === [...ids].sort().join() && done.every((x) => x.to_state === to) ? { status: 200, body: { replay: true, changed: done.length, action, to_state: to } } : bad(409, 'request id reused for a different request');
  const rows = []; const blocked = [], stale = [], unchanged = [];
  for (const id of ids) {
    const r = await intel.prepare('SELECT r.id, r.family, r.held_back, r.doc, r.run_id, r.source_id, COALESCE(c.state, r.state) AS state FROM intel_records r LEFT JOIN intel_current c ON c.record_id = r.id WHERE r.id = ?').bind(id).first();
    if (!r) return bad(404, 'record not found', { id });
    if (!FAMILIES.includes(r.family) || r.family === 'yara') return bad(400, 'this family is decided elsewhere', { id });
    if (!mayRead(r.family)) return bad(403, 'you may not act on records of this family', { id, code: 'forbidden' });   // deciding needs the family's own inspect permission
    if (expect && Object.hasOwn(expect, id) && expect[id] !== r.state) { stale.push({ id, state: r.state }); continue; }
    if (r.state === to) { unchanged.push(id); continue; }
    if (r.state === 'PUBLISHED') return bad(409, 'a published record is withdrawn through the publication workflow, not decided here', { id });
    if (action === 'approve') { const run = await intel.prepare('SELECT * FROM intel_runs WHERE id = ?').bind(r.run_id).first(), src = await intel.prepare('SELECT * FROM intel_sources WHERE id = ?').bind(r.source_id).first(), a = approvability(r, run, src); if (!a.ok) { blocked.push({ id, reasons: a.reasons }); continue; } }
    rows.push({ id, family: r.family, from: r.state });
  }
  if (stale.length) return bad(409, 'the state changed since you saw it', { stale });
  if (blocked.length) return bad(409, 'some records cannot be approved: nothing was changed', { blocked });
  if (!rows.length) return { status: 200, body: { changed: 0, unchanged: unchanged.length, action, to_state: to } };
  const ins = () => intel.prepare('INSERT INTO intel_decisions (record_id, family, action, from_state, to_state, reason, actor, actor_id, at, request_id) VALUES (?,?,?,?,?,?,?,?,?,?)');   // one statement object per row
  try { await intel.batch(rows.map((x) => ins().bind(x.id, x.family, action, x.from, to, reason, actor.login, actor.id, now, request_id))); } catch { return bad(409, 'the decision could not be recorded; nothing was changed'); }
  const fams = {}; for (const x of rows) fams[x.family] = (fams[x.family] || 0) + 1;
  try {
    await appendAudit(panel, { actor: actor.login, role: actor.role, action: 'intel.decision', target: rows.length === 1 ? rows[0].id : `${rows.length} records`, detail: { request_id, decision: action, to_state: to, count: rows.length, ids: rows.slice(0, MAX_BATCH).map((x) => x.id), families: fams, actor_id: actor.id, reason } }, now);
    await intel.prepare('UPDATE intel_decisions SET audited = 1 WHERE request_id = ?').bind(request_id).run();
  } catch { return { status: 500, body: { error: 'the decision was recorded but its audit entry could not be written; it is flagged as unaudited', request_id } }; }
  return { status: 200, body: { changed: rows.length, unchanged: unchanged.length, action, to_state: to, request_id } };
}

/** Decisions without a matching audit entry: an anomaly that is shown, never hidden. */
export async function unaudited(intel) { return (await intel.prepare('SELECT COUNT(*) AS n FROM intel_decisions WHERE audited = 0').first()).n; }

/** What a future per-family, per-source package build may read: the records that are APPROVED now, were approved by a person (decision audited), still pass the evidence checks, and the records that
 *  were approved once and no longer are (a package that contained them must be revoked). Reading this publishes nothing: a package needs its own build, quality gates and Sigstore signature. */
export async function approvalsSnapshot(intel, { family = null, source = null, limit = 5000 } = {}) {
  const where = ["COALESCE(c.state, r.state) = 'APPROVED'"], args = []; if (family) { where.push('r.family = ?'); args.push(family); } if (source) { where.push('r.source_id = ?'); args.push(source); }
  const rows = (await intel.prepare(`SELECT r.id, r.family, r.source_id, r.key, r.doc_sha256, r.held_back, r.doc, r.run_id, d.id AS decision_id, d.actor, d.actor_id, d.at, d.request_id, d.audited FROM intel_records r JOIN intel_current c ON c.record_id = r.id JOIN intel_decisions d ON d.record_id = r.id AND d.id = (SELECT MAX(x.id) FROM intel_decisions x WHERE x.record_id = r.id) WHERE ${where.join(' AND ')} ORDER BY r.id LIMIT ?`).bind(...args, limit + 1).all()).results;
  const runs = new Map(), srcs = new Map(), eligible = [], blocked = [];
  for (const r of rows.slice(0, limit)) {
    if (!runs.has(r.run_id)) runs.set(r.run_id, await intel.prepare('SELECT * FROM intel_runs WHERE id = ?').bind(r.run_id).first()); if (!srcs.has(r.source_id)) srcs.set(r.source_id, await intel.prepare('SELECT * FROM intel_sources WHERE id = ?').bind(r.source_id).first());
    const a = approvability({ held_back: r.held_back, doc: r.doc }, runs.get(r.run_id), srcs.get(r.source_id));
    if (!r.audited) blocked.push({ id: r.id, reasons: [{ code: 'unaudited_decision' }] }); else if (!a.ok) blocked.push({ id: r.id, reasons: a.reasons });
    else eligible.push({ id: r.id, family: r.family, source_id: r.source_id, key: r.key, doc_sha256: r.doc_sha256, decision: { id: r.decision_id, by_id: r.actor_id, by: r.actor, at: r.at, request_id: r.request_id } });
  }
  const demoted = (await intel.prepare("SELECT DISTINCT d.record_id AS id, d.family FROM intel_decisions d JOIN intel_current c ON c.record_id = d.record_id WHERE d.to_state = 'APPROVED' AND c.state != 'APPROVED' ORDER BY d.record_id LIMIT 5000").all()).results;
  const groups = {}; for (const e of eligible) { const k = `${e.family}/${e.source_id}`; groups[k] = (groups[k] || 0) + 1; }
  return { schema: 1, note: 'approved for a future package; nothing here is published', eligible, blocked, withdrawn_after_approval: demoted, packages: Object.entries(groups).map(([k, n]) => ({ family: k.split('/')[0], source_id: k.split('/')[1], records: n })), truncated: rows.length > limit };
}
