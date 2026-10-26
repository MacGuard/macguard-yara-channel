// Human decisions about promoted intelligence records of every family: hold, quarantine, reject, approve. Same shape as the YARA decisions (reason required, idempotent request id, a batch
// is all-or-nothing, the audit chain records it) but stored in the INTEL database, as an append-only overlay on the imported state. "Approve" means approved for the NEXT publication: this
// panel never publishes a non-YARA record; PUBLISHED is only ever set by the pipeline that signs a release. A record that cannot be approved says why, from the evidence.
import { approvability, FAMILIES } from './intel_data.js';
import { appendAudit } from './store.js';

export const ACTIONS = { hold: 'RETENIDA', quarantine: 'QUARANTINED', reject: 'REJECTED', approve: 'APPROVED' };
const ID = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,199}$/, REQID = /^[A-Za-z0-9_-]{16,80}$/;
const visible = (s) => String(s).replace(/[\s\p{Cf}]/gu, '').length;
const bad = (status, error, extra = {}) => ({ status, body: { error, ...extra } });
export const MAX_BATCH = 50;

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
export async function decide({ intel, panel }, body, actor, now) {
  const v = validate(body); if (v.error) return bad(400, v.error); const { action, ids, reason, request_id, expect } = v.value, to = ACTIONS[action];
  const done = (await intel.prepare('SELECT record_id, to_state FROM intel_decisions WHERE request_id = ? ORDER BY id').bind(request_id).all()).results;
  if (done.length) return done.map((x) => x.record_id).sort().join() === [...ids].sort().join() && done.every((x) => x.to_state === to) ? { status: 200, body: { replay: true, changed: done.length, action, to_state: to } } : bad(409, 'request id reused for a different request');
  const rows = []; const blocked = [], stale = [], unchanged = [];
  for (const id of ids) {
    const r = await intel.prepare('SELECT r.id, r.family, r.held_back, r.doc, r.run_id, r.source_id, COALESCE(c.state, r.state) AS state FROM intel_records r LEFT JOIN intel_current c ON c.record_id = r.id WHERE r.id = ?').bind(id).first();
    if (!r) return bad(404, 'record not found', { id });
    if (!FAMILIES.includes(r.family) || r.family === 'yara') return bad(400, 'this family is decided elsewhere', { id });
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
