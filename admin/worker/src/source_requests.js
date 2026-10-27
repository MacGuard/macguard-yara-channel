// Requests to add or retire a source of any family. The Worker never fetches the URL a person types (no outbound request, no SSRF surface): it records the request, who made it and why, and an ADMIN
// accepts or rejects it. Accepting means "build the connector" (a reviewed code change); nothing is enabled or downloaded because of a request. Every step is one entry in the audit chain.
import { FAMILIES } from './intel_data.js';
import { appendAudit } from './store.js';

export const FORMATS = ['json', 'csv', 'xml', 'rss', 'text', 'api', 'git', 'other'], AUTHS = ['none', 'api_key', 'unknown'];
const REQID = /^[A-Za-z0-9_-]{16,80}$/, visible = (s) => String(s).replace(/[\s\p{Cf}]/gu, '').length;
const bad = (status, error) => ({ status, body: { error } });

/** https only, a plain host, no credentials, no port, no fragment: the URL is data for people, never something this Worker requests. */
export function cleanUrl(u) {
  if (typeof u !== 'string' || u.length < 12 || u.length > 300 || /[\s\u0000-\u001f]/u.test(u)) return null;
  let x; try { x = new URL(u); } catch { return null; }
  if (x.protocol !== 'https:' || x.username || x.password || x.port || x.hash || !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(x.hostname) || x.hostname.includes('..')) return null;
  return x.toString();
}
export function validate(b) {
  if (!b || typeof b !== 'object' || Array.isArray(b)) return { error: 'JSON body required' };
  const kind = b.kind === undefined ? 'ADD' : b.kind; if (!['ADD', 'RETIRE'].includes(kind)) return { error: 'kind must be ADD or RETIRE' };
  if (kind === 'RETIRE' && (typeof b.target_source !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{1,79}$/.test(b.target_source))) return { error: 'target_source (the id of the source to retire) is required' };
  const url = cleanUrl(b.url); if (!url) return { error: 'url must be a plain https address (no credentials, port or fragment)' };
  if (!FAMILIES.includes(b.family)) return { error: `family must be one of ${FAMILIES.join(', ')}` };
  if (typeof b.name !== 'string' || visible(b.name) < 2 || b.name.length > 80) return { error: 'name: 2 to 80 characters' };
  if (!FORMATS.includes(b.format)) return { error: `format must be one of ${FORMATS.join(', ')}` };
  if (!AUTHS.includes(b.auth)) return { error: `auth must be one of ${AUTHS.join(', ')}` };
  if (b.license_note !== undefined && b.license_note !== null && (typeof b.license_note !== 'string' || b.license_note.length > 500)) return { error: 'license_note: at most 500 characters' };
  if (typeof b.reason !== 'string' || visible(b.reason) < 5 || b.reason.length > 2000) return { error: 'a reason of 5 to 2000 visible characters is required' };
  if (typeof b.request_id !== 'string' || !REQID.test(b.request_id)) return { error: 'request_id (16-80 url-safe characters) is required' };
  return { value: { kind, target_source: kind === 'RETIRE' ? b.target_source : null, family: b.family, name: b.name.trim(), url, format: b.format, auth: b.auth, license_note: (b.license_note || '').trim() || null, reason: b.reason.trim(), request_id: b.request_id } };
}
const view = (r) => r && { ...r };

export async function list(db) { return { schema: 1, items: (await db.prepare('SELECT * FROM source_requests ORDER BY requested_at DESC, id LIMIT 200').all()).results.map(view) }; }

export async function create(db, body, actor, now, newId) {
  const v = validate(body); if (v.error) return bad(400, v.error); const x = v.value;
  const prior = await db.prepare('SELECT * FROM source_requests WHERE request_id = ?').bind(x.request_id).first();
  if (prior) return prior.requested_by_id === actor.id && prior.url === x.url ? { status: 200, body: { replay: true, request: view(prior) } } : bad(409, 'request id reused for a different request');
  const id = newId();
  try { await db.prepare('INSERT INTO source_requests (id, request_id, kind, target_source, family, name, url, format, auth, license_note, reason, requested_by, requested_by_id, requested_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(id, x.request_id, x.kind, x.target_source, x.family, x.name, x.url, x.format, x.auth, x.license_note, x.reason, actor.login, actor.id, now).run(); }
  catch (e) { return bad(409, /UNIQUE/.test(String(e)) ? 'an open request of this kind for this address already exists' : 'the request could not be recorded'); }
  await appendAudit(db, { actor: actor.login, role: actor.role, action: x.kind === 'RETIRE' ? 'source.retire_requested' : 'source.requested', target: id, detail: { kind: x.kind, target_source: x.target_source, family: x.family, name: x.name, url: x.url, format: x.format, auth: x.auth, request_id: x.request_id, actor_id: actor.id, reason: x.reason } }, now);
  return { status: 200, body: { request: view(await db.prepare('SELECT * FROM source_requests WHERE id = ?').bind(id).first()) } };
}

/** outcome: 'ACCEPTED' | 'REJECTED' by an administrator, 'CANCELLED' by the requester or an administrator. */
export async function decide(db, id, outcome, body, actor, now, isAdmin) {
  const row = await db.prepare('SELECT * FROM source_requests WHERE id = ?').bind(id).first(); if (!row) return bad(404, 'not found');
  if (!body || typeof body !== 'object' || typeof body.reason !== 'string' || visible(body.reason) < 5 || body.reason.length > 2000) return bad(400, 'a reason of 5 to 2000 visible characters is required');
  if (!Number.isInteger(body.expect_version)) return bad(400, 'expect_version (the version you saw) is required');
  if (outcome !== 'CANCELLED' && isAdmin && row.requested_by_id === actor.id) return { status: 403, body: { error: 'the person who asked cannot also decide the request: another identity must', code: 'same_identity' } };
  if (outcome === 'CANCELLED' ? !(isAdmin || row.requested_by_id === actor.id) : !isAdmin) return bad(403, outcome === 'CANCELLED' ? 'only the requester or an administrator may cancel' : 'the permission sources.review is required');
  if (row.state !== 'REQUESTED') return bad(409, `a request in state ${row.state} is final`); if (row.version !== body.expect_version) return bad(409, 'the request changed since you saw it');
  const r = await db.prepare("UPDATE source_requests SET state = ?, version = version + 1, decided_by = ?, decided_by_id = ?, decided_at = ?, decision_reason = ? WHERE id = ? AND version = ? AND state = 'REQUESTED'").bind(outcome, actor.login, actor.id, now, body.reason.trim(), id, row.version).run();
  if (!r.meta || r.meta.changes !== 1) return bad(409, 'the request changed while it was being decided; nothing was changed');
  await appendAudit(db, { actor: actor.login, role: actor.role, action: `source.${outcome.toLowerCase()}`, target: id, detail: { name: row.name, url: row.url, family: row.family, actor_id: actor.id, reason: body.reason.trim() } }, now);
  return { status: 200, body: { request: view(await db.prepare('SELECT * FROM source_requests WHERE id = ?').bind(id).first()) } };
}
