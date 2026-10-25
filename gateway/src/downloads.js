// Premium downloads: three distinct things are recorded. REQUEST (the API call), AUTHORISATION (a short-lived token bound to one key) and TRANSFER (bytes actually served).
// The bucket is private and only reachable through the R2 binding of this Worker; a token without the key it was issued to is useless, so a shared link does not leak the file.
import { HttpError, iso, randomHex, randomToken, sha256Hex, safeEqual, windows } from './util.js';
import { consume } from './pipeline.js';
import { emit } from './events.js';
import { audit } from './audit.js';

const TTL_DEFAULT = 120, TTL_MAX = 600, MAX_USES = 6;

// Content in the promotion or in a paid release must be licensed for it: every source in the bundle has to be approved for Premium RIGHT NOW (a later revocation closes the door).
export async function licenseGate(db, sourceIds) {
  const bad = [];
  for (const id of sourceIds) {
    const s = await db.prepare('SELECT * FROM intel_sources WHERE source_id = ?').bind(id).first();
    if (!s || s.status !== 'PREMIUM_APPROVED' || s.owner_confirmed !== 1 || !JSON.parse(s.approved_products).includes('premium')) bad.push(id);
  }
  return bad;
}
export async function listReleases(db, edition = 'premium') {
  const rows = (await db.prepare("SELECT id, published_at, size, sha256, manifest_sha256, rules_root, source_ids FROM releases WHERE edition = ? AND status = 'published' ORDER BY published_at DESC, id DESC").bind(edition).all()).results;
  const out = [];
  for (const { source_ids, ...r } of rows) if (edition === 'community' || (await licenseGate(db, JSON.parse(source_ids))).length === 0) out.push(r);     // a release that could not be downloaded is not announced either
  return out;
}
export async function authorizeDownload(db, clock, ctx, eff, releaseId, ttlSeconds = TTL_DEFAULT) {
  const rel = await db.prepare("SELECT * FROM releases WHERE id = ? AND edition = 'premium' AND status = 'published'").bind(releaseId).first();
  if (!rel) throw new HttpError(404, 'not_found', 'No such release.');
  const bad = await licenseGate(db, JSON.parse(rel.source_ids));
  if (bad.length) { await audit(db, clock, ctx.tenant.id, 'download.blocked_license', { release_id: rel.id, sources: bad }); throw new HttpError(409, 'release_not_licensed', 'This release cannot be distributed: some of its content is not licensed for it.'); }
  const ttl = Math.min(Math.max(1, ttlSeconds | 0), TTL_MAX), token = 'dlt_' + randomToken(32), id = 'dl_' + randomHex(10), now = clock();
  await db.prepare('INSERT INTO downloads(id,tenant_id,api_key_id,release_id,state,token_hash,expires_at,max_uses,usage_event_id,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)')
    .bind(id, ctx.tenant.id, ctx.key.id, rel.id, 'authorized', await sha256Hex(token), Math.floor(now.getTime() / 1000) + ttl, MAX_USES, ctx.usageEventId ?? 'pending', iso(now)).run();
  return { download_id: id, token, url_path: `/v1/dl/${token}`, expires_at: iso(new Date(now.getTime() + ttl * 1000)), sha256: rel.sha256, size: rel.size, mode: 'gateway-stream', resumable: true };
}

function parseRange(h, size) {
  if (!h) return { offset: 0, length: size, partial: false };
  const m = /^bytes=(\d*)-(\d*)$/.exec(h.trim());
  if (!m || (m[1] === '' && m[2] === '')) throw new HttpError(416, 'bad_range', 'Unsupported Range header.', { size });
  let start, end;
  if (m[1] === '') { const n = Number(m[2]); if (n === 0) throw new HttpError(416, 'bad_range', 'Unsatisfiable range.', { size }); start = Math.max(size - n, 0); end = size - 1; }
  else { start = Number(m[1]); end = m[2] === '' ? size - 1 : Math.min(Number(m[2]), size - 1); }
  if (start >= size || start > end) throw new HttpError(416, 'bad_range', 'Unsatisfiable range.', { size });
  return { offset: start, length: end - start + 1, partial: true };
}

// `ctx` is an authenticated context (the SAME key that asked for the authorisation must present the token). `defer` registers work that must finish after the response (waitUntil).
export async function serveDownload(env, db, clock, ctx, eff, request, token, defer) {
  const row = await db.prepare('SELECT * FROM downloads WHERE token_hash = ?').bind(await sha256Hex(token)).first();
  if (!row) throw new HttpError(404, 'not_found', 'No such download.');                              // unknown, malformed and other-tenant tokens are indistinguishable
  if (row.tenant_id !== ctx.tenant.id) throw new HttpError(404, 'not_found', 'No such download.');
  if (!safeEqual(row.api_key_id, ctx.key.id)) { await audit(db, clock, ctx.tenant.id, 'download.shared_link_rejected', { download_id: row.id }); await emit(env, clock, 'download.rejected', { tenant_id: ctx.tenant.id, reason: 'shared_link' }); throw new HttpError(403, 'forbidden', 'This download was issued to a different key.'); }
  if (Math.floor(clock().getTime() / 1000) >= row.expires_at) { await db.prepare("UPDATE downloads SET state = 'expired' WHERE id = ? AND state != 'completed'").bind(row.id).run(); throw new HttpError(410, 'expired', 'This download link has expired: request a new authorisation.'); }
  if (row.state === 'completed') throw new HttpError(410, 'expired', 'This download was already completed.');
  if (row.uses >= row.max_uses) throw new HttpError(429, 'too_many_attempts', 'Too many attempts for this authorisation.');
  const rel = await db.prepare('SELECT * FROM releases WHERE id = ?').bind(row.release_id).first();
  const { offset, length, partial } = parseRange(request.headers.get('range'), rel.size);
  if ((await consume(db, ctx.tenant.id, 'bytes', windows(clock()).month, eff.quotas.bytes_month, length)) === null) throw new HttpError(429, 'bandwidth_exceeded', 'The monthly transfer allowance of your current access was reached.', { scope: 'bytes_month' });
  const fail = async (code) => { await db.prepare('UPDATE downloads SET failed_at = ?, fail_code = ?, last_activity_at = ? WHERE id = ?').bind(iso(clock()), code, iso(clock()), row.id).run().catch(() => {}); await emit(env, clock, 'gateway.incident', { component: 'origin', code }); };
  let obj;
  try { obj = await env.PREMIUM.get(rel.object_key, partial ? { range: { offset, length } } : undefined); }
  catch { await fail('r2_error'); throw new HttpError(503, 'origin_unavailable', 'The file is temporarily unavailable. Try again later.'); }
  if (!obj) { await fail('object_missing'); throw new HttpError(503, 'origin_unavailable', 'The file is temporarily unavailable. Try again later.'); }
  const t0 = Date.now(), now = iso(clock());
  await db.prepare("UPDATE downloads SET uses = uses + 1, state = CASE WHEN state = 'authorized' THEN 'in_progress' ELSE state END, started_at = COALESCE(started_at, ?), last_activity_at = ? WHERE id = ?").bind(now, now, row.id).run();
  let sent = 0, recorded = false;
  const record = () => {                                                // runs on flush (finished) AND on cancel (the client went away): either way the bytes really sent are accounted
    if (recorded) return; recorded = true;
    defer(recordTransfer(db, clock, row.id, rel.size, offset, sent).then(() => (ctx.track ? ctx.track({ channel: 'download', product: 'premium', operation: 'premium.transfer', httpStatus: partial ? 206 : 200, bytes: sent, durationMs: Date.now() - t0 }) : null)));
  };
  const body = obj.body.pipeThrough(new TransformStream({ transform(chunk, c) { sent += chunk.byteLength; c.enqueue(chunk); }, flush() { record(); }, cancel() { record(); } }));
  const headers = { 'content-type': 'application/gzip', 'content-length': String(length), 'accept-ranges': 'bytes', 'cache-control': 'private, no-store', 'x-content-type-options': 'nosniff', etag: `"${rel.sha256}"`, 'x-content-sha256': rel.sha256 };
  if (partial) headers['content-range'] = `bytes ${offset}-${offset + length - 1}/${rel.size}`;
  return new Response(body, { status: partial ? 206 : 200, headers });
}

// Merge [start, end) into a sorted list of disjoint intervals. Pure: the coverage logic is tested on its own against a brute-force model.
export function mergeRange(list, start, end) {
  if (!(end > start)) return list;
  const out = []; let s = start, e = end, placed = false;
  for (const [a, b] of list) {
    if (b < s) out.push([a, b]);
    else if (a > e) { if (!placed) { out.push([s, e]); placed = true; } out.push([a, b]); }
    else { s = Math.min(s, a); e = Math.max(e, b); }
  }
  if (!placed) out.push([s, e]);
  return out;
}
export const covers = (list, size) => list.length === 1 && list[0][0] === 0 && list[0][1] >= size;

// A download is COMPLETED only when the bytes actually delivered (as a union of ranges) cover the whole file. A last fragment on its own is a PARTIAL transfer, not a download.
// Compare-and-set on the stored intervals: two concurrent fragments cannot lose each other's bytes.
export async function recordTransfer(db, clock, id, size, offset, sent) {
  for (let i = 0; i < 6; i++) {
    const row = await db.prepare('SELECT ranges, bytes FROM downloads WHERE id = ?').bind(id).first(); if (!row) return false;
    const next = mergeRange(JSON.parse(row.ranges), offset, offset + sent), done = covers(next, size), at = iso(clock());
    const r = await db.prepare("UPDATE downloads SET ranges = ?, bytes = bytes + ?, last_activity_at = ?, state = CASE WHEN ? = 1 THEN 'completed' ELSE state END, completed_at = CASE WHEN ? = 1 THEN COALESCE(completed_at, ?) ELSE completed_at END WHERE id = ? AND ranges = ?")
      .bind(JSON.stringify(next), sent, at, done ? 1 : 0, done ? 1 : 0, at, id, row.ranges).run();
    if (r.meta.changes === 1) return true;
  }
  return false;
}
// The user-facing state of one download authorisation, derived from facts (never from a redirect or a minted link).
export function downloadState(row, nowSeconds) {
  const covered = JSON.parse(row.ranges).reduce((n, [a, b]) => n + (b - a), 0);
  if (row.state === 'completed') return 'COMPLETED';
  if (row.failed_at && covered === 0) return 'FAILED';
  if (covered > 0) return 'PARTIAL';
  if (row.uses > 0) return nowSeconds >= row.expires_at ? 'UNKNOWN' : 'STARTED';                  // a transfer began but nothing was accounted
  return 'AUTHORIZED';
}
