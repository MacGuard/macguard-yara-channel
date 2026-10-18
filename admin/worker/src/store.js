// Data access for the quarantine service. `db` is a Cloudflare D1 binding (or the test shim with the same API).
import { GENESIS, chainHash, humanTransition, pipelineTransition } from './core.js';

const J = (v) => JSON.stringify(v ?? null);
const parse = (s, d) => { try { return JSON.parse(s); } catch { return d; } };
const row = (r) => r && { ...r, reasons: parse(r.reasons, []), metrics: parse(r.metrics, {}), depends_on: parse(r.depends_on, []), related: parse(r.related, []) };

export async function appendAudit(db, { actor, role, action, target, detail }, now) {
  for (let attempt = 0; attempt < 6; attempt++) {
    const last = await db.prepare('SELECT hash FROM audit ORDER BY seq DESC LIMIT 1').first();
    const prev = last ? last.hash : GENESIS;
    const entry = { at: now, actor, role, action, target, detail: J(detail) };
    const hash = await chainHash(prev, entry);
    try {
      await db.prepare('INSERT INTO audit (at, actor, role, action, target, detail, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?)').bind(now, actor, role, action, target, entry.detail, prev, hash).run();
      return hash;
    } catch (e) { if (!/UNIQUE|constraint/i.test(String(e))) throw e; }   // another writer took this link: re-read and retry
  }
  throw new Error('audit chain is contended');
}
export async function auditRows(db, limit = 200) { return (await db.prepare('SELECT * FROM audit ORDER BY seq ASC LIMIT ?').bind(limit).all()).results; }
export async function auditTail(db, limit = 50) { return (await db.prepare('SELECT seq, at, actor, role, action, target FROM audit ORDER BY seq DESC LIMIT ?').bind(limit).all()).results; }

export async function upsertCandidate(db, item, now, newId) {
  const known = await db.prepare('SELECT * FROM candidates WHERE sha256 = ? AND path = ?').bind(item.sha256, item.path).first();
  if (known) {
    // The same bytes keep their state. Rejected content is never re-opened by the pipeline.
    if (known.state !== 'REJECTED' && known.state !== 'RELEASED') await db.prepare('UPDATE candidates SET reasons=?, metrics=?, updated_at=? WHERE id=?').bind(J(item.reasons), J(item.metrics || {}), now, known.id).run();
    return { id: known.id, status: known.state === 'REJECTED' ? 'known-rejected' : 'known', state: known.state };
  }
  const prev = await db.prepare('SELECT id, state, sha256 FROM candidates WHERE path = ? ORDER BY detected_at DESC LIMIT 1').bind(item.path).first();
  const id = newId();
  const related = prev ? [{ id: prev.id, sha256: prev.sha256, state: prev.state, relation: 'earlier version of the same file' }] : [];
  await db.prepare('INSERT INTO candidates (id, sha256, path, name, source, upstream_commit, bytes, detected_at, state, reasons, metrics, depends_on, related, version, previous_id, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
    .bind(id, item.sha256, item.path, item.path.split('/').pop(), item.source, item.commit || null, item.bytes || 0, now, 'PENDING', J(item.reasons), J(item.metrics || {}), J(item.depends_on || []), J(related), 1, prev ? prev.id : null, now).run();
  if (item.content_b64) {
    const text = new TextDecoder('utf-8', { fatal: false }).decode(Uint8Array.from(atob(item.content_b64), (c) => c.charCodeAt(0)));
    await db.prepare('INSERT OR IGNORE INTO blobs (sha256, content) VALUES (?,?)').bind(item.sha256, text).run();
  }
  return { id, status: 'created', state: 'PENDING', previous: prev ? prev.id : null };
}

export async function listCandidates(db, { state, q, source, page = 1, pageSize = 25 } = {}) {
  const where = [], args = [];
  if (state) { where.push('state = ?'); args.push(state); }
  if (source) { where.push('source = ?'); args.push(source); }
  if (q) { where.push('(path LIKE ? OR sha256 LIKE ?)'); args.push(`%${q.replace(/[%_]/g, '')}%`, `${q.replace(/[%_]/g, '')}%`); }
  const clause = where.length ? 'WHERE ' + where.join(' AND ') : '';
  const total = (await db.prepare(`SELECT COUNT(*) AS n FROM candidates ${clause}`).bind(...args).first()).n;
  const size = Math.min(Math.max(pageSize | 0, 1), 100), off = (Math.max(page | 0, 1) - 1) * size;
  const rows = (await db.prepare(`SELECT * FROM candidates ${clause} ORDER BY detected_at DESC, path ASC LIMIT ? OFFSET ?`).bind(...args, size, off).all()).results.map(row);
  return { total, page, pageSize: size, items: rows };
}
export async function getCandidate(db, id) {
  const c = row(await db.prepare('SELECT * FROM candidates WHERE id = ?').bind(id).first());
  if (!c) return null;
  c.decisions = (await db.prepare('SELECT action, from_state, to_state, candidate_version, actor, role, reason, batch_id, at FROM decisions WHERE candidate_id = ? ORDER BY id ASC').bind(id).all()).results;
  const blob = await db.prepare('SELECT content FROM blobs WHERE sha256 = ?').bind(c.sha256).first();
  c.content = blob ? blob.content : null;
  c.history = (await db.prepare('SELECT id, sha256, state, detected_at, metrics, release_tag FROM candidates WHERE path = ? AND id != ? ORDER BY detected_at DESC LIMIT 20').bind(c.path, id).all()).results.map((h) => ({ ...h, metrics: parse(h.metrics, {}) }));
  return c;
}
export async function counts(db) {
  const out = {}; for (const r of (await db.prepare('SELECT state, COUNT(*) AS n FROM candidates GROUP BY state').all()).results) out[r.state] = r.n; return out;
}

/** Apply one human action to a set of candidates. All-or-nothing on the pre-check; each update is also guarded by version. */
export async function decide(db, req, actor, now) {
  const { action, ids, reason, request_id, expect } = req;
  const placeholders = ids.map(() => '?').join(',');
  const rows = (await db.prepare(`SELECT * FROM candidates WHERE id IN (${placeholders})`).bind(...ids).all()).results;
  if (rows.length !== ids.length) return { status: 404, error: 'some candidates do not exist', missing: ids.filter((i) => !rows.find((r) => r.id === i)) };
  // idempotent replay: the same request id already produced decisions for these candidates
  const done = (await db.prepare(`SELECT candidate_id FROM decisions WHERE request_id = ? AND candidate_id IN (${placeholders})`).bind(request_id, ...ids).all()).results;
  if (done.length === ids.length) return { status: 200, replay: true, applied: [], message: 'this request was already applied' };
  if (done.length) return { status: 409, error: 'request id reused for a different selection' };
  const conflicts = [];
  for (const r of rows) {
    const t = humanTransition(action, r.state);
    if (!t.ok) conflicts.push({ id: r.id, error: t.error });
    else if (r.version !== expect[r.id]) conflicts.push({ id: r.id, error: `changed since you loaded it (version ${r.version}, you saw ${expect[r.id]})` });
  }
  if (conflicts.length) return { status: 409, error: 'nothing was changed', conflicts };
  // One atomic batch: guarded updates, their decision rows, a guard that aborts everything if any update did not apply,
  // and the audit entry. Either every selected candidate changes and is recorded, or nothing does.
  const stmts = [], applied = [];
  for (const r of rows) {
    const to = humanTransition(action, r.state).to;
    stmts.push(db.prepare('UPDATE candidates SET state=?, version=version+1, updated_at=? WHERE id=? AND version=? AND state=?').bind(to, now, r.id, r.version, r.state));
    stmts.push(db.prepare('INSERT INTO decisions (candidate_id, sha256, action, from_state, to_state, candidate_version, actor, actor_id, role, reason, batch_id, request_id, at) SELECT ?,?,?,?,?,?,?,?,?,?,?,?,? WHERE changes() = 1')
      .bind(r.id, r.sha256, action, r.state, to, r.version + 1, actor.login, actor.id, actor.role, reason, ids.length > 1 ? request_id : null, request_id, now));
    applied.push({ id: r.id, sha256: r.sha256, from: r.state, to, version: r.version + 1 });
  }
  const guard = applied.map(() => '(SELECT COUNT(*) FROM candidates WHERE id = ? AND state = ? AND version = ?) = 1').join(' AND ');
  stmts.push(db.prepare(`SELECT CASE WHEN ${guard} THEN 1 ELSE json('not-json') END`).bind(...applied.flatMap((a) => [a.id, a.to, a.version])));
  const last = await db.prepare('SELECT hash FROM audit ORDER BY seq DESC LIMIT 1').first();
  const prev = last ? last.hash : GENESIS;
  const entry = { at: now, actor: actor.login, role: actor.role, action: `decision.${action}`, target: ids.length === 1 ? ids[0] : `batch:${ids.length}`,
    detail: J({ request_id, reason, applied: applied.map((a) => ({ id: a.id, sha256: a.sha256, to: a.to })) }) };
  stmts.push(db.prepare('INSERT INTO audit (at, actor, role, action, target, detail, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?)').bind(entry.at, entry.actor, entry.role, entry.action, entry.target, entry.detail, prev, await chainHash(prev, entry)));
  try { await db.batch(stmts); }
  catch (e) { return { status: 409, error: 'the candidates changed while the decision was being applied; nothing was changed', retry: true }; }
  return { status: 200, applied: applied.map(({ id, sha256, from, to }) => ({ id, sha256, from, to })) };
}

export async function requestRetest(db, id, actor, now) {
  const r = await db.prepare('UPDATE candidates SET retest_requested = 1, updated_at = ? WHERE id = ?').bind(now, id).run();
  if (!r.meta || r.meta.changes !== 1) return false;
  await appendAudit(db, { actor: actor.login, role: actor.role, action: 'retest.requested', target: id, detail: {} }, now); return true;
}

// ---- pipeline side ---------------------------------------------------------------------------
export async function decisionsMap(db) {
  const out = {};
  for (const r of (await db.prepare("SELECT c.sha256, c.state, d.actor, d.at, d.reason FROM candidates c LEFT JOIN decisions d ON d.candidate_id = c.id AND d.id = (SELECT MAX(id) FROM decisions WHERE candidate_id = c.id) WHERE c.state IN ('APPROVED_PENDING_VALIDATION','REJECTED','RELEASED')").all()).results)
    out[r.sha256] = { state: r.state, by: r.actor, at: r.at, reason: r.reason };
  return out;
}
export async function retestList(db) { return (await db.prepare('SELECT id, sha256, path FROM candidates WHERE retest_requested = 1').all()).results; }
export async function clearRetest(db, ids) { for (const id of ids) await db.prepare('UPDATE candidates SET retest_requested = 0 WHERE id = ?').bind(id).run(); }
export async function pipelineEvent(db, event, hashes, info, actor, now) {
  const changed = [], skipped = [];
  for (const sha of hashes) {
    const rows = (await db.prepare('SELECT * FROM candidates WHERE sha256 = ?').bind(sha).all()).results;
    for (const r of rows) {
      const t = pipelineTransition(event, r.state);
      if (!t.ok) { skipped.push({ sha256: sha, reason: t.error }); continue; }
      await db.prepare('UPDATE candidates SET state=?, version=version+1, release_tag=COALESCE(?, release_tag), revalidation_failed=?, updated_at=? WHERE id=?').bind(t.to, info.tag || null, event === 'revalidation_failed' ? (info.reason || 'failed the technical checks') : null, now, r.id).run();
      changed.push({ id: r.id, sha256: sha, to: t.to });
    }
  }
  await appendAudit(db, { actor, role: 'PIPELINE', action: `pipeline.${event}`, target: info.tag || info.run_id || 'run', detail: { changed: changed.length, skipped: skipped.length, run_url: info.run_url || null } }, now);
  return { changed, skipped };
}
export async function recordRun(db, run, now) { await db.prepare('INSERT OR REPLACE INTO pipeline_runs (run_id, workflow, at, summary) VALUES (?,?,?,?)').bind(run.run_id, run.workflow, now, J(run.summary)).run(); }
export async function memberRole(db, login) { const r = await db.prepare('SELECT role FROM members WHERE login = ?').bind(login.toLowerCase()).first(); return r ? r.role : null; }
export async function setMember(db, login, role, grantedBy, now) {
  if (role === null) await db.prepare('DELETE FROM members WHERE login = ?').bind(login.toLowerCase()).run();
  else await db.prepare('INSERT OR REPLACE INTO members (login, role, granted_by, at) VALUES (?,?,?,?)').bind(login.toLowerCase(), role, grantedBy, now).run();
}
export async function listMembers(db) { return (await db.prepare('SELECT login, role, granted_by, at FROM members ORDER BY login').all()).results; }
