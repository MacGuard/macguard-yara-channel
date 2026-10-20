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
/** True when this actor already looked at this candidate in the last `seconds`: views are audited once per window, not per request. */
export async function viewedRecently(db, actor, target, nowIso, seconds = 600) {
  const since = new Date(Date.parse(nowIso) - seconds * 1000).toISOString();
  return !!(await db.prepare("SELECT 1 AS x FROM audit WHERE action = 'access.view' AND actor = ? AND target = ? AND at > ? LIMIT 1").bind(actor, target, since).first());
}
export async function purgeExpired(db, now) {
  await db.prepare('DELETE FROM oauth_states WHERE expires_at < ?').bind(now).run();
  await db.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(now).run();
}
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
  const where = ['archived_at IS NULL'], args = [];
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
  const out = {}; for (const r of (await db.prepare('SELECT state, COUNT(*) AS n FROM candidates WHERE archived_at IS NULL GROUP BY state').all()).results) out[r.state] = r.n; return out;
}

/** Apply one human action to a set of candidates. All-or-nothing on the pre-check; each update is also guarded by version. */
export async function decide(db, req, actor, now) {
  const { action, ids, reason, request_id, expect } = req;
  const rows = [];
  for (let i = 0; i < ids.length; i += 50) {   // D1 limits bound parameters per statement
    const part = ids.slice(i, i + 50);
    rows.push(...(await db.prepare(`SELECT * FROM candidates WHERE id IN (${part.map(() => '?').join(',')})`).bind(...part).all()).results);
  }
  if (rows.length !== ids.length) return { status: 404, error: 'some candidates do not exist', missing: ids.filter((i) => !rows.find((r) => r.id === i)) };
  // idempotent replay: the same request id already produced decisions for these candidates
  const wanted = new Set(ids);
  const done = (await db.prepare('SELECT candidate_id, action FROM decisions WHERE request_id = ?').bind(request_id).all()).results;
  if (done.length) {
    if (done.length === ids.length && done.every((d) => wanted.has(d.candidate_id) && d.action === action)) return { status: 200, replay: true, applied: [], message: 'this request was already applied' };
    return { status: 409, error: 'request id reused for a different selection or action' };
  }
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
  // The guard counts the decision rows THIS request wrote: a concurrent writer that reached the same state first leaves ours at zero,
  // so no audit entry can claim a decision that did not take effect.
  stmts.push(db.prepare(`SELECT CASE WHEN (SELECT COUNT(*) FROM decisions WHERE request_id = ?) = ${applied.length} THEN 1 ELSE json('not-json') END`).bind(request_id));
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
  // The pipeline asks by content hash, but a hash can sit at several paths. A human rejection of ANY of them wins, so identical bytes
  // approved or released elsewhere can never override it; otherwise the result must not depend on row order.
  const out = {};
  for (const r of (await db.prepare("SELECT c.sha256, c.state, d.actor, d.at, d.reason FROM candidates c LEFT JOIN decisions d ON d.candidate_id = c.id AND d.id = (SELECT MAX(id) FROM decisions WHERE candidate_id = c.id) WHERE c.archived_at IS NULL AND c.state IN ('APPROVED_PENDING_VALIDATION','REJECTED','RELEASED') ORDER BY c.sha256, c.path").all()).results) {
    if (out[r.sha256] && !(r.state === 'REJECTED' && out[r.sha256].state !== 'REJECTED')) continue;   // first row wins, except that a rejection replaces an approval
    out[r.sha256] = { state: r.state, by: r.actor, at: r.at, reason: r.reason };
  }
  return out;
}
export async function retestList(db) { return (await db.prepare('SELECT id, sha256, path FROM candidates WHERE retest_requested = 1 AND archived_at IS NULL').all()).results; }
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
/** A grant is honoured only for the account it was made to. A row bound to an id never matches another account that now carries the same login
 *  (renames and re-registration); a legacy row without an id matches by name and is reported as unbound until an ADMIN resolves it. */
export async function memberRole(db, login, userId) {
  const byId = userId == null ? null : await db.prepare('SELECT role FROM members WHERE user_id = ?').bind(userId).first();
  if (byId) return byId.role;
  const legacy = await db.prepare('SELECT role FROM members WHERE login = ? AND user_id IS NULL').bind(String(login).toLowerCase()).first();
  return legacy ? legacy.role : null;
}
const memberRow = (r) => r && { login: r.login, user_id: r.user_id ?? null, role: r.role, granted_by: r.granted_by, at: r.at, updated_at: r.updated_at || r.at };
export async function findMember(db, userId, login) {
  const byId = await db.prepare('SELECT * FROM members WHERE user_id = ?').bind(userId).first();
  if (byId) return { row: memberRow(byId), kind: 'bound' };
  const byLogin = await db.prepare('SELECT * FROM members WHERE login = ?').bind(String(login).toLowerCase()).first();
  if (!byLogin) return { row: null, kind: 'none' };
  return byLogin.user_id == null ? { row: memberRow(byLogin), kind: 'legacy' } : { row: memberRow(byLogin), kind: 'other-identity' };
}

/** Grant, change or revoke (role === null) one member, atomically with its audit entry. The caller has already authorized the actor and resolved the
 *  account from GitHub by id. `durableAdmin` says the actor is a GitHub repository admin, who cannot be removed from this panel. */
export async function changeMember(db, { account, role, reason, actor, durableAdmin }, now) {
  const found = await findMember(db, account.id, account.login);
  if (found.kind === 'other-identity') return { status: 409, error: `the login ${account.login} is held by a different GitHub account (id ${found.row.user_id}); revoke that grant first` };
  const from = found.row ? found.row.role : null;
  if (from === role) return { status: 409, error: role === null ? 'this account has no explicit grant to revoke' : 'the account already has this role' };
  const stmts = [];
  if (from === 'ADMIN' && role !== 'ADMIN' && !durableAdmin) {   // never leave the panel without an administrator who cannot be removed from it
    stmts.push(db.prepare(`SELECT CASE WHEN (SELECT COUNT(*) FROM members WHERE role = 'ADMIN' AND COALESCE(user_id, -1) != ? AND login != ?) >= 1 THEN 1 ELSE json('not-json') END`).bind(account.id, account.login.toLowerCase()));
  }
  const key = found.kind === 'legacy' ? ['login = ? AND user_id IS NULL', found.row.login] : ['user_id = ?', account.id];
  if (role === null) stmts.push(db.prepare(`DELETE FROM members WHERE ${key[0]}`).bind(key[1]));
  else if (found.row) stmts.push(db.prepare(`UPDATE members SET login = ?, role = ?, user_id = ?, updated_at = ? WHERE ${key[0]}`).bind(account.login.toLowerCase(), role, account.id, now, key[1]));
  else stmts.push(db.prepare('INSERT INTO members (login, role, granted_by, at, user_id, updated_at) VALUES (?,?,?,?,?,?)').bind(account.login.toLowerCase(), role, actor.login, now, account.id, now));
  const last = await db.prepare('SELECT hash FROM audit ORDER BY seq DESC LIMIT 1').first(); const prev = last ? last.hash : GENESIS;
  const entry = { at: now, actor: actor.login, role: actor.role, action: 'member.set', target: `user:${account.id}`,
    detail: J({ user_id: account.id, login: account.login, from_role: from, to_role: role, reason, actor_id: actor.id, bound_legacy: found.kind === 'legacy' }) };
  stmts.push(db.prepare('INSERT INTO audit (at, actor, role, action, target, detail, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?)').bind(entry.at, entry.actor, entry.role, entry.action, entry.target, entry.detail, prev, await chainHash(prev, entry)));
  try { await db.batch(stmts); } catch (e) { return { status: 409, error: from === 'ADMIN' && role !== 'ADMIN' && !durableAdmin ? 'this would remove the last administrator who cannot be removed from the panel; nothing was changed' : 'the membership changed while this was being applied; nothing was changed', retry: true }; }
  return { status: 200, user_id: account.id, login: account.login, from_role: from, to_role: role };
}

/** Everyone the panel knows about, merged by immutable id: explicit grants, people who signed in (audit), live sessions (their last GitHub permission) and revoked grants. */
export async function listPeople(db, { q = '', status = '', page = 1, pageSize = 25 } = {}, roleFromPerm, highest) {
  const people = new Map(), byLogin = new Map();
  const at = (login, id) => {
    const lk = String(login).toLowerCase(); let key = id != null ? `id:${id}` : byLogin.get(lk) || `login:${lk}`;
    if (id != null && byLogin.get(lk) && byLogin.get(lk) !== key) { const old = people.get(byLogin.get(lk)); if (old) { people.delete(byLogin.get(lk)); people.set(key, { ...(people.get(key) || {}), ...old }); } }
    if (!people.has(key)) people.set(key, { login: lk, user_id: id ?? null, manual_role: null, bound: true, last_login: null, logins: 0, repo_perm: null, perm_at: null, created_at: null, updated_at: null, granted_by: null, revoked_at: null });
    const p = people.get(key); if (id != null) p.user_id = id; p.login = lk; byLogin.set(lk, key); return p;
  };
  for (const m of (await db.prepare('SELECT * FROM members').all()).results) { const p = at(m.login, m.user_id); p.manual_role = m.role; p.bound = m.user_id != null; p.created_at = m.at; p.updated_at = m.updated_at || m.at; p.granted_by = m.granted_by; }
  for (const l of (await db.prepare("SELECT actor, MAX(at) AS last, COUNT(*) AS n, MAX(json_extract(detail, '$.user_id')) AS uid FROM audit WHERE action = 'session.login' GROUP BY actor").all()).results) { const p = at(l.actor, l.uid ?? null); p.last_login = l.last; p.logins = l.n; }
  for (const s of (await db.prepare('SELECT login, user_id, perm, perm_at FROM sessions ORDER BY perm_at ASC').all()).results) { const p = at(s.login, s.user_id); if (s.perm) { p.repo_perm = s.perm; p.perm_at = s.perm_at; } }
  const changes = new Map();   // latest member.set per account: a revoked grant is a grant whose last change set the role to null and that has no row now
  for (const a of (await db.prepare("SELECT at, detail FROM audit WHERE action = 'member.set' ORDER BY seq ASC").all()).results) { let d = {}; try { d = JSON.parse(a.detail); } catch {} if (d.login) changes.set(d.user_id != null ? `id:${d.user_id}` : `login:${String(d.login).toLowerCase()}`, { at: a.at, to: d.to_role, id: d.user_id ?? null, login: d.login }); }
  for (const c of changes.values()) { const p = at(c.login, c.id); if (c.to === null && p.manual_role === null) p.revoked_at = c.at; }
  let out = [...people.values()].map((p) => {
    const repo_role = p.repo_perm ? roleFromPerm(p.repo_perm) : null, effective = highest(repo_role, p.manual_role);
    const origin = repo_role && p.manual_role ? 'both' : repo_role ? 'repo' : p.manual_role ? 'manual' : 'none';
    const state = effective ? (p.manual_role && !p.bound ? 'unbound' : 'authorized') : p.revoked_at ? 'revoked' : 'unauthorized';
    return { user_id: p.user_id, login: p.login, effective_role: effective || 'NONE', origin, repo_role, repo_perm: p.repo_perm, repo_checked_at: p.perm_at, manual_role: p.manual_role, state, bound: p.bound, granted_by: p.granted_by, created_at: p.created_at, updated_at: p.updated_at, revoked_at: p.revoked_at, last_login: p.last_login, logins: p.logins };
  });
  const counts = { authorized: 0, unauthorized: 0, revoked: 0, unbound: 0 }; for (const p of out) counts[p.state] = (counts[p.state] || 0) + 1;
  if (status) out = out.filter((p) => p.state === status);
  if (q) { const n = q.toLowerCase().replace(/^@/, ''); out = out.filter((p) => p.login.includes(n) || String(p.user_id) === n); }
  out.sort((a, b) => (b.last_login || '').localeCompare(a.last_login || '') || a.login.localeCompare(b.login));
  const size = Math.min(Math.max(pageSize | 0, 1), 100), pg = Math.max(page | 0, 1);
  return { total: out.length, page: pg, pageSize: size, counts, items: out.slice((pg - 1) * size, pg * size) };
}
export async function memberHistory(db, userId, login) {
  const rows = (await db.prepare("SELECT seq, at, actor, role, detail FROM audit WHERE action = 'member.set' AND (target = ? OR target = ?) ORDER BY seq DESC LIMIT 100").bind(`user:${userId}`, String(login).toLowerCase()).all()).results;
  return rows.map((r) => { let d = {}; try { d = JSON.parse(r.detail); } catch {} return { seq: r.seq, at: r.at, actor: r.actor, actor_role: r.role, from_role: d.from_role ?? null, to_role: d.to_role ?? null, reason: d.reason || null }; });
}
export async function listMembers(db) { return (await db.prepare('SELECT login, user_id, role, granted_by, at, updated_at FROM members ORDER BY login').all()).results; }
