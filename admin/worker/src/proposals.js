// Source proposals: a person proposes a GitHub rules repository, the Worker verifies public facts about it, an ADMIN authorizes it, and a reviewed pull request
// (opened by a GitHub Actions workflow, never by this Worker) is the only way it can reach config/sources.json. Design: docs/audit/source-proposals-spec.md.
// The Worker holds NO GitHub write credential: every outbound request here is a GET to the constant host api.github.com carrying the admin's own token.
import { GENESIS, SYNTHETIC_SOURCE, atLeast, chainHash, sha256Hex } from './core.js';

export const STATES = ['proposed', 'verified', 'approved', 'rejected', 'pr_open', 'active', 'retired'];
export const TRANSITIONS = { proposed: ['verified', 'rejected', 'proposed'], verified: ['verified', 'rejected', 'approved'], approved: ['pr_open', 'rejected', 'retired'], pr_open: ['active', 'approved', 'retired'], active: ['retired'] };
export const API_HOST = 'api.github.com';
export const LIMITS = { sizeKb: 90_000, entries: 25_000, fileBytes: 1_000_000, youngRepoDays: 90, youngOwnerDays: 180, staleMonths: 24, verifyPerHour: 10, verificationMaxAgeS: 86_400, bodyBytes: 20_000, caps: { repo: 256_000, license: 512_000, commit: 256_000, tree: 5_000_000, user: 64_000 } };
export const enabled = (env) => env.SOURCE_PROPOSALS_ENABLED === '1';   // off unless the owner turns it on: an undeployed or disabled feature answers 404

// ---- syntax of what a person types (the same rules are enforced again by scripts/admission.py before a pull request is built) ----
const bad = (error) => ({ ok: false, error });
const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/, REPO = /^[A-Za-z0-9._-]{1,100}$/, SOURCE_ID = /^[a-z0-9][a-z0-9-]{1,31}$/, PATH = /^[A-Za-z0-9._][A-Za-z0-9._/-]{0,99}$/, REQUEST_ID = /^[A-Za-z0-9_-]{8,80}$/;
/** Only `https://github.com/{owner}/{repo}` (optional `.git`, optional one trailing slash). No URL supplied by a person is ever requested: it is reduced to (owner, repo). */
export function parseRepoUrl(input) {
  if (typeof input !== 'string' || input.length > 200) return bad('a GitHub repository URL is required');
  const m = input.match(/^https:\/\/github\.com\/([A-Za-z0-9-]{1,39})\/([A-Za-z0-9._-]{1,104})\/?$/);   // ASCII only: no userinfo, port, query, fragment, escapes, extra segments, other hosts, other case of the host
  if (!m) return bad('only https://github.com/{owner}/{repo} is accepted');
  const owner = m[1]; let repo = m[2]; if (repo.endsWith('.git')) repo = repo.slice(0, -4);
  if (!OWNER.test(owner) || owner.includes('--')) return bad('not a valid GitHub owner name');
  if (!REPO.test(repo) || repo === '.' || repo === '..' || repo.endsWith('.git')) return bad('not a valid GitHub repository name');
  return { ok: true, owner, repo, full: `${owner}/${repo}` };
}
export function validateSourceId(id) { return typeof id === 'string' && SOURCE_ID.test(id) && id !== SYNTHETIC_SOURCE && !id.endsWith('-') ? { ok: true, value: id } : bad('source id: 2 to 32 characters of a-z, 0-9 and hyphen'); }
export function validatePaths(paths) {
  if (!Array.isArray(paths) || paths.length < 1 || paths.length > 20) return bad('1 to 20 paths are required');
  for (const p of paths) {
    if (typeof p !== 'string' || !PATH.test(p) || p.endsWith('/') || p.includes('//') || p.split('/').some((s) => s === '.' || s === '..')) return bad(`not a valid path: ${String(p).slice(0, 40).replace(/[^\x20-\x7e]/g, '?')}`);
  }
  if (new Set(paths).size !== paths.length) return bad('duplicate paths');
  return { ok: true, value: paths };
}
export const validReason = (r) => typeof r === 'string' && r.replace(/[\s\p{Cf}]/gu, '').length >= 5 && r.length <= 2000;
export function validateCreate(b) {
  if (!b || typeof b !== 'object') return bad('JSON body required');
  if (typeof b.request_id !== 'string' || !REQUEST_ID.test(b.request_id)) return bad('request_id required (8 to 80 characters)');
  const u = parseRepoUrl(b.url); if (!u.ok) return u;
  const id = validateSourceId(b.source_id); if (!id.ok) return id;
  const p = validatePaths(b.paths); if (!p.ok) return p;
  if (!validReason(b.reason)) return bad('a reason of 5 to 2000 visible characters is required');
  return { ok: true, value: { request_id: b.request_id, owner: u.owner, repo: u.repo, full: u.full, source_id: id.value, paths: p.value, reason: b.reason.trim() } };
}

// ---- the outbound guard ----
/** Called immediately before every fetch. The only reachable shape: https://api.github.com/{repos|users}/..., default port, no userinfo, no fragment, no escapes. */
export function assertAllowedUrl(raw) {
  if (typeof raw !== 'string' || !raw.startsWith(`https://${API_HOST}/`) || /[^\x21-\x7e]/.test(raw) || raw.includes('\\')) return { ok: false, klass: 'host' };
  let u; try { u = new URL(raw); } catch { return { ok: false, klass: 'host' }; }
  if (raw !== `https://${API_HOST}${u.pathname}${u.search}`) return { ok: false, klass: 'path' };   // the parser must not have rewritten anything (%2e%2e, dot segments, default port, case)
  if (u.protocol !== 'https:') return { ok: false, klass: 'scheme' };
  if (u.hostname !== API_HOST) return { ok: false, klass: 'host' };
  if (u.port !== '') return { ok: false, klass: 'port' };
  if (u.username || u.password) return { ok: false, klass: 'userinfo' };
  if (u.hash || (u.search !== '' && u.search !== '?recursive=1')) return { ok: false, klass: 'path' };
  if (!/^\/(repos|users)\/[A-Za-z0-9._/-]+$/.test(u.pathname) || u.pathname.includes('..') || u.pathname.includes('//')) return { ok: false, klass: 'path' };
  return { ok: true };
}
const stop = () => (typeof AbortSignal !== 'undefined' && AbortSignal.timeout ? AbortSignal.timeout(10_000) : undefined);
/** One bounded GET. Never follows a redirect, never reads more than `cap` bytes, accepts only JSON. Returns {status,data} or {err}. */
async function ghGet(deps, url, token, cap, trace) {
  const g = assertAllowedUrl(url); if (!g.ok) return { err: 'SSRF_GUARD', klass: g.klass };
  trace.requests.push(url);
  let res;
  try { res = await deps.fetch(url, { method: 'GET', redirect: 'manual', signal: stop(), headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'macguard-admin', ...(token ? { Authorization: `Bearer ${token}` } : {}) } }); } catch { return { err: 'SOURCE_UNAVAILABLE' }; }
  const hd = (k) => (res.headers && res.headers.get ? res.headers.get(k) : null);
  if (hd('x-ratelimit-remaining') !== null) trace.rate_remaining = Number(hd('x-ratelimit-remaining'));
  if (res.status >= 300 && res.status < 400) return { err: 'REDIRECT', status: res.status, location: hd('location') || '' };
  if (res.status === 404) return { status: 404 };
  if (res.status !== 200) return { err: 'SOURCE_UNAVAILABLE', status: res.status };   // 403/429 (rate limit), 5xx, anything else: neither a pass nor a rejection
  if (!/^application\/json\b/i.test(hd('content-type') || '')) return { err: 'UNEXPECTED_CONTENT' };
  if (Number(hd('content-length') || 0) > cap) return { err: 'RESPONSE_TOO_LARGE' };
  let text;
  try {
    if (res.body && res.body.getReader) {
      const rd = res.body.getReader(), parts = []; let n = 0;
      for (;;) { const { done, value } = await rd.read(); if (done) break; n += value.length; if (n > cap) { try { await rd.cancel(); } catch { /* already closed */ } return { err: 'RESPONSE_TOO_LARGE' }; } parts.push(value); }
      const all = new Uint8Array(n); let o = 0; for (const p of parts) { all.set(p, o); o += p.length; } text = new TextDecoder().decode(all);
    } else { text = await res.text(); if (text.length > cap) return { err: 'RESPONSE_TOO_LARGE' }; }
  } catch { return { err: 'SOURCE_UNAVAILABLE' }; }
  try { return { status: 200, data: JSON.parse(text) }; } catch { return { err: 'UNEXPECTED_CONTENT' }; }
}

// ---- verification (facts only; the Worker never fetches or judges rule content) ----
const LICENSES = {   // permissive licences whose text is recognisable; everything else is a legal decision (LIC_NEEDS_LEGAL) shown to the ADMIN. Open decision 4 in the spec: who maintains this list.
  MIT: /permission is hereby granted, free of charge/i, 'Apache-2.0': /apache license[\s\S]{0,40}version 2\.0/i, 'BSD-2-Clause': /redistribution and use in source and binary forms/i,
  'BSD-3-Clause': /redistribution and use in source and binary forms/i, ISC: /permission to use, copy, modify, and\/or distribute/i, 'CC0-1.0': /cc0|creative commons zero/i,
};
const norm = (s) => String(s).toLowerCase().replace(/[-_.]/g, '');
export function distance(a, b) {
  const m = a.length, n = b.length; let prev = Array.from({ length: n + 1 }, (_, j) => j);
  for (let i = 1; i <= m; i++) { const cur = [i]; for (let j = 1; j <= n; j++) cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)); prev = cur; }
  return prev[n];
}
/** Existing sources (config/sources.json plus proposals already in flight) the candidate must not duplicate or imitate. */
export function lookalikes(candidate, existing) {
  const out = []; const full = candidate.full.toLowerCase(), id = candidate.source_id;
  for (const e of existing || []) {
    const er = String(e.repo || '').toLowerCase(), eid = String(e.id || '');
    if (er && er === full) out.push({ code: 'DUPLICATE', severity: 'block', ref: e.id });
    else if (e.repo_id && candidate.repo_id && e.repo_id === candidate.repo_id) out.push({ code: 'DUPLICATE', severity: 'block', ref: e.id });
    else if (er && (norm(er) === norm(full) || distance(er, full) <= 2 || er.split('/')[1] === full.split('/')[1])) out.push({ code: 'LOOKALIKE', severity: 'warn', ref: e.id });
    if (eid && eid === id) out.push({ code: 'DUPLICATE_ID', severity: 'block', ref: e.id });
    else if (eid && (norm(eid) === norm(id) || (eid.length >= 5 && distance(eid, id) <= 1))) out.push({ code: 'LOOKALIKE', severity: 'warn', ref: e.id });
  }
  return out;
}
const days = (iso, nowMs) => (nowMs - Date.parse(iso)) / 86_400_000;
const decodeB64 = (s) => { const bin = atob(String(s).replace(/\s/g, '')); return Uint8Array.from(bin, (c) => c.charCodeAt(0)); };

/** Verify (owner, repo, paths) against GitHub. `candidate` = { owner, repo, full, source_id, paths }, `existing` = [{ id, repo, repo_id? }], `ctx` = { token, nowMs }.
 *  Returns { outcome: 'verified' | 'rejected' | 'unavailable', findings: [{code, severity}], evidence, repo, repo_id, commit, license_spdx, license_sha256 }. Nothing from a response is ever requested. */
export async function verifyRepo(deps, candidate, existing, ctx) {
  const trace = { requests: [], rate_remaining: null }, findings = [], ev = {};
  const add = (code, severity, extra = {}) => findings.push({ code, severity, ...extra });
  const finish = (outcome) => ({ outcome, findings, evidence: { ...ev, requests: trace.requests, rate_remaining: trace.rate_remaining }, repo: ev.full_name || candidate.full, repo_id: ev.repo_id ?? null, commit: ev.commit || null, license_spdx: ev.license_spdx ?? null, license_sha256: ev.license_sha256 || null });
  const fail = (r, redirectOk = false) => {   // maps a transport-level problem; returns the outcome or null when the response is usable
    if (!r.err) return null;
    if (r.err === 'SOURCE_UNAVAILABLE') { add('SOURCE_UNAVAILABLE', 'info'); return finish('unavailable'); }
    if (r.err === 'REDIRECT') { if (redirectOk && r.status === 301 && /^https:\/\/api\.github\.com\/repositories\/[0-9]{1,12}$/.test(r.location)) add('RENAMED', 'block'); else add('REDIRECT_REFUSED', 'block'); return finish('rejected'); }
    if (r.err === 'SSRF_GUARD') add('SSRF_GUARD', 'block', { klass: r.klass }); else add(r.err, 'block');
    return finish('rejected');
  };
  const { owner, repo } = candidate, base = `https://${API_HOST}/repos/${owner}/${repo}`;

  const f1 = await ghGet(deps, base, ctx.token, LIMITS.caps.repo, trace); let out = fail(f1, true); if (out) return out;
  if (f1.status === 404) { add('NOT_FOUND_OR_PRIVATE', 'block'); return finish('rejected'); }
  const r = f1.data;
  if (!r || !Number.isInteger(r.id) || typeof r.full_name !== 'string' || r.full_name.toLowerCase() !== candidate.full.toLowerCase() || !/^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(r.full_name)) { add(r && typeof r.full_name === 'string' && r.full_name.toLowerCase() !== candidate.full.toLowerCase() ? 'RENAMED' : 'UNEXPECTED_CONTENT', 'block'); return finish('rejected'); }
  Object.assign(ev, { repo_id: r.id, full_name: r.full_name, default_branch: typeof r.default_branch === 'string' ? r.default_branch.slice(0, 100) : null, size_kb: Number.isFinite(r.size) ? r.size : null, stars: Number(r.stargazers_count) || 0, forks: Number(r.forks_count) || 0, created_at: r.created_at, pushed_at: r.pushed_at, owner_type: r.owner && r.owner.type, license_spdx: r.license && typeof r.license.spdx_id === 'string' ? r.license.spdx_id : null });
  const canon = { ...candidate, full: r.full_name, repo_id: r.id };
  if (r.private) add('PRIVATE', 'block'); if (r.fork) add('FORK', 'block'); if (r.archived) add('ARCHIVED', 'block'); if (r.disabled) add('DISABLED', 'block');
  if (Number.isFinite(r.size) && r.size > LIMITS.sizeKb) add('TOO_BIG', 'block');
  if (r.created_at && days(r.created_at, ctx.nowMs) < LIMITS.youngRepoDays) add('YOUNG_REPO', 'warn');
  if (r.pushed_at && days(r.pushed_at, ctx.nowMs) > LIMITS.staleMonths * 30.44) add('STALE', 'warn');
  for (const f of lookalikes(canon, existing)) add(f.code, f.severity, { ref: f.ref });
  if (findings.some((f) => f.severity === 'block')) return finish('rejected');   // no further requests for a repository that is already refused

  const f2 = await ghGet(deps, `${base}/license`, ctx.token, LIMITS.caps.license, trace); out = fail(f2); if (out) return out;
  if (f2.status === 404) add('LIC_MISSING', 'block');
  else {
    const l = f2.data, spdx = l && l.license && typeof l.license.spdx_id === 'string' ? l.license.spdx_id : null;
    if (spdx !== ev.license_spdx) add('LIC_MISMATCH', 'block');
    let text = '';
    try { if (typeof (l && l.content) !== 'string') throw new Error('no content'); text = new TextDecoder().decode(decodeB64(l.content)); } catch { add('UNEXPECTED_CONTENT', 'block'); }
    if (text) {
      ev.license_sha256 = await sha256Hex(new TextEncoder().encode(text));   // the same digest scripts/licensing.py computes (UTF-8 with replacement), so the pipeline's policy entry matches
      if (spdx && LICENSES[spdx]) { if (!LICENSES[spdx].test(text)) add('LIC_TEXT_MISMATCH', 'block'); } else add('LIC_NEEDS_LEGAL', 'warn');
    } else if (!findings.some((f) => f.code === 'UNEXPECTED_CONTENT')) add('LIC_MISSING', 'block');
  }
  if (findings.some((f) => f.severity === 'block')) return finish('rejected');

  const f3 = await ghGet(deps, `${base}/commits/HEAD`, ctx.token, LIMITS.caps.commit, trace); out = fail(f3); if (out) return out;
  const sha = f3.status === 200 && f3.data && f3.data.sha;
  if (typeof sha !== 'string' || !/^[0-9a-f]{40}$/.test(sha)) { add('UNEXPECTED_CONTENT', 'block'); return finish('rejected'); }
  ev.commit = sha; if (!(f3.data.commit && f3.data.commit.verification && f3.data.commit.verification.verified)) add('UNVERIFIED_HEAD', 'info');

  const f4 = await ghGet(deps, `${base}/git/trees/${sha}?recursive=1`, ctx.token, LIMITS.caps.tree, trace); out = fail(f4); if (out) return out;
  const tree = f4.status === 200 && f4.data && Array.isArray(f4.data.tree) ? f4.data : null;
  if (!tree) { add('UNEXPECTED_CONTENT', 'block'); return finish('rejected'); }
  if (tree.truncated === true || tree.tree.length > LIMITS.entries) { add('TREE_TRUNCATED', 'block'); return finish('rejected'); }
  const inPaths = (p) => candidate.paths.some((d) => p === d || p.startsWith(`${d}/`));
  let rules = 0, oversize = 0, extraLic = 0;
  for (const e of tree.tree) {
    if (!e || e.type !== 'blob' || typeof e.path !== 'string' || !inPaths(e.path)) continue;
    if (/\.(yar|yara)$/.test(e.path)) { rules++; if (Number(e.size) > LIMITS.fileBytes) oversize++; }
    else if (/^(license|licence|copying)/i.test(e.path.split('/').pop())) extraLic++;
  }
  Object.assign(ev, { rule_files: rules, oversize_skipped: oversize });
  if (!rules) add('NO_RULE_FILES', 'block');
  if (extraLic) add('EXTRA_LICENSE_FILES', 'warn');
  if (findings.some((f) => f.severity === 'block')) return finish('rejected');

  const f5 = await ghGet(deps, `https://${API_HOST}/users/${owner}`, ctx.token, LIMITS.caps.user, trace); out = fail(f5);   // informational only
  if (!out && f5.status === 200 && f5.data && f5.data.created_at) { ev.owner_created_at = f5.data.created_at; if (days(f5.data.created_at, ctx.nowMs) < LIMITS.youngOwnerDays) add('YOUNG_ACCOUNT', 'warn'); }
  return finish('verified');
}

// ---- persistence: every transition is ONE batch, each statement guarded by changes() = 1, and the audit row is written in the same batch ----
const J = (v) => JSON.stringify(v ?? null);
const parse = (s, d) => { try { return JSON.parse(s); } catch { return d; } };
export const view = (r) => r && ({ id: r.id, source_id: r.source_id, repo: r.repo, kind: r.kind, paths: parse(r.paths, []), state: r.state, state_reason: r.state_reason, version: r.version, reason: r.reason, proposer: r.proposer, created_at: r.created_at, updated_at: r.updated_at,
  verified_at: r.verified_at, verified_commit: r.verified_commit, verification: parse(r.verification, null), findings: parse(r.findings, []), acks: parse(r.acks, []), license_spdx: r.license_spdx, license_sha256: r.license_sha256,
  payload: parse(r.payload, null), payload_sha256: r.payload_sha256, approved_by: r.approved_by, approved_at: r.approved_at, pr_number: r.pr_number, pr_url: r.pr_url, pr_branch: r.pr_branch });
export const getRaw = (db, id) => db.prepare('SELECT * FROM source_proposals WHERE id = ?').bind(id).first();
export async function getProposal(db, id) { const r = await getRaw(db, id); return r ? { ...view(r), events: (await db.prepare('SELECT at, actor, role, event, from_state, to_state, version, detail FROM source_proposal_events WHERE proposal_id = ? ORDER BY seq').bind(id).all()).results.map((e) => ({ ...e, detail: parse(e.detail, {}) })) } : null; }
export async function listProposals(db, { state } = {}) {
  const rows = state && STATES.includes(state) ? (await db.prepare('SELECT * FROM source_proposals WHERE state = ? ORDER BY created_at DESC LIMIT 200').bind(state).all()).results : (await db.prepare('SELECT * FROM source_proposals ORDER BY created_at DESC LIMIT 200').all()).results;
  return rows.map(view);
}
/** The only thing the pipeline may see: proposals an ADMIN authorized, with the frozen payload and its digest. */
export async function approvedForPipeline(db) {
  return (await db.prepare("SELECT id, version, payload, payload_sha256 FROM source_proposals WHERE state = 'approved' AND payload IS NOT NULL AND payload_sha256 IS NOT NULL ORDER BY created_at LIMIT 50").all()).results.map((r) => ({ id: r.id, version: r.version, payload: parse(r.payload, null), payload_sha256: r.payload_sha256 }));
}
/** Canonical form of the payload: keys sorted, no whitespace, ASCII only; scripts/admission.py recomputes exactly this digest. */
export function canonicalPayload(p) { const o = {}; for (const k of Object.keys(p).sort()) o[k] = p[k] && typeof p[k] === 'object' && !Array.isArray(p[k]) ? canonicalPayload(p[k]) : p[k]; return o; }
export const payloadDigest = (p) => sha256Hex(new TextEncoder().encode(JSON.stringify(canonicalPayload(p))));

async function auditStmts(db, a, now) {
  const last = await db.prepare('SELECT hash FROM audit ORDER BY seq DESC LIMIT 1').first(), prev = last ? last.hash : GENESIS;
  const entry = { at: now, actor: a.actor, role: a.role, action: a.action, target: a.target, detail: J(a.detail) }, hash = await chainHash(prev, entry);
  return { hash, stmt: db.prepare('INSERT INTO audit (at, actor, role, action, target, detail, prev_hash, hash) SELECT ?,?,?,?,?,?,?,? WHERE changes() = 1').bind(entry.at, entry.actor, entry.role, entry.action, entry.target, entry.detail, prev, hash) };
}
const eventStmt = (db, e, auditHash) => db.prepare('INSERT INTO source_proposal_events (proposal_id, at, actor, actor_id, role, event, from_state, to_state, version, request_id, detail, audit_hash) SELECT ?,?,?,?,?,?,?,?,?,?,?,? WHERE changes() = 1')
  .bind(e.proposal_id, e.at, e.actor, e.actor_id ?? null, e.role, e.event, e.from_state, e.to_state, e.version, e.request_id, J(e.detail), auditHash);
const guardStmt = (db, id, version, requestId) => db.prepare("SELECT CASE WHEN (SELECT COUNT(*) FROM source_proposal_events WHERE proposal_id = ? AND version = ? AND request_id = ?) = 1 THEN 1 ELSE json('not-json') END").bind(id, version, requestId);   // counts what THIS request wrote: a concurrent writer that won leaves it at zero
const conflict = (e) => (/UNIQUE|constraint/i.test(String(e)) ? { status: 409, error: 'another proposal for this repository or source id is already open, or a concurrent change won; nothing was changed', retry: true } : null);

export async function create(db, v, actor, iso, newId) {
  const prior = await db.prepare('SELECT * FROM source_proposals WHERE request_id = ?').bind(v.request_id).first();
  if (prior) return prior.proposer_id === actor.id && prior.repo_lc === v.full.toLowerCase() && prior.source_id === v.source_id ? { status: 200, replay: true, proposal: view(prior) } : { status: 409, error: 'request id reused for a different proposal' };
  const id = newId(), detail = { request_id: v.request_id, repo_lc: v.full.toLowerCase(), source_id: v.source_id, paths: v.paths, reason_len: v.reason.length };
  const au = await auditStmts(db, { actor: actor.login, role: actor.role, action: 'source.proposed', target: id, detail }, iso);
  const stmts = [
    db.prepare("INSERT INTO source_proposals (id, source_id, repo, repo_lc, kind, paths, state, version, reason, proposer, proposer_id, request_id, created_at, updated_at) VALUES (?,?,?,?, 'rules', ?, 'proposed', 1, ?,?,?,?,?,?)")
      .bind(id, v.source_id, v.full, v.full.toLowerCase(), J(v.paths), v.reason, actor.login, actor.id, v.request_id, iso, iso),
    eventStmt(db, { proposal_id: id, at: iso, actor: actor.login, actor_id: actor.id, role: actor.role, event: 'proposed', from_state: null, to_state: 'proposed', version: 1, request_id: v.request_id, detail }, au.hash), au.stmt, guardStmt(db, id, 1, v.request_id)];
  try { await db.batch(stmts); } catch (e) {
    const won = await db.prepare('SELECT * FROM source_proposals WHERE request_id = ?').bind(v.request_id).first();   // an identical request got there first: that is a replay, not a conflict
    if (won && won.proposer_id === actor.id && won.repo_lc === v.full.toLowerCase() && won.source_id === v.source_id) return { status: 200, replay: true, proposal: view(won) };
    return conflict(e) || { status: 500, error: 'the proposal could not be saved; nothing was changed' };
  }
  return { status: 200, proposal: view(await getRaw(db, id)) };
}

/** Move a proposal. `spec` = { from: [states], to, event, action (audit), version (expected), request_id, sets: {column: value}, detail, reason }. Atomic: either the row, its event and its audit entry change, or none. */
export async function transition(db, id, spec, actor, iso) {
  const cur = await getRaw(db, id); if (!cur) return { status: 404, error: 'not found' };
  const seen = await db.prepare('SELECT proposal_id, event FROM source_proposal_events WHERE request_id = ?').bind(spec.request_id).first();
  if (seen) return seen.proposal_id === id && seen.event === spec.event ? { status: 200, replay: true, proposal: view(cur) } : { status: 409, error: 'request id reused for a different action' };
  if (!spec.from.includes(cur.state)) return { status: 409, error: `a proposal in state ${cur.state} cannot do that`, state: cur.state };
  if (spec.version !== undefined && cur.version !== spec.version) return { status: 409, error: `changed since you loaded it (version ${cur.version}, you saw ${spec.version})`, state: cur.state };
  if (!(TRANSITIONS[cur.state] || []).includes(spec.to)) return { status: 409, error: `${cur.state} to ${spec.to} is not allowed`, state: cur.state };
  const next = cur.version + 1, sets = { ...(spec.sets || {}) }, cols = Object.keys(sets);
  if (cols.some((c) => !/^[a-z_0-9]+$/.test(c))) throw new Error('bad column');
  const detail = { request_id: spec.request_id, from: cur.state, to: spec.to, ...(spec.detail || {}) };
  const au = await auditStmts(db, { actor: actor.login, role: actor.role, action: spec.action, target: id, detail }, iso);
  const stmts = [
    db.prepare(`UPDATE source_proposals SET state = ?, state_reason = ?, version = version + 1, updated_at = ?${cols.map((c) => `, ${c} = ?`).join('')} WHERE id = ? AND version = ? AND state = ?`).bind(spec.to, spec.state_reason ?? null, iso, ...cols.map((c) => sets[c]), id, cur.version, cur.state),
    eventStmt(db, { proposal_id: id, at: iso, actor: actor.login, actor_id: actor.id, role: actor.role, event: spec.event, from_state: cur.state, to_state: spec.to, version: next, request_id: spec.request_id, detail }, au.hash), au.stmt, guardStmt(db, id, next, spec.request_id)];
  try { await db.batch(stmts); } catch (e) { return conflict(e) || { status: 409, error: 'the proposal changed while the action was being applied; nothing was changed', retry: true }; }
  return { status: 200, proposal: view(await getRaw(db, id)) };
}

// ---- HTTP surface (called by index.js; returns { status, body } or null when the path is not ours) ----
const none = { status: 404, body: { error: 'unknown endpoint' } };
const reply = (r) => { const { status, ...body } = r; return { status, body }; };
async function existingSources(c, exceptId) {
  const raw = c.env.GITHUB_RAW || 'https://raw.githubusercontent.com'; let list;
  try { const res = await c.deps.fetch(`${raw}/${c.env.REPO}/main/config/sources.json`, { headers: { Accept: 'application/json', 'User-Agent': 'macguard-admin' }, signal: stop() }); if (!res.ok) return null; list = (await res.json()).sources; } catch { return null; }
  if (!Array.isArray(list)) return null;
  const mine = (await c.db.prepare("SELECT source_id AS id, repo, repo_id FROM source_proposals WHERE state IN ('approved','pr_open','active') AND id != ?").bind(exceptId || '').all()).results;
  return [...list.filter((s) => s && typeof s.id === 'string' && typeof s.repo === 'string').map((s) => ({ id: s.id, repo: s.repo })), ...mine];
}
const ack = (a) => Array.isArray(a) && a.every((x) => typeof x === 'string' && /^[A-Z_]{3,30}$/.test(x));

export async function handleApi(c) {
  const { method, path, role, actor, db, iso } = c;
  if (!enabled(c.env)) return none;
  if (method === 'GET' && path === '/api/source-proposals') return { status: 200, body: { proposals: await listProposals(db, { state: c.url.searchParams.get('state') || undefined }), can_propose: atLeast(role, 'REVIEWER'), can_authorize: atLeast(role, 'ADMIN') } };
  const m = path.match(/^\/api\/source-proposals\/([0-9a-f-]{8,64})(?:\/(verify|authorize|reject|retire))?$/);
  if (method === 'GET' && m && !m[2]) { const p = await getProposal(db, m[1]); return p ? { status: 200, body: p } : { status: 404, body: { error: 'not found' } }; }
  const readBody = async () => { const r = await c.readJson(LIMITS.bodyBytes); return r.tooLarge ? { error: { status: 413, body: { error: 'request body too large' } } } : { body: r.body }; };
  if (method === 'POST' && path === '/api/source-proposals') {
    if (!atLeast(role, 'REVIEWER')) return { status: 403, body: { error: 'reviewer role required to propose a source' } };
    const rb = await readBody(); if (rb.error) return rb.error;
    const v = validateCreate(rb.body); if (!v.ok) return { status: 400, body: { error: v.error } };
    return reply(await create(db, v.value, actor, iso, c.deps.uuid));
  }
  if (method !== 'POST' || !m || !m[2]) return null;
  const id = m[1], op = m[2], rb = await readBody(); if (rb.error) return rb.error; const b = rb.body;
  if (!b || typeof b.request_id !== 'string' || !REQUEST_ID.test(b.request_id)) return { status: 400, body: { error: 'request_id required (8 to 80 characters)' } };
  const EVENT = { verify: /^verify\./, authorize: /^approved$/, reject: /^rejected$/, retire: /^retired$/ };
  const replayOf = async () => {   // the same request id again: answered from the first outcome, never applied twice; for another proposal or action it is refused
    const seen = await db.prepare('SELECT proposal_id, event FROM source_proposal_events WHERE request_id = ?').bind(b.request_id).first(); if (!seen) return null;
    return seen.proposal_id === id && EVENT[op].test(seen.event) ? { status: 200, body: { replay: true, proposal: view(await getRaw(db, id)) } } : { status: 409, body: { error: 'request id reused for a different action' } };
  };
  if (op === 'verify') {
    if (!atLeast(role, 'REVIEWER')) return { status: 403, body: { error: 'reviewer role required' } };
    const cur = await getRaw(db, id); if (!cur) return { status: 404, body: { error: 'not found' } };
    if (!['proposed', 'verified'].includes(cur.state)) return { status: 409, body: { error: `a proposal in state ${cur.state} cannot be verified`, state: cur.state } };
    const again = await replayOf(); if (again) return again;
    const since = new Date(Date.parse(iso) - 3_600_000).toISOString();
    if ((await db.prepare("SELECT COUNT(*) AS n FROM source_proposal_events WHERE actor = ? AND event LIKE 'verify.%' AND at > ?").bind(actor.login, since).first()).n >= LIMITS.verifyPerHour) return { status: 429, body: { error: `at most ${LIMITS.verifyPerHour} verifications per hour` } };
    const token = await c.getToken(); if (!token) return { status: 401, body: { error: 'sign in again', code: 'reauth' }, reauth: true };
    const existing = await existingSources(c, id);
    const res = existing ? await verifyRepo(c.deps, { owner: cur.repo.split('/')[0], repo: cur.repo.split('/')[1], full: cur.repo, source_id: cur.source_id, paths: parse(cur.paths, []) }, existing, { token, nowMs: Date.parse(iso) })
      : { outcome: 'unavailable', findings: [{ code: 'SOURCE_UNAVAILABLE', severity: 'info' }], evidence: { requests: [], rate_remaining: null }, repo: cur.repo };
    const codes = res.findings.map((f) => f.code), guard = res.findings.find((f) => f.code === 'SSRF_GUARD');
    if (guard) await c.audit({ actor: actor.login, role, action: 'source.ssrf_guard', target: id, detail: { blocked_url_class: guard.klass } });
    const detail = { outcome: res.outcome, findings: codes, repo_id: res.repo_id ?? null, commit: res.commit ?? null, license_spdx: res.license_spdx ?? null, license_sha256: res.license_sha256 ?? null, requests: res.evidence.requests, rate_remaining: res.evidence.rate_remaining };
    if (res.outcome === 'unavailable') return reply(await transition(db, id, { from: ['proposed', 'verified'], to: cur.state, event: 'verify.unavailable', action: 'source.verify', version: b.expect_version, request_id: b.request_id, detail }, actor, iso));
    const sets = { verification: J(res.evidence), verified_at: iso, verified_commit: res.commit, license_spdx: res.license_spdx, license_sha256: res.license_sha256, findings: J(res.findings.map(({ code, severity, ref }) => ({ code, severity, ...(ref ? { ref } : {}) }))), acks: '[]', repo_id: res.repo_id ?? null };
    if (res.outcome === 'verified') { sets.repo = res.repo; sets.repo_lc = res.repo.toLowerCase(); }
    return reply(await transition(db, id, { from: ['proposed', 'verified'], to: res.outcome === 'verified' ? 'verified' : 'rejected', event: res.outcome === 'verified' ? 'verify.ok' : 'verify.rejected', action: 'source.verify', version: b.expect_version, request_id: b.request_id, state_reason: res.outcome === 'rejected' ? (res.findings.find((f) => f.severity === 'block') || {}).code : null, sets, detail }, actor, iso));
  }
  if (!atLeast(role, 'ADMIN')) return { status: 403, body: { error: 'admin role required' } };   // authorize, reject and retire are ADMIN only, whatever the UI shows
  const again = await replayOf(); if (again) return again;
  if (!validReason(b.reason)) return { status: 400, body: { error: 'a reason of 5 to 2000 visible characters is required' } };
  if (!Number.isInteger(b.expect_version)) return { status: 400, body: { error: 'expect_version required' } };
  if (op === 'reject') return reply(await transition(db, id, { from: ['proposed', 'verified', 'approved'], to: 'rejected', event: 'rejected', action: 'source.rejected', version: b.expect_version, request_id: b.request_id, state_reason: 'rejected_by_admin', detail: { reason_len: b.reason.length } }, actor, iso));
  if (op === 'retire') return reply(await transition(db, id, { from: ['approved', 'pr_open', 'active'], to: 'retired', event: 'retired', action: 'source.retired', version: b.expect_version, request_id: b.request_id, state_reason: 'retired_by_admin', detail: { reason_len: b.reason.length } }, actor, iso));
  // authorize
  const cur = await getRaw(db, id); if (!cur) return { status: 404, body: { error: 'not found' } };
  if (cur.state !== 'verified') return { status: 409, body: { error: `only a verified proposal can be authorized (it is ${cur.state})`, state: cur.state } };
  if (cur.version !== b.expect_version) return { status: 409, body: { error: `changed since you loaded it (version ${cur.version}, you saw ${b.expect_version})` } };
  if (!cur.verified_at || Date.parse(iso) - Date.parse(cur.verified_at) > LIMITS.verificationMaxAgeS * 1000) return { status: 409, body: { error: 'the verification is older than 24 hours: verify again', code: 'stale_verification' } };
  const found = parse(cur.findings, []), warn = found.filter((f) => f.severity === 'warn').map((f) => f.code);
  if (found.some((f) => f.severity === 'block')) return { status: 409, body: { error: 'a blocking finding cannot be authorized' } };
  if (!ack(b.acks) || !warn.every((w) => b.acks.includes(w))) return { status: 409, body: { error: 'every warning must be acknowledged', missing: warn.filter((w) => !Array.isArray(b.acks) || !b.acks.includes(w)) } };
  if (b.confirm_repo !== cur.repo) return { status: 400, body: { error: 'type the repository as owner/repo to confirm' } };
  const payload = { admission: 'probation', id: cur.source_id, kind: 'rules', license: { sha256: cur.license_sha256, spdx: cur.license_spdx }, paths: parse(cur.paths, []), repo: cur.repo, verified_commit: cur.verified_commit };
  const digest = await payloadDigest(payload);
  return reply(await transition(db, id, { from: ['verified'], to: 'approved', event: 'approved', action: 'source.approved', version: b.expect_version, request_id: b.request_id,
    sets: { payload: JSON.stringify(canonicalPayload(payload)), payload_sha256: digest, acks: J(b.acks), approved_by: actor.login, approved_by_id: actor.id, approved_at: iso }, detail: { payload_sha256: digest, acks: b.acks, confirm_repo: b.confirm_repo, reason_len: b.reason.length, verification_age_s: Math.round((Date.parse(iso) - Date.parse(cur.verified_at)) / 1000) } }, actor, iso));
}

/** GET /api/pipeline/source-proposals (OIDC, workflow source-proposals.yml on main): only the proposals an ADMIN authorized. */
export async function handlePipeline(c) {
  if (!enabled(c.env)) return none;
  if (c.workflow !== 'source-proposals.yml') return { status: 403, body: { error: 'only the source-proposals workflow reads proposals' } };
  return { status: 200, body: { schema: 1, proposals: await approvedForPipeline(c.db) } };
}

/** POST /api/pipeline/source-proposals/{id}/pr and /api/pipeline/source-proposals/sync (OIDC, workflow source-proposals.yml on main).
 *  The Worker never takes the word of the workflow about a merge: it reads config/sources.json of main itself and requires the entry to equal the frozen payload. */
export async function handlePipelinePost(c) {
  if (!enabled(c.env)) return none;
  if (c.workflow !== 'source-proposals.yml') return { status: 403, body: { error: 'only the source-proposals workflow reports on proposals' } };
  const b = c.body || {}, actor = { login: `pipeline:${c.workflow}`, id: null, role: 'PIPELINE' }, run = { token_run_id: String(c.claims.run_id ?? ''), run_attempt: Number(c.claims.run_attempt) || null };
  const pr = c.path.match(/^\/api\/pipeline\/source-proposals\/([0-9a-f-]{8,64})\/pr$/);
  if (pr) {
    const cur = await getRaw(c.db, pr[1]); if (!cur) return { status: 404, body: { error: 'not found' } };
    const branch = `proposal/${cur.source_id}-${String(cur.payload_sha256 || '').slice(0, 8)}`;
    if (!Number.isInteger(b.pr_number) || b.pr_number < 1 || b.pr_number > 10_000_000) return { status: 400, body: { error: 'pr_number required' } };
    if (b.branch !== branch || b.pr_url !== `https://github.com/${c.env.REPO}/pull/${b.pr_number}` || !/^[0-9a-f]{40}$/.test(String(b.head_sha || ''))) return { status: 400, body: { error: 'branch, pr_url or head_sha do not match this proposal' } };
    if (b.payload_sha256 !== cur.payload_sha256) return { status: 409, body: { error: 'the proposal changed since the payload was read' } };
    if (cur.state === 'pr_open' && cur.pr_number !== b.pr_number) return { status: 409, body: { error: 'another pull request is already recorded for this proposal' } };
    return reply(await transition(c.db, cur.id, { from: ['approved'], to: 'pr_open', event: 'pr.opened', action: 'source.pr_opened', request_id: `pr_${cur.id}_${b.pr_number}`, sets: { pr_number: b.pr_number, pr_url: b.pr_url, pr_branch: branch },
      detail: { pr_number: b.pr_number, pr_url: b.pr_url, branch, head_sha: b.head_sha, payload_sha256: cur.payload_sha256, ...run } }, actor, c.iso));
  }
  if (c.path === '/api/pipeline/source-proposals/sync') {
    if (typeof b.branch !== 'string' || !/^proposal\/[a-z0-9-]{2,32}-[0-9a-f]{8}$/.test(b.branch) || !['merged', 'closed_unmerged'].includes(b.outcome)) return { status: 400, body: { error: 'branch and outcome (merged | closed_unmerged) required' } };
    const cur = await c.db.prepare("SELECT * FROM source_proposals WHERE pr_branch = ? AND state = 'pr_open'").bind(b.branch).first(); if (!cur) return { status: 404, body: { error: 'no open pull request is recorded for that branch' } };
    if (b.outcome === 'closed_unmerged') return reply(await transition(c.db, cur.id, { from: ['pr_open'], to: 'approved', event: 'pr.closed', action: 'source.pr_closed', request_id: `close_${cur.id}_${cur.pr_number}`, sets: { pr_number: null, pr_url: null, pr_branch: null }, detail: { pr_number: cur.pr_number, outcome: 'closed_unmerged', ...run } }, actor, c.iso));
    const raw = c.env.GITHUB_RAW || 'https://raw.githubusercontent.com'; let list;
    try { const res = await c.deps.fetch(`${raw}/${c.env.REPO}/main/config/sources.json`, { headers: { Accept: 'application/json', 'User-Agent': 'macguard-admin' }, signal: stop() }); if (!res.ok) return { status: 502, body: { error: 'config/sources.json of main could not be read; nothing was changed' } }; list = (await res.json()).sources; } catch { return { status: 502, body: { error: 'config/sources.json of main could not be read; nothing was changed' } }; }
    const want = parse(cur.payload, {}), entry = Array.isArray(list) ? list.find((s) => s && s.id === want.id) : null;
    const same = entry && typeof entry.repo === 'string' && entry.repo.toLowerCase() === want.repo.toLowerCase() && entry.kind === 'rules' && J(entry.paths) === J(want.paths) && entry.admission === want.admission;
    if (!same) return { status: 409, body: { error: 'main does not contain this proposal exactly as authorized; nothing was changed' } };
    const entryDigest = await sha256Hex(new TextEncoder().encode(JSON.stringify(canonicalPayload(entry))));
    return reply(await transition(c.db, cur.id, { from: ['pr_open'], to: 'active', event: 'activated', action: 'source.activated', request_id: `act_${cur.id}`, detail: { pr_number: cur.pr_number, main_entry_sha256: entryDigest, equal: true, ...run } }, actor, c.iso));
  }
  return none;
}
