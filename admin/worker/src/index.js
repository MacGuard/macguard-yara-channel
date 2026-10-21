// MacGuard quarantine service: private API + admin UI assets. The public site never talks to this worker.
import { MAX_BATCH, RELEASE_TAG, atLeast, blobError, highestRole, roleFromRepoPermission, publicStats, validateDecisionRequest, validateSubmission, verifyChain } from './core.js';
import * as store from './store.js';
import * as ops from './ops.js';
import { fetchPublication } from './publication.js';
import { REAUTH, STATE_COOKIE, openToken, resolveGithubAccount, clearCookie, clearStateCookie, createSession, destroySession, effectiveRole, finishLogin, getSession, parseCookies, sessionCookie, startLogin, stateCookie, timingSafeEqual, verifyActionsToken } from './auth.js';

export const HEADERS = {
  'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: https://avatars.githubusercontent.com; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store', 'Cross-Origin-Opener-Policy': 'same-origin', 'Strict-Transport-Security': 'max-age=31536000',
};
const json = (obj, status = 200, extra = {}) => new Response(JSON.stringify(obj), { status, headers: { ...HEADERS, 'Content-Type': 'application/json; charset=utf-8', ...extra } });
const err = (status, message, extra = {}) => json({ error: message, ...extra }, status);
const back = (code, extra = {}) => new Response(null, { status: 302, headers: (() => { const h = new Headers(HEADERS); h.set('Location', `/?e=${code}`); for (const c of extra.cookies || []) h.append('Set-Cookie', c); return h; })() });   // failed browser navigations return to the sign-in screen, which explains them
/** JSON body with a size cap (the platform's own limit is far above what any legitimate request needs). */
async function readJson(request, max) {
  const declared = Number(request.headers.get('Content-Length') || 0); if (declared > max) return { tooLarge: true };
  const text = await request.text(); if (text.length > max) return { tooLarge: true };
  try { return { body: JSON.parse(text) }; } catch { return { body: null }; }
}

export async function handle(request, env, deps) {
  const url = new URL(request.url), now = deps.now(), db = env.DB, method = request.method, path = url.pathname;
  try {
    // ---- pipeline (GitHub Actions OIDC) ----
    if (path.startsWith('/api/pipeline/')) {
      const auth = (request.headers.get('Authorization') || '').replace(/^Bearer /, '');
      const v = await verifyActionsToken(auth, env, deps, now); if (!v.ok) return err(401, v.error);
      const actor = `pipeline:${v.workflow}`;
      // what the signed token says about this execution (not what the request body claims): which run and which attempt of it
      const attempt = (tok, receipt) => ({ token_run_id: String(tok.claims.run_id ?? ''), run_attempt: Number(tok.claims.run_attempt) || null, receipt });
      if (method === 'GET' && path === '/api/pipeline/decisions') return json({ schema: 1, decisions: await store.decisionsMap(db), retest: await store.retestList(db) });
      if (method !== 'POST') return err(405, 'method not allowed');
      const read = await readJson(request, 64_000_000); if (read.tooLarge) return err(413, 'request body too large'); const body = read.body; if (!body) return err(400, 'JSON body required');
      if (path === '/api/pipeline/submit') {
        if (v.workflow !== 'daily.yml') return err(403, 'only the daily review submits candidates');
        if (!Array.isArray(body.candidates) || body.candidates.length > 2000) return err(400, 'candidates (max 2000) required');
        const results = [];
        for (const item of body.candidates) { const bad = validateSubmission(item) || await blobError(item); if (bad) return err(400, `${bad} (${String(item && item.path).slice(0, 80)}); nothing was stored`); }   // validate everything before writing anything
        for (const item of body.candidates) results.push({ sha256: item.sha256, ...(await store.upsertCandidate(db, item, new Date(now * 1000).toISOString(), deps.uuid, { id: String(v.claims.run_id ?? ''), attempt: Number(v.claims.run_attempt) || null })) });
        await store.appendAudit(db, { actor, role: 'PIPELINE', action: 'pipeline.submit', target: String(body.run_id || 'run'), detail: { count: results.length, created: results.filter((r) => r.status === 'created').length, run_url: body.run_url || null, ...attempt(v, results.some((r) => r.status === 'created') ? 'first' : 'idempotent_retry') } }, new Date(now * 1000).toISOString());
        if (Array.isArray(body.retested)) await store.clearRetest(db, body.retested.filter((i) => typeof i === 'string'));
        return json({ schema: 1, results });
      }
      if (path === '/api/pipeline/released' || path === '/api/pipeline/revalidation-failed') {
        if (!Array.isArray(body.hashes) || body.hashes.some((h) => !/^[0-9a-f]{64}$/.test(h))) return err(400, 'hashes required');
        const ev = path.endsWith('released') ? 'released' : 'revalidation_failed';
        if (ev === 'released' && v.workflow !== 'publish.yml') return err(403, 'only the publish workflow marks rules as released');
        if (ev === 'released') {   // never on the word of the request: the Worker reads the public release itself and only an exact (path, SHA-256) listed in its manifest is released
          const tag = String(body.tag || ''); if (!RELEASE_TAG.test(tag)) return err(400, 'a release tag like rules-YYYYMMDD-N is required');
          const pub = await fetchPublication(env, deps, tag); if (!pub.ok) return err(pub.status, `${pub.error}; nothing was changed`);
          const listed = new Set([...pub.files.values()].map((f) => f.sha256));
          return json(await store.markReleased(db, pub, { trigger: 'publish', claimed: body.hashes.length, claimed_not_in_manifest: body.hashes.filter((h) => !listed.has(h)).length, run_url: body.run_url, token_run_id: String(v.claims.run_id ?? ''), run_attempt: Number(v.claims.run_attempt) || null }, actor, new Date(now * 1000).toISOString()));
        }
        return json(await store.pipelineEvent(db, ev, body.hashes, { tag: body.tag, reason: body.reason, run_url: body.run_url, run_id: body.run_id, token: attempt(v, null) }, actor, new Date(now * 1000).toISOString()));
      }
      return err(404, 'unknown pipeline endpoint');
    }

    // ---- public (counts only) ----
    if (method === 'GET' && path === '/public/stats') return json(publicStats(await store.counts(db)), 200, { 'Cache-Control': 'public, max-age=300' });

    // ---- login flow ----
    if (path === '/auth/login' && method === 'GET') {
      await store.purgeExpired(db, now);
      const { location, state } = await startLogin(db, env, now);
      return new Response(null, { status: 302, headers: { ...HEADERS, Location: location, 'Set-Cookie': stateCookie(state) } });   // the state is also bound to this browser
    }
    if (path === '/auth/callback' && method === 'GET') {
      const done = { cookies: [clearStateCookie()] };
      if (url.searchParams.get('error')) return back('cancelled', done);   // the person declined on GitHub
      const bound = parseCookies(request.headers.get('Cookie'))[STATE_COOKIE] || '';
      const given = url.searchParams.get('state') || '';
      if (!given || !timingSafeEqual(bound, given)) return back('state', done);
      const r = await finishLogin(db, env, url.searchParams.get('code'), given, deps, now); if (!r.ok) return back('oauth', done);
      const s = await createSession(db, r.user, now, env);
      await store.appendAudit(db, { actor: r.user.login, role: 'NONE', action: 'session.login', target: 'session', detail: { user_id: r.user.id } }, new Date(now * 1000).toISOString());
      return new Response(null, { status: 302, headers: (() => { const h = new Headers(HEADERS); h.set('Location', '/'); h.append('Set-Cookie', sessionCookie(s.id, s.ttl)); h.append('Set-Cookie', clearStateCookie()); return h; })() });
    }

    // ---- authenticated API ----
    if (path.startsWith('/api/')) {
      const session = await getSession(db, request, now); if (!session) return err(401, 'sign in required', { code: 'signin' });
      const unsafe = method !== 'GET' && method !== 'HEAD';
      const role = await effectiveRole(db, session, env, deps, now, { fresh: unsafe });
      if (role === REAUTH) return json({ error: 'sign in again: your GitHub authorization is no longer valid', code: 'reauth' }, 401, { 'Set-Cookie': clearCookie() });
      if (!role && !((method === 'GET' && path === '/api/me') || (method === 'POST' && path === '/api/logout'))) return err(403, 'your GitHub account has no access to this panel', { code: 'no_access' });   // a person without a role can only see that, and sign out
      const actor = { login: session.login, id: session.user_id, role };
      if (unsafe) {   // CSRF: same-origin request carrying the per-session token
        if (request.headers.get('Origin') !== url.origin) return err(403, 'cross-origin request refused');
        if (!timingSafeEqual(request.headers.get('X-CSRF-Token') || '', session.csrf)) return err(403, 'missing or wrong CSRF token');
      }
      const iso = new Date(now * 1000).toISOString();
      if (method === 'GET' && path === '/api/me' && !role) return json({ error: 'your GitHub account has no access to this panel', code: 'no_access', login: session.login, csrf: session.csrf }, 403);
      if (method === 'GET' && path === '/api/me') return json({ login: session.login, user_id: session.user_id, role, csrf: session.csrf, max_batch: MAX_BATCH });
      if (method === 'POST' && path === '/api/logout') { await destroySession(db, session.id); return json({ ok: true }, 200, { 'Set-Cookie': clearCookie() }); }
      if (method === 'GET' && path === '/api/candidates') {
        return json(await store.listCandidates(db, { state: url.searchParams.get('state') || undefined, q: url.searchParams.get('q') || undefined, source: url.searchParams.get('source') || undefined, page: +url.searchParams.get('page') || 1, pageSize: +url.searchParams.get('pageSize') || 25 }));
      }
      const m = path.match(/^\/api\/candidates\/([0-9a-f-]{8,64})$/);
      if (method === 'GET' && m) {
        const c = await store.getCandidate(db, m[1]); if (!c) return err(404, 'not found');
        if (!(await store.viewedRecently(db, session.login, c.id, iso))) await store.appendAudit(db, { actor: session.login, role, action: 'access.view', target: c.id, detail: { path: c.path, sha256: c.sha256 } }, iso);   // who looked at which rule (once per 10 minutes)
        return json(c);
      }
      if (method === 'GET' && path === '/api/ops/overview') {   // public pipeline records, cached at the edge; any signed-in role may read them
        const key = new Request(`${env.PUBLIC_URL}/__cache/ops-overview-v1`);
        const hit = deps.cache ? await deps.cache.match(key) : null;
        if (hit) { const body = await hit.json(); return json({ ...body, cache: { hit: true, age_s: Math.max(0, now - Math.floor(Date.parse(body.generated_at) / 1000)) } }); }
        const tok = await openToken(env, session.id, session.token); if (!tok) return json({ error: 'sign in again', code: 'reauth' }, 401, { 'Set-Cookie': clearCookie() });
        const data = await ops.loadOverview(env, deps, tok, now * 1000, 30);
        if (deps.cache) await deps.cache.put(key, new Response(JSON.stringify(data), { headers: { 'Content-Type': 'application/json', 'Cache-Control': `max-age=${data.unavailable.length ? 60 : ops.CACHE_SECONDS}` } }));   // a partial answer is kept for a minute only
        return json({ ...data, cache: { hit: false, age_s: 0 } });
      }
      if (method === 'GET' && path === '/api/stats') { const c = await store.counts(db); return json({ counts: c, sources: await store.sourceCounts(db), public: publicStats(c) }); }
      if (method === 'POST' && path === '/api/decisions') {
        const read = await readJson(request, 200_000); if (read.tooLarge) return err(413, 'request body too large');
        const v = validateDecisionRequest(read.body, role); if (!v.ok) return err(v.status, v.error);
        const r = await store.decide(db, v.value, actor, iso);
        const { status, ...rest } = r; return json(rest, status);
      }
      const rt = path.match(/^\/api\/candidates\/([0-9a-f-]{8,64})\/retest$/);
      if (method === 'POST' && rt) { if (!atLeast(role, 'REVIEWER')) return err(403, 'reviewer role required'); return (await store.requestRetest(db, rt[1], actor, iso)) ? json({ ok: true, note: 'the next pipeline run will test it again' }) : err(404, 'not found'); }
      if (method === 'GET' && path === '/api/audit') { if (!atLeast(role, 'REVIEWER')) return err(403, 'reviewer role required'); const fam = url.searchParams.get('family') || ''; return json(await store.auditQuery(db, { limit: Math.min(+url.searchParams.get('limit') || 50, 200), before: +url.searchParams.get('before') || undefined, family: /^[a-z]{1,20}$/.test(fam) ? fam : undefined, actor: (url.searchParams.get('actor') || '').slice(0, 80) || undefined })); }
      if (method === 'GET' && path === '/api/audit/verify') { if (!atLeast(role, 'ADMIN')) return err(403, 'admin role required'); const rows = await store.auditRows(db, 100001); if (rows.length > 100000) return json({ ok: false, error: 'the audit log is longer than one verification pass covers; it was NOT verified' }); return json(await verifyChain(rows)); }
      if (path === '/api/members' || path.startsWith('/api/members/')) {
        if (!atLeast(role, 'ADMIN')) return err(403, 'admin role required');   // enforced here, whatever the UI shows
        const adminToken = () => openToken(env, session.id, session.token);
        if (method === 'GET' && path === '/api/members') return json(await store.listPeople(db, { q: url.searchParams.get('q') || '', status: url.searchParams.get('status') || '', page: +url.searchParams.get('page') || 1, pageSize: +url.searchParams.get('pageSize') || 25 }, roleFromRepoPermission, highestRole));
        if (method === 'GET' && path === '/api/members/lookup') {   // resolves the real GitHub account before anything can be saved
          const login = url.searchParams.get('login') || ''; if (!/^[A-Za-z0-9-]{1,39}$/.test(login)) return err(400, 'a GitHub login is required');
          const tok = await adminToken(); if (!tok) return json({ error: 'sign in again', code: 'reauth' }, 401, { 'Set-Cookie': clearCookie() });
          const r = await resolveGithubAccount(deps, env, tok, { login }); if (!r.ok) return err(r.status, r.error);
          const found = await store.findMember(db, r.account.id, r.account.login);
          return json({ account: { ...r.account, avatar_url: `https://avatars.githubusercontent.com/u/${r.account.id}?s=96` }, current_role: found.kind === 'other-identity' ? null : found.row ? found.row.role : null, legacy_unbound: found.kind === 'legacy', login_held_by_other_id: found.kind === 'other-identity' ? found.row.user_id : null, is_self: r.account.id === session.user_id });
        }
        const hm = path.match(/^\/api\/members\/(\d{1,12})\/history$/);
        if (method === 'GET' && hm) return json({ history: await store.memberHistory(db, +hm[1], url.searchParams.get('login') || '') });
        if (method === 'POST' && path === '/api/members') {
          const read = await readJson(request, 10_000); if (read.tooLarge) return err(413, 'request body too large'); const b = read.body;
          if (!b || !Number.isInteger(b.user_id) || b.user_id < 1 || !['VIEWER', 'REVIEWER', 'ADMIN', null].includes(b.role)) return err(400, 'user_id (the GitHub account id) and role (VIEWER, REVIEWER, ADMIN or null to revoke) required');
          if (typeof b.reason !== 'string' || b.reason.replace(/[\s\p{Cf}]/gu, '').length < 5 || b.reason.length > 2000) return err(400, 'a reason of 5 to 2000 visible characters is required');
          if (b.user_id === session.user_id) return err(400, 'you cannot change your own role');
          const tok = await adminToken(); if (!tok) return json({ error: 'sign in again', code: 'reauth' }, 401, { 'Set-Cookie': clearCookie() });
          const acc = await resolveGithubAccount(deps, env, tok, { id: b.user_id }); if (!acc.ok) return err(acc.status, acc.error);
          if (acc.account.login.toLowerCase() === session.login.toLowerCase()) return err(400, 'you cannot change your own role');
          const permNow = (await db.prepare('SELECT perm FROM sessions WHERE id = ?').bind(session.id).first())?.perm;   // fresh: the write above asked GitHub again
          const r = await store.changeMember(db, { account: acc.account, role: b.role, reason: b.reason.trim(), actor: { login: session.login, id: session.user_id, role }, durableAdmin: permNow === 'admin' }, iso);
          const { status, ...rest } = r; return json(rest, status);
        }
      }
      return err(404, 'unknown endpoint');
    }

    // ---- UI assets ----
    if (method === 'GET' && env.ASSETS) { const r = await env.ASSETS.fetch(request); const h = new Headers(r.headers); for (const [k, v] of Object.entries(HEADERS)) h.set(k, v); return new Response(r.body, { status: r.status, headers: h }); }
    return err(404, 'not found');
  } catch (e) {
    // A failing store or API must never look like an approval.
    if (path.startsWith('/auth/')) return back('unavailable');
    return err(500, 'the service could not complete the request; nothing was changed unless the response says so');
  }
}

export default {
  fetch(request, env) { return handle(request, env, { cache: typeof caches !== 'undefined' ? caches.default : null, fetch: (...a) => fetch(...a), now: () => Math.floor(Date.now() / 1000), uuid: () => crypto.randomUUID() }); },
};
