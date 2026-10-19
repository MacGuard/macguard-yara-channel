// MacGuard quarantine service: private API + admin UI assets. The public site never talks to this worker.
import { MAX_BATCH, atLeast, blobError, publicStats, validateDecisionRequest, validateSubmission, verifyChain } from './core.js';
import * as store from './store.js';
import { STATE_COOKIE, clearCookie, clearStateCookie, createSession, destroySession, effectiveRole, finishLogin, getSession, parseCookies, sessionCookie, startLogin, stateCookie, timingSafeEqual, verifyActionsToken } from './auth.js';

export const HEADERS = {
  'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store', 'Cross-Origin-Opener-Policy': 'same-origin', 'Strict-Transport-Security': 'max-age=31536000',
};
const json = (obj, status = 200, extra = {}) => new Response(JSON.stringify(obj), { status, headers: { ...HEADERS, 'Content-Type': 'application/json; charset=utf-8', ...extra } });
const err = (status, message, extra = {}) => json({ error: message, ...extra }, status);
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
      if (method === 'GET' && path === '/api/pipeline/decisions') return json({ schema: 1, decisions: await store.decisionsMap(db), retest: await store.retestList(db) });
      if (method !== 'POST') return err(405, 'method not allowed');
      const read = await readJson(request, 64_000_000); if (read.tooLarge) return err(413, 'request body too large'); const body = read.body; if (!body) return err(400, 'JSON body required');
      if (path === '/api/pipeline/submit') {
        if (v.workflow !== 'daily.yml') return err(403, 'only the daily review submits candidates');
        if (!Array.isArray(body.candidates) || body.candidates.length > 2000) return err(400, 'candidates (max 2000) required');
        const results = [];
        for (const item of body.candidates) { const bad = validateSubmission(item) || await blobError(item); if (bad) return err(400, `${bad} (${String(item && item.path).slice(0, 80)}); nothing was stored`); }   // validate everything before writing anything
        for (const item of body.candidates) results.push({ sha256: item.sha256, ...(await store.upsertCandidate(db, item, new Date(now * 1000).toISOString(), deps.uuid)) });
        await store.appendAudit(db, { actor, role: 'PIPELINE', action: 'pipeline.submit', target: String(body.run_id || 'run'), detail: { count: results.length, created: results.filter((r) => r.status === 'created').length, run_url: body.run_url || null } }, new Date(now * 1000).toISOString());
        if (Array.isArray(body.retested)) await store.clearRetest(db, body.retested.filter((i) => typeof i === 'string'));
        return json({ schema: 1, results });
      }
      if (path === '/api/pipeline/released' || path === '/api/pipeline/revalidation-failed') {
        if (!Array.isArray(body.hashes) || body.hashes.some((h) => !/^[0-9a-f]{64}$/.test(h))) return err(400, 'hashes required');
        const ev = path.endsWith('released') ? 'released' : 'revalidation_failed';
        if (ev === 'released' && v.workflow !== 'publish.yml') return err(403, 'only the publish workflow marks rules as released');
        return json(await store.pipelineEvent(db, ev, body.hashes, { tag: body.tag, reason: body.reason, run_url: body.run_url, run_id: body.run_id }, actor, new Date(now * 1000).toISOString()));
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
      const bound = parseCookies(request.headers.get('Cookie'))[STATE_COOKIE] || '';
      const given = url.searchParams.get('state') || '';
      if (!given || !timingSafeEqual(bound, given)) return err(400, 'login state does not belong to this browser');
      const r = await finishLogin(db, env, url.searchParams.get('code'), given, deps, now); if (!r.ok) return err(400, r.error);
      const s = await createSession(db, r.user, now);
      await store.appendAudit(db, { actor: r.user.login, role: 'NONE', action: 'session.login', target: 'session', detail: {} }, new Date(now * 1000).toISOString());
      return new Response(null, { status: 302, headers: (() => { const h = new Headers(HEADERS); h.set('Location', '/'); h.append('Set-Cookie', sessionCookie(s.id, s.ttl)); h.append('Set-Cookie', clearStateCookie()); return h; })() });
    }

    // ---- authenticated API ----
    if (path.startsWith('/api/')) {
      const session = await getSession(db, request, now); if (!session) return err(401, 'sign in required');
      const unsafe = method !== 'GET' && method !== 'HEAD';
      const role = await effectiveRole(db, session, env, deps, now, { fresh: unsafe });
      if (!role) return err(403, 'your GitHub account has no access to this panel');
      const actor = { login: session.login, id: session.user_id, role };
      if (unsafe) {   // CSRF: same-origin request carrying the per-session token
        if (request.headers.get('Origin') !== url.origin) return err(403, 'cross-origin request refused');
        if (!timingSafeEqual(request.headers.get('X-CSRF-Token') || '', session.csrf)) return err(403, 'missing or wrong CSRF token');
      }
      const iso = new Date(now * 1000).toISOString();
      if (method === 'GET' && path === '/api/me') return json({ login: session.login, role, csrf: session.csrf, max_batch: MAX_BATCH });
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
      if (method === 'GET' && path === '/api/stats') return json({ counts: await store.counts(db), public: publicStats(await store.counts(db)) });
      if (method === 'POST' && path === '/api/decisions') {
        const read = await readJson(request, 200_000); if (read.tooLarge) return err(413, 'request body too large');
        const v = validateDecisionRequest(read.body, role); if (!v.ok) return err(v.status, v.error);
        const r = await store.decide(db, v.value, actor, iso);
        const { status, ...rest } = r; return json(rest, status);
      }
      const rt = path.match(/^\/api\/candidates\/([0-9a-f-]{8,64})\/retest$/);
      if (method === 'POST' && rt) { if (!atLeast(role, 'REVIEWER')) return err(403, 'reviewer role required'); return (await store.requestRetest(db, rt[1], actor, iso)) ? json({ ok: true, note: 'the next pipeline run will test it again' }) : err(404, 'not found'); }
      if (method === 'GET' && path === '/api/audit') { if (!atLeast(role, 'REVIEWER')) return err(403, 'reviewer role required'); return json({ entries: await store.auditTail(db, Math.min(+url.searchParams.get('limit') || 50, 200)) }); }
      if (method === 'GET' && path === '/api/audit/verify') { if (!atLeast(role, 'ADMIN')) return err(403, 'admin role required'); const rows = await store.auditRows(db, 100001); if (rows.length > 100000) return json({ ok: false, error: 'the audit log is longer than one verification pass covers; it was NOT verified' }); return json(await verifyChain(rows)); }
      if (path === '/api/members') {
        if (!atLeast(role, 'ADMIN')) return err(403, 'admin role required');
        if (method === 'GET') return json({ members: await store.listMembers(db) });
        if (method === 'POST') {
          const read = await readJson(request, 10_000); if (read.tooLarge) return err(413, 'request body too large'); const b = read.body;
          if (!b || typeof b.login !== 'string' || !/^[A-Za-z0-9-]{1,39}$/.test(b.login) || !['VIEWER', 'REVIEWER', 'ADMIN', null].includes(b.role)) return err(400, 'login and role (VIEWER, REVIEWER, ADMIN or null) required');
          if (b.login.toLowerCase() === session.login.toLowerCase()) return err(400, 'you cannot change your own role');
          await store.setMember(db, b.login, b.role, session.login, iso);
          await store.appendAudit(db, { actor: session.login, role, action: 'member.set', target: b.login.toLowerCase(), detail: { role: b.role } }, iso);
          return json({ ok: true });
        }
      }
      return err(404, 'unknown endpoint');
    }

    // ---- UI assets ----
    if (method === 'GET' && env.ASSETS) { const r = await env.ASSETS.fetch(request); const h = new Headers(r.headers); for (const [k, v] of Object.entries(HEADERS)) h.set(k, v); return new Response(r.body, { status: r.status, headers: h }); }
    return err(404, 'not found');
  } catch (e) {
    // A failing store or API must never look like an approval.
    return err(500, 'the service could not complete the request; nothing was changed unless the response says so');
  }
}

export default {
  fetch(request, env) { return handle(request, env, { fetch: (...a) => fetch(...a), now: () => Math.floor(Date.now() / 1000), uuid: () => crypto.randomUUID() }); },
};
