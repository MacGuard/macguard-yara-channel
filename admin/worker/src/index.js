// MacGuard quarantine service: private API + admin UI assets. The public site never talks to this worker.
import { MAX_BATCH, RELEASE_TAG, reconcilePublished, PUBLISHED_STATUS, blobError, roleFromRepoPermission, publicStats, validateDecisionRequest, validateSubmission, verifyChain } from './core.js';
import * as store from './store.js';
import { verifyAuditChain, listAnchors } from './anchor.js';
import * as ops from './ops.js';
import * as restore from './restore.js';
import * as proposals from './proposals.js';
import { fetchPublication } from './publication.js';
import * as policies from './policies.js';
import * as publishedRules from './published_rules.js';
import * as intelFamilies from './intel_families.js';
import * as intelData from './intel_data.js';
import * as intelDecisions from './intel_decisions.js';
import * as sourceRequests from './source_requests.js';
import * as approvals from './approvals.js';
import { can, permissionFor, primaryRole, permissionsOf, matrix, familyPermission, isCritical, GRANTABLE_ROLES } from './rbac.js';   // policy: persistent administrative withdrawals (migration 0003)
import { REAUTH, STATE_COOKIE, openToken, resolveGithubAccount, clearCookie, clearStateCookie, createSession, destroySession, effectiveRoles, finishLogin, getSession, parseCookies, sessionCookie, startLogin, stateCookie, timingSafeEqual, verifyActionsToken } from './auth.js';

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
      if (method === 'GET' && path === '/api/pipeline/source-proposals') { const r = await proposals.handlePipeline({ env, db, workflow: v.workflow }); return json(r.body, r.status); }   // source proposals: only what an ADMIN authorized
      if (method === 'GET' && path === '/api/pipeline/policy-snapshot') return json(await policies.snapshot(db, new Date(now * 1000).toISOString()));   // policy: daily.yml and publish.yml only (the allow-list of verifyActionsToken)
      if (method === 'GET' && path === '/api/pipeline/intel-approvals') {   // publish.yml only: what a future per-family, per-source package build may read. Read-only; publishes nothing.
        if (v.workflow !== 'publish.yml') return err(403, 'only the publication workflow reads approvals');
        if (!env.INTEL) return json(intelData.unavailable().body, 503);
        const fam = url.searchParams.get('family'), src = url.searchParams.get('source'); if ((fam && !intelData.FAMILIES.includes(fam)) || (src && !/^[a-z0-9][a-z0-9_-]{1,40}$/.test(src))) return err(400, 'invalid filter');
        try { return json(await intelDecisions.approvalsSnapshot(env.INTEL, { family: fam, source: src })); } catch (e) { if (intelData.overlayMissing(e)) return err(503, 'migration INTEL 0002 has not been applied to the intelligence database yet', { code: 'migration_pending' }); throw e; }
      }
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
          const released = await store.markReleased(db, pub, { trigger: 'publish', claimed: body.hashes.length, claimed_not_in_manifest: body.hashes.filter((h) => !listed.has(h)).length, run_url: body.run_url, token_run_id: String(v.claims.run_id ?? ''), run_attempt: Number(v.claims.run_attempt) || null }, actor, new Date(now * 1000).toISOString());
          // policy: confirm withdrawals on this same verified evidence. Never changes what markReleased did; a failure here leaves the withdrawal pending (ADMIN reconcile redoes it).
          let confirmation = null; try { confirmation = await policies.reconcilePolicies(db, pub, { trigger: 'publish', run_url: body.run_url, token_run_id: String(v.claims.run_id ?? ''), run_attempt: Number(v.claims.run_attempt) || null }, actor, new Date(now * 1000).toISOString()); } catch { confirmation = { error: 'the policy confirmation could not be recorded; withdrawals stay pending' }; }
          return json(confirmation && (confirmation.recorded || confirmation.error) ? { ...released, policies: confirmation } : released);
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
      const found = await effectiveRoles(db, session, env, deps, now, { fresh: unsafe }), roles = Array.isArray(found) ? found : [], role = primaryRole(roles);
      if (found === REAUTH) return json({ error: 'sign in again: your GitHub authorization is no longer valid', code: 'reauth' }, 401, { 'Set-Cookie': clearCookie() });
      if (!role && !((method === 'GET' && path === '/api/me') || (method === 'POST' && path === '/api/logout'))) return err(403, 'your GitHub account has no access to this panel', { code: 'no_access' });   // a person without a role can only see that, and sign out
      const actor = { login: session.login, id: session.user_id, role, roles };
      if (unsafe) {   // CSRF: same-origin request carrying the per-session token
        if (request.headers.get('Origin') !== url.origin) return err(403, 'cross-origin request refused');
        if (!timingSafeEqual(request.headers.get('X-CSRF-Token') || '', session.csrf)) return err(403, 'missing or wrong CSRF token');
      }
      const iso = new Date(now * 1000).toISOString();
      if (method === 'GET' && path === '/api/me' && !role) return json({ error: 'your GitHub account has no access to this panel', code: 'no_access', login: session.login, csrf: session.csrf }, 403);
      if (method === 'GET' && path === '/api/me') return json({ login: session.login, user_id: session.user_id, role, roles, permissions: permissionsOf(roles), csrf: session.csrf, max_batch: MAX_BATCH });
      if (method === 'POST' && path === '/api/logout') { await destroySession(db, session.id); return json({ ok: true }, 200, { 'Set-Cookie': clearCookie() }); }
      // ---- authorization: one route table, default deny. An unknown route is refused here and never reaches a handler; every known route names the permission it needs. ----
      const need = permissionFor(method, path);
      if (!need) return err(404, 'unknown endpoint');
      if (need !== 'INTEL_BY_FAMILY' && !can(roles, need)) {
        if (unsafe) await store.appendAudit(db, { actor: session.login, role, action: 'authz.denied', target: path.slice(0, 120), detail: { method, permission: need } }, iso).catch(() => {});   // failed attempts are kept
        return err(403, `the permission ${need} is required`, { code: 'forbidden', permission: need });
      }
      if (unsafe && (need === 'APPROVAL_BY_OP' || (need !== 'INTEL_BY_FAMILY' && isCritical(need)))) {   // critical operations: GitHub was asked again just now (fresh), and the sign-in itself must be recent
        const max = Number(env.CRITICAL_REAUTH_S || 1800);
        if (now - session.created_at > max) return json({ error: 'this operation needs a recent sign-in: sign in again', code: 'reauth_required', permission: need }, 401);
      }
      if (method === 'GET' && path === '/api/permissions') return json({ schema: 1, you: { roles, permissions: permissionsOf(roles) }, ...matrix() });   // admin.permissions.read (gate above)
      if (method === 'GET' && path === '/api/candidates') {
        return json(await store.listCandidates(db, { state: url.searchParams.get('state') || undefined, q: url.searchParams.get('q') || undefined, source: url.searchParams.get('source') || undefined, synthetic: url.searchParams.get('synthetic') === '1', page: +url.searchParams.get('page') || 1, pageSize: +url.searchParams.get('pageSize') || 25 }));
      }
      const inventory = async () => {   // the current signed release as the Worker verified it, cached for ten minutes
        const key = new Request(`${env.PUBLIC_URL}/__cache/published-v1`);
        let inv = null; const hit = deps.cache ? await deps.cache.match(key) : null;
        if (hit) { try { inv = await hit.json(); } catch { inv = null; } }
        if (inv && !inv.meta) inv = null;   // an entry cached before the manifest metadata was kept
        if (!inv) {
          const pub = await fetchPublication(env, deps, null); if (!pub.ok) return { error: err(pub.status, `the current release could not be read: ${pub.error}`) };
          inv = { tag: pub.tag, published_at: pub.release.published_at, evidence: pub.release.evidence, manifest_sha256: pub.manifest_sha256, rules_root: pub.rules_root, generated_at: new Date(now * 1000).toISOString(), files: [...pub.files], meta: pub.meta || {} };
          if (deps.cache) await deps.cache.put(key, new Response(JSON.stringify(inv), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'max-age=600' } }));
        }
        return { inv };
      };
      if (path === '/api/source-requests' || path.startsWith('/api/source-requests/')) {   // a request to add or retire a source of any family; recorded, never fetched. Permissions come from the route table (src/rbac.js)
        const sm = path.match(/^\/api\/source-requests\/([0-9a-f-]{8,64})\/(accept|reject|cancel)$/);
        if (method === 'GET' && path === '/api/source-requests') return json(await sourceRequests.list(db));
        if (method === 'POST' && path === '/api/source-requests') { const rd = await readJson(request, 20_000); if (rd.tooLarge) return err(413, 'request too large'); const out = await sourceRequests.create(db, rd.body, actor, iso, deps.uuid); return json(out.body, out.status); }
        if (method === 'POST' && sm) { const rd = await readJson(request, 20_000); if (rd.tooLarge) return err(413, 'request too large'); const out = await sourceRequests.decide(db, sm[1], { accept: 'ACCEPTED', reject: 'REJECTED', cancel: 'CANCELLED' }[sm[2]], rd.body, actor, iso, can(roles, 'sources.review')); if (out.status === 403 && out.body.code === 'same_identity') await store.appendAudit(db, { actor: session.login, role, action: 'authz.denied', target: `source-request:${sm[1]}`, detail: { reason: 'same_identity' } }, iso).catch(() => {}); return json(out.body, out.status); }
        return err(404, 'unknown endpoint');
      }
      if (path.startsWith('/api/intel/')) {   // REVIEWER and above: licence and publication decisions are internal. Read only.
        if (method === 'POST' && path === '/api/intel/decisions') {   // hold / quarantine / reject (intel.decide) and approve-for-next-publication (intel.approve), any family but YARA; each id also needs that family's inspect permission
          if (!env.INTEL) return json(intelData.unavailable().body, 503);
          const rd = await readJson(request, 20_000); if (rd.tooLarge) return err(413, 'request too large');
          const need = intelDecisions.permissionForAction(rd.body && rd.body.action); if (!need) return err(400, 'unknown action');
          if (!can(roles, need)) { await store.appendAudit(db, { actor: session.login, role, action: 'authz.denied', target: '/api/intel/decisions', detail: { method, permission: need } }, iso).catch(() => {}); return err(403, `the permission ${need} is required`, { code: 'forbidden', permission: need }); }
          const out = await intelDecisions.decide({ intel: env.INTEL, panel: db }, rd.body, { ...actor, roles }, iso, (family) => can(roles, familyPermission(family))); return json(out.body, out.status);
        }
        if (method !== 'GET') return err(405, 'method not allowed');
        const NS = { 'Cache-Control': 'private, no-store' }, sp = url.searchParams, send = (r) => json(r.body, r.status, NS);
        if (path === '/api/intel/families') { const got = await inventory(); return json(await intelFamilies.loadFamilies(env, deps, got.inv || null), 200, NS); }
        if (!env.INTEL) return send(intelData.unavailable());
        if (path === '/api/intel/sources') return json(await intelData.listSources(env.INTEL), 200, NS);
        if (path === '/api/intel/runs') return send(await intelData.listRuns(env.INTEL, sp));
        if (path === '/api/intel/records') {   // each family is its own permission; an unknown family is a 400 from the validator, never a way around the check
          const asked = (sp.get('family') || 'yara,suricata,sigma,ioc,hash,cve,kev,advisory,attack,epss').split(',');
          const lacking = asked.find((f) => familyPermission(f) && !can(roles, familyPermission(f))); if (lacking) return err(403, `the permission ${familyPermission(lacking)} is required`, { code: 'forbidden', permission: familyPermission(lacking) });
          return send(await intelData.listRecords(env.INTEL, sp));
        }
        if (path === '/api/intel/stats') return json(await intelData.stats(env.INTEL), 200, { 'Cache-Control': 'private, max-age=60' });
        if (path === '/api/intel/events') return send(await intelData.listEvents(env.INTEL, sp));
        const rm = path.match(/^\/api\/intel\/records\/(.+)$/); if (rm) { let id; try { id = decodeURIComponent(rm[1]); } catch { return err(400, 'invalid id'); } const got = await intelData.getRecord(env.INTEL, id); if (got.status === 200) { const need = familyPermission(got.body.record.family); if (!need || !can(roles, need)) return err(403, `the permission ${need || 'unknown'} is required`, { code: 'forbidden', permission: need }); } return send(got); }
        return err(404, 'unknown endpoint');
      }
      if (method === 'GET' && path === '/api/published/file') {   // one published rule: manifest identity, signed content, provenance, record, policy; any signed-in role
        const got = await inventory(); if (got.error) return got.error;
        const d = await publishedRules.publishedRuleDetail(db, env, deps, got.inv, url.searchParams.get('path') || ''); if (d.status !== 200) return err(d.status, d.error);
        const { status: _s, ...rest } = d;
        const pol = rest.record ? await policies.candidateView(db, { id: rest.record.id, sha256: rest.file.sha256, path: rest.file.path, source: rest.file.source, state: rest.record.state }, iso) : await policies.candidateView(db, { id: '', sha256: rest.file.sha256, path: rest.file.path, source: rest.file.source, state: 'RELEASED' }, iso);
        return json({ ...rest, publication: pol });
      }
      if (method === 'POST' && path === '/api/published/adopt') {   // ADMIN: register a published rule the panel never saw so that it can be withdrawn
        const rd = await readJson(request, 2_000); if (rd.tooLarge || !rd.body || typeof rd.body.path !== 'string') return err(400, 'path required');
        const got = await inventory(); if (got.error) return got.error;
        const hit = (got.inv.files || []).find(([p]) => p === rd.body.path);   // separation of duties: whoever APPROVED this exact content in review does not also register it for publication management
        if (hit && (await db.prepare("SELECT 1 AS x FROM decisions WHERE actor_id = ? AND action = 'approve' AND sha256 = ? LIMIT 1").bind(session.user_id, hit[1].sha256).first())) { await store.appendAudit(db, { actor: session.login, role, action: 'authz.denied', target: 'published.adopt', detail: { reason: 'separation_of_duties', sha256: hit[1].sha256 } }, iso).catch(() => {}); return err(403, 'separation of duties: you approved this content in review, so someone else must register it', { code: 'separation_of_duties' }); }
        const r = await publishedRules.adoptPublished(db, env, deps, got.inv, { path: rd.body.path, request_id: rd.body.request_id }, actor, iso, deps.uuid);
        if (r.status !== 200) return err(r.status, r.error);
        if (r.audit) await store.appendAudit(db, { actor: session.login, role, action: r.audit.action, target: r.audit.target, detail: r.audit.detail }, iso);
        return json({ id: r.id, existing: r.existing });
      }
      if (method === 'GET' && path === '/api/published') {   // the inventory of the current signed release, reconciled with D1 (a published file may have no record there)
        const got = await inventory(); if (got.error) return got.error; const inv = got.inv;
        const p = url.searchParams, status = p.get('status') || '';
        const view = reconcilePublished(new Map(inv.files), await store.reconcileRows(db), { q: p.get('q') || '', source: p.get('source') || '', status: PUBLISHED_STATUS.includes(status) ? status : '', page: +p.get('page') || 1, pageSize: +p.get('pageSize') || 50 });
        view.items = await policies.annotateItems(db, view.items);   // policy: withdrawal pending / confirmed / lifted next to each file
        return json({ release: { url: `https://github.com/${env.REPO}/releases/tag/${inv.tag}`, tag: inv.tag, published_at: inv.published_at, manifest_sha256: inv.manifest_sha256, rules_root: inv.rules_root, files: inv.files.length, read_at: inv.generated_at }, ...view });
      }
      // ---- policy: persistent administrative withdrawals (every write is ADMIN only, checked by the validators before anything is read) ----
      if (path === '/api/policies' || path.startsWith('/api/policies/')) {
        const send = (r) => { const { status, ...rest } = r; return json(rest, status); };
        const readBody = async () => { const rd = await readJson(request, 20_000); return rd.tooLarge ? null : rd.body; };
        if (method === 'GET' && path === '/api/policies') return json(await policies.listPolicies(db, { status: url.searchParams.get('status') || '' }, iso));
        if (method === 'GET' && path === '/api/policies/preview') { return send(await policies.previewWithdrawal(db, env, deps, { candidate_id: url.searchParams.get('candidate_id') || '', scope: url.searchParams.get('scope') || '' })); }
        if (method === 'POST' && path === '/api/policies/suspensions') { const x = policies.validateSuspensionRequest(await readBody(), roles); if (!x.ok) return err(x.status, x.error); return send(await policies.requestWithdrawal(db, env, deps, x.value, actor, iso)); }
        if (method === 'POST' && path === '/api/policies/withdrawals') { const x = policies.validateWithdrawalRequest(await readBody(), roles); if (!x.ok) return err(x.status, x.error); return send(await policies.requestWithdrawal(db, env, deps, x.value, actor, iso)); }
        if (method === 'POST' && path === '/api/policies/reconcile') { return send(await policies.reconcileNow(db, env, deps, actor, iso)); }
        const pm = path.match(/^\/api\/policies\/([0-9a-f-]{8,64})$/);
        if (method === 'GET' && pm) { const r = await policies.getPolicy(db, pm[1], iso); return r ? json(r) : err(404, 'not found'); }
        const pl = path.match(/^\/api\/policies\/([0-9a-f-]{8,64})\/lifts$/);
        if (method === 'POST' && pl) { const x = policies.validateLiftRequest(await readBody(), roles); if (!x.ok) return err(x.status, x.error); return send(await policies.requestLift(db, pl[1], x.value, actor, iso)); }
        const lm = path.match(/^\/api\/policies\/lifts\/([A-Za-z0-9-]{8,64})\/(authorize|execute|cancel|review)$/);
        if (method === 'POST' && lm) {
          const op = lm[2], x = policies.validateLiftStep(await readBody(), roles, { reason: op !== 'execute', outcome: op === 'review', perm: { authorize: 'publication.lift.authorize', execute: 'publication.lift.breakglass', cancel: 'publication.lift.request', review: 'publication.lift.review' }[op] }); if (!x.ok) return err(x.status, x.error);
          const fn = { authorize: policies.authorizeLift, execute: policies.executeBreakglass, cancel: policies.cancelLift, review: policies.reviewBreakglass }[op];
          return send(await fn(db, lm[1], x.value, actor, iso));
        }
        return err(404, 'unknown endpoint');
      }
      const m = path.match(/^\/api\/candidates\/([0-9a-f-]{8,64})$/);
      if (method === 'GET' && m) {
        const c = await store.getCandidate(db, m[1]); if (!c) return err(404, 'not found');
        if (!(await store.viewedRecently(db, session.login, c.id, iso))) await store.appendAudit(db, { actor: session.login, role, action: 'access.view', target: c.id, detail: { path: c.path, sha256: c.sha256 } }, iso);   // who looked at which rule (once per 10 minutes)
        c.publication = await policies.candidateView(db, c, iso);   // policy: derived publication state, the policy and its lifts
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
      if (method === 'GET' && path === '/api/restore/status') {   // recovery status from public records only (GitHub Actions, the trust policy, repository files); REVIEWER and above
        const key = new Request(`${env.PUBLIC_URL}/__cache/restore-status-v1`);
        const hit = deps.cache ? await deps.cache.match(key) : null;
        if (hit) { const body = await hit.json(); return json({ ...body, cache: { hit: true, age_s: Math.max(0, now - Math.floor(Date.parse(body.generated_at) / 1000)) } }); }
        const tok = await openToken(env, session.id, session.token); if (!tok) return json({ error: 'sign in again', code: 'reauth' }, 401, { 'Set-Cookie': clearCookie() });
        const data = await restore.loadRecoveryStatus(env, deps, tok, now * 1000);
        if (deps.cache) await deps.cache.put(key, new Response(JSON.stringify(data), { headers: { 'Content-Type': 'application/json', 'Cache-Control': `max-age=${data.unavailable.length ? 30 : restore.CACHE_SECONDS}` } }));
        return json({ ...data, cache: { hit: false, age_s: 0 } });
      }
      if (method === 'GET' && path === '/api/restore/procedures') { return json(restore.procedureBundle(), 200, { 'Cache-Control': 'private, no-store' }); }
      if (method === 'POST' && path === '/api/restore/event') {   // audited progress of a recovery procedure: records, never executes
        const read = await readJson(request, 2_000); if (read.tooLarge) return err(413, 'request body too large');
        const v = restore.validateEvent(read.body, roles); if (!v.ok) return err(v.status, v.error);
        if (read.body.authorization_id !== undefined) { const au = await approvals.authorisationFor(db, read.body.authorization_id, { procedure: read.body.procedure, run: read.body.run }, iso); if (!au.ok) { await store.appendAudit(db, { actor: session.login, role, action: 'authz.denied', target: 'restore.event', detail: { reason: 'no valid authorisation', procedure: read.body.procedure } }, iso).catch(() => {}); return err(403, au.error, { code: 'no_authorisation' }); } }
        if (await store.auditExists(db, { actor: session.login, action: v.action, target: v.target, detail: v.detail })) return json({ ok: true, duplicate: true });
        await store.appendAudit(db, { actor: session.login, role, action: v.action, target: v.target, detail: v.detail }, iso);
        return json({ ok: true, duplicate: false });
      }
      if (method === 'GET' && path === '/api/stats') { const c = await store.counts(db); return json({ counts: c, sources: await store.sourceCounts(db), synthetic: await store.syntheticCount(db), public: publicStats(c) }); }
      if (method === 'POST' && path === '/api/decisions') {
        const read = await readJson(request, 200_000); if (read.tooLarge) return err(413, 'request body too large');
        const v = validateDecisionRequest(read.body, roles); if (!v.ok) return err(v.status, v.error);
        if (v.value.action === 'approve') { const blocked = await policies.blockedByPolicy(db, v.value.ids); if (blocked.length) return err(409, 'nothing was changed', { conflicts: blocked }); }   // policy: an approval under an administrative prohibition can never take effect
        const r = await store.decide(db, v.value, actor, iso);
        const { status, ...rest } = r; return json(rest, status);
      }
      const rt = path.match(/^\/api\/candidates\/([0-9a-f-]{8,64})\/retest$/);
      if (method === 'POST' && rt) { return (await store.requestRetest(db, rt[1], actor, iso)) ? json({ ok: true, note: 'the next pipeline run will test it again' }) : err(404, 'not found'); }
      if (method === 'GET' && path === '/api/audit') { const fam = url.searchParams.get('family') || ''; return json(await store.auditQuery(db, { limit: Math.min(+url.searchParams.get('limit') || 50, 200), before: +url.searchParams.get('before') || undefined, family: /^[a-z]{1,20}$/.test(fam) ? fam : undefined, actor: (url.searchParams.get('actor') || '').slice(0, 80) || undefined })); }
      if (method === 'GET' && path === '/api/audit/anchors') {   // what the chain is anchored to (audit.read). An empty list is said as such, never presented as protection
        const head = await db.prepare('SELECT seq, hash, at FROM audit ORDER BY seq DESC LIMIT 1').first(), n = await db.prepare('SELECT COUNT(*) AS n FROM audit').first(), anchors = await listAnchors(db);
        return json({ schema: 1, entries: n.n, head: head ? { seq: head.seq, hash: head.hash, at: head.at } : null, anchors, external_anchor: anchors.length > 0 });
      }
      if (method === 'GET' && path === '/api/audit/verify') { return json(await verifyAuditChain(db, { after: Math.max(0, +url.searchParams.get('after') || 0), head: url.searchParams.get('head') || null })); }   // archive P1: paginated, anchor-aware
      if (path === '/api/approvals' || path.startsWith('/api/approvals/')) {   // second-identity approvals (src/approvals.js); every write needs a recent sign-in (gate above)
        const readBody = async () => { const rd = await readJson(request, 20_000); return rd.tooLarge ? null : rd.body; };
        const send = (r) => { const { status, ...rest } = r; return json(rest, status); };
        const token = () => openToken(env, session.id, session.token);
        const apply = async (row, by) => {   // the effect of an approved (or emergency-executed) operation
          if (row.op === 'role.grant') {
            const tok = await token(); if (!tok) return { status: 401, error: 'sign in again', code: 'reauth' };
            const acc = await resolveGithubAccount(deps, env, tok, { id: row.params.user_id }); if (!acc.ok) return { status: acc.status, error: acc.error };
            if (acc.account.login.toLowerCase() !== row.params.login) return { status: 409, error: 'the GitHub account no longer has the login that was approved; nothing was changed' };
            const permNow = (await db.prepare('SELECT perm FROM sessions WHERE id = ?').bind(session.id).first())?.perm;
            const r = await store.changeMember(db, { account: acc.account, role: row.params.role, reason: `approval ${row.id}: ${row.reason}`.slice(0, 2000), actor: { login: by.login, id: by.id, role: by.role }, durableAdmin: permNow === 'admin', extra: { approval_id: row.id, requested_by_id: row.requested_by_id, approved_by_id: row.approved_by_id ?? null, mode: row.mode } }, iso);
            return r.status === 200 || (r.status === 409 && /already has this role/.test(r.error || '')) ? { status: 200 } : r;
          }
          if (row.op === 'policy.revoke_confirm') return policies.confirmRevocation(db, row.params.policy_id, row, by, iso);
          return { status: 200 };   // restore.real: the authorisation is the effect; recovery events consume it
        };
        const sp = url.searchParams, am = path.match(/^\/api\/approvals\/([0-9a-f-]{8,64})(?:\/(approve|execute|cancel|review))?$/);
        if (method === 'GET' && path === '/api/approvals') return json(await approvals.list(db, { state: sp.get('state') || undefined, op: sp.get('op') || undefined }, iso));
        if (method === 'GET' && am && !am[2]) { const a = await approvals.getOne(db, am[1], iso); return a ? json(a) : err(404, 'not found'); }
        if (method === 'POST' && path === '/api/approvals') {
          const v = approvals.validateCreate(await readBody(), roles); if (!v.ok) { if (v.status === 403) await store.appendAudit(db, { actor: session.login, role, action: 'authz.denied', target: 'approvals.create', detail: { permission_missing: v.error } }, iso).catch(() => {}); return err(v.status, v.error); }
          if (v.value.op === 'role.grant') {
            if (v.value.params.user_id === session.user_id) return err(400, 'you cannot request a role for yourself');
            const tok = await token(); if (!tok) return json({ error: 'sign in again', code: 'reauth' }, 401, { 'Set-Cookie': clearCookie() });
            const acc = await resolveGithubAccount(deps, env, tok, { id: v.value.params.user_id }); if (!acc.ok) return err(acc.status, acc.error);
            if (acc.account.login.toLowerCase() !== v.value.params.login) return err(409, 'the login does not belong to that GitHub account id');
          }
          if (v.value.op === 'policy.revoke_confirm') { const p = await db.prepare('SELECT kind, status FROM policies WHERE id = ?').bind(v.value.params.policy_id).first(); if (!p || p.kind !== 'SUSPENSION' || p.status !== 'ACTIVE') return err(409, 'only a suspension that is still in force can become a definitive revocation'); }
          return send(await approvals.create(db, v.value, actor, iso, deps.uuid));
        }
        if (method === 'POST' && am && am[2]) {
          const stepName = am[2], x = approvals.validateStep(await readBody(), { reason: stepName !== 'execute', outcome: stepName === 'review' }); if (!x.ok) return err(x.status, x.error);
          if (stepName === 'review') return send(await approvals.review(db, am[1], x.value, actor, iso));
          if (stepName === 'cancel') return send(await approvals.cancel(db, am[1], x.value, actor, iso));
          if (stepName === 'approve') {
            const r = await approvals.approve(db, am[1], x.value, actor, iso); if (r.status !== 200) { if (r.status === 403) await store.appendAudit(db, { actor: session.login, role, action: 'authz.denied', target: `approval:${am[1]}`, detail: { reason: r.code || 'approve', error: r.error } }, iso).catch(() => {}); return send(r); }
            if (r.approval.op === 'restore.real') return send(r);
            const eff = await apply(r.approval, actor); if (eff.status !== 200) return json({ approval: r.approval, effect_error: eff.error, note: 'approved, but the effect could not be applied; retry it with execute' }, 200);
            const m = await approvals.markExecuted(db, am[1], actor, iso, { effect: 'applied' }); return send(m);
          }
          const ready = await approvals.readyToExecute(db, am[1], actor, iso); if (ready.status !== 200) return send(ready);
          if (ready.row.op === 'restore.real' && ready.row.mode === 'DUAL') return err(409, 'a dual recovery authorisation is used directly by the recovery events; it is not executed');
          if (ready.row.op !== 'restore.real') { const eff = await apply(ready.row, actor); if (eff.status !== 200) return send(eff); }
          return send(await approvals.markExecuted(db, am[1], actor, iso, { breakglass: ready.row.mode === 'BREAKGLASS' }));
        }
        return err(404, 'unknown endpoint');
      }
      if (path === '/api/members' || path.startsWith('/api/members/')) {
        const adminToken = () => openToken(env, session.id, session.token);
        if (method === 'GET' && path === '/api/members/migration-plan') {   // preparation only: nothing is written. Who holds access today through the GitHub repository permission alone, by stable id, for the owner to review before explicit grants replace the mapping
          const first = await store.listPeople(db, { page: 1, pageSize: 100 }, roleFromRepoPermission), people = [...first.items];
          for (let pg = 2; pg <= Math.ceil(first.total / 100); pg++) people.push(...(await store.listPeople(db, { page: pg, pageSize: 100 }, roleFromRepoPermission)).items);
          const items = people.filter((p) => p.origin === 'repo').map((p) => ({ user_id: p.user_id, login: p.login, repo_role: p.repo_role, repo_perm: p.repo_perm, repo_checked_at: p.repo_checked_at, last_login: p.last_login, proposed_grant: p.repo_role, bound: p.user_id != null }));
          return json({ schema: 1, mapping: 'GITHUB_PERMISSION', note: 'Access still follows the GitHub permission. No grant has been written. Review each account, then grant it explicitly (POST /api/members; an ADMIN grant needs a second approver once two administrators exist).', total: items.length, items });
        }
        if (method === 'GET' && path === '/api/members') return json(await store.listPeople(db, { q: url.searchParams.get('q') || '', status: url.searchParams.get('status') || '', page: +url.searchParams.get('page') || 1, pageSize: +url.searchParams.get('pageSize') || 25 }, roleFromRepoPermission));
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
          if (!b || !Number.isInteger(b.user_id) || b.user_id < 1 || ![...GRANTABLE_ROLES, null].includes(b.role)) return err(400, 'user_id (the GitHub account id) and role (one of VIEWER, REVIEWER, PUBLISHER, SECURITY_ADMIN, ADMIN, or null to revoke) required');
          if (typeof b.reason !== 'string' || b.reason.replace(/[\s\p{Cf}]/gu, '').length < 5 || b.reason.length > 2000) return err(400, 'a reason of 5 to 2000 visible characters is required');
          if (b.user_id === session.user_id) return err(400, 'you cannot change your own role');
          const tok = await adminToken(); if (!tok) return json({ error: 'sign in again', code: 'reauth' }, 401, { 'Set-Cookie': clearCookie() });
          const acc = await resolveGithubAccount(deps, env, tok, { id: b.user_id }); if (!acc.ok) return err(acc.status, acc.error);
          if (acc.account.login.toLowerCase() === session.login.toLowerCase()) return err(400, 'you cannot change your own role');
          let extra = {};
          if (b.role && approvals.PRIVILEGED_ROLES.includes(b.role)) {   // PUBLISHER, SECURITY_ADMIN and ADMIN are never granted by one hand once two administrators exist
            const n = await store.adminCount(db, iso);
            if (n >= 2) return err(409, 'granting this role needs a second approver: open an approval request (POST /api/approvals, op role.grant)', { code: 'approval_required', op: 'role.grant', administrators: n });
            if (now - session.created_at > Number(env.REINFORCED_REAUTH_S || 600)) return json({ error: 'a privileged grant needs a sign-in within the last 10 minutes: sign in again', code: 'reauth_required' }, 401);
            if (typeof b.confirm_login !== 'string' || b.confirm_login.toLowerCase() !== acc.account.login.toLowerCase()) return err(400, 'confirm_login must equal the login of the account that receives the role', { code: 'confirm_required' });
            extra = { mode: 'SINGLE_ADMIN', administrators_known: n };   // reinforced single-administrator mode, recorded as such
          }
          const permNow = (await db.prepare('SELECT perm FROM sessions WHERE id = ?').bind(session.id).first())?.perm;   // fresh: the write above asked GitHub again
          const r = await store.changeMember(db, { account: acc.account, role: b.role, reason: b.reason.trim(), actor: { login: session.login, id: session.user_id, role }, durableAdmin: permNow === 'admin', extra }, iso);
          const { status, ...rest } = r; return json(rest, status);
        }
      }
      if (path === '/api/source-proposals' || path.startsWith('/api/source-proposals/')) {   // source proposals (src/proposals.js)
        const r = await proposals.handleApi({ method, path, url, role, roles, actor, env, deps, db, iso, readJson: (max) => readJson(request, max), getToken: () => openToken(env, session.id, session.token), audit: (a) => store.appendAudit(db, a, iso) });
        if (r) return json(r.body, r.status, r.reauth ? { 'Set-Cookie': clearCookie() } : {});
      }
      return err(404, 'unknown endpoint');
    }

    // ---- UI assets ----
    if (method === 'GET' && env.ASSETS) { const r = await env.ASSETS.fetch(request); const h = new Headers(r.headers); for (const [k, v] of Object.entries(HEADERS)) h.set(k, v); return new Response(r.body, { status: r.status, headers: h }); }
    return err(404, 'not found');
  } catch (e) {
    // A failing store or API must never look like an approval.
    const miss = String((e && e.message) || '').match(/no such table: (?:main\.)?(\w+)/), mig = miss && { policies: '0003', policy_lifts: '0003', policy_events: '0003', audit_anchor: '0004', source_proposals: '0005', source_proposal_events: '0005', approvals: '0006', source_requests: '0007' }[miss[1]];
    if (mig && path.startsWith('/api/')) return err(503, `migration ${mig} has not been applied to this database yet; nothing was changed`, { code: 'migration_pending' });   // a new feature asked before its additive migration: say which one
    if (path.startsWith('/auth/')) return back('unavailable');
    return err(500, 'the service could not complete the request; nothing was changed unless the response says so');
  }
}

export default {
  fetch(request, env) { return handle(request, env, { cache: typeof caches !== 'undefined' ? caches.default : null, fetch: (...a) => fetch(...a), now: () => Math.floor(Date.now() / 1000), uuid: () => crypto.randomUUID() }); },
};
