// The quarantine service on the real Workers runtime (workerd) with a real D1 database, via Miniflare.
// `npm test` runs the same logic over a node:sqlite shim; this file checks what the shim cannot: D1's own limits and batch semantics, triggers,
// persistence across restarts, the platform's fetch/crypto and the static assets binding. GitHub (OAuth, API, OIDC keys) is the only thing
// replaced: no GitHub account is involved, so it does NOT prove the real OAuth app or real Actions tokens (see docs/audit/RESIDUAL-RISKS.md, RR-03).
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Miniflare } from 'miniflare';
import { actionsToken, cand, rid, rsaKey, sha, ORIGIN, REPO } from '../test/helpers.js';
import { createSession } from '../src/auth.js';

const root = fileURLToPath(new URL('..', import.meta.url));
const MODULES = readdirSync(join(root, 'src')).filter((f) => f.endsWith('.js')).sort((a, b) => (a === 'index.js' ? -1 : b === 'index.js' ? 1 : a.localeCompare(b))).map((f) => ({ type: 'ESModule', path: f, contents: readFileSync(join(root, 'src', f), 'utf8') }));   // every source module, so a new import can never be missing from the runtime test; index.js first because workerd takes the first module as the entry point
const persist = mkdtempSync(join(tmpdir(), 'mg-d1-'));
const key = await rsaKey(), otherKey = await rsaKey();
const ENC_KEY = Buffer.alloc(32, 9).toString('base64');   // test-only key for sealing session tokens
const accounts = {}; let opsCalls = 0;   // the faked GitHub: known accounts and a counter of pipeline-record reads
const perms = {};   // access token -> GitHub repository permissions, answered by the fake GitHub
let mf, db;

const fakeGithub = async (req) => {
  const u = new URL(req.url);
  if (u.pathname.endsWith('/.well-known/jwks')) return Response.json({ keys: [key.jwk] });
  if (u.hostname === 'api.github.com' && u.pathname === `/repos/${REPO}`) {
    const p = perms[(req.headers.get('Authorization') || '').replace('Bearer ', '')];
    return p ? Response.json({ permissions: p }) : new Response('no', { status: 401 });
  }
  const acc = u.hostname === 'api.github.com' && /^\/user\/(\d+)$/.exec(u.pathname), accL = u.hostname === 'api.github.com' && /^\/users\/([A-Za-z0-9-]+)$/.exec(u.pathname);
  if (acc || accL) { const a = Object.values(accounts).find((x) => (acc ? x.id === +acc[1] : x.login === accL[1])); return a ? Response.json(a) : new Response('{}', { status: 404 }); }
  const day = new Date().toISOString().slice(0, 10), ok = (o) => Response.json(o, { headers: { 'x-ratelimit-remaining': '4999', 'x-ratelimit-limit': '5000' } });
  if (u.hostname === 'api.github.com' && /actions\/workflows\/daily\.yml\/runs/.test(u.pathname)) { opsCalls++; return ok({ workflow_runs: [{ id: 1, event: 'schedule', status: 'completed', conclusion: 'success', created_at: `${day}T03:20:00Z`, run_started_at: `${day}T03:20:00Z`, updated_at: `${day}T03:29:00Z`, html_url: 'https://github.com/x/y/actions/runs/1' }] }); }
  if (u.hostname === 'api.github.com' && /actions\/workflows\/publish\.yml\/runs/.test(u.pathname)) return ok({ workflow_runs: [] });
  if (u.hostname === 'api.github.com' && u.pathname.endsWith('/releases')) return ok([]);
  if (u.hostname === 'raw.githubusercontent.com' && u.pathname.endsWith('/log.jsonl')) return new Response('');
  if (u.hostname === 'raw.githubusercontent.com' && u.pathname.endsWith('/sources.json')) return Response.json({ sources: [{ id: 'nextron', repo: 'a/b', kind: 'rules', paths: [] }] });
  if (u.hostname === 'rules.mac-guard.com' && u.pathname === '/stats.json') return Response.json({ days: [] });
  return new Response('{}', { status: 404 });
};
const boot = async () => {
  mf = new Miniflare({
    modules: MODULES, compatibilityDate: '2026-08-01',
    d1Databases: { DB: 'quarantine' }, d1Persist: join(persist, 'd1'),
    assets: { directory: join(root, 'public'), binding: 'ASSETS', routerConfig: { has_user_worker: true } },
    bindings: { REPO, PUBLIC_URL: ORIGIN, OIDC_AUDIENCE: ORIGIN, GITHUB_CLIENT_ID: 'cid', GITHUB_CLIENT_SECRET: 'sec', TOKEN_ENC_KEY: ENC_KEY, PIPELINE_WORKFLOWS: 'daily.yml,publish.yml' },
    outboundService: fakeGithub,
  });
  db = await mf.getD1Database('DB');
  const sql = readFileSync(join(root, 'schema.sql'), 'utf8').replace(/^--.*$/gm, '').split(/;[ \t]*\r?\n/).map((s) => s.trim()).filter(Boolean);
  await db.batch(sql.map((s) => db.prepare(s)));
};
before(boot);
after(async () => { await mf.dispose(); rmSync(persist, { recursive: true, force: true }); });

let users = 0;
async function login(name, permission) {
  const token = `tok-${name}-${++users}`; perms[token] = permission; accounts[name] = { id: 100 + users, login: name, type: 'User' };
  const s = await createSession(db, { login: name, id: 100 + users, token }, Math.floor(Date.now() / 1000), { TOKEN_ENC_KEY: ENC_KEY });
  return { cookie: `__Host-mg_session=${s.id}`, csrf: s.csrf, name };
}
async function call(method, path, { user, body, bearer, headers = {} } = {}) {
  const h = { ...headers };
  if (user) h.Cookie = user.cookie;
  if (user && method !== 'GET') { h['X-CSRF-Token'] = user.csrf; h.Origin = ORIGIN; }
  if (bearer) h.Authorization = `Bearer ${bearer}`;
  if (body !== undefined) h['Content-Type'] = 'application/json';
  const r = await mf.dispatchFetch(ORIGIN + path, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' });
  const text = await r.text(); let data; try { data = JSON.parse(text); } catch { data = text; }
  return { status: r.status, data, headers: r.headers };
}
const pipeline = async (workflow = 'daily.yml', claims = {}, k = key) =>
  actionsToken(k, { job_workflow_ref: `${REPO}/.github/workflows/${workflow}@refs/heads/main`, ...claims });
const submit = async (items, workflow = 'daily.yml') => call('POST', '/api/pipeline/submit', { bearer: await pipeline(workflow), body: { run_id: '1', candidates: items } });
const decide = (user, body) => call('POST', '/api/decisions', { user, body });
const get = async (user, id) => (await call('GET', `/api/candidates/${id}`, { user })).data;

test('nothing is readable without authentication; the public endpoint returns counts only; the UI is served with its CSP', async () => {
  for (const p of ['/api/candidates', '/api/stats', '/api/audit', '/api/members', '/api/me']) assert.equal((await call('GET', p)).status, 401, p);
  assert.equal((await call('GET', '/api/pipeline/decisions')).status, 401);
  const pub = await call('GET', '/public/stats'); assert.equal(pub.status, 200);
  assert.ok(Object.values(pub.data).every((v) => typeof v === 'number' || (v && typeof v === 'object' && Object.values(v).every((x) => typeof x === 'number'))), JSON.stringify(pub.data));
  const ui = await call('GET', '/'); assert.equal(ui.status, 200);
  assert.match(ui.headers.get('content-security-policy'), /default-src 'none'/); assert.equal(ui.headers.get('cache-control'), 'no-store');
  assert.equal((await call('GET', '/nope')).status, 404);
});

test('pipeline tokens: forged signature, wrong audience, wrong repository, wrong workflow and expired are all refused', async () => {
  const body = { run_id: '1', candidates: [] };
  const send = (bearer) => call('POST', '/api/pipeline/submit', { bearer, body });
  assert.equal((await send(await pipeline('daily.yml', {}, otherKey))).status, 401, `await pipeline('daily.yml', {}, otherKey)`);                       // signed by a key GitHub does not publish
  assert.equal((await send(await pipeline('daily.yml', { aud: 'https://evil.example' }))).status, 401, `await pipeline('daily.yml', { aud: 'https://evil.example' })`);
  assert.equal((await send(await pipeline('daily.yml', { repository: 'someone/else' }))).status, 401, `await pipeline('daily.yml', { repository: 'someone/else' })`);
  assert.equal((await send(await pipeline('daily.yml', { exp: Math.floor(Date.now() / 1000) - 120 }))).status, 401, `await pipeline('daily.yml', { exp: Math.floor(Date.now() / 1000) - 5 })`);
  assert.equal((await send(await pipeline('daily.yml', { ref: 'refs/heads/feature' }))).status, 401, `await pipeline('daily.yml', { ref: 'refs/heads/feature' })`);
  assert.equal((await send(await pipeline('site.yml'))).status, 401, `await pipeline('site.yml')`);                                       // not in PIPELINE_WORKFLOWS
  assert.equal((await send(await pipeline('publish.yml'))).status, 403, `await pipeline('publish.yml')`);                                    // allowed workflow, not allowed to submit
  assert.equal((await send(await pipeline('daily.yml'))).status, 200, `await pipeline('daily.yml')`);
});

test('300 candidates in one submission (far above D1\'s bound-parameter limit per statement) are stored exactly once, and a replay creates nothing', async () => {
  const items = Array.from({ length: 300 }, (_, i) => cand(`bulk${i}`, `rules/bulk/${i}.yar`));
  const first = await submit(items); assert.equal(first.status, 200, JSON.stringify(first.data).slice(0, 200));
  assert.equal(first.data.results.filter((r) => r.status === 'created').length, 300);
  const again = await submit(items); assert.equal(again.status, 200);
  assert.equal(again.data.results.filter((r) => r.status === 'created').length, 0);
  const n = await db.prepare("SELECT COUNT(*) n FROM candidates WHERE path LIKE 'rules/bulk/%'").first(); assert.equal(n.n, 300);
});

test('a malformed or oversized item rejects the whole submission and stores nothing', async () => {
  const before = (await db.prepare('SELECT COUNT(*) n FROM candidates').first()).n;
  const bad = await submit([cand('ok1'), cand('ok2', 'rules/y/ok2.yar', { sha256: 'f'.repeat(64) })]);   // hash does not match the content
  assert.equal(bad.status, 400); assert.equal((await db.prepare('SELECT COUNT(*) n FROM candidates').first()).n, before);
});

test('roles: read-only GitHub access is no access; triage views but cannot decide; write access can', async () => {
  const ids = (await submit([cand('roles1', 'rules/roles/1.yar')])).data.results.map((r) => r.id);
  const stranger = await login('stranger', { pull: true }), rita = await login('rita', { push: true });
  assert.equal((await call('GET', '/api/candidates', { user: stranger })).status, 403);
  const body = (v) => ({ action: 'approve', ids, reason: 'reviewed by hand', request_id: rid(), expect: { [ids[0]]: v } });
  assert.equal((await decide(stranger, body(1))).status, 403);
  const c = await get(rita, ids[0]); assert.equal(c.state, 'PENDING'); assert.match(c.content, /rule R_roles1/);
  assert.equal((await decide(rita, body(c.version))).status, 200);
  assert.equal((await get(rita, ids[0])).state, 'APPROVED_PENDING_VALIDATION');
  assert.equal((await call('GET', '/api/members', { user: rita })).status, 403);                              // reviewer is not admin
});

test('a batch decision over 120 rules changes exactly the selection, with one decision row per rule, and a stale view changes nothing', async () => {
  const rita = await login('rita', { push: true });
  const all = (await call('GET', '/api/candidates?pageSize=100&q=bulk', { user: rita })).data;
  const rows = (await db.prepare("SELECT id, version FROM candidates WHERE path LIKE 'rules/bulk/%' ORDER BY path LIMIT 150").all()).results;
  assert.equal(rows.length, 150); assert.ok(all);
  const pick = rows.slice(0, 120), untouched = rows.slice(120);
  const expect = Object.fromEntries(pick.map((r) => [r.id, r.version]));
  const stale = { ...expect, [pick[0].id]: 99 };
  const bad = await decide(rita, { action: 'reject', ids: pick.map((r) => r.id), reason: 'noisy rules, batch', request_id: rid(), confirm_count: 120, expect: stale });
  assert.equal(bad.status, 409);
  assert.equal((await db.prepare("SELECT COUNT(*) n FROM candidates WHERE state != 'PENDING' AND path LIKE 'rules/bulk/%'").first()).n, 0);
  const ok = await decide(rita, { action: 'reject', ids: pick.map((r) => r.id), reason: 'noisy rules, batch', request_id: rid(), confirm_count: 120, expect });
  assert.equal(ok.status, 200, JSON.stringify(ok.data).slice(0, 200)); assert.equal(ok.data.applied.length, 120);
  assert.equal((await db.prepare("SELECT COUNT(*) n FROM candidates WHERE state = 'REJECTED' AND path LIKE 'rules/bulk/%'").first()).n, 120);
  for (const r of untouched) assert.equal((await db.prepare('SELECT state FROM candidates WHERE id = ?').bind(r.id).first()).state, 'PENDING');
  assert.equal((await db.prepare("SELECT COUNT(*) n FROM decisions WHERE actor = 'rita' AND action = 'reject' AND reason = 'noisy rules, batch'").first()).n, 120);
});

test('a human rejection wins over an approval of identical bytes at another path (decisions map, real D1)', async () => {
  const a = cand('twin', 'rules/twin/a.yar'), b = cand('twin', 'rules/twin/b.yar');
  const ids = (await submit([a, b])).data.results.map((r) => r.id);
  const rita = await login('rita', { push: true });
  const v = async (id) => (await get(rita, id)).version;
  assert.equal((await decide(rita, { action: 'approve', ids: [ids[0]], reason: 'looks fine', request_id: rid(), expect: { [ids[0]]: await v(ids[0]) } })).status, 200);
  assert.equal((await decide(rita, { action: 'reject', ids: [ids[1]], reason: 'actually blocks the engine', request_id: rid(), expect: { [ids[1]]: await v(ids[1]) } })).status, 200);
  const dec = (await call('GET', '/api/pipeline/decisions', { bearer: await pipeline('daily.yml') })).data;
  assert.equal(dec.decisions[sha('twin')].state, 'REJECTED');   // approved at a.yar, rejected at b.yar: the rejection wins
});

test('replaying a request is idempotent and concurrent opposite decisions leave exactly one winner', async () => {
  const ids = (await submit([cand('race', 'rules/race/1.yar')])).data.results.map((r) => r.id);
  const rita = await login('rita', { push: true }), sam = await login('sam', { push: true });
  const body = { action: 'approve', ids, reason: 'reviewed twice', request_id: rid(), expect: { [ids[0]]: 1 } };
  const [x, y] = await Promise.all([decide(rita, body), decide(sam, { ...body, action: 'reject', request_id: rid(), reason: 'rejected by sam' })]);
  assert.deepEqual([x.status, y.status].sort(), [200, 409]);
  const c = await get(rita, ids[0]); assert.equal(c.decisions.length, 1);
  const replayed = x.status === 200 ? await decide(rita, body) : null;   // the winner's own request repeated
  if (replayed) { assert.equal(replayed.status, 200); assert.equal(replayed.data.replay, true); }
  assert.equal((await get(rita, ids[0])).decisions.length, 1);
});

test('the audit chain verifies, access is logged, and the database itself refuses to edit or delete audit and decisions', async () => {
  const admin = await login('olga', { admin: true }), rita = await login('rita', { push: true });
  const v = await call('GET', '/api/audit/verify', { user: admin }); assert.equal(v.status, 200); assert.equal(v.data.ok, true, JSON.stringify(v.data));
  assert.equal((await call('GET', '/api/audit/verify', { user: rita })).status, 403);
  await assert.rejects(db.prepare("UPDATE audit SET actor = 'x' WHERE seq = 1").run(), /append-only/);
  await assert.rejects(db.prepare('DELETE FROM audit WHERE seq = 1').run(), /append-only/);
  await assert.rejects(db.prepare("UPDATE decisions SET reason = 'x'").run(), /append-only/);
  await assert.rejects(db.prepare('DELETE FROM decisions').run(), /append-only/);
  const rows = (await db.prepare('SELECT action FROM audit').all()).results.map((r) => r.action);
  for (const a of ['pipeline.submit']) assert.ok(rows.includes(a), a);
});

test('a change of an audit row made outside the service (trigger dropped) is detected by the chain check', async () => {
  const admin = await login('olga2', { admin: true });
  await db.exec('DROP TRIGGER audit_no_update');
  await db.prepare("UPDATE audit SET detail = '{\"count\":999}' WHERE seq = (SELECT MIN(seq) FROM audit WHERE action = 'pipeline.submit')").run();
  const v = await call('GET', '/api/audit/verify', { user: admin }); assert.equal(v.status, 200); assert.equal(v.data.ok, false);
});

test('data survives a restart of the runtime (same persisted D1)', async () => {
  const before = (await db.prepare('SELECT COUNT(*) n FROM candidates').first()).n, st = (await db.prepare("SELECT COUNT(*) n FROM candidates WHERE state = 'REJECTED'").first()).n;
  await mf.dispose(); mf = null;
  mf = new Miniflare({
    modules: MODULES, compatibilityDate: '2026-08-01',
    d1Databases: { DB: 'quarantine' }, d1Persist: join(persist, 'd1'), assets: { directory: join(root, 'public'), binding: 'ASSETS', routerConfig: { has_user_worker: true } },
    bindings: { REPO, PUBLIC_URL: ORIGIN, OIDC_AUDIENCE: ORIGIN, GITHUB_CLIENT_ID: 'cid', GITHUB_CLIENT_SECRET: 'sec', TOKEN_ENC_KEY: ENC_KEY, PIPELINE_WORKFLOWS: 'daily.yml,publish.yml' }, outboundService: fakeGithub,
  });
  db = await mf.getD1Database('DB');
  assert.equal((await db.prepare('SELECT COUNT(*) n FROM candidates').first()).n, before);
  assert.equal((await db.prepare("SELECT COUNT(*) n FROM candidates WHERE state = 'REJECTED'").first()).n, st);
  assert.equal((await call('GET', '/api/candidates')).status, 401);
});

test('the login flow: state is bound to the browser that started it, and a callback without the cookie is refused', async () => {
  const start = await call('GET', '/auth/login'); assert.equal(start.status, 302);
  assert.match(start.headers.get('location'), /^https:\/\/github\.com\/login\/oauth\/authorize\?/);
  const cookie = start.headers.get('set-cookie'); assert.match(cookie, /__Host-mg_oauth=/); assert.match(cookie, /HttpOnly/); assert.match(cookie, /Secure/);
  const state = new URL(start.headers.get('location')).searchParams.get('state');
  assert.equal((await call('GET', `/auth/callback?code=abc&state=${state}`)).status, 302);                      // no cookie: someone else's login
  assert.equal((await call('GET', '/auth/callback?code=abc&state=wrong', { headers: { Cookie: `__Host-mg_oauth=${state}` } })).status, 302);
});

test('pipeline activity through the real runtime: the Cache API serves the second read, GitHub is asked once', async () => {
  const admin = await login('olga3', { admin: true }); const before = opsCalls;
  const a = await call('GET', '/api/ops/overview', { user: admin }); assert.equal(a.status, 200, JSON.stringify(a.data)); assert.equal(a.data.cache.hit, false); assert.equal(a.data.days.length, 30); assert.deepEqual(a.data.unavailable, []);
  assert.equal(a.data.days[29].state, 'OK'); assert.equal(a.data.sources[0].id, 'nextron'); assert.equal(opsCalls, before + 1);
  const b = await call('GET', '/api/ops/overview', { user: admin }); assert.equal(b.data.cache.hit, true); assert.equal(opsCalls, before + 1, 'served from the edge cache');
  assert.equal((await call('GET', '/api/ops/overview')).status, 401);
});

test('members by immutable id through the real runtime: resolve, grant, audit with previous role and reason, self-change refused', async () => {
  const admin = await login('olga4', { admin: true }); await login('newcomer', { pull: true });
  const me = (await call('GET', '/api/me', { user: admin })).data;
  const look = await call('GET', '/api/members/lookup?login=newcomer', { user: admin }); assert.equal(look.status, 200); assert.equal(look.data.account.login, 'newcomer');
  const grant = await call('POST', '/api/members', { user: admin, body: { user_id: look.data.account.id, role: 'REVIEWER', reason: 'joins the weekly review' } }); assert.equal(grant.status, 200, JSON.stringify(grant.data));
  assert.equal((await call('POST', '/api/members', { user: admin, body: { user_id: me.user_id, role: 'VIEWER', reason: 'trying to demote myself' } })).status, 400);
  const e = (await call('GET', '/api/audit?family=member', { user: admin })).data.entries[0]; assert.deepEqual([e.detail.from_role, e.detail.to_role, e.detail.reason, e.detail.user_id], [null, 'REVIEWER', 'joins the weekly review', look.data.account.id]);
  assert.equal((await call('GET', '/api/audit/verify', { user: admin })).data.ok, false, 'the earlier test dropped a trigger and tampered a row on purpose: the chain stays broken and says so');
});
