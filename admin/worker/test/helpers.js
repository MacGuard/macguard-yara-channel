import { createHash } from 'node:crypto';
import { handle } from '../src/index.js';
import { newDb } from './d1shim.js';
import { createSession } from '../src/auth.js';

export const REPO = 'MacGuard/macguard-yara-channel';
export const ORIGIN = 'https://admin.example.test';
const b64u = (buf) => Buffer.from(buf).toString('base64url');

export async function rsaKey() {
  const kp = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', kp.publicKey); return { priv: kp.privateKey, jwk: { ...jwk, kid: 'k1' } };
}
export async function actionsToken(key, claims = {}, header = {}) {
  const now = Math.floor(Date.now() / 1000);
  const c = { iss: 'https://token.actions.githubusercontent.com', aud: ORIGIN, exp: now + 300, nbf: now - 10, repository: REPO, ref: 'refs/heads/main', job_workflow_ref: `${REPO}/.github/workflows/daily.yml@refs/heads/main`, ...claims };
  const h = { alg: 'RS256', kid: 'k1', ...header };
  const body = b64u(JSON.stringify(h)) + '.' + b64u(JSON.stringify(c));
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key.priv, new TextEncoder().encode(body));
  return body + '.' + b64u(sig);
}

export async function world() {
  const db = newDb(); const key = await rsaKey();
  const perms = {};            // token -> {admin, maintain, push, triage} or 'down'
  let clock = Math.floor(Date.now() / 1000), n = 0;
  const env = { DB: db, REPO, PUBLIC_URL: ORIGIN, OIDC_AUDIENCE: ORIGIN, GITHUB_CLIENT_ID: 'cid', GITHUB_CLIENT_SECRET: 'sec', TOKEN_ENC_KEY: Buffer.alloc(32, 7).toString('base64') };
  const deps = {
    now: () => clock, uuid: () => `00000000-0000-4000-8000-${String(++n).padStart(12, '0')}`,
    fetch: async (url, init = {}) => {
      if (String(url).includes('/.well-known/jwks')) return new Response(JSON.stringify({ keys: [key.jwk] }));
      if (String(url).endsWith(`/repos/${REPO}`)) {
        const token = (init.headers?.Authorization || '').replace('Bearer ', ''); const p = perms[token];
        if (p === 'down') return new Response('boom', { status: 502 });
        if (p === 'denied') return new Response('no', { status: 403 });   // GitHub refuses the repository to this person (permissions removed)
        if (!p) return new Response('no', { status: 401 });
        return new Response(JSON.stringify({ permissions: p }));
      }
      return new Response('{}', { status: 404 });
    },
  };
  const w = {
    db, env, deps, key, perms, tick: (s) => { clock += s; }, now: () => clock,
    async login(login, permission, { id = 1 } = {}) {
      const token = `tok-${login}`; perms[token] = permission === 'down' ? 'down' : permission; const s = await createSession(db, { login, id, token }, clock, env);
      return { cookie: `__Host-mg_session=${s.id}`, csrf: s.csrf, sid: s.id };
    },
    async call(method, path, { user, body, headers = {}, csrf = true, origin = true, bearer } = {}) {
      const h = { ...headers };
      if (user) h.Cookie = user.cookie;
      if (user && method !== 'GET' && csrf) h['X-CSRF-Token'] = user.csrf;
      if (user && method !== 'GET' && origin) h.Origin = ORIGIN;
      if (bearer) h.Authorization = `Bearer ${bearer}`;
      if (body !== undefined) h['Content-Type'] = 'application/json';
      const r = await handle(new Request(ORIGIN + path, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) }), env, deps);
      const text = await r.text(); let data; try { data = JSON.parse(text); } catch { data = text; }
      return { status: r.status, data, headers: r.headers };
    },
    async pipelineToken(workflow = 'daily.yml', claims = {}) { return actionsToken(key, { job_workflow_ref: `${REPO}/.github/workflows/${workflow}@refs/heads/main`, ...claims }); },
    async submit(items, workflow = 'daily.yml') { return this.call('POST', '/api/pipeline/submit', { bearer: await this.pipelineToken(workflow), body: { run_id: '1', candidates: items } }); },
  };
  return w;
}
// The service now checks that content hashes to its sha256, so the fixtures use the real hash of their content.
const contentFor = (c) => `rule R_${c} { condition: true }`;
export const hashOf = (text) => createHash('sha256').update(text).digest('hex');
export const sha = (c) => hashOf(contentFor(c));
export const cand = (c, path = `rules/x/${c}.yar`, extra = {}) => {
  const content_b64 = extra.content_b64 ?? Buffer.from(contentFor(c)).toString('base64');
  return { sha256: extra.sha256 ?? hashOf(Buffer.from(content_b64, 'base64')), path, source: 'nextron', commit: 'abc', reasons: ['costly-regex'], bytes: 120, metrics: { cpu_s: 1.2, rss_mb: 40 }, ...extra, content_b64 };
};
export const rid = () => 'req_' + Math.random().toString(36).slice(2).padEnd(20, 'x');
