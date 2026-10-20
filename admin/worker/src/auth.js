// Authentication and authorization. Nothing privileged is ever sent to the browser: the GitHub token stays in D1.
import { highestRole, roleFromRepoPermission } from './core.js';
import { memberRole } from './store.js';

export const COOKIE = '__Host-mg_session';
const enc = new TextEncoder();
export function randomToken(bytes = 32) { const a = crypto.getRandomValues(new Uint8Array(bytes)); return [...a].map((b) => b.toString(16).padStart(2, '0')).join(''); }
export function timingSafeEqual(a, b) {
  const x = enc.encode(String(a)), y = enc.encode(String(b)); if (x.length !== y.length) return false;
  let d = 0; for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i]; return d === 0;
}
export function parseCookies(header) { const out = {}; for (const part of (header || '').split(/;\s*/)) { const i = part.indexOf('='); if (i > 0) out[part.slice(0, i)] = part.slice(i + 1); } return out; }
export function sessionCookie(id, maxAge) { return `${COOKIE}=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`; }
export const STATE_COOKIE = '__Host-mg_oauth';
export function stateCookie(state) { return `${STATE_COOKIE}=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`; }   // Lax: GitHub returns with a cross-site top-level GET
export function clearStateCookie() { return `${STATE_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`; }
export function clearCookie() { return `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`; }

// The GitHub access token is sealed at rest (AES-256-GCM, key = Worker secret TOKEN_ENC_KEY, bound to the session id): a copy of D1 alone
// does not yield usable tokens. A missing or malformed key throws, so the service cannot silently fall back to plaintext.
const toB64 = (u8) => btoa(String.fromCharCode(...u8));
const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
async function aesKey(env) {
  const raw = fromB64(env.TOKEN_ENC_KEY || '');
  if (raw.length !== 32) throw new Error('TOKEN_ENC_KEY must be 32 random bytes, base64-encoded');
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
export async function sealToken(env, sessionId, token) {
  const key = await aesKey(env), iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(sessionId) }, key, enc.encode(token)));
  return `v1.${toB64(iv)}.${toB64(ct)}`;
}
/** null when the value is not a valid seal for this session (legacy plaintext, tampering, another session's row). */
export async function openToken(env, sessionId, sealed) {
  const key = await aesKey(env), parts = String(sealed || '').split('.');
  if (parts.length !== 3 || parts[0] !== 'v1') return null;
  try { return new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(parts[1]), additionalData: enc.encode(sessionId) }, key, fromB64(parts[2]))); } catch { return null; }
}
/** Returned by effectiveRole when the GitHub authorization itself is gone (revoked or expired token): the person must sign in again. */
export const REAUTH = 'REAUTH';

export async function createSession(db, user, now, env, ttl = 8 * 3600) {
  const id = randomToken(32), csrf = randomToken(24);
  if (user.expires_in) ttl = Math.max(60, Math.min(ttl, Number(user.expires_in) - 60));   // never outlive an expiring GitHub token
  await db.prepare('INSERT INTO sessions (id, login, user_id, token, csrf, created_at, expires_at) VALUES (?,?,?,?,?,?,?)').bind(id, user.login, user.id, await sealToken(env, id, user.token), csrf, now, now + ttl).run();
  return { id, csrf, ttl };
}
export async function getSession(db, request, now) {
  const sid = parseCookies(request.headers.get('Cookie'))[COOKIE]; if (!sid || !/^[0-9a-f]{64}$/.test(sid)) return null;
  const s = await db.prepare('SELECT * FROM sessions WHERE id = ?').bind(sid).first();
  if (!s || s.expires_at <= now) return null; return s;
}
export async function destroySession(db, id) { await db.prepare('DELETE FROM sessions WHERE id = ?').bind(id).run(); }

/** The role is recomputed from GitHub on every protected call (cached 60 s). Fail closed when GitHub cannot be asked.
 *  A 401 means the person's token was revoked or expired: the session is destroyed and REAUTH is returned (no role survives, not even a `members` grant).
 *  A 403/404 means GitHub denies the repository to this person (permissions removed): only an explicit `members` grant can still give a role. */
export async function effectiveRole(db, session, env, deps, now, { fresh = false } = {}) {
  let perm = session.perm;
  if (fresh || !perm || now - session.perm_at > 60) {   // `fresh`: a change of state always asks GitHub again, and never falls back to a stale grant
    const token = await openToken(env, session.id, session.token);
    if (!token) { await destroySession(db, session.id); return REAUTH; }
    try {
      const r = await deps.fetch(`${env.GITHUB_API || 'https://api.github.com'}/repos/${env.REPO}`, { headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'User-Agent': 'macguard-admin' } });
      if (r.status === 401) { await destroySession(db, session.id); return REAUTH; }
      else if (r.status === 403 || r.status === 404) { perm = 'none'; }
      else if (!r.ok) throw new Error(`GitHub ${r.status}`);
      else { const p = (await r.json()).permissions || {}; perm = p.admin ? 'admin' : p.maintain ? 'maintain' : p.push ? 'write' : p.triage ? 'triage' : 'read'; }
      await db.prepare('UPDATE sessions SET perm = ?, perm_at = ? WHERE id = ?').bind(perm, now, session.id).run();
    } catch (e) {
      if (fresh || !session.perm || now - session.perm_at > 600) return null;   // stale or unknown: no access (reads may use a grant up to 10 minutes old, writes never)
      perm = session.perm;
    }
  }
  return highestRole(roleFromRepoPermission(perm), await memberRole(db, session.login, session.user_id));
}

/** Resolve a GitHub account with the acting administrator's own token. `by` is {id} (authoritative) or {login} (lookup for the add form). Returns
 *  {ok, account:{id, login, type}} or {ok:false, status, error}. Only real user accounts can be members. */
export async function resolveGithubAccount(deps, env, token, by) {
  const path = by.id != null ? `/user/${encodeURIComponent(by.id)}` : `/users/${encodeURIComponent(by.login)}`;
  let r; try { r = await deps.fetch(`${env.GITHUB_API || 'https://api.github.com'}${path}`, { headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'User-Agent': 'macguard-admin' } }); } catch { return { ok: false, status: 502, error: 'GitHub could not be reached; nothing was changed' }; }
  if (r.status === 401) return { ok: false, status: 401, error: 'sign in again: your GitHub authorization is no longer valid' };
  if (r.status === 404) return { ok: false, status: 404, error: 'no such GitHub account' };
  if (!r.ok) return { ok: false, status: 502, error: `GitHub answered ${r.status}; nothing was changed` };
  const u = await r.json();
  if (u.type !== 'User' || !Number.isInteger(u.id) || typeof u.login !== 'string') return { ok: false, status: 400, error: 'only personal GitHub accounts can be members' };
  if (by.id != null && u.id !== Number(by.id)) return { ok: false, status: 409, error: 'GitHub returned a different account id' };
  return { ok: true, account: { id: u.id, login: u.login, type: u.type } };
}

// ---- GitHub OAuth ----------------------------------------------------------------------------
export async function startLogin(db, env, now) {
  const state = randomToken(16);
  await db.prepare('INSERT INTO oauth_states (state, expires_at) VALUES (?,?)').bind(state, now + 600).run();
  const q = new URLSearchParams({ client_id: env.GITHUB_CLIENT_ID, redirect_uri: `${env.PUBLIC_URL}/auth/callback`, state, scope: 'read:user', allow_signup: 'false' });
  return { location: `${env.GITHUB_OAUTH_BASE || 'https://github.com'}/login/oauth/authorize?${q}`, state };
}
export async function finishLogin(db, env, code, state, deps, now) {
  const row = await db.prepare('SELECT * FROM oauth_states WHERE state = ?').bind(state || '').first();
  if (!row || row.expires_at <= now) return { ok: false, error: 'login state is unknown or expired' };
  await db.prepare('DELETE FROM oauth_states WHERE state = ?').bind(state).run();   // single use
  const t = await deps.fetch(`${env.GITHUB_OAUTH_BASE || 'https://github.com'}/login/oauth/access_token`, { method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'User-Agent': 'macguard-admin' },
    body: JSON.stringify({ client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET, code, redirect_uri: `${env.PUBLIC_URL}/auth/callback` }) });
  const tok = await t.json(); if (!tok.access_token) return { ok: false, error: 'GitHub refused the code' };
  const u = await deps.fetch(`${env.GITHUB_API || 'https://api.github.com'}/user`, { headers: { Authorization: `Bearer ${tok.access_token}`, 'User-Agent': 'macguard-admin' } });
  if (!u.ok) return { ok: false, error: 'could not read the GitHub profile' };
  const user = await u.json(); return { ok: true, user: { login: user.login, id: user.id, token: tok.access_token, expires_in: tok.expires_in } };
}

// ---- GitHub Actions OIDC (pipeline -> service, no stored secret) ----------------------------
const b64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=')), (c) => c.charCodeAt(0));
export async function verifyActionsToken(token, env, deps, now) {
  const fail = (m) => ({ ok: false, error: m });
  const parts = String(token || '').split('.'); if (parts.length !== 3) return fail('not a JWT');
  let header, claims; try { header = JSON.parse(new TextDecoder().decode(b64u(parts[0]))); claims = JSON.parse(new TextDecoder().decode(b64u(parts[1]))); } catch { return fail('malformed JWT'); }
  if (header.alg !== 'RS256') return fail('only RS256 is accepted');
  const jwks = await (await deps.fetch(env.OIDC_JWKS || 'https://token.actions.githubusercontent.com/.well-known/jwks')).json();
  const jwk = (jwks.keys || []).find((k) => k.kid === header.kid); if (!jwk) return fail('unknown signing key');
  const key = await crypto.subtle.importKey('jwk', { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: 'RS256', ext: true }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  if (!(await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64u(parts[2]), enc.encode(parts[0] + '.' + parts[1])))) return fail('bad signature');
  if (claims.iss !== (env.OIDC_ISSUER || 'https://token.actions.githubusercontent.com')) return fail('wrong issuer');
  if (!env.OIDC_AUDIENCE || claims.aud !== env.OIDC_AUDIENCE) return fail('wrong audience');
  if (!(claims.exp > now - 30)) return fail('token expired'); if (claims.nbf && claims.nbf > now + 30) return fail('token not yet valid');
  if (claims.repository !== env.REPO) return fail('wrong repository');
  if (claims.ref !== 'refs/heads/main') return fail('only the main branch may call the pipeline API');
  const allowed = (env.PIPELINE_WORKFLOWS || 'daily.yml,publish.yml').split(',').map((w) => `${env.REPO}/.github/workflows/${w.trim()}@refs/heads/main`);
  if (!allowed.includes(claims.job_workflow_ref)) return fail('this workflow is not allowed to call the pipeline API');
  return { ok: true, claims, workflow: claims.job_workflow_ref.split('@')[0].split('/').pop() };
}
