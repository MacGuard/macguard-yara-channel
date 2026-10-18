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
export function clearCookie() { return `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`; }

export async function createSession(db, user, now, ttl = 8 * 3600) {
  const id = randomToken(32), csrf = randomToken(24);
  await db.prepare('INSERT INTO sessions (id, login, user_id, token, csrf, created_at, expires_at) VALUES (?,?,?,?,?,?,?)').bind(id, user.login, user.id, user.token, csrf, now, now + ttl).run();
  return { id, csrf, ttl };
}
export async function getSession(db, request, now) {
  const sid = parseCookies(request.headers.get('Cookie'))[COOKIE]; if (!sid || !/^[0-9a-f]{64}$/.test(sid)) return null;
  const s = await db.prepare('SELECT * FROM sessions WHERE id = ?').bind(sid).first();
  if (!s || s.expires_at <= now) return null; return s;
}
export async function destroySession(db, id) { await db.prepare('DELETE FROM sessions WHERE id = ?').bind(id).run(); }

/** The role is recomputed from GitHub on every protected call (cached 60 s). Fail closed when GitHub cannot be asked. */
export async function effectiveRole(db, session, env, deps, now) {
  let perm = session.perm;
  if (!perm || now - session.perm_at > 60) {
    try {
      const r = await deps.fetch(`${env.GITHUB_API || 'https://api.github.com'}/repos/${env.REPO}`, { headers: { Authorization: `Bearer ${session.token}`, Accept: 'application/vnd.github+json', 'User-Agent': 'macguard-admin' } });
      if (r.status === 401 || r.status === 403 || r.status === 404) { perm = 'none'; }
      else if (!r.ok) throw new Error(`GitHub ${r.status}`);
      else { const p = (await r.json()).permissions || {}; perm = p.admin ? 'admin' : p.maintain ? 'maintain' : p.push ? 'write' : p.triage ? 'triage' : 'read'; }
      await db.prepare('UPDATE sessions SET perm = ?, perm_at = ? WHERE id = ?').bind(perm, now, session.id).run();
    } catch (e) {
      if (!session.perm || now - session.perm_at > 600) return null;   // stale or unknown: no access
      perm = session.perm;
    }
  }
  return highestRole(roleFromRepoPermission(perm), await memberRole(db, session.login));
}

// ---- GitHub OAuth ----------------------------------------------------------------------------
export async function startLogin(db, env, now) {
  const state = randomToken(16);
  await db.prepare('INSERT INTO oauth_states (state, expires_at) VALUES (?,?)').bind(state, now + 600).run();
  const q = new URLSearchParams({ client_id: env.GITHUB_CLIENT_ID, redirect_uri: `${env.PUBLIC_URL}/auth/callback`, state, scope: 'read:user', allow_signup: 'false' });
  return `${env.GITHUB_OAUTH_BASE || 'https://github.com'}/login/oauth/authorize?${q}`;
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
  const user = await u.json(); return { ok: true, user: { login: user.login, id: user.id, token: tok.access_token } };
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
  if (claims.aud !== env.OIDC_AUDIENCE) return fail('wrong audience');
  if (!(claims.exp > now - 30)) return fail('token expired'); if (claims.nbf && claims.nbf > now + 30) return fail('token not yet valid');
  if (claims.repository !== env.REPO) return fail('wrong repository');
  if (claims.ref !== 'refs/heads/main') return fail('only the main branch may call the pipeline API');
  const allowed = (env.PIPELINE_WORKFLOWS || 'daily.yml,publish.yml').split(',').map((w) => `${env.REPO}/.github/workflows/${w.trim()}@refs/heads/main`);
  if (!allowed.includes(claims.job_workflow_ref)) return fail('this workflow is not allowed to call the pipeline API');
  return { ok: true, claims, workflow: claims.job_workflow_ref.split('@')[0].split('/').pop() };
}
