// Smoke and security checks for a deployed gateway. READ-ONLY: GETs and unauthenticated requests that must be refused; it creates, charges and deletes nothing, and it carries no credential.
// `runSmoke(fetchFn, base)` is the same code used in-process by the tests (a fake fetch over the Worker) and against a real URL from the command line:
//   node tools/smoke.mjs --base-url https://<staging worker>   (exit 0 = every check passed, 1 = at least one failed)
// A check that cannot be evaluated says SKIP with the reason; SKIP is never counted as a pass.
const SENSITIVE = /(sk_(live|test)_|whsec_|mga_|mgk_)[A-Za-z0-9_]{6,}|-----BEGIN|AGE-SECRET-KEY-/;

export async function runSmoke(doFetch, base, { hostProbe = null } = {}) {
  const out = []; const add = (name, ok, detail = '') => out.push({ name, status: ok === null ? 'SKIP' : ok ? 'PASS' : 'FAIL', detail });
  const get = (path, init = {}) => doFetch(base + path, { redirect: 'manual', ...init });
  const seen = [];   // every response, to check headers that must never appear anywhere

  const h = await get('/v1/health'); seen.push(h); const hb = await h.clone().json().catch(() => null);
  add('health answers 200 {ok:true}', h.status === 200 && hb?.ok === true, `status ${h.status}`);

  const c = await get('/v1/community/releases/latest'); seen.push(c);
  add('Community latest answers (200, or a redirect to the configured origin) without credentials', c.status === 200 || (c.status >= 300 && c.status < 400), `status ${c.status}`);

  for (const [path, init, want, name] of [
    ['/admin/v1/analytics/kpis', {}, [401, 403, 404], 'admin analytics refuses an anonymous caller'],
    ['/admin/v1/tenants', {}, [401, 403, 404], 'tenant administration refuses an anonymous caller'],
    ['/admin/v1/policy', {}, [401, 403, 404], 'policy administration refuses an anonymous caller'],
    ['/v1/account/usage', {}, [401, 403], 'a tenant route refuses a call without a key'],
    ['/v1/account/usage', { headers: { authorization: 'Bearer mga_not_a_real_key_0000000000000000' } }, [401, 403], 'an administrator-shaped token does not open a tenant route'],
    ['/mcp', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' }, [401, 403], 'MCP refuses a call without a key'],
    ['/this/route/does/not/exist', {}, [404], 'an unknown path is a plain 404'],
  ]) { const r = await get(path, init); seen.push(r); add(name, want.includes(r.status), `status ${r.status}, expected ${want.join('/')}`); }

  // The gateway authenticates by header: no cookie may exist, and no CORS grant may be given (it would let a browser page of another subdomain read answers).
  add('no response sets a cookie', seen.every((r) => !r.headers.get('set-cookie')), `${seen.filter((r) => r.headers.get('set-cookie')).length} response(s) set one`);
  add('no response grants CORS', seen.every((r) => !r.headers.get('access-control-allow-origin')), '');
  const bodies = await Promise.all(seen.map((r) => r.clone().text().catch(() => '')));
  add('no response body or header contains a secret-shaped value', bodies.every((t, i) => !SENSITIVE.test(t) && ![...seen[i].headers.values()].some((v) => SENSITIVE.test(v))), '');
  add('an error body does not reveal internals (stack, binding names)', bodies.every((t) => !/\n\s+at |binding|wrangler|cloudflare_account/i.test(t)), '');

  if (hostProbe) { const r = await hostProbe(); add('a hostname the Worker does not own answers 404 (host gate)', r.status === 404, `status ${r.status}`); }
  else add('a hostname the Worker does not own answers 404 (host gate)', null, 'needs an in-process host probe; a real URL cannot change its Host header');
  return { base, ok: out.every((x) => x.status !== 'FAIL'), passed: out.filter((x) => x.status === 'PASS').length, failed: out.filter((x) => x.status === 'FAIL').length, skipped: out.filter((x) => x.status === 'SKIP').length, checks: out };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const i = process.argv.indexOf('--base-url'), base = i > 0 ? process.argv[i + 1] : null;
  if (!base || !/^https:\/\/[a-z0-9.-]+$/.test(base)) { console.error('usage: smoke.mjs --base-url https://host   (https only, no path)'); process.exit(2); }
  if (/^https:\/\/(api|quarantine-api|panel|rules)\.mac-guard\.com$/.test(base) && !process.argv.includes('--production')) { console.error('refusing a production hostname without --production: this tool is for the staging step of docs/analytics/STAGING-SEQUENCE.md'); process.exit(2); }
  const r = await runSmoke(fetch, base);
  for (const c of r.checks) console.log(`${c.status}  ${c.name}${c.detail ? ' (' + c.detail + ')' : ''}`);
  console.log(`\n${r.passed} passed, ${r.failed} failed, ${r.skipped} skipped -> ${r.ok ? 'OK' : 'FAILED'}`); process.exit(r.ok ? 0 : 1);
}
