import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { routes, AREAS, render } from '../tools/route_inventory.mjs';
import { RULES, matches } from '../hardening/rules.js';
import { apiWorld } from './apiworld.js';
import { fromBase32, totp, stepOf } from '../src/totp.js';
import { createAdmin } from '../src/admin.js';

const fill = (p) => p.replace('/dashboards/{id}', '/dashboards/api').replace('/proposals/{id}', '/proposals/pp_' + '0'.repeat(20)).replace('/leads/{id}', '/leads/ld_' + '0'.repeat(16)).replace('{token}', 'dlt_' + 'A'.repeat(43)).replace('{key}', '0'.repeat(16)).replace('{id}', 'x1').replace('{kind}', 'daily').replace('{any}', 'x').replace('{sha256}', 'a'.repeat(64));
test('the committed inventory is current and every route has an area with all its columns', () => {
  execFileSync('node', [new URL('../tools/route_inventory.mjs', import.meta.url).pathname, '--check']);
  for (const r of routes()) { assert.ok(AREAS[r.area], r.path); for (const c of ['what', 'auth', 'perm', 'deps', 'risk', 'smoke', 'rollback']) assert.ok(AREAS[r.area][c], `${r.area}.${c}`); }
});
test('every listed route really exists in the router (a documented method+path never answers the generic "Not found."), so the inventory cannot drift', async () => {
  const w = await apiWorld({ envExtra: { KEY_PEPPER: 'k'.repeat(40) } }), adm = await createAdmin(w.env.DB, w.env, w.clock, { name: 'root' }), seed = fromBase32(adm.totp_seed_base32);
  const hdr = async () => { w.clock.advance(60000); return { authorization: `Bearer ${adm.key}`, 'x-mfa-code': await totp(seed, stepOf(w.clock().getTime())) }; };
  for (const r of routes()) {
    if (r.path === '/x402/{any}') continue;                                                                                                 // disabled on purpose: answers 404 until enabled
    const res = await w.call(fill(r.path), { method: r.method, json: ['POST', 'PUT'].includes(r.method) ? {} : undefined, headers: r.area.startsWith('admin') ? await hdr() : {} });
    assert.ok(!(res.status === 404 && res.json?.error?.message === 'Not found.'), `${r.method} ${r.path} -> ${res.status} ${res.text.slice(0, 80)}`);
    if (r.area.startsWith('admin')) assert.notEqual(res.status, 401, `${r.method} ${r.path}: the administrator must reach it`);
  }
});
test('an undocumented path is a 404, and no listed Community or health route is touched by an edge limit or block', async () => {
  const w = await apiWorld({ envExtra: { KEY_PEPPER: 'k'.repeat(40) } }); assert.equal((await w.call('/v1/not-a-route')).status, 404); assert.equal((await w.call('/admin/v1/nope')).status, 401);
  for (const r of routes().filter((x) => x.area === 'community' || x.area === 'health')) assert.deepEqual(RULES.filter((x) => matches(x, { method: r.method, path: fill(r.path), host: 'api.mac-guard.com' }, 'api.mac-guard.com')).map((x) => x.id), [], `${r.method} ${r.path}`);
  assert.ok(render().includes('quarantine-api.mac-guard.com'));
});
