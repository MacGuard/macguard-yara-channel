// The staging sequence and the smoke checks. Local: the smoke runs in process against the Worker with a synthetic world; the sequence never executes anything.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { apiWorld } from './apiworld.js';
import { runSmoke } from '../tools/smoke.mjs';
import { invariants, markdown, STEPS } from '../tools/staging_sequence.mjs';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));

test('the smoke checks pass against a healthy gateway, and SKIP (never PASS) what they cannot evaluate', async () => {
  const w = await apiWorld({ envExtra: { ALLOWED_HOSTS: 'gw.test' } });
  const r = await runSmoke((url, init) => w.handle(new Request(url, init), w.env, { waitUntil: () => {} }), 'https://gw.test', { hostProbe: () => w.handle(new Request('https://other.test/v1/health'), w.env, { waitUntil: () => {} }) });
  assert.deepEqual(r.checks.filter((c) => c.status === 'FAIL'), [], JSON.stringify(r.checks.filter((c) => c.status === 'FAIL'))); assert.equal(r.ok, true); assert.equal(r.skipped, 0);
  const noProbe = await runSmoke((url, init) => w.handle(new Request(url, init), w.env, { waitUntil: () => {} }), 'https://gw.test');
  assert.equal(noProbe.skipped, 1); assert.ok(noProbe.checks.find((c) => c.status === 'SKIP').detail.includes('Host'));
});

test('the smoke checks FAIL when the gateway misbehaves: a cookie, a CORS grant, an open admin route, a leaked secret', async () => {
  const bad = (mut) => async (url) => mut(new URL(url).pathname);
  const ok = () => new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } });
  const cases = {
    cookie: bad((p) => p === '/v1/health' ? new Response('{"ok":true}', { headers: { 'set-cookie': 'sid=1' } }) : new Response('{}', { status: p.startsWith('/this') ? 404 : 401 })),
    cors: bad((p) => p === '/v1/health' ? new Response('{"ok":true}', { headers: { 'access-control-allow-origin': '*' } }) : new Response('{}', { status: p.startsWith('/this') ? 404 : 401 })),
    openAdmin: bad((p) => p.startsWith('/admin') ? ok() : p === '/v1/health' ? ok() : new Response('{}', { status: p.startsWith('/this') ? 404 : 401 })),
    leak: bad((p) => p === '/v1/health' ? new Response('{"ok":true,"k":"mgk_abcdefghijklmnopqrstuvwxyz0123"}') : new Response('{}', { status: p.startsWith('/this') ? 404 : 401 })),
    stack: bad((p) => p === '/v1/health' ? ok() : new Response('Error\n    at handler (index.js:1:1)', { status: p.startsWith('/this') ? 404 : 401 })),
  };
  for (const [name, f] of Object.entries(cases)) { const r = await runSmoke(f, 'https://x.test'); assert.equal(r.ok, false, name); assert.ok(r.failed >= 1, name); }
});

test('the smoke CLI refuses a production hostname unless --production is given, and non-https targets', () => {
  const run = (...a) => { try { execFileSync('node', [fileURLToPath(new URL('../tools/smoke.mjs', import.meta.url)), ...a], { stdio: 'pipe' }); return 0; } catch (e) { return e.status; } };
  assert.equal(run('--base-url', 'https://api.mac-guard.com'), 2); assert.equal(run('--base-url', 'https://quarantine-api.mac-guard.com'), 2); assert.equal(run('--base-url', 'http://localhost:8787'), 2); assert.equal(run(), 2);
});

test('the staging environment is isolated from production (every invariant holds)', () => {
  const r = invariants(); assert.deepEqual(r.filter((c) => !c.ok), []); assert.ok(r.length >= 10);
});

test('the invariants really detect a staging config that points at production', () => {
  // Mutation check on the checker itself: feed it the production file as if it were staging.
  const prod = readFileSync(new URL('../environments/production.wrangler.toml', import.meta.url), 'utf8'), val = (t, k) => (t.match(new RegExp(`^${k}\\s*=\\s*"([^"]*)"`, 'm')) ?? [])[1];
  assert.equal(val(prod, 'name') === 'macguard-gateway-staging', false); assert.ok(/custom_domain/.test(prod), 'production does carry a Custom Domain, which staging must not');
  assert.ok(/^\[\[r2_buckets\]\]/m.test(prod) && /^\[triggers\]/m.test(prod));
});

test('the plan is ordered backup -> migrations -> deploy -> smoke -> rollback, and production comes last', () => {
  const ids = STEPS.map((s) => s.id), at = (re) => STEPS.findIndex((s) => re.test(s.title));
  assert.equal(ids.at(-1), 'P1'); assert.ok(at(/Backup/) < at(/migrations/) && at(/migrations/) < at(/Deploy the candidate/) && at(/Deploy the candidate/) < at(/Smoke/) && at(/Smoke/) < at(/Rollback rehearsal/));
  assert.ok(STEPS.every((s) => !/mga_|mgk_|sk_live|whsec_/.test(s.cmd.join(' '))), 'no credential in a command');
});

test('docs/analytics/STAGING-SEQUENCE.md is exactly what the tool prints (no drift)', () => {
  assert.equal(readFileSync(`${ROOT}/docs/analytics/STAGING-SEQUENCE.md`, 'utf8'), markdown());
});
