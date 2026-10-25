import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { checkSecret, upload, SHAPES } from '../tools/set_worker_secret.mjs';

const GOOD = 'github_pat_' + 'A1b2C3d4_'.repeat(6), CLASSIC = 'ghp_' + 'a1B2c3D4'.repeat(5);
test('only well-shaped values for known secrets are accepted; whitespace noise is trimmed, interior whitespace and wrong shapes are refused, and the value is never echoed', () => {
  assert.equal(checkSecret('GITHUB_TOKEN', GOOD + '\n').ok, true); assert.equal(checkSecret('GITHUB_TOKEN', '  ' + CLASSIC + '  \n').ok, true); assert.equal(checkSecret('GITHUB_TOKEN', CLASSIC + '\n').length, CLASSIC.length);
  for (const bad of ['', '   ', 'hello world', 'ghp_short', GOOD.slice(0, 20), GOOD + ' extra', 'ghp_' + 'a'.repeat(40) + '\nX-Evil: 1', '"' + GOOD + '"', 'sk_live_' + 'a'.repeat(30)]) { const r = checkSecret('GITHUB_TOKEN', bad); assert.equal(r.ok, false, JSON.stringify(bad)); assert.ok(!JSON.stringify(r).includes('A1b2C3d4'), 'the reason never contains the value'); }
  assert.equal(checkSecret('KEY_PEPPER', 'x'.repeat(40)).ok, true, 'shape only: whether a pepper may be set is decided by the Worker name (staging only), tested below'); assert.equal(checkSecret('STRIPE_API_KEY', 'sk_live_' + 'a'.repeat(30)).ok, false, 'payment keys are never set through this tool'); assert.deepEqual(Object.keys(SHAPES).sort(), ['ADMIN_PEPPER', 'GITHUB_TOKEN', 'GUARDOPS_INGEST_TOKEN', 'KEY_PEPPER', 'TOTP_SEAL_KEY']);
});
test('upload sends the value only through stdin to `wrangler secret put <name>` for the account in the config, never in the arguments', () => {
  const calls = []; const { mkdtempSync, writeFileSync, rmSync } = require_fs(); const d = mkdtempSync(new URL('file:///tmp/').pathname + 'mgs-'); const cfg = d + '/w.toml'; writeFileSync(cfg, 'account_id = "9e96e19f6dc0ccdd53e02f7c3b5cacab"\n');
  try { upload('GITHUB_TOKEN', GOOD, cfg, (args, input) => { calls.push({ args, input }); return 'ok'; }); } finally { rmSync(d, { recursive: true }); }
  assert.deepEqual(calls[0].args.slice(0, 3), ['secret', 'put', 'GITHUB_TOKEN']); assert.equal(calls[0].input, GOOD); assert.ok(!calls[0].args.join(' ').includes(GOOD), 'not in the command line'); assert.equal(process.env.CLOUDFLARE_ACCOUNT_ID, '9e96e19f6dc0ccdd53e02f7c3b5cacab');
});
test('the command line tool: dry run validates and prints only a length; a bad value exits non-zero without uploading', () => {
  const tool = new URL('../tools/set_worker_secret.mjs', import.meta.url).pathname, run = (input, ...a) => spawnSync(process.execPath, [tool, ...a], { input, encoding: 'utf8' });
  const ok = run(GOOD + '\n', '--name', 'GITHUB_TOKEN', '--dry-run'); assert.equal(ok.status, 0); assert.match(ok.stdout, /nothing uploaded/); assert.ok(!(ok.stdout + ok.stderr).includes('A1b2C3d4'), 'the value is not printed');
  const bad = run('not a token\n', '--name', 'GITHUB_TOKEN', '--dry-run'); assert.equal(bad.status, 1); assert.match(bad.stderr, /refused/); assert.equal(run('x', '--name', 'NOPE').status, 1);
});
function require_fs() { return { mkdtempSync: (p) => nodeFs.mkdtempSync(p), writeFileSync: (...a) => nodeFs.writeFileSync(...a), rmSync: (...a) => nodeFs.rmSync(...a) }; }
import * as nodeFs from 'node:fs';

test('the gateway peppers can be set only on a Worker whose name ends in -staging; production refuses them; the real configs behave that way', async () => {
  const { placeAllowed, checkSecret } = await import('../tools/set_worker_secret.mjs'), env = (n) => new URL(`../environments/${n}`, import.meta.url).pathname;
  for (const n of ['KEY_PEPPER', 'ADMIN_PEPPER', 'TOTP_SEAL_KEY']) { assert.equal(placeAllowed(n, env('production.wrangler.toml')), false, n); assert.equal(placeAllowed(n, env('production-target.wrangler.toml')), false, n); assert.equal(placeAllowed(n, env('staging.wrangler.toml')), true, n); }
  assert.equal(placeAllowed('GITHUB_TOKEN', env('production.wrangler.toml')), true, 'the read-only token is a production secret');
  assert.equal(checkSecret('KEY_PEPPER', 'short').ok, false); assert.equal(checkSecret('KEY_PEPPER', 'A'.repeat(48)).ok, true);
});
