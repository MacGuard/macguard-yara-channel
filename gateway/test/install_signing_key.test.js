// install_signing_key.sh: a restore can never leave a truncated or wrong key in place. Throw-away keys only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, statSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const SH = new URL('../tools/install_signing_key.sh', import.meta.url).pathname;
const gen = (f) => execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 't', '-f', f]);
const run = (key, input) => spawnSync('sh', [SH, key], { input, encoding: 'utf8' });

test('installs a matching key atomically with mode 400, and refuses empty input, a wrong key, garbage and an existing key without touching the target', () => {
  const d = mkdtempSync(join(tmpdir(), 'mg-inst-')); try {
    const src = join(d, 'src'), other = join(d, 'other'), key = join(d, 'live'); gen(src); gen(other); writeFileSync(key + '.pub', readFileSync(src + '.pub'));
    let r = run(key, ''); assert.equal(r.status, 1); assert.match(r.stdout, /nothing came in/); assert.equal(existsSync(key), false);
    r = run(key, readFileSync(other)); assert.equal(r.status, 1); assert.match(r.stdout, /does not match/); assert.equal(existsSync(key), false);
    r = run(key, 'not a key\n'); assert.equal(r.status, 1); assert.match(r.stdout, /not a usable private key/); assert.equal(existsSync(key), false);
    assert.deepEqual(readdirSync(d).filter((f) => f.startsWith('.install')), [], 'no temp file is left behind');
    r = run(key, readFileSync(src)); assert.equal(r.status, 0, r.stdout); assert.equal((statSync(key).mode & 0o777).toString(8), '400'); assert.deepEqual(readFileSync(key), readFileSync(src));
    const before = readFileSync(key); r = run(key, readFileSync(other)); assert.equal(r.status, 1); assert.match(r.stdout, /never replaced/); assert.deepEqual(readFileSync(key), before);
    assert.ok(!/PRIVATE/.test(r.stdout + r.stderr), 'the key is never echoed');
  } finally { rmSync(d, { recursive: true, force: true }); }
});
