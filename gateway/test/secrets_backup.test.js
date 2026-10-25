import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';

const TOOL = new URL('../tools/secrets_backup.mjs', import.meta.url).pathname;
test('secrets are exported encrypted for an age recipient, round-trip exactly, and the tool refuses temporary folders and bad input', { skip: !existsSync('/usr/local/bin/age') || process.platform !== 'darwin' }, () => {
  const svc = 'macguard-test-' + Math.random().toString(36).slice(2), dir = mkdtempSync(join(homedir(), '.mg-test-')), key = join(dir, 'key.txt');
  try {
    execFileSync('age-keygen', ['-o', key], { stdio: 'ignore' }); const pub = execFileSync('age-keygen', ['-y', key], { encoding: 'utf8' }).trim();
    for (const [n, v] of [['A', 'secret-value-one'], ['B', 'second/value+=_-']]) execFileSync('security', ['add-generic-password', '-U', '-s', svc, '-a', n, '-w', v]);
    const out = join(dir, 'backup.age'), r = spawnSync('node', [TOOL, '--recipient', pub, '--out', out, '--service', svc, '--names', 'A,B'], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr); assert.ok(!r.stdout.includes('secret-value-one') && !r.stdout.includes('second/'), 'values never printed');
    assert.ok(!readFileSync(out).includes('secret-value-one'), 'ciphertext only');
    const plain = JSON.parse(execFileSync('age', ['-d', '-i', key, out], { encoding: 'utf8' })); assert.deepEqual(plain.secrets, { A: 'secret-value-one', B: 'second/value+=_-' });
    assert.notEqual(spawnSync('node', [TOOL, '--recipient', pub, '--out', join(tmpdir(), 'x.age'), '--service', svc, '--names', 'A'], { encoding: 'utf8' }).status, 0, 'temporary folder refused');
    assert.notEqual(spawnSync('node', [TOOL, '--recipient', 'not-a-key', '--out', out], { encoding: 'utf8' }).status, 0);
    assert.notEqual(spawnSync('node', [TOOL, '--recipient', pub, '--out', join(dir, 'm.age'), '--service', svc, '--names', 'A,MISSING'], { encoding: 'utf8' }).status, 0, 'a missing secret fails loudly');
  } finally { for (const n of ['A', 'B']) spawnSync('security', ['delete-generic-password', '-s', svc, '-a', n], { stdio: 'ignore' }); rmSync(dir, { recursive: true, force: true }); }
});
