import test from 'node:test';
import { HAVE_AGE } from './tools_available.js';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { dumpSql } from '../tools/backup_lib.mjs';
import { runBackup, rekeyBackup, check } from '../tools/backup_flow.mjs';
import { world } from './helpers.js';
import { audit } from '../src/audit.js';

const sha = (b) => createHash('sha256').update(b).digest('hex');
const keypair = (dir, name) => { const f = join(dir, name); execFileSync('age-keygen', ['-o', f], { stdio: 'ignore' }); return { file: f, pub: execFileSync('age-keygen', ['-y', f], { encoding: 'utf8' }).trim() }; };
async function setup() { const w = await world({ now: '2026-10-24T05:00:00Z' }); await w.tenant('t1'); await audit(w.db, w.clock, 't1', 'x.y', {}); const root = mkdtempSync(join(homedir(), '.mg-kc-')), keys = mkdtempSync(join(homedir(), '.mg-kk-'));
  return { w, root, keys, done: () => { rmSync(root, { recursive: true, force: true }); rmSync(keys, { recursive: true, force: true }); } }; }

test('rotating the backup key: the new key opens it, the old key cannot, the original backup is untouched, and bad inputs create nothing', { skip: !HAVE_AGE }, async () => {
  const s = await setup();
  try {
    const oldK = keypair(s.keys, 'old.txt'), newK = keypair(s.keys, 'new.txt'), other = keypair(s.keys, 'other.txt');
    const b = await runBackup({ exportFn: async (p) => writeFileSync(p, dumpSql(s.w.db.raw)), root: s.root, recipient: oldK.pub, clock: () => new Date('2026-10-24T06:00:00Z') });
    const before = sha(readFileSync(join(b.dir, 'd1-export.sql.age')));
    const r = await rekeyBackup({ dir: b.dir, identityFile: oldK.file, newRecipient: newK.pub, newIdentityFile: newK.file, root: s.root, clock: () => new Date('2026-10-25T06:00:00Z') });
    assert.equal(r.ok, true); assert.equal(r.verified_new_key, true); assert.equal(sha(readFileSync(join(b.dir, 'd1-export.sql.age'))), before, 'the original is untouched');
    const nm = JSON.parse(readFileSync(join(r.dir, 'manifest.json'), 'utf8')); assert.equal(nm.rekeyed_from, b.dir.split('/').pop()); assert.equal(nm.plaintext_sha256, b.manifest.plaintext_sha256);
    const dec = execFileSync('age', ['-d', '-i', newK.file, join(r.dir, 'd1-export.sql.age')]); assert.equal(sha(dec), b.manifest.plaintext_sha256, 'the new key restores exactly the verified bytes');
    assert.throws(() => execFileSync('age', ['-d', '-i', oldK.file, join(r.dir, 'd1-export.sql.age')], { stdio: 'pipe' }), /no identity matched|failed/i, 'the old key does not open the new copy');
    const n = readdirSync(s.root).length;
    await assert.rejects(rekeyBackup({ dir: b.dir, identityFile: other.file, newRecipient: newK.pub, root: s.root }), /cannot decrypt/); await assert.rejects(rekeyBackup({ dir: b.dir, identityFile: oldK.file, newRecipient: 'nope', root: s.root }), /public key/);
    writeFileSync(join(b.dir, 'd1-export.sql.age'), Buffer.concat([readFileSync(join(b.dir, 'd1-export.sql.age')), Buffer.from('x')])); await assert.rejects(rekeyBackup({ dir: b.dir, identityFile: oldK.file, newRecipient: newK.pub, root: s.root }), /checksum/);
    assert.equal(readdirSync(s.root).length, n, 'no failed attempt left a directory behind');
    await assert.rejects(rekeyBackup({ dir: b.dir, identityFile: oldK.file, newRecipient: newK.pub, root: '/private/tmp/x' }), /temporary/);
  } finally { s.done(); }
});
test('restoring "on another machine": only the ciphertext, the manifest and the private key text are needed; no Keychain, no home-directory state, no network', { skip: !HAVE_AGE }, async () => {
  const s = await setup();
  try {
    const k = keypair(s.keys, 'k.txt'); const b = await runBackup({ exportFn: async (p) => writeFileSync(p, dumpSql(s.w.db.raw)), root: s.root, recipient: k.pub, clock: () => new Date('2026-10-24T06:00:00Z') });
    const fakeHome = mkdtempSync(join(homedir(), '.mg-home-')), carried = mkdtempSync(join(homedir(), '.mg-carry-'));            // "the other machine": an empty home and only the three carried files
    for (const f of ['d1-export.sql.age', 'manifest.json']) writeFileSync(join(carried, f), readFileSync(join(b.dir, f))); writeFileSync(join(carried, 'key.txt'), readFileSync(k.file));
    const tool = new URL('../tools/restore_verify.mjs', import.meta.url).pathname;
    const r = spawnSync(process.execPath, [tool, join(carried, 'd1-export.sql.age'), join(carried, 'manifest.json'), '--identity', join(carried, 'key.txt')], { encoding: 'utf8', env: { HOME: fakeHome, PATH: '/usr/local/bin:/usr/bin:/bin' } });
    assert.equal(r.status, 0, r.stdout + r.stderr); assert.match(r.stdout, /RESTORE VERIFIED/); assert.deepEqual(readdirSync(fakeHome), [], 'nothing was written to the home directory');
    for (const f of ['tools/restore_verify.mjs', 'tools/backup_lib.mjs']) assert.ok(!/\bsecurity\b|find-generic-password|keychain/i.test(readFileSync(new URL('../' + f, import.meta.url), 'utf8').replace(/\/\/.*$/gm, '')), f + ' must not touch the Keychain');
    const wrong = spawnSync(process.execPath, [tool, join(carried, 'd1-export.sql.age'), '--identity', join(s.keys, 'nonexistent.txt')], { encoding: 'utf8', env: { HOME: fakeHome, PATH: '/usr/local/bin:/usr/bin:/bin' } }); assert.notEqual(wrong.status, 0, 'without the key nothing is restored');
    rmSync(fakeHome, { recursive: true, force: true }); rmSync(carried, { recursive: true, force: true });
  } finally { s.done(); }
});
