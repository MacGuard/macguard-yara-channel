// An additional encrypted copy of a plaintext backup: byte-identical after decryption, restorable in isolation, the original untouched, nothing overwritten, a wrong key or a damaged copy fails.
import test from 'node:test';
import { HAVE_AGE } from './tools_available.js';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { dumpSql } from '../tools/backup_lib.mjs';
import { encryptLegacy, verifyLegacyCopy } from '../tools/backup_encrypt_legacy.mjs';
import { world } from './helpers.js';
import { audit } from '../src/audit.js';

const sha = (b) => createHash('sha256').update(b).digest('hex');
const keypair = (dir, n) => { const f = join(dir, n); execFileSync('age-keygen', ['-o', f], { stdio: 'ignore' }); return { file: f, pub: execFileSync('age-keygen', ['-y', f], { encoding: 'utf8' }).trim() }; };

test('plaintext backup -> additional encrypted copy: identical bytes after decryption, restore checks pass, original untouched, wrong key and damage fail, nothing overwritten', { skip: !HAVE_AGE }, async () => {
  const w = await world({ now: '2026-10-23T20:00:00Z' }); await w.tenant('t1'); await audit(w.db, w.clock, 't1', 'x.y', {});
  const home = mkdtempSync(join(homedir(), '.mg-leg-')), src = join(home, 'legacy', '20261023T200122Z'), out = join(home, 'enc'), keys = join(home, 'keys'); mkdirSync(src, { recursive: true }); mkdirSync(keys);
  try {
    const sql = dumpSql(w.db.raw); writeFileSync(join(src, 'd1-export.sql'), sql); writeFileSync(join(src, 'wrangler.toml'), 'name = "x"\n'); const m = { plaintext_sha256: sha(sql), encrypted: false };
    writeFileSync(join(src, 'manifest.json'), JSON.stringify(m)); writeFileSync(join(src, 'SHA256SUMS'), ['d1-export.sql', 'wrangler.toml', 'manifest.json'].map((f) => `${sha(readFileSync(join(src, f)))}  ${f}`).join('\n') + '\n');
    const before = Object.fromEntries(readdirSync(src).map((f) => [f, sha(readFileSync(join(src, f)))])), k = keypair(keys, 'k.txt'), other = keypair(keys, 'o.txt');
    const r = await encryptLegacy({ src, recipient: k.pub, out }); assert.equal(r.plaintext_sha256, sha(sql)); assert.ok(!readFileSync(join(r.dir, 'd1-export.sql.age')).includes(Buffer.from('CREATE TABLE')), 'ciphertext holds no readable SQL');
    const v = await verifyLegacyCopy({ copy: r.dir, src, identityFile: k.file }); assert.equal(v.ok, true, JSON.stringify(v.checks.filter((c) => !c.ok))); assert.equal(v.original_untouched, true);
    assert.deepEqual(Object.fromEntries(readdirSync(src).map((f) => [f, sha(readFileSync(join(src, f)))])), before, 'the original is byte-identical after the whole operation');
    assert.equal(statSync(r.dir).mode & 0o777, 0o700); assert.equal(statSync(join(r.dir, 'd1-export.sql.age')).mode & 0o777, 0o600);
    await assert.rejects(() => encryptLegacy({ src, recipient: k.pub, out }), /already exists/);
    await assert.rejects(() => verifyLegacyCopy({ copy: r.dir, src, identityFile: other.file }), /no identity matched|Command failed/);
    const bad = join(home, 'bad'); cpSync(r.dir, bad, { recursive: true }); const f = join(bad, 'd1-export.sql.age'); const b = readFileSync(f); b[b.length - 5] ^= 1; writeFileSync(f, b);
    const dv = await verifyLegacyCopy({ copy: bad, src, identityFile: k.file }).catch((e) => ({ ok: false, err: String(e.message) })); assert.equal(dv.ok, false, 'a damaged copy never verifies');
    const tampered = join(home, 'legacy2', '20261024T010101Z'); mkdirSync(tampered, { recursive: true }); cpSync(src, tampered, { recursive: true }); writeFileSync(join(tampered, 'd1-export.sql'), 'altered'); await assert.rejects(() => encryptLegacy({ src: tampered, recipient: k.pub, out }), /SHA256SUMS/);
    const enc = join(home, 'legacy3', '20261024T020202Z'); mkdirSync(enc, { recursive: true }); writeFileSync(join(enc, 'd1-export.sql.age'), 'x'); await assert.rejects(() => encryptLegacy({ src: enc, recipient: k.pub, out }), /already encrypted/);
    await assert.rejects(() => encryptLegacy({ src, recipient: 'not-a-key', out: join(home, 'o2') }), /public key/); await assert.rejects(() => encryptLegacy({ src, recipient: k.pub, out: '/private/tmp/x' }), /temporary/);
  } finally { rmSync(home, { recursive: true, force: true }); }
});
