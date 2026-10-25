// The independent recovery path: recover_verify.sh (nothing from this repository) on a clean directory, and the recovery kit that carries only public facts. Throw-away keys only; no real identity is read.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync, copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { signBackup } from '../tools/backup_anchor.mjs';
import { makeKit } from '../tools/backup_kit.mjs';

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), '..', 'tools', 'recover_verify.sh');
let HAVE = true; for (const t of ['age', 'age-keygen', 'ssh-keygen', 'python3']) { try { execFileSync('which', [t], { stdio: 'pipe' }); } catch { HAVE = false; } }
const skip = { skip: !HAVE && 'age, age-keygen, ssh-keygen and python3 are needed' }, sha = (b) => createHash('sha256').update(b).digest('hex');

function ws() {
  const root = mkdtempSync(join(tmpdir(), 'mg-recovery-test-')), sshKey = (n) => { const f = join(root, n); execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', n, '-f', f]); return { file: f, pub: readFileSync(f + '.pub', 'utf8').trim() }; };
  const ageId = (n) => { const f = join(root, n + '.age'); const out = execFileSync('age-keygen', ['-o', f], { stdio: 'pipe', encoding: 'utf8' }) + ''; chmodSync(f, 0o600); const rec = readFileSync(f, 'utf8').match(/public key: (age1\S+)/)[1]; return { file: f, recipient: rec }; };
  function backup(name, sql, signer, id, prev = null) {
    const dir = join(root, 'local', name); mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'd1-export.sql.age'), execFileSync('age', ['-r', id.recipient], { input: Buffer.from(sql) }));
    writeFileSync(join(dir, 'manifest.json'), JSON.stringify({ schema: 'macguard.gateway-backup/2', plaintext_sha256: sha(Buffer.from(sql)) }));
    writeFileSync(join(dir, 'SHA256SUMS'), ['d1-export.sql.age', 'manifest.json'].map((f) => `${sha(readFileSync(join(dir, f)))}  ${f}`).join('\n') + '\n');
    signBackup({ dir, signingKey: signer.file, previousDir: prev, clock: () => new Date('2026-10-25T05:00:00Z') }); return dir;
  }
  const clean = (dir) => { const c = mkdtempSync(join(root, 'clean-')); for (const f of ['d1-export.sql.age', 'manifest.json', 'SHA256SUMS', 'ANCHOR.json', 'ANCHOR.json.sig']) if (existsSync(join(dir, f))) copyFileSync(join(dir, f), join(c, f)); return c; };
  const run = (args, extraEnv = {}) => spawnSync('sh', [SCRIPT, ...args], { encoding: 'utf8', cwd: root, env: { PATH: process.env.PATH, HOME: root, TMPDIR: tmpdir(), MG_ALLOW_NO_CHECKPOINT: '1', ...extraEnv } });
  return { root, sshKey, ageId, backup, clean, run, done: () => rmSync(root, { recursive: true, force: true }) };
}

test('clean machine: the five files, the trusted public key and the age identity are enough to authenticate and decrypt', skip, () => {
  const w = ws(); try {
    const owner = w.sshKey('owner'), id = w.ageId('id'), dir = w.backup('20261024T050235Z', 'CREATE TABLE t(x);\nINSERT INTO t VALUES (1);\n', owner, id), c = w.clean(dir), out = join(w.root, 'restored.sql');
    const r = w.run([c, owner.pub, '1', id.file, out]); assert.equal(r.status, 0, r.stderr); assert.match(r.stdout, /ANCHORED OK stamp=20261024T050235Z sequence=1 head_sha256=[0-9a-f]{64}/); assert.match(r.stdout, /DECRYPTED OK plaintext_sha256=/);
    assert.equal(readFileSync(out, 'utf8'), 'CREATE TABLE t(x);\nINSERT INTO t VALUES (1);\n'); assert.equal(statSync(out).mode & 0o077, 0, 'the restored file is private (mode 600)');
    assert.ok(!r.stdout.includes('AGE-SECRET-KEY') && !r.stderr.includes('AGE-SECRET-KEY'), 'no private material is printed');
    const verifyOnly = w.run([c, join(w.root, 'owner.pub'), '1']); assert.equal(verifyOnly.status, 0, 'the key may be given as a file whose first line is the key');
  } finally { w.done(); }
});

test('refusals: tampered ciphertext, forged anchor, wrong key, rollback, missing statement, wrong identity: nothing is decrypted and no output file is left', skip, () => {
  const w = ws(); try {
    const owner = w.sshKey('owner'), attacker = w.sshKey('attacker'), id = w.ageId('id'), other = w.ageId('other'), good = w.backup('20261024T050235Z', 'SELECT 1;\n', owner, id), out = join(w.root, 'restored.sql');
    const bad = (c, key = owner.pub, seq = '1', ident = id.file) => { const r = w.run([c, key, seq, ident, out]); assert.equal(r.status, 1, r.stdout + r.stderr); assert.ok(!existsSync(out), 'no output file'); return r.stderr; };
    let c = w.clean(good); writeFileSync(join(c, 'd1-export.sql.age'), Buffer.concat([readFileSync(join(c, 'd1-export.sql.age')), Buffer.from('x')])); assert.match(bad(c), /does not match the signed statement/);
    c = w.clean(good); writeFileSync(join(c, 'manifest.json'), '{"plaintext_sha256":"00"}'); assert.match(bad(c), /manifest\.json does not match/);
    const fake = w.backup('20261025T000000Z', 'DROP TABLE users;\n', attacker, id); assert.match(bad(w.clean(fake)), /signature does not verify/);                 // self-consistent and signed, but not by the trusted key
    assert.match(bad(w.clean(good), owner.pub, '5'), /rollback: sequence 1 is older than the newest known \(5\)/);
    c = w.clean(good); rmSync(join(c, 'ANCHOR.json.sig')); assert.match(bad(c), /carries no signed anchor/);
    assert.match(bad(w.clean(good), owner.pub, '1', other.file), /age could not decrypt/);
    assert.match(bad(w.clean(good), owner.pub + '\nattacker ssh-ed25519 AAAA'), /single ssh-ed25519 line/); assert.match(bad(w.clean(good), 'cert-authority ' + owner.pub), /single ssh-ed25519 line/);
    const noSeq = w.run([w.clean(good), owner.pub, 'abc']); assert.equal(noSeq.status, 2);
  } finally { w.done(); }
});

test('the recovery kit holds public facts only and refuses anything that looks private', skip, () => {
  const w = ws(); try {
    const owner = w.sshKey('owner'), id = w.ageId('id'), dir = w.backup('20261024T050235Z', 'SELECT 1;\n', owner, id), kit = makeKit({ publicKey: owner.pub, ageRecipient: id.recipient, headDir: dir, now: () => new Date('2026-10-25T12:00:00Z') });
    assert.ok(kit.includes(owner.pub) && kit.includes(id.recipient) && /sequence 1, stamp 20261024T050235Z, head SHA-256 [0-9a-f]{64}/.test(kit)); for (const b of ['macguard-archive-b2', 'macguard-archive-scw', 'macguard-archive-r2']) assert.ok(kit.includes(b));
    assert.ok(!/AGE-SECRET-KEY|-----BEGIN [A-Z ]*PRIVATE KEY|SECRET_ACCESS/.test(kit), 'no private material in the kit');
    const secret = readFileSync(id.file, 'utf8').match(/AGE-SECRET-KEY-\S+/)[0];
    assert.throws(() => makeKit({ publicKey: owner.pub, ageRecipient: secret }), /looks like private material/);
    assert.throws(() => makeKit({ publicKey: readFileSync(owner.file, 'utf8'), ageRecipient: id.recipient }), /looks like private material/);
    assert.throws(() => makeKit({ publicKey: 'ssh-rsa AAAA', ageRecipient: id.recipient }), /ssh-ed25519/); assert.throws(() => makeKit({ publicKey: owner.pub, ageRecipient: 'age1short' }), /age1/);
  } finally { w.done(); }
});

test('the restore is NOT declared valid, and nothing is decrypted, when no trusted checkpoint is given (default); the explicit rehearsal opt-out says it is unprotected against rollback', skip, () => {
  const w = ws(); try {
    const owner = w.sshKey('owner'), id = w.ageId('id'), dir = w.backup('20261024T050235Z', 'SELECT 1;\n', owner, id), c = w.clean(dir), out = join(w.root, 'restored.sql');
    const r = w.run([c, owner.pub, '1', id.file, out], { MG_ALLOW_NO_CHECKPOINT: '' }); assert.equal(r.status, 1); assert.match(r.stderr, /no trusted checkpoint was given/); assert.ok(!existsSync(out)); assert.ok(!/ANCHORED OK|DECRYPTED OK/.test(r.stdout));
    const opt = w.run([c, owner.pub, '1']); assert.equal(opt.status, 0); assert.match(opt.stdout, /checkpoint=none NOT-PROTECTED-AGAINST-ROLLBACK/);
  } finally { w.done(); }
});
