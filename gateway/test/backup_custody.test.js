// Custody checks: a private copy restored from the password manager or from paper must correspond to the public kit, with no secret printed, and custody mistakes (open permissions, inside a git tree) are flagged.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeKit } from '../tools/backup_kit.mjs';
import { signBackup, signCheckpoint } from '../tools/backup_anchor.mjs';

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), '..', 'tools', 'verify_custody.sh');
let HAVE = true; for (const t of ['age-keygen', 'ssh-keygen', 'git']) { try { execFileSync('which', [t], { stdio: 'pipe' }); } catch { HAVE = false; } }
const skip = { skip: !HAVE && 'age-keygen, ssh-keygen and git are needed' };

function ws() {
  const root = mkdtempSync(join(tmpdir(), 'mg-custody-test-')), sshKey = (n, dir = root) => { const f = join(dir, n); execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', n, '-f', f]); chmodSync(f, 0o600); return { file: f, pub: readFileSync(f + '.pub', 'utf8').trim() }; };
  const ageId = (n, dir = root) => { const f = join(dir, n); execFileSync('age-keygen', ['-o', f], { stdio: 'pipe' }); chmodSync(f, 0o600); return { file: f, recipient: readFileSync(f, 'utf8').match(/public key: (age1\S+)/)[1] }; };
  const run = (args) => spawnSync('sh', [SCRIPT, ...args], { encoding: 'utf8', cwd: root, env: { PATH: process.env.PATH, HOME: root } });
  return { root, sshKey, ageId, run, done: () => rmSync(root, { recursive: true, force: true }) };
}
const secretsIn = (text, w, ...files) => files.some((f) => { const body = readFileSync(f, 'utf8'); return [...body.split('\n').filter((l) => /AGE-SECRET-KEY|^[A-Za-z0-9+/=]{40,}$/.test(l))].some((l) => text.includes(l)); });

test('matching private copies are confirmed against the kit and nothing secret is printed', skip, () => {
  const w = ws(); try {
    const sign = w.sshKey('sign'), id = w.ageId('id'), kitFile = join(w.root, 'kit.txt'); writeFileSync(kitFile, makeKit({ publicKey: sign.pub, ageRecipient: id.recipient }));
    const r = w.run([kitFile, '--age-identity', id.file, '--signing-key', sign.file]); assert.equal(r.status, 0, r.stdout + r.stderr); assert.match(r.stdout, /OK: the age identity matches/); assert.match(r.stdout, /OK: the signing key matches/);
    assert.ok(!secretsIn(r.stdout + r.stderr, w, id.file, sign.file), 'no private line appears in the output');
  } finally { w.done(); }
});

test('a copy that is not the one in the kit is a MISMATCH (a wrong, corrupted or swapped copy)', skip, () => {
  const w = ws(); try {
    const sign = w.sshKey('sign'), other = w.sshKey('other'), id = w.ageId('id'), otherId = w.ageId('other-id'), kitFile = join(w.root, 'kit.txt'); writeFileSync(kitFile, makeKit({ publicKey: sign.pub, ageRecipient: id.recipient }));
    let r = w.run([kitFile, '--age-identity', otherId.file]); assert.equal(r.status, 1); assert.match(r.stdout, /MISMATCH: the age identity/);
    r = w.run([kitFile, '--signing-key', other.file]); assert.equal(r.status, 1); assert.match(r.stdout, /MISMATCH: the signing key/);
    const broken = join(w.root, 'broken'); writeFileSync(broken, 'AGE-SECRET-KEY-1TRUNCATED\n'); chmodSync(broken, 0o600); r = w.run([kitFile, '--age-identity', broken]); assert.equal(r.status, 1); assert.match(r.stdout, /MISMATCH/); assert.ok(!r.stdout.includes('TRUNCATED'));
  } finally { w.done(); }
});

test('custody mistakes are flagged: open permissions and a private key inside a git working tree', skip, () => {
  const w = ws(); try {
    const sign = w.sshKey('sign'), id = w.ageId('id'), kitFile = join(w.root, 'kit.txt'); writeFileSync(kitFile, makeKit({ publicKey: sign.pub, ageRecipient: id.recipient }));
    chmodSync(id.file, 0o644); let r = w.run([kitFile, '--age-identity', id.file]); assert.equal(r.status, 1); assert.match(r.stdout, /WARNING: the age identity has permissions open/); assert.match(r.stdout, /OK: the age identity matches/, 'it still says whether the copy is the right one');
    chmodSync(id.file, 0o600); const repo = join(w.root, 'repo'); mkdirSync(repo); execFileSync('git', ['init', '-q', repo]); const inRepo = w.ageId('id-in-repo', repo); const kit2 = join(w.root, 'kit2.txt'); writeFileSync(kit2, makeKit({ publicKey: sign.pub, ageRecipient: inRepo.recipient }));
    r = w.run([kit2, '--age-identity', inRepo.file]); assert.equal(r.status, 1); assert.match(r.stdout, /WARNING: the age identity is inside a git working tree/);
    assert.equal(w.run([kitFile]).status, 0, 'nothing given, nothing to flag'); assert.equal(w.run(['/nonexistent', '--age-identity', id.file]).status, 2);
  } finally { w.done(); }
});

test('the kit names the fingerprint, the schemas, the artifact hashes and the checkpoint anchor, and never carries private material', skip, () => {
  const w = ws(); try {
    const sign = w.sshKey('sign'), id = w.ageId('id'), dir = join(w.root, '20261024T050235Z'); mkdirSync(dir);
    for (const f of ['d1-export.sql.age', 'manifest.json', 'SHA256SUMS']) writeFileSync(join(dir, f), f);
    signBackup({ dir, signingKey: sign.file, publicKey: sign.pub }); const ck = join(w.root, 'ck'); signCheckpoint({ backupDir: dir, outDir: ck, signingKey: sign.file, publicKey: sign.pub });
    const kit = makeKit({ publicKey: sign.pub, ageRecipient: id.recipient, headDir: dir, checkpointDir: ck }), fp = execFileSync('ssh-keygen', ['-l', '-f', sign.file + '.pub']).toString().split(' ')[1];
    assert.ok(kit.includes(fp), 'fingerprint equals the one ssh-keygen computes'); assert.match(kit, /macguard-backup-checkpoint\/1/); assert.match(kit, /macguard\.backup-anchor\/1/); assert.match(kit, /TRUSTED CHECKPOINT ANCHOR[\s\S]*sequence 1/); assert.match(kit, /ARTIFACTS OF THAT HEAD[\s\S]*ANCHOR\.json\.sig/);
    assert.ok(!/BEGIN [A-Z ]*PRIVATE KEY|AGE-SECRET-KEY/.test(kit)); assert.throws(() => makeKit({ publicKey: sign.pub, ageRecipient: id.recipient, headDir: dir, checkpointDir: join(w.root, 'nope') }), /lacks CHECKPOINT/);
    const kitFile = join(w.root, 'kit.txt'); writeFileSync(kitFile, kit); const r = w.run([kitFile, '--age-identity', id.file, '--signing-key', sign.file]); assert.equal(r.status, 0, r.stdout + r.stderr);
  } finally { w.done(); }
});

test('the kit records the signing policy: Ed25519 up to the freeze, the exact Sigstore workflow identity after it, and refuses a loose policy', skip, () => {
  const w = ws(); try {
    const sign = w.sshKey('sign'), id = w.ageId('id'), ID = 'https://github.com/MacGuard/macguard-yara-channel/.github/workflows/backup.yml@refs/heads/main', sigstore = { identity: ID, repository: 'MacGuard/macguard-yara-channel' };
    const kit = makeKit({ publicKey: sign.pub, ageRecipient: id.recipient, sigstore, ed25519MaxSequence: 1 });
    assert.match(kit, /sequence 1\.\.1: Ed25519/); assert.match(kit, /sequence 2 and later: Sigstore keyless/); assert.ok(kit.includes(ID)); assert.match(kit, /MG_SIGSTORE_IDENTITY='https:\/\/github\.com\/MacGuard/); assert.match(kit, /MG_ED25519_MAX_SEQUENCE=1/);
    assert.throws(() => makeKit({ publicKey: sign.pub, ageRecipient: id.recipient, sigstore: { identity: 'https://github.com/MacGuard/.*', repository: 'MacGuard/x' }, ed25519MaxSequence: 1 }), /exact GitHub workflow identity/);
    assert.throws(() => makeKit({ publicKey: sign.pub, ageRecipient: id.recipient, sigstore }), /ed25519MaxSequence/);
    assert.match(makeKit({ publicKey: sign.pub, ageRecipient: id.recipient }), /Ed25519 only \(no Sigstore policy recorded yet\)/);
  } finally { w.done(); }
});
