// Adversarial tests of the signing path: whatever goes wrong while signing, a backup is never left looking signed, a valid anchor that already exists is never touched, and the private key file is never written. Throw-away keys only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { signBackup, signCheckpoint, verifyAnchor, verifyCheckpoint, checkAgainstCheckpoint } from '../tools/backup_anchor.mjs';

let HAVE = true; try { execFileSync('ssh-keygen', ['-Y', 'find-principals'], { stdio: 'pipe' }); } catch (e) { HAVE = !/unknown option|illegal option|usage: ssh-keygen/i.test(String(e.stderr)) || /find-principals/.test(String(e.stderr)); }
const skip = { skip: !HAVE && 'ssh-keygen with -Y support is needed' };
const MOD = new URL('../tools/backup_anchor.mjs', import.meta.url).href;

function ws() {
  const root = mkdtempSync(join(tmpdir(), 'mg-sign-')), key = (n) => { const f = join(root, n); execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', n, '-f', f]); return { file: f, pub: readFileSync(f + '.pub', 'utf8').trim() }; };
  const backup = (stamp) => { const dir = join(root, stamp); mkdirSync(dir); for (const f of ['d1-export.sql.age', 'manifest.json', 'SHA256SUMS']) writeFileSync(join(dir, f), f + stamp); return dir; };
  const stub = (name, body) => { const f = join(root, name); writeFileSync(f, '#!/bin/sh\n' + body + '\n'); chmodSync(f, 0o755); return f; };
  const snap = (dir) => Object.fromEntries(readdirSync(dir).sort().map((f) => [f, statSync(join(dir, f)).isDirectory() ? 'DIR' : readFileSync(join(dir, f)).toString('hex')]));
  return { root, key, backup, stub, snap, done: () => rmSync(root, { recursive: true, force: true }) };
}

test('wrong trusted public key: the signature is made but verification fails, so nothing is published', skip, () => {
  const w = ws(); try {
    const owner = w.key('owner'), other = w.key('other'), dir = w.backup('20261026T000000Z'), before = w.snap(dir);
    assert.throws(() => signBackup({ dir, signingKey: owner.file, publicKey: other.pub }), /does not verify with the trusted key, nothing was kept/); assert.deepEqual(w.snap(dir), before);
  } finally { w.done(); }
});

test('an anchor that already exists, valid, survives every later attempt byte for byte, with or without a good key', skip, () => {
  const w = ws(); try {
    const owner = w.key('owner'), other = w.key('other'), dir = w.backup('20261026T000000Z'); signBackup({ dir, signingKey: owner.file, publicKey: owner.pub }); const before = w.snap(dir);
    for (const [k, p] of [[owner, owner], [other, other], [other, owner]]) assert.throws(() => signBackup({ dir, signingKey: k.file, publicKey: p.pub }), /already has an anchor/);
    assert.deepEqual(w.snap(dir), before); assert.equal(verifyAnchor({ files: Object.fromEntries(Object.entries(w.snap(dir)).map(([f, h]) => [f, Buffer.from(h, 'hex')])), publicKey: owner.pub }).ok, true);
  } finally { w.done(); }
});

test('ssh-keygen fails while signing (exit 1), or "succeeds" without producing a signature: no file is kept and no temp is left', skip, () => {
  const w = ws(); try {
    const owner = w.key('owner'), dir = w.backup('20261026T000000Z'), before = w.snap(dir);
    assert.throws(() => signBackup({ dir, signingKey: owner.file, publicKey: owner.pub, sshKeygen: w.stub('fail', 'echo "Load key: error in libcrypto" >&2; exit 1') }), /signing failed/); assert.deepEqual(w.snap(dir), before);
    assert.throws(() => signBackup({ dir, signingKey: owner.file, publicKey: owner.pub, sshKeygen: w.stub('noop', 'exit 0') }), /no usable signature/); assert.deepEqual(w.snap(dir), before);
  } finally { w.done(); }
});

test('a truncated signature (below the minimum, or cut mid-way) is refused and nothing is published; a truncated published signature does not verify', skip, () => {
  const w = ws(); try {
    const owner = w.key('owner'), dir = w.backup('20261026T000000Z'), before = w.snap(dir);
    for (const n of [10, 120]) {
      const cut = w.stub('cut' + n, `if [ "$2" = sign ]; then /usr/bin/ssh-keygen "$@" || exit $?; for a; do :; done; head -c ${n} "$a.sig" > "$a.sig.t" && mv "$a.sig.t" "$a.sig"; else exec /usr/bin/ssh-keygen "$@"; fi`);
      assert.throws(() => signBackup({ dir, signingKey: owner.file, publicKey: owner.pub, sshKeygen: cut }), /no usable signature|does not verify/); assert.deepEqual(w.snap(dir), before);
    }
    signBackup({ dir, signingKey: owner.file, publicKey: owner.pub }); const files = Object.fromEntries(Object.entries(w.snap(dir)).map(([f, h]) => [f, Buffer.from(h, 'hex')]));
    files['ANCHOR.json.sig'] = files['ANCHOR.json.sig'].subarray(0, files['ANCHOR.json.sig'].length - 40); assert.equal(verifyAnchor({ files, publicKey: owner.pub }).ok, false);
  } finally { w.done(); }
});

test('the process is killed (SIGKILL) while ssh-keygen runs: the backup is not signed, and the next run signs normally and cleans the leftover', skip, () => {
  const w = ws(); try {
    const owner = w.key('owner'), dir = w.backup('20261026T000000Z'), killer = w.stub('kill', 'kill -9 $PPID; sleep 5');
    const r = spawnSync(process.execPath, ['--input-type=module', '-e', `import { signBackup } from ${JSON.stringify(MOD)}; signBackup({ dir: ${JSON.stringify(dir)}, signingKey: ${JSON.stringify(owner.file)}, publicKey: ${JSON.stringify(owner.pub)}, sshKeygen: ${JSON.stringify(killer)} });`], { encoding: 'utf8' });
    assert.equal(r.signal, 'SIGKILL'); assert.equal(existsSync(join(dir, 'ANCHOR.json')), false); assert.equal(existsSync(join(dir, 'ANCHOR.json.sig')), false);
    writeFileSync(join(dir, 'ANCHOR.json.sig'), 'stray half of an interrupted publication');                                                       // the other possible trace: the signature linked, the statement not
    assert.equal(signBackup({ dir, signingKey: owner.file, publicKey: owner.pub }).sequence, 1);
    assert.deepEqual(readdirSync(dir).sort(), ['ANCHOR.json', 'ANCHOR.json.sig', 'SHA256SUMS', 'd1-export.sql.age', 'manifest.json']);
  } finally { w.done(); }
});

test('the private key file is never written: its bytes and mtime are identical after good and failed signing', skip, () => {
  const w = ws(); try {
    const owner = w.key('owner'), other = w.key('other'), bytes = readFileSync(owner.file), m = statSync(owner.file).mtimeMs, d1 = w.backup('20261026T000000Z'), d2 = w.backup('20261027T000000Z');
    assert.throws(() => signBackup({ dir: d1, signingKey: owner.file, publicKey: other.pub })); signBackup({ dir: d2, signingKey: owner.file, publicKey: owner.pub });
    assert.deepEqual(readFileSync(owner.file), bytes); assert.equal(statSync(owner.file).mtimeMs, m);
    const empty = join(w.root, 'empty'); writeFileSync(empty, ''); assert.throws(() => signBackup({ dir: d1, signingKey: empty, publicKey: owner.pub }), /empty or truncated/); assert.equal(statSync(empty).size, 0);
  } finally { w.done(); }
});

test('checkpoint: same guarantees (wrong public key keeps nothing, an existing checkpoint is never replaced, empty key refused) and the signed one verifies', skip, () => {
  const w = ws(); try {
    const owner = w.key('owner'), other = w.key('other'), dir = w.backup('20261026T000000Z'); signBackup({ dir, signingKey: owner.file, publicKey: owner.pub });
    const out = join(w.root, 'ck'); mkdirSync(out); assert.throws(() => signCheckpoint({ backupDir: dir, outDir: out, signingKey: owner.file, publicKey: other.pub }), /nothing was kept/); assert.deepEqual(readdirSync(out), []);
    const r = signCheckpoint({ backupDir: dir, outDir: out, signingKey: owner.file, publicKey: owner.pub }); assert.equal(r.sequence, 1); const before = w.snap(out);
    assert.throws(() => signCheckpoint({ backupDir: dir, outDir: out, signingKey: owner.file, publicKey: owner.pub }), /never overwritten/); assert.deepEqual(w.snap(out), before);
    const files = Object.fromEntries(Object.entries(before).map(([f, h]) => [f, Buffer.from(h, 'hex')])); assert.equal(verifyCheckpoint({ files, publicKey: owner.pub }).ok, true);
    const empty = join(w.root, 'empty'); writeFileSync(empty, ''); assert.throws(() => signCheckpoint({ backupDir: dir, outDir: join(w.root, 'ck2'), signingKey: empty }), /empty or truncated/);
  } finally { w.done(); }
});

test('agent mode: the key is served by a throw-away ssh-agent, signing uses only the PUBLIC key file, and the result verifies', skip, async () => {
  const w = ws(); const sock = join(w.root, 'a.sock'); const agent = spawn('ssh-agent', ['-D', '-a', sock], { stdio: 'ignore' }); const old = process.env.SSH_AUTH_SOCK;
  try {
    for (let i = 0; i < 50 && !existsSync(sock); i++) await new Promise((r) => setTimeout(r, 50));
    const owner = w.key('owner'), dir = w.backup('20261026T000000Z'); process.env.SSH_AUTH_SOCK = sock; execFileSync('ssh-add', [owner.file], { stdio: 'pipe' });
    rmSync(owner.file);                                                                                                                                  // no private key file exists any more: only the agent holds it
    assert.equal(signBackup({ dir, signingKey: owner.file + '.pub', agent: true, publicKey: owner.pub }).sequence, 1);
  } finally { agent.kill(); if (old === undefined) delete process.env.SSH_AUTH_SOCK; else process.env.SSH_AUTH_SOCK = old; w.done(); }
});

test('checkpoint against anchor: the matching one passes; a checkpoint of a HIGHER sequence is a rollback of the served copy; the same sequence with another head is a fork; a lower one is only an older confirmation', skip, () => {
  const w = ws(); try {
    const owner = w.key('owner'), d1 = w.backup('20261026T000000Z'), d2 = w.backup('20261027T000000Z');
    signBackup({ dir: d1, signingKey: owner.file, publicKey: owner.pub }); signBackup({ dir: d2, signingKey: owner.file, publicKey: owner.pub, previousDir: d1 });
    const ck = (d, n) => { const o = join(w.root, n); signCheckpoint({ backupDir: d, outDir: o, signingKey: owner.file, publicKey: owner.pub }); return verifyCheckpoint({ files: Object.fromEntries(readdirSync(o).map((f) => [f, readFileSync(join(o, f))])), publicKey: owner.pub }).checkpoint; };
    const load = (d) => verifyAnchor({ files: Object.fromEntries(readdirSync(d).filter((f) => !f.startsWith('.')).map((f) => [f, readFileSync(join(d, f))])), publicKey: owner.pub });
    const c1 = ck(d1, 'c1'), c2 = ck(d2, 'c2'); assert.deepEqual([c1.sequence, c2.sequence], [1, 2]);
    assert.equal(checkAgainstCheckpoint(load(d2), c2).ok, true); assert.equal(checkAgainstCheckpoint(load(d1), c2).ok, false); assert.match(checkAgainstCheckpoint(load(d1), c2).reason, /rollback or loss/);
    assert.equal(checkAgainstCheckpoint(load(d2), c1).ahead_of_checkpoint, true);
    assert.match(checkAgainstCheckpoint(load(d1), { ...c1, head_sha256: 'f'.repeat(64) }).reason, /fork/);
  } finally { w.done(); }
});
