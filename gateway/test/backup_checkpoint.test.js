// The external checkpoint: "the newest backup I confirmed is sequence N". It exists for the case no check inside the buckets can catch: ALL THREE providers serving an old, coherent, genuinely signed backup.
// Throw-away keys only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync, copyFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { signBackup, signCheckpoint, verifyCheckpoint, bestCheckpoint, checkAgainstCheckpoint, verifyAnchor, verifyChain } from '../tools/backup_anchor.mjs';
import { DEFAULT_CONFIG, headsAll, loadCheckpoint } from '../tools/backup_objstore.mjs';

let HAVE = true; for (const t of ['ssh-keygen', 'python3']) { try { execFileSync('which', [t], { stdio: 'pipe' }); } catch { HAVE = false; } }
const skip = { skip: !HAVE && 'ssh-keygen and python3 are needed' }, sha = (b) => createHash('sha256').update(b).digest('hex'), SCRIPT = join(dirname(fileURLToPath(import.meta.url)), '..', 'tools', 'recover_verify.sh');

function ws() {
  const root = mkdtempSync(join(tmpdir(), 'mg-ckpt-test-')), key = (n) => { const f = join(root, n); execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', n, '-f', f]); return { file: f, pub: readFileSync(f + '.pub', 'utf8').trim() }; };
  const backup = (stamp, body, prev, k, t) => {
    const dir = join(root, 'local', stamp); mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'd1-export.sql.age'), Buffer.from('age-encryption.org/v1 ' + body)); writeFileSync(join(dir, 'manifest.json'), JSON.stringify({ stamp, body }));
    writeFileSync(join(dir, 'SHA256SUMS'), ['d1-export.sql.age', 'manifest.json'].map((f) => `${sha(readFileSync(join(dir, f)))}  ${f}`).join('\n') + '\n');
    signBackup({ dir, signingKey: k.file, previousDir: prev, clock: () => new Date(t) }); return dir;
  };
  const files = (dir) => Object.fromEntries(readdirSync(dir).map((f) => [f, readFileSync(join(dir, f))]));
  const stores = () => Object.fromEntries(['b2', 'scaleway', 'r2'].map((n) => { const m = new Map(); return [n, { m, get: async (k) => m.get(k) ?? null, put: async (k, v) => { m.set(k, v); }, bucket: async () => 'EXISTS' }]; }));
  const publish = (st, names, stamp, dir) => { for (const n of names) for (const [f, b] of Object.entries(files(dir))) st[n].m.set(`${DEFAULT_CONFIG.prefix}/${stamp}/${f}`, b); };
  const ckpt = (name, backupDir, k, at) => { const out = join(root, name); signCheckpoint({ backupDir, outDir: out, signingKey: k.file, confirmedAt: at }); return out; };
  return { root, key, backup, files, stores, publish, ckpt, done: () => rmSync(root, { recursive: true, force: true }) };
}
const chain = (w, k) => { const b1 = w.backup('20261024T050235Z', 'one', null, k, '2026-10-24T05:00:00Z'), b2 = w.backup('20261025T050235Z', 'two', b1, k, '2026-10-25T05:00:00Z'), b3 = w.backup('20261026T050235Z', 'three', b2, k, '2026-10-26T05:00:00Z'); return { b1, b2, b3 }; };

test('ALL THREE providers serve an old but coherent signed backup: caught by the external checkpoint, invisible without it', skip, async () => {
  const w = ws(); try {
    const k = w.key('owner'), { b1, b2, b3 } = chain(w, k), cpDir = w.ckpt('cp-seq3', b3, k, '2026-10-26T05:30:00Z'), st = w.stores();
    // the attacker (or a bad restore) makes every provider answer with sequence 2 under the newest stamp's keys: genuine, signed, internally consistent
    for (const n of ['b2', 'scaleway', 'r2']) for (const [f, b] of Object.entries(w.files(b2))) st[n].m.set(`${DEFAULT_CONFIG.prefix}/20261026T050235Z/${f}`, b);
    const over = { config: DEFAULT_CONFIG, clientOverride: st, stamp: '20261026T050235Z' };
    const noCheckpoint = await headsAll({ ...over, trust: { publicKey: k.pub } });
    assert.ok(noCheckpoint.failed.length === 3 && /is for 20261025T050235Z, not for 20261026T050235Z/.test(noCheckpoint.failed[0].reason), 'the stamp check already refuses a relabelled copy');
    // the harder variant: the old backup is served under ITS OWN stamp, which is what a rollback of the newest-known pointer looks like
    const old = { config: DEFAULT_CONFIG, clientOverride: (() => { const s2 = w.stores(); w.publish(s2, ['b2', 'scaleway', 'r2'], '20261025T050235Z', b2); return s2; })(), stamp: '20261025T050235Z' };
    const blind = await headsAll({ ...old, trust: { publicKey: k.pub } }); assert.deepEqual(blind.current.sort(), ['b2', 'r2', 'scaleway'], 'without a checkpoint three coherent old copies look perfectly healthy');
    const cp = loadCheckpoint([cpDir], k.pub); assert.equal(cp.ok, true); assert.equal(cp.checkpoint.sequence, 3);
    const caught = await headsAll({ ...old, trust: { publicKey: k.pub, checkpoint: cp.checkpoint } });
    assert.equal(caught.rollback_everywhere, true); assert.deepEqual(caught.current, []); assert.equal(caught.failed.length, 3); assert.match(caught.failed[0].reason, /rollback or loss: this copy is sequence 2 but sequence 3 was confirmed/); assert.equal(caught.best_available_sequence, 2); assert.equal(caught.checkpoint_sequence, 3);
    assert.ok(b1);
  } finally { w.done(); }
});

test('one provider still holds the confirmed head: it is current, the two behind are reported as rollback', skip, async () => {
  const w = ws(); try {
    const k = w.key('owner'), { b2, b3 } = chain(w, k), cp = loadCheckpoint([w.ckpt('cp3', b3, k)], k.pub), st = w.stores();
    w.publish(st, ['b2', 'scaleway'], '20261025T050235Z', b2); w.publish(st, ['r2'], '20261025T050235Z', b2); const over = { config: DEFAULT_CONFIG, clientOverride: st, stamp: '20261025T050235Z' };
    const r = await headsAll({ ...over, trust: { publicKey: k.pub, checkpoint: cp.checkpoint } }); assert.equal(r.rollback_everywhere, true);
    const st3 = w.stores(); w.publish(st3, ['b2'], '20261026T050235Z', b3); w.publish(st3, ['scaleway', 'r2'], '20261026T050235Z', b3); st3.scaleway.m.clear();
    const ok = await headsAll({ config: DEFAULT_CONFIG, clientOverride: st3, stamp: '20261026T050235Z', trust: { publicKey: k.pub, checkpoint: cp.checkpoint } }); assert.deepEqual(ok.current.sort(), ['b2', 'r2']); assert.deepEqual(ok.gone, ['scaleway']); assert.equal(ok.rollback_everywhere, false);
  } finally { w.done(); }
});

test('a head older than the checkpoint is a rollback, the same sequence with another head is a fork, a newer head is fine', skip, async () => {
  const w = ws(); try {
    const k = w.key('owner'), { b2, b3 } = chain(w, k), cp = loadCheckpoint([w.ckpt('cp3', b3, k)], k.pub);
    const old = readFileSync(join(b2, 'ANCHOR.json')), a2 = JSON.parse(old.toString()); const v2 = verifyAnchor({ files: w.files(b2), publicKey: k.pub });
    const r = checkAgainstCheckpoint(v2, cp.checkpoint); assert.equal(r.ok, false); assert.match(r.reason, /rollback or loss/);
    const v3 = verifyAnchor({ files: w.files(b3), publicKey: k.pub }); assert.equal(checkAgainstCheckpoint(v3, cp.checkpoint).ok, true);
    assert.equal(checkAgainstCheckpoint({ ...v3, head_sha256: '0'.repeat(64) }, cp.checkpoint).ok, false, 'same sequence, another head = fork'); assert.match(checkAgainstCheckpoint({ ...v3, head_sha256: '0'.repeat(64) }, cp.checkpoint).reason, /fork/);
    assert.equal(a2.sequence, 2);
  } finally { w.done(); }
});

test('a forged checkpoint, a checkpoint signed for another purpose and a backup signature used as a checkpoint are all refused', skip, () => {
  const w = ws(); try {
    const owner = w.key('owner'), attacker = w.key('attacker'), { b3 } = chain(w, owner);
    const forged = w.ckpt('forged', b3, owner); rmSync(join(forged, 'CHECKPOINT.json.sig'));
    const evil = w.backup('20261099T000000Z', 'evil', null, attacker, '2026-10-27T00:00:00Z'); const fcp = w.ckpt('attacker-cp', evil, attacker);
    assert.match(verifyCheckpoint({ files: w.files(fcp), publicKey: owner.pub }).reason, /signature does not verify/);
    assert.match(verifyCheckpoint({ files: w.files(forged), publicKey: owner.pub }).reason, /incomplete/);
    // the backup's own signature (namespace macguard-backup/1) must not be accepted as a checkpoint, and the reverse
    const real = w.ckpt('real', b3, owner); const swapped = { 'CHECKPOINT.json': readFileSync(join(real, 'CHECKPOINT.json')), 'CHECKPOINT.json.sig': readFileSync(join(b3, 'ANCHOR.json.sig')) };
    assert.match(verifyCheckpoint({ files: swapped, publicKey: owner.pub }).reason, /signature does not verify/);
    const asAnchor = { ...w.files(b3), 'ANCHOR.json': readFileSync(join(real, 'CHECKPOINT.json')), 'ANCHOR.json.sig': readFileSync(join(real, 'CHECKPOINT.json.sig')) };
    assert.match(verifyAnchor({ files: asAnchor, publicKey: owner.pub }).reason, /signature does not verify/);
    assert.equal(verifyCheckpoint({ files: w.files(real), publicKey: owner.pub }).ok, true);
    assert.match(verifyCheckpoint({ files: w.files(real), publicKey: 'ssh-ed25519 AAAA\nx' }).reason, /single ssh-ed25519 line/);
  } finally { w.done(); }
});

test('several external copies: the newest authentic one counts; replacing one copy with an older authentic one does not lower the bar; two authentic copies that disagree are equivocation', skip, () => {
  const w = ws(); try {
    const k = w.key('owner'), { b1, b2, b3 } = chain(w, k), c1 = w.ckpt('c1', b1, k, '2026-10-24T05:30:00Z'), c2 = w.ckpt('c2', b2, k, '2026-10-25T05:30:00Z'), c3 = w.ckpt('c3', b3, k, '2026-10-26T05:30:00Z');
    assert.equal(loadCheckpoint([c1, c3], k.pub).checkpoint.sequence, 3, 'the repository copy was swapped for the old one, the password-manager copy still says 3');
    assert.equal(loadCheckpoint([c1, c2], k.pub).checkpoint.sequence, 2, 'if EVERY copy is old, nothing can tell: this is the residual risk and why several copies are kept');
    const fork = w.backup('20261026T050236Z', 'three-prime', b2, k, '2026-10-26T05:00:01Z'), cf = w.ckpt('cf', fork, k, '2026-10-26T05:30:01Z'); const eq = loadCheckpoint([c3, cf], k.pub); assert.equal(eq.ok, false); assert.match(eq.reason, /equivocation/);
    const junk = loadCheckpoint([join(w.root, 'nowhere')], k.pub); assert.equal(junk.ok, false); assert.match(junk.reason, /no authentic checkpoint/);
    assert.equal(verifyChain([readFileSync(join(b1, 'ANCHOR.json')), readFileSync(join(b2, 'ANCHOR.json')), readFileSync(join(b3, 'ANCHOR.json'))]).ok, true);
  } finally { w.done(); }
});

test('an old checkpoint is authentic but stale: it is flagged because it can no longer exclude a recent rollback', skip, () => {
  const w = ws(); try {
    const k = w.key('owner'), { b1 } = chain(w, k), c = w.ckpt('c', b1, k, '2026-10-24T05:30:00Z');
    const fresh = verifyCheckpoint({ files: w.files(c), publicKey: k.pub, maxAgeDays: 30, now: () => new Date('2026-10-30T00:00:00Z') }); assert.equal(fresh.stale, false);
    const old = verifyCheckpoint({ files: w.files(c), publicKey: k.pub, maxAgeDays: 3, now: () => new Date('2026-10-30T00:00:00Z') }); assert.equal(old.ok, true); assert.equal(old.stale, true); assert.ok(old.age_days > 5);
    assert.equal(loadCheckpoint([c], k.pub, { maxAgeDays: 3, now: () => new Date('2026-10-30T00:00:00Z') }).stale, true);
  } finally { w.done(); }
});

test('signing a checkpoint needs an anchored backup and never overwrites a checkpoint', skip, () => {
  const w = ws(); try {
    const k = w.key('owner'), { b3 } = chain(w, k), out = join(w.root, 'cp'); signCheckpoint({ backupDir: b3, outDir: out, signingKey: k.file });
    assert.throws(() => signCheckpoint({ backupDir: b3, outDir: out, signingKey: k.file }), /already exists/);
    const bare = join(w.root, 'bare'); mkdirSync(bare); assert.throws(() => signCheckpoint({ backupDir: bare, outDir: join(w.root, 'cp2'), signingKey: k.file }), /has no anchor/);
    assert.throws(() => signCheckpoint({ backupDir: b3, outDir: join(w.root, 'cp3'), signingKey: join(w.root, 'missing') }), /signing key file is missing/);
  } finally { w.done(); }
});

test('clean-machine shell verifier with external checkpoints: an old backup, a fork and a forged checkpoint are refused; the newest passes', skip, () => {
  const w = ws(); try {
    const owner = w.key('owner'), attacker = w.key('attacker'), { b2, b3 } = chain(w, owner), good = w.ckpt('good', b3, owner), evilBackup = w.backup('20261099T000000Z', 'evil', null, attacker, '2026-10-27T00:00:00Z'), bad = w.ckpt('bad', evilBackup, attacker);
    const clean = (dir) => { const c = mkdtempSync(join(w.root, 'clean-')); for (const f of ['d1-export.sql.age', 'manifest.json', 'SHA256SUMS', 'ANCHOR.json', 'ANCHOR.json.sig']) copyFileSync(join(dir, f), join(c, f)); return c; };
    const run = (dir, cps, seq = '1') => spawnSync('sh', [SCRIPT, clean(dir), owner.pub, seq], { encoding: 'utf8', cwd: w.root, env: { PATH: process.env.PATH, HOME: w.root, TMPDIR: tmpdir(), MG_CHECKPOINT_DIRS: cps.join(':') } });
    let r = run(b3, [good]); assert.equal(r.status, 0, r.stderr); assert.match(r.stdout, /sequence=3 .*checkpoint_sequence=3/);
    r = run(b2, [good]); assert.equal(r.status, 1); assert.match(r.stderr, /rollback or loss: this backup is sequence 2 but sequence 3 was confirmed/);
    r = run(b2, [bad]); assert.equal(r.status, 1); assert.match(r.stderr, /no authentic checkpoint copy was found/, 'a forged checkpoint is ignored, and with nothing authentic left the old backup is not waved through');
    r = run(b2, [bad, good]); assert.equal(r.status, 1); assert.match(r.stderr, /sequence 2 but sequence 3/);
    r = run(b3, [bad, good]); assert.equal(r.status, 0, r.stderr); assert.match(r.stderr, /checkpoint copy 1 is missing or not authentic and is ignored/);
    const bare = (extra) => spawnSync('sh', [SCRIPT, clean(b2), owner.pub, '1'], { encoding: 'utf8', cwd: w.root, env: { PATH: process.env.PATH, HOME: w.root, TMPDIR: tmpdir(), ...extra } });
    r = bare({}); assert.equal(r.status, 1, 'by default the old backup is REFUSED when no trusted checkpoint is given'); assert.match(r.stderr, /no trusted checkpoint was given/);
    r = bare({ MG_ALLOW_NO_CHECKPOINT: '1' }); assert.equal(r.status, 0); assert.match(r.stdout, /checkpoint=none NOT-PROTECTED-AGAINST-ROLLBACK/, 'only the explicit opt-out lets it pass, and the output says it is unprotected');
    assert.ok(existsSync(good));
  } finally { w.done(); }
});
