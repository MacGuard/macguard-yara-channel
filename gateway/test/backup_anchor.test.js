// Adversarial tests of the independent backup anchor: a forged self-consistent backup, an altered manifest, a rollback, the loss of a provider and the loss of the original machine.
// Keys are throw-away ed25519 keys made for each test; no real key, identity or secret is read.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { signBackup, verifyAnchor, compareHeads, verifyChain, headSha, NAMESPACE } from '../tools/backup_anchor.mjs';

let HAVE = true; try { execFileSync('ssh-keygen', ['-Y', 'find-principals'], { stdio: 'pipe' }); } catch (e) { HAVE = !/unknown option|illegal option|usage: ssh-keygen/i.test(String(e.stderr)) || /find-principals/.test(String(e.stderr)); }
const skip = { skip: !HAVE && 'ssh-keygen with -Y support is needed' };

function workspace() {
  const root = mkdtempSync(join(tmpdir(), 'mg-anchor-test-')), key = (n) => { const f = join(root, n); execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', n, '-f', f]); return { file: f, pub: readFileSync(f + '.pub', 'utf8').trim() }; };
  const backup = (stamp, body, prev = null, k, t = '2026-10-24T05:00:00Z') => {
    const dir = join(root, 'local', stamp); mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'd1-export.sql.age'), Buffer.from('age-encryption.org/v1 ' + body)); writeFileSync(join(dir, 'manifest.json'), JSON.stringify({ schema: 'macguard.gateway-backup/2', stamp, body }));
    writeFileSync(join(dir, 'SHA256SUMS'), ['d1-export.sql.age', 'manifest.json'].map((f) => `${createHash('sha256').update(readFileSync(join(dir, f))).digest('hex')}  ${f}`).join('\n') + '\n');
    return { dir, signed: signBackup({ dir, signingKey: k.file, previousDir: prev, clock: () => new Date(t) }) };
  };
  const files = (dir) => Object.fromEntries(readdirSync(dir).map((f) => [f, readFileSync(join(dir, f))]));
  return { root, key, backup, files, done: () => rmSync(root, { recursive: true, force: true }) };
}

test('a genuine signed backup verifies with only the public key, the statement and the files (no local copy, no Mac)', skip, () => {
  const w = workspace(); try {
    const k = w.key('owner'), b1 = w.backup('20261024T050235Z', 'one', null, k), bucket = new Map(Object.entries(w.files(b1.dir)));
    rmSync(join(w.root, 'local'), { recursive: true });                                                    // the original machine is gone: only the bucket's bytes and the public key remain
    const v = verifyAnchor({ files: bucket, publicKey: k.pub, expectedStamp: '20261024T050235Z' }); assert.equal(v.ok, true, v.reason); assert.equal(v.anchor.sequence, 1); assert.equal(v.anchor.previous_head_sha256, null);
  } finally { w.done(); }
});

test('a forged backup that is perfectly self-consistent is rejected: the attacker has no signing key', skip, () => {
  const w = workspace(); try {
    const owner = w.key('owner'), attacker = w.key('attacker'), real = w.backup('20261024T050235Z', 'real', null, owner);
    const fake = w.backup('20261024T060000Z', 'fake', null, attacker);                                    // consistent files, anchor signed by the attacker's own key
    const asServed = { ...w.files(fake.dir) };
    assert.match(verifyAnchor({ files: asServed, publicKey: owner.pub }).reason, /signature does not verify/);
    const spliced = { ...w.files(fake.dir), 'ANCHOR.json': readFileSync(join(real.dir, 'ANCHOR.json')), 'ANCHOR.json.sig': readFileSync(join(real.dir, 'ANCHOR.json.sig')) };   // a genuine signature glued onto the fake files
    assert.match(verifyAnchor({ files: spliced, publicKey: owner.pub }).reason, /does not match the signed statement/);
  } finally { w.done(); }
});

test('an altered manifest, checksum list, ciphertext or statement is rejected, naming what changed', skip, () => {
  const w = workspace(); try {
    const k = w.key('owner'), b = w.backup('20261024T050235Z', 'x', null, k), good = w.files(b.dir);
    for (const f of ['manifest.json', 'SHA256SUMS', 'd1-export.sql.age']) { const bad = { ...good, [f]: Buffer.concat([good[f], Buffer.from(' ')]) }; assert.match(verifyAnchor({ files: bad, publicKey: k.pub }).reason, new RegExp(f.replace('.', '\\.') + ' does not match')); }
    const bumped = { ...good, 'ANCHOR.json': Buffer.from(good['ANCHOR.json'].toString().replace('"sequence":1', '"sequence":9')) }; assert.match(verifyAnchor({ files: bumped, publicKey: k.pub }).reason, /signature does not verify/);
    assert.match(verifyAnchor({ files: { ...good, 'ANCHOR.json.sig': undefined }, publicKey: k.pub }).reason, /no signed anchor/);
    assert.equal(verifyAnchor({ files: good, publicKey: k.pub }).ok, true, 'the untouched backup still verifies');
  } finally { w.done(); }
});

test('a signature made for another purpose (another namespace) is refused', skip, () => {
  const w = workspace(); try {
    const k = w.key('owner'), b = w.backup('20261024T050235Z', 'x', null, k); rmSync(join(b.dir, 'ANCHOR.json.sig'));
    execFileSync('ssh-keygen', ['-Y', 'sign', '-f', k.file, '-n', 'some-other-service/1', join(b.dir, 'ANCHOR.json')], { stdio: 'pipe' });
    assert.match(verifyAnchor({ files: w.files(b.dir), publicKey: k.pub }).reason, /signature does not verify/);
  } finally { w.done(); }
});

test('rollback: an older genuine backup is refused when a newer sequence is known; a provider serving an older head is reported stale', skip, () => {
  const w = workspace(); try {
    const k = w.key('owner'), b1 = w.backup('20261024T050235Z', 'one', null, k), b2 = w.backup('20261025T050235Z', 'two', b1.dir, k, '2026-10-25T05:00:00Z'), b3 = w.backup('20261026T050235Z', 'three', b2.dir, k, '2026-10-26T05:00:00Z');
    assert.deepEqual([b1.signed.sequence, b2.signed.sequence, b3.signed.sequence], [1, 2, 3]); assert.equal(b2.signed.previous_head_sha256, b1.signed.head_sha256);
    assert.match(verifyAnchor({ files: w.files(b1.dir), publicKey: k.pub, minSequence: 3 }).reason, /rollback: sequence 1 is older than the newest known \(3\)/);
    const r = { b2: verifyAnchor({ files: w.files(b3.dir), publicKey: k.pub }), scaleway: verifyAnchor({ files: w.files(b2.dir), publicKey: k.pub }), r2: verifyAnchor({ files: w.files(b3.dir), publicKey: k.pub }) };
    const c = compareHeads(r); assert.equal(c.newest, 3); assert.deepEqual(c.current.sort(), ['b2', 'r2']); assert.deepEqual(c.stale, ['scaleway']); assert.deepEqual(c.conflicts, []);
  } finally { w.done(); }
});

test('equivocation: two different signed statements with the same sequence are reported, not silently accepted', skip, () => {
  const w = workspace(); try {
    const k = w.key('owner'), a = w.backup('20261024T050235Z', 'one', null, k), b = w.backup('20261024T050236Z', 'other', null, k, '2026-10-24T05:00:01Z');
    const c = compareHeads({ b2: verifyAnchor({ files: w.files(a.dir), publicKey: k.pub }), r2: verifyAnchor({ files: w.files(b.dir), publicKey: k.pub }) }); assert.equal(c.conflicts.length, 1); assert.match(c.conflicts[0].reason, /equivocation/);
  } finally { w.done(); }
});

test('loss of a provider: the others verify and the lost one is reported gone; losing all but one still authenticates', skip, () => {
  const w = workspace(); try {
    const k = w.key('owner'), b = w.backup('20261024T050235Z', 'one', null, k), ok = verifyAnchor({ files: w.files(b.dir), publicKey: k.pub });
    const c = compareHeads({ b2: null, scaleway: ok, r2: null }); assert.deepEqual(c.gone.sort(), ['b2', 'r2']); assert.deepEqual(c.current, ['scaleway']); assert.equal(c.newest, 1);
    assert.equal(compareHeads({ b2: null, scaleway: null, r2: null }).newest, null, 'nothing left is stated as nothing, not as a pass');
  } finally { w.done(); }
});

test('the chain of statements detects a missing or re-ordered link', skip, () => {
  const w = workspace(); try {
    const k = w.key('owner'), b1 = w.backup('20261024T050235Z', 'one', null, k), b2 = w.backup('20261025T050235Z', 'two', b1.dir, k, '2026-10-25T05:00:00Z'), b3 = w.backup('20261026T050235Z', 'three', b2.dir, k, '2026-10-26T05:00:00Z');
    const a = (b) => readFileSync(join(b.dir, 'ANCHOR.json'));
    assert.equal(verifyChain([a(b1), a(b2), a(b3)]).ok, true); assert.match(verifyChain([a(b1), a(b3)]).reason, /missing before sequence 3/); assert.match(verifyChain([a(b2), a(b3)]).reason, /missing before sequence 2/);
    const b2alt = w.backup('20261025T060000Z', 'two-alt', b1.dir, k, '2026-10-25T06:00:00Z'); assert.match(verifyChain([a(b1), a(b2alt), a(b3)]).reason, /does not name the statement that precedes it/);
  } finally { w.done(); }
});

test('the trusted key cannot be used to smuggle options or a second principal into the verifier', skip, () => {
  const w = workspace(); try {
    const k = w.key('owner'), b = w.backup('20261024T050235Z', 'one', null, k), f = w.files(b.dir);
    for (const evil of [k.pub + '\nattacker ssh-ed25519 AAAA', 'cert-authority ' + k.pub, k.pub.replace('ssh-ed25519', 'ssh-rsa'), '', 'namespaces="*" ' + k.pub]) assert.match(verifyAnchor({ files: f, publicKey: evil }).reason, /not a single ssh-ed25519 line/, JSON.stringify(evil).slice(0, 40));
    assert.match(verifyAnchor({ files: f, publicKey: k.pub, principal: 'a b' }).reason, /invalid principal/);
  } finally { w.done(); }
});

test('a backup replayed under another stamp is refused; signing never overwrites an anchor; a successor needs a predecessor that is anchored', skip, () => {
  const w = workspace(); try {
    const k = w.key('owner'), b1 = w.backup('20261024T050235Z', 'one', null, k);
    assert.match(verifyAnchor({ files: w.files(b1.dir), publicKey: k.pub, expectedStamp: '20261099T000000Z' }).reason, /is for 20261024T050235Z, not for 20261099T000000Z/);
    assert.throws(() => signBackup({ dir: b1.dir, signingKey: k.file }), /already has an anchor/);
    const dir = join(w.root, 'local', '20261025T050235Z'); mkdirSync(dir); for (const f of ['d1-export.sql.age', 'manifest.json', 'SHA256SUMS']) writeFileSync(join(dir, f), 'x');
    assert.throws(() => signBackup({ dir, signingKey: k.file, previousDir: join(w.root, 'local', 'nope') }), /previous backup has no anchor/);
    assert.equal(NAMESPACE, 'macguard-backup/1'); assert.equal(headSha(Buffer.from('a')).length, 64);
  } finally { w.done(); }
});

test('a backup is never left looking signed: an empty key, a key that is not the trusted one, and a missing public key all leave no statement', skip, () => {
  const w = workspace(); try {
    const owner = w.key('owner'), other = w.key('other'), dir = join(w.root, 'local', '20261026T050235Z'); mkdirSync(dir, { recursive: true });
    for (const f of ['d1-export.sql.age', 'manifest.json', 'SHA256SUMS']) writeFileSync(join(dir, f), 'x'); const none = () => readdirSync(dir).filter((f) => f.startsWith('ANCHOR'));
    const empty = join(w.root, 'empty-key'); writeFileSync(empty, '', { mode: 0o600 });
    assert.throws(() => signBackup({ dir, signingKey: empty, publicKey: owner.pub }), /empty or truncated/); assert.deepEqual(none(), []);
    assert.throws(() => signBackup({ dir, signingKey: other.file, publicKey: owner.pub }), /does not verify with the trusted key, nothing was kept/); assert.deepEqual(none(), []);
    assert.equal(signBackup({ dir, signingKey: owner.file, publicKey: owner.pub }).sequence, 1); assert.deepEqual(none().sort(), ['ANCHOR.json', 'ANCHOR.json.sig']);
  } finally { w.done(); }
});
