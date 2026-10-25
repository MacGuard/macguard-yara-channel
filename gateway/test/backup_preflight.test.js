// The go / no-go before the first real copy: it must refuse whatever it was asked to be sure of, and it must never touch a secret or the network.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { signBackup, signCheckpoint } from '../tools/backup_anchor.mjs';
import { makeKit } from '../tools/backup_kit.mjs';
import { preflight, ageStanzas } from '../tools/backup_preflight.mjs';

let HAVE = true; for (const t of ['age', 'age-keygen', 'ssh-keygen']) { try { execFileSync('which', [t], { stdio: 'pipe' }); } catch { HAVE = false; } }
const skip = { skip: !HAVE && 'age, age-keygen and ssh-keygen are needed' }, sha = (b) => createHash('sha256').update(b).digest('hex');

function ws() {
  const root = mkdtempSync(join(tmpdir(), 'mg-preflight-test-')), ssh = (n) => { const f = join(root, n); execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', n, '-f', f]); return { file: f, pub: readFileSync(f + '.pub', 'utf8').trim() }; };
  const age = (n) => { const f = join(root, n); execFileSync('age-keygen', ['-o', f], { stdio: 'pipe' }); chmodSync(f, 0o600); return { file: f, recipient: readFileSync(f, 'utf8').match(/public key: (age1\S+)/)[1] }; };
  const backups = join(root, 'backups'); mkdirSync(backups);
  const backup = (stamp, rcpts, signer, prev = null, t = '2026-10-24T05:00:00Z', plain = 'CREATE TABLE t(x);\n') => {
    const dir = join(backups, stamp); mkdirSync(dir); const args = rcpts.flatMap((r) => ['-r', r]);
    writeFileSync(join(dir, 'd1-export.sql.age'), execFileSync('age', args, { input: Buffer.from(plain) })); writeFileSync(join(dir, 'manifest.json'), JSON.stringify({ schema: 'macguard.gateway-backup/2', created_at: t, encrypted: true, plaintext_sha256: sha(Buffer.from(plain)) }));
    writeFileSync(join(dir, 'SHA256SUMS'), ['d1-export.sql.age', 'manifest.json'].map((f) => `${sha(readFileSync(join(dir, f)))}  ${f}`).join('\n') + '\n'); if (signer) signBackup({ dir, signingKey: signer.file, previousDir: prev, clock: () => new Date(t) }); return dir;
  };
  return { root, backups, ssh, age, backup, done: () => rmSync(root, { recursive: true, force: true }) };
}
const by = (r, id) => r.checks.find((c) => c.id === id);

test('GO: an intact, singly-addressed, anchored backup whose recipient matches the kit and the identity; write permission and a real restore stay explicit human steps', skip, () => {
  const w = ws(); try {
    const sign = w.ssh('sign'), id = w.age('id'), b1 = w.backup('20261024T050235Z', [id.recipient], sign); writeFileSync(join(w.backups, 'recipient.txt'), id.recipient + '\n'); const kit = join(w.root, 'kit.txt'); writeFileSync(kit, makeKit({ publicKey: sign.pub, ageRecipient: id.recipient, headDir: b1 }));
    const cp = join(w.root, 'cp'); signCheckpoint({ backupDir: b1, outDir: cp, signingKey: sign.file });
    const r = preflight({ root: w.backups, trustKey: sign.pub, kit, identity: id.file, checkpointDirs: [cp], env: {} });
    assert.equal(r.verdict, 'GO', JSON.stringify(r.failures) + JSON.stringify(r.required_not_passed)); for (const c of ['integrity', 'age_header', 'anchor', 'anchor_chain', 'recipient_vs_kit', 'identity_matches_recipient', 'checkpoint']) assert.equal(by(r, c).state, 'PASS', c);
    assert.ok(r.human_steps.includes('write_permission') && r.human_steps.includes('real_restore')); assert.match(by(r, 'cost').detail, /5 objects/);
    assert.ok(!JSON.stringify(r).includes('AGE-SECRET-KEY'), 'no secret in the output');
  } finally { w.done(); }
});

test('NO_GO: tampered ciphertext, a second recipient, an unanchored or forged backup, a recipient that is not the kit\'s, an identity that does not match', skip, () => {
  const w = ws(); try {
    const sign = w.ssh('sign'), attacker = w.ssh('attacker'), id = w.age('id'), other = w.age('other'); writeFileSync(join(w.backups, 'recipient.txt'), id.recipient + '\n'); const kit = join(w.root, 'kit.txt'); writeFileSync(kit, makeKit({ publicKey: sign.pub, ageRecipient: id.recipient }));
    const run = (extra = {}) => preflight({ root: w.backups, trustKey: sign.pub, kit, env: {}, ...extra });
    // 1 tampered ciphertext after signing
    let dir = w.backup('20261024T050235Z', [id.recipient], sign); writeFileSync(join(dir, 'd1-export.sql.age'), Buffer.concat([readFileSync(join(dir, 'd1-export.sql.age')), Buffer.from('x')])); let r = run(); assert.equal(r.verdict, 'NO_GO'); assert.equal(by(r, 'integrity').state, 'FAIL'); rmSync(dir, { recursive: true });
    // 2 a second recipient could also decrypt
    dir = w.backup('20261025T050235Z', [id.recipient, other.recipient], sign); r = run(); assert.equal(r.verdict, 'NO_GO'); assert.equal(by(r, 'age_header').state, 'FAIL'); assert.match(by(r, 'age_header').detail, /X25519, X25519/); rmSync(dir, { recursive: true });
    // 3 not anchored / anchored by someone else
    dir = w.backup('20261026T050235Z', [id.recipient], null); r = run(); assert.equal(r.verdict, 'NO_GO'); assert.match(by(r, 'anchor').detail, /no signed anchor/); rmSync(dir, { recursive: true });
    dir = w.backup('20261027T050235Z', [id.recipient], attacker); r = run(); assert.equal(r.verdict, 'NO_GO'); assert.match(by(r, 'anchor').detail, /signature does not verify/); rmSync(dir, { recursive: true });
    // 4 without the trusted key authenticity is not checked, and that alone is NO_GO
    dir = w.backup('20261028T050235Z', [id.recipient], sign); r = preflight({ root: w.backups, kit, env: {} }); assert.equal(r.verdict, 'NO_GO'); assert.equal(by(r, 'anchor').state, 'NOT_RUN'); assert.ok(r.required_not_passed.includes('anchor'));
    // 5 recipient.txt is not the kit's recipient; the identity held is not the recipient
    writeFileSync(join(w.backups, 'recipient.txt'), other.recipient + '\n'); r = run(); assert.equal(by(r, 'recipient_vs_kit').state, 'FAIL'); assert.equal(r.verdict, 'NO_GO');
    writeFileSync(join(w.backups, 'recipient.txt'), id.recipient + '\n'); r = run({ identity: other.file }); assert.equal(by(r, 'identity_matches_recipient').state, 'FAIL'); assert.equal(r.verdict, 'NO_GO');
    r = run({ identity: id.file }); assert.equal(r.verdict, 'NO_GO', 'everything else is fine, but WITHOUT a trusted checkpoint it is not a GO'); assert.deepEqual(r.required_not_passed, ['checkpoint']);
    const cpd = join(w.root, 'cp-final'); signCheckpoint({ backupDir: dir, outDir: cpd, signingKey: sign.file }); assert.equal(run({ identity: id.file, checkpointDirs: [cpd] }).verdict, 'GO');
  } finally { w.done(); }
});

test('rollback and plaintext: an anchored backup older than the external checkpoint is refused; a directory with only plaintext is never a candidate', skip, () => {
  const w = ws(); try {
    const sign = w.ssh('sign'), id = w.age('id'); writeFileSync(join(w.backups, 'recipient.txt'), id.recipient + '\n'); const b1 = w.backup('20261024T050235Z', [id.recipient], sign), b2 = w.backup('20261025T050235Z', [id.recipient], sign, b1, '2026-10-25T05:00:00Z'); const kit = join(w.root, 'kit.txt'); writeFileSync(kit, makeKit({ publicKey: sign.pub, ageRecipient: id.recipient }));
    const cp2 = join(w.root, 'cp2'); signCheckpoint({ backupDir: b2, outDir: cp2, signingKey: sign.file });
    assert.equal(preflight({ root: w.backups, stamp: '20261024T050235Z', trustKey: sign.pub, kit, checkpointDirs: [cp2], env: {} }).verdict, 'NO_GO', 'sequence 1 is behind the confirmed sequence 2');
    assert.equal(preflight({ root: w.backups, trustKey: sign.pub, kit, checkpointDirs: [cp2], env: {} }).verdict, 'GO');
    const plain = mkdtempSync(join(tmpdir(), 'mg-plain-')); mkdirSync(join(plain, '20261023T200122Z')); writeFileSync(join(plain, '20261023T200122Z', 'd1-export.sql'), 'secret rows'); const r = preflight({ root: plain, trustKey: sign.pub, env: {} }); assert.equal(r.verdict, 'NO_GO'); assert.equal(by(r, 'candidate').state, 'FAIL'); rmSync(plain, { recursive: true });
  } finally { w.done(); }
});

test('permissions: a write key that can also delete or bypass retention is a WARN, no writer is a FAIL, no data is a human step; credentials are reported by name only', skip, () => {
  const w = ws(); try {
    const sign = w.ssh('sign'), id = w.age('id'); writeFileSync(join(w.backups, 'recipient.txt'), id.recipient + '\n'); w.backup('20261024T050235Z', [id.recipient], sign); const kit = join(w.root, 'kit.txt'); writeFileSync(kit, makeKit({ publicKey: sign.pub, ageRecipient: id.recipient }));
    const caps = join(w.root, 'caps.json'); writeFileSync(caps, JSON.stringify({ b2: [{ name: 'macguard-b2-write', bucket_scoped: true, capabilities: ['listBuckets', 'writeFiles', 'deleteFiles', 'bypassGovernance'] }, { name: 'macguard-b2-read', bucket_scoped: true, capabilities: ['readFiles'] }], scaleway: [{ name: 'k', bucket_scoped: true, capabilities: ['readFiles'] }], r2: [{ name: 'tok', bucket_scoped: true, capabilities: ['write'] }] }));
    const r = preflight({ root: w.backups, trustKey: sign.pub, kit, capabilities: caps, env: { MG_B2_KEY_ID: 'AAAA-secret-id', MG_B2_SECRET: 'SUPER-SECRET-VALUE' } });
    assert.equal(by(r, 'permissions_b2').state, 'WARN'); assert.match(by(r, 'permissions_b2').detail, /can delete\/bypass retention/); assert.equal(by(r, 'permissions_scaleway').state, 'FAIL'); assert.equal(by(r, 'permissions_r2').state, 'PASS'); assert.equal(r.verdict, 'NO_GO');
    assert.match(by(r, 'destination_b2').detail, /present/); assert.match(by(r, 'destination_r2').detail, /absent/); assert.ok(!JSON.stringify(r).includes('SUPER-SECRET-VALUE') && !JSON.stringify(r).includes('AAAA-secret-id'), 'credential values are never read into the report');
    assert.equal(by(preflight({ root: w.backups, trustKey: sign.pub, kit, env: {} }), 'permissions_b2').state, 'NOT_RUN');
  } finally { w.done(); }
});

test('the age header reader sees stanza types and rejects non-age data', () => {
  assert.deepEqual(ageStanzas(Buffer.from('age-encryption.org/v1\n-> X25519 abc\nAAAA\n-> scrypt salt 18\nBBBB\n--- mac\nbinary')), ['X25519', 'scrypt']); assert.equal(ageStanzas(Buffer.from('not age')), null); assert.equal(ageStanzas(Buffer.from('age-encryption.org/v1\n-> X25519 abc\nno terminator')), null);
});
