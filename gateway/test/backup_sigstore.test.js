// Sigstore keyless signing of ANCHOR.json / CHECKPOINT.json: policy, identity pinning, scheme selection and the refusal of any downgrade.
// IMPORTANT: `cosign` is replaced here by a STAND-IN that binds a bundle to the SHA-256 of the signed bytes and to an identity taken from an environment variable. It exercises our policy and glue; it does NOT exercise
// Fulcio, Rekor or the certificate chain. The cryptographic evidence for those is the real workflow run verified with the real cosign (docs/analytics/BACKUP-SIGSTORE-MIGRATION-2026-10-25.md). Throw-away Ed25519 keys only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { signBackup, signBackupSigstore, signCheckpoint, signCheckpointSigstore, verifyAnchor, verifyCheckpoint, verifyChain, sigstorePolicyError, SIGSTORE_ISSUER, ANCHOR_BUNDLE, CHECKPOINT_BUNDLE } from '../tools/backup_anchor.mjs';

let HAVE = true; try { execFileSync('ssh-keygen', ['-Y', 'find-principals'], { stdio: 'pipe' }); } catch (e) { HAVE = !/unknown option|illegal option|usage: ssh-keygen/i.test(String(e.stderr)) || /find-principals/.test(String(e.stderr)); }
const skip = { skip: !HAVE && 'ssh-keygen with -Y support is needed' };
const ID = 'https://github.com/MacGuard/macguard-yara-channel/.github/workflows/backup.yml@refs/heads/main', REPO = 'MacGuard/macguard-yara-channel';
const POLICY = (root, extra = {}) => ({ identity: ID, repository: REPO, cosign: join(root, 'cosign'), ...extra });
const STUB = `#!/usr/bin/env node
const fs = require('fs'), crypto = require('crypto'); const a = process.argv.slice(2), sha = (f) => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex'), opt = (n) => { const i = a.indexOf(n); return i >= 0 ? a[i + 1] : null; };
if (a[0] === 'sign-blob') { if (process.env.STUB_FAIL) { console.error('Error: no OIDC token'); process.exit(1); } const out = opt('--bundle'), file = a[a.length - 1]; const b = JSON.stringify({ stub: 'cosign', sha256: sha(file), identity: process.env.STUB_IDENTITY, pad: 'x'.repeat(40) }); fs.writeFileSync(out, process.env.STUB_TRUNCATE ? b.slice(0, 12) : b); process.exit(0); }
if (a[0] === 'verify-blob') { let b; try { b = JSON.parse(fs.readFileSync(opt('--bundle'), 'utf8')); } catch { console.error('Error: bad bundle'); process.exit(1); }
  if (opt('--certificate-oidc-issuer') !== '${SIGSTORE_ISSUER}') { console.error('Error: issuer'); process.exit(1); } if (!opt('--certificate-github-workflow-repository')) { console.error('Error: repo not pinned'); process.exit(1); }
  if (b.sha256 !== sha(a[a.length - 1])) { console.error('Error: signature does not match the blob'); process.exit(1); } if (b.identity !== opt('--certificate-identity')) { console.error('Error: certificate identity does not match'); process.exit(1); } process.exit(0); }
process.exit(2);
`;

function ws() {
  const root = mkdtempSync(join(tmpdir(), 'mg-sigstore-test-')); writeFileSync(join(root, 'cosign'), STUB); chmodSync(join(root, 'cosign'), 0o755);
  const key = (n) => { const f = join(root, n); execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', n, '-f', f]); return { file: f, pub: readFileSync(f + '.pub', 'utf8').trim() }; };
  const backup = (stamp) => { const dir = join(root, stamp); mkdirSync(dir); for (const f of ['d1-export.sql.age', 'manifest.json', 'SHA256SUMS']) writeFileSync(join(dir, f), f + stamp); return dir; };
  const load = (d) => Object.fromEntries(readdirSync(d).filter((f) => !f.startsWith('.')).map((f) => [f, readFileSync(join(d, f))]));
  return { root, key, backup, load, done: () => rmSync(root, { recursive: true, force: true }) };
}
const withEnv = (env, fn) => { const old = {}; for (const k of Object.keys(env)) { old[k] = process.env[k]; process.env[k] = env[k]; } try { return fn(); } finally { for (const k of Object.keys(env)) { if (old[k] === undefined) delete process.env[k]; else process.env[k] = old[k]; } } };

test('history stays valid and new backups are Sigstore: sequence 1 (Ed25519) and sequence 2 (keyless) both verify under one policy, and the chain links them', skip, () => {
  const w = ws(); try {
    const owner = w.key('owner'), d1 = w.backup('20261024T050235Z'), d2 = w.backup('20261026T020000Z'), pol = POLICY(w.root);
    signBackup({ dir: d1, signingKey: owner.file, publicKey: owner.pub });
    const r = withEnv({ STUB_IDENTITY: ID }, () => signBackupSigstore({ dir: d2, sigstore: pol, ed25519MaxSequence: 1, previousDir: d1 })); assert.equal(r.sequence, 2); assert.equal(r.scheme, 'sigstore');
    const v1 = verifyAnchor({ files: w.load(d1), publicKey: owner.pub, sigstore: pol, ed25519MaxSequence: 1 }), v2 = verifyAnchor({ files: w.load(d2), publicKey: owner.pub, sigstore: pol, ed25519MaxSequence: 1 });
    assert.deepEqual([v1.ok, v1.scheme, v2.ok, v2.scheme], [true, 'ed25519', true, 'sigstore'], v1.reason + v2.reason); assert.equal(verifyChain([readFileSync(join(d1, 'ANCHOR.json')), readFileSync(join(d2, 'ANCHOR.json'))]).ok, true);
    assert.equal(verifyAnchor({ files: w.load(d1), publicKey: owner.pub }).ok, true, 'the pre-migration verifier still accepts the historical backup');
    assert.equal(verifyAnchor({ files: w.load(d2), publicKey: owner.pub }).ok, false, 'and refuses a Sigstore backup (it carries no Ed25519 signature)');
  } finally { w.done(); }
});

test('only the pinned workflow may sign: another workflow file, branch or repository publishes nothing', skip, () => {
  const w = ws(); try {
    const owner = w.key('owner'), pol = POLICY(w.root), d1 = w.backup('20261024T050235Z'), d = w.backup('20261026T020000Z'), before = readdirSync(d).sort(); signBackup({ dir: d1, signingKey: owner.file, publicKey: owner.pub });
    for (const evil of ['https://github.com/MacGuard/macguard-yara-channel/.github/workflows/backup.yml@refs/heads/evil', 'https://github.com/MacGuard/macguard-yara-channel/.github/workflows/other.yml@refs/heads/main', 'https://github.com/attacker/macguard-yara-channel/.github/workflows/backup.yml@refs/heads/main', 'https://github.com/MacGuard/macguard-yara-channel/.github/workflows/backup.yml@refs/pull/1/merge'])
      assert.throws(() => withEnv({ STUB_IDENTITY: evil }, () => signBackupSigstore({ dir: d, sigstore: pol, ed25519MaxSequence: 1, previousDir: d1 })), /does not verify for the pinned identity|nothing was kept/); assert.deepEqual(readdirSync(d).sort(), before);
    assert.throws(() => withEnv({ STUB_IDENTITY: ID, STUB_FAIL: '1' }, () => signBackupSigstore({ dir: d, sigstore: pol, ed25519MaxSequence: 1, previousDir: d1 })), /signing failed/); assert.deepEqual(readdirSync(d).sort(), before);
    assert.throws(() => withEnv({ STUB_IDENTITY: ID, STUB_TRUNCATE: '1' }, () => signBackupSigstore({ dir: d, sigstore: pol, ed25519MaxSequence: 1, previousDir: d1 })), /no usable signature|bundle/); assert.deepEqual(readdirSync(d).sort(), before);
  } finally { w.done(); }
});

test('no downgrade: an Ed25519 signature on sequence 2 (a leaked old key) is refused, a bundle cannot be moved to another statement, a tampered statement fails', skip, () => {
  const w = ws(); try {
    const owner = w.key('owner'), pol = POLICY(w.root), d1 = w.backup('20261024T050235Z'), d2 = w.backup('20261026T020000Z'), d3 = w.backup('20261027T020000Z');
    signBackup({ dir: d1, signingKey: owner.file, publicKey: owner.pub });
    signBackup({ dir: d2, signingKey: owner.file, publicKey: owner.pub, previousDir: d1 });                                                               // the old key signs sequence 2 itself
    const down = verifyAnchor({ files: w.load(d2), publicKey: owner.pub, sigstore: pol, ed25519MaxSequence: 1 }); assert.equal(down.ok, false); assert.match(down.reason, /must be signed with Sigstore keyless.*no downgrade/);
    withEnv({ STUB_IDENTITY: ID }, () => signBackupSigstore({ dir: d3, sigstore: pol, ed25519MaxSequence: 1, sequence: 3, previousDir: d2 }));
    const files = w.load(d3), other = { ...files, 'ANCHOR.json': readFileSync(join(d2, 'ANCHOR.json')) }; assert.match(verifyAnchor({ files: other, publicKey: owner.pub, sigstore: pol, ed25519MaxSequence: 1 }).reason, /does not verify for the pinned identity/);
    const tampered = { ...files, 'ANCHOR.json': Buffer.from(files['ANCHOR.json'].toString().replace('"sequence":3', '"sequence":9')) }; assert.equal(verifyAnchor({ files: tampered, publicKey: owner.pub, sigstore: pol, ed25519MaxSequence: 1 }).ok, false);
    const both = { ...files, 'ANCHOR.json.sig': readFileSync(join(d2, 'ANCHOR.json.sig')) }; assert.equal(verifyAnchor({ files: both, publicKey: owner.pub, sigstore: pol, ed25519MaxSequence: 1 }).ok, true, 'an extra Ed25519 file is ignored; only the required scheme counts');
    const wrongId = { ...pol, identity: ID.replace('main', 'dev') }; assert.equal(verifyAnchor({ files, publicKey: owner.pub, sigstore: wrongId, ed25519MaxSequence: 1 }).ok, false, 'a verifier that pins another identity refuses it');
    const noBundle = { ...files }; delete noBundle[ANCHOR_BUNDLE]; assert.match(verifyAnchor({ files: noBundle, publicKey: owner.pub, sigstore: pol, ed25519MaxSequence: 1 }).reason, /no downgrade/);
  } finally { w.done(); }
});

test('the policy itself is strict: no pattern identity, no missing freeze point, repository must match, issuer must be GitHub Actions', () => {
  assert.equal(sigstorePolicyError({ identity: ID, repository: REPO }, 1), null);
  for (const [p, f, re] of [[{ identity: 'https://github.com/MacGuard/.*', repository: REPO }, 1, /exact GitHub workflow identity/], [{ identity: ID, repository: REPO }, undefined, /ed25519MaxSequence/], [{ identity: ID, repository: 'Other/repo' }, 1, /match the identity/], [{ identity: ID, repository: REPO, issuer: 'https://accounts.google.com' }, 1, /issuer/], [{ identity: ID.replace('@refs/heads/main', ''), repository: REPO }, 1, /exact GitHub workflow identity/], [null, 1, /no Sigstore policy/]]) assert.match(sigstorePolicyError(p, f), re);
});

test('sequences inside the frozen Ed25519 range cannot be signed keylessly, and a missing previous anchor stops the chain', skip, () => {
  const w = ws(); try {
    const pol = POLICY(w.root), d = w.backup('20261026T020000Z');
    assert.throws(() => withEnv({ STUB_IDENTITY: ID }, () => signBackupSigstore({ dir: d, sigstore: pol, ed25519MaxSequence: 1 })), /frozen Ed25519 range/);
    assert.throws(() => withEnv({ STUB_IDENTITY: ID }, () => signBackupSigstore({ dir: d, sigstore: pol, ed25519MaxSequence: 1, previousDir: join(w.root, 'nope') })), /previous backup has no anchor/);
    assert.deepEqual(readdirSync(d).sort(), ['SHA256SUMS', 'd1-export.sql.age', 'manifest.json']);
  } finally { w.done(); }
});

test('the checkpoint follows the same rules: keyless after the freeze, Ed25519 refused for it, wrong identity publishes nothing, a bundle of another statement is refused', skip, () => {
  const w = ws(); try {
    const owner = w.key('owner'), pol = POLICY(w.root), d1 = w.backup('20261024T050235Z'), d2 = w.backup('20261026T020000Z');
    signBackup({ dir: d1, signingKey: owner.file, publicKey: owner.pub }); withEnv({ STUB_IDENTITY: ID }, () => signBackupSigstore({ dir: d2, sigstore: pol, ed25519MaxSequence: 1, previousDir: d1 }));
    const c2 = join(w.root, 'c2'); mkdirSync(c2);
    assert.throws(() => withEnv({ STUB_IDENTITY: ID.replace('main', 'x') }, () => signCheckpointSigstore({ backupDir: d2, outDir: c2, sigstore: pol, ed25519MaxSequence: 1 })), /nothing was kept/); assert.deepEqual(readdirSync(c2), []);
    const r = withEnv({ STUB_IDENTITY: ID }, () => signCheckpointSigstore({ backupDir: d2, outDir: c2, sigstore: pol, ed25519MaxSequence: 1 })); assert.equal(r.sequence, 2);
    const v = verifyCheckpoint({ files: w.load(c2), publicKey: owner.pub, sigstore: pol, ed25519MaxSequence: 1 }); assert.equal(v.ok, true, v.reason); assert.equal(v.scheme, 'sigstore');
    const cEd = join(w.root, 'ced'); signCheckpoint({ backupDir: d2, outDir: cEd, signingKey: owner.file, publicKey: owner.pub }); assert.match(verifyCheckpoint({ files: w.load(cEd), publicKey: owner.pub, sigstore: pol, ed25519MaxSequence: 1 }).reason, /no downgrade/);
    const swapped = { ...w.load(c2), [CHECKPOINT_BUNDLE]: readFileSync(join(d2, ANCHOR_BUNDLE)) }; assert.equal(verifyCheckpoint({ files: swapped, publicKey: owner.pub, sigstore: pol, ed25519MaxSequence: 1 }).ok, false, 'the anchor bundle does not authenticate a checkpoint');
    assert.throws(() => withEnv({ STUB_IDENTITY: ID }, () => signCheckpointSigstore({ backupDir: d1, outDir: join(w.root, 'c1'), sigstore: pol, ed25519MaxSequence: 1 })), /frozen Ed25519 range/);
    const hist = join(w.root, 'c1h'); signCheckpoint({ backupDir: d1, outDir: hist, signingKey: owner.file, publicKey: owner.pub }); assert.equal(verifyCheckpoint({ files: w.load(hist), publicKey: owner.pub, sigstore: pol, ed25519MaxSequence: 1 }).ok, true, 'the historical checkpoint still verifies');
  } finally { w.done(); }
});

test('CLI: sign-sigstore refuses to run without the pinned identity, repository and freeze point (exit 2) and verify reports the scheme', skip, () => {
  const w = ws(); try {
    const owner = w.key('owner'), d1 = w.backup('20261024T050235Z'), CLI = new URL('../tools/backup_anchor.mjs', import.meta.url).pathname; signBackup({ dir: d1, signingKey: owner.file, publicKey: owner.pub });
    for (const args of [['sign-sigstore', '--dir', d1], ['sign-sigstore', '--dir', d1, '--sigstore-identity', ID], ['sign-sigstore', '--dir', d1, '--sigstore-identity', ID, '--sigstore-repo', REPO]]) assert.equal(spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' }).status, 2);
    const r = spawnSync(process.execPath, [CLI, 'verify', '--dir', d1, '--public-key', owner.pub, '--sigstore-identity', ID, '--sigstore-repo', REPO, '--ed25519-max-sequence', '1'], { encoding: 'utf8' }); assert.equal(r.status, 0, r.stderr); assert.equal(JSON.parse(r.stdout).scheme, 'ed25519');
  } finally { w.done(); }
});

test('clean-machine shell verifier: a Sigstore backup passes with the pinned identity; Ed25519 above the freeze, another identity, an incomplete policy and an unbundled checkpoint are refused', skip, () => {
  const w = ws(); try {
    const owner = w.key('owner'), pol = POLICY(w.root), d1 = w.backup('20261024T050235Z'), d2 = w.backup('20261026T020000Z'), d2ed = w.backup('20261026T030000Z'), SH = new URL('../tools/recover_verify.sh', import.meta.url).pathname;
    signBackup({ dir: d1, signingKey: owner.file, publicKey: owner.pub }); withEnv({ STUB_IDENTITY: ID }, () => signBackupSigstore({ dir: d2, sigstore: pol, ed25519MaxSequence: 1, previousDir: d1 })); signBackup({ dir: d2ed, signingKey: owner.file, publicKey: owner.pub, previousDir: d1 });
    const c2 = join(w.root, 'c2'); mkdirSync(c2); withEnv({ STUB_IDENTITY: ID }, () => signCheckpointSigstore({ backupDir: d2, outDir: c2, sigstore: pol, ed25519MaxSequence: 1 }));
    const cEd = join(w.root, 'ced'); signCheckpoint({ backupDir: d2ed, outDir: cEd, signingKey: owner.file, publicKey: owner.pub });
    const clean = (d) => { const c = mkdtempSync(join(w.root, 'clean-')); for (const f of readdirSync(d)) writeFileSync(join(c, f), readFileSync(join(d, f))); return c; };
    const run = (dir, cps, env = {}) => spawnSync('sh', [SH, clean(dir), owner.pub, '1'], { encoding: 'utf8', cwd: w.root, env: { PATH: w.root + ':' + process.env.PATH, HOME: w.root, TMPDIR: tmpdir(), MG_CHECKPOINT_DIRS: cps.join(':'), STUB_IDENTITY: ID, MG_SIGSTORE_IDENTITY: ID, MG_SIGSTORE_REPO: REPO, MG_ED25519_MAX_SEQUENCE: '1', ...env } });
    let r = run(d2, [c2]); assert.equal(r.status, 0, r.stderr); assert.match(r.stdout, /ANCHORED OK stamp=20261026T020000Z sequence=2 .*scheme=sigstore.*checkpoint_sequence=2/);
    r = run(d1, [c2]); assert.equal(r.status, 1); assert.match(r.stderr, /rollback or loss: this backup is sequence 1 but sequence 2 was confirmed/, 'the historical Ed25519 backup still authenticates, then the checkpoint calls it a rollback');
    r = run(d2ed, [cEd]); assert.equal(r.status, 1); assert.match(r.stderr, /no downgrade/);
    r = run(d2, [c2], { MG_SIGSTORE_IDENTITY: ID.replace('main', 'dev') }); assert.equal(r.status, 1); assert.match(r.stderr, /does not verify for the pinned workflow identity/);
    r = run(d2, [c2], { MG_SIGSTORE_IDENTITY: 'https://github.com/MacGuard/.*' }); assert.equal(r.status, 1); assert.match(r.stderr, /exact GitHub workflow identity/);
    r = run(d2, [c2], { MG_ED25519_MAX_SEQUENCE: '' }); assert.equal(r.status, 1); assert.match(r.stderr, /must be given together/);
    r = run(d2, [cEd]); assert.equal(r.status, 1, 'an Ed25519 checkpoint for a sequence above the freeze is ignored, so no authentic checkpoint remains'); assert.match(r.stderr, /no authentic checkpoint copy/);
    r = run(d1, [join(w.root, 'none')], { MG_SIGSTORE_IDENTITY: '', MG_SIGSTORE_REPO: '', MG_ED25519_MAX_SEQUENCE: '' }); assert.equal(r.status, 1);
  } finally { w.done(); }
});
