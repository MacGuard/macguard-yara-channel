// checkBundleBinding on REAL Sigstore bundles produced in GitHub Actions by an ephemeral lab (run 40791969186, exp/sigstore-lab, commit 3337c40): the same synthetic checkpoint bytes signed by two different
// workflows (a = sigstore-lab.yml, b = sigstore-lab-other.yml). Nothing sensitive: the checkpoint is {count, head} of a synthetic log. This checks what the bundle SAYS; the cryptographic verdict is cosign's
// and was exercised for real in the lab (docs/audit/evidence/sigstore-lab-2026-10-29.md). A bundle that cosign would accept must still say the right file, identity, issuer and carry transparency evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkBundleBinding } from '../tools/evidence_chain.mjs';

const FX = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'evidence-checkpoint-lab');
const REPO = 'https://github.com/MacGuard/macguard-yara-channel/.github/workflows/';
const ID_A = REPO + 'sigstore-lab.yml@refs/heads/exp/sigstore-lab', ID_B = REPO + 'sigstore-lab-other.yml@refs/heads/exp/sigstore-lab', ISS = 'https://token.actions.githubusercontent.com';
const tmp = mkdtempSync(join(tmpdir(), 'mg-bind-')); test.after(() => rmSync(tmp, { recursive: true, force: true }));
const cp = join(FX, 'checkpoint.json'), A = join(FX, 'a.sigstore.json'), B = join(FX, 'b.sigstore.json');
const edit = (src, name, fn) => { const j = JSON.parse(readFileSync(src, 'utf8')); fn(j); const f = join(tmp, name); writeFileSync(f, JSON.stringify(j)); return f; };
const check = (over = {}) => checkBundleBinding({ checkpointFile: cp, bundleFile: A, identity: ID_A, issuer: ISS, ...over });

test('a real bundle binds the exact file, the exact workflow identity, the exact issuer and a transparency entry with an inclusion proof', () => {
  assert.deepEqual(check(), { ok: true }); assert.deepEqual(check({ bundleFile: B, identity: ID_B }), { ok: true }, 'the other workflow\'s bundle is equally well-formed for ITS identity');
});

test('each property is enforced on its own: altered file, other identity, other workflow, other issuer, look-alike identity', () => {
  const altered = join(tmp, 'cp.json'); writeFileSync(altered, readFileSync(cp, 'utf8').replace('"count":3', '"count":2'));
  assert.match(check({ checkpointFile: altered }).problem, /digest is not the SHA-256 of the checkpoint file/);
  assert.match(check({ identity: REPO + 'evidence-checkpoint.yml@refs/heads/main' }).problem, /identity is not exactly the authorised workflow/);
  assert.match(check({ bundleFile: B }).problem, /identity is not exactly/, 'a genuine signature by a DIFFERENT workflow');
  assert.match(check({ issuer: 'https://accounts.google.com' }).problem, /OIDC issuer is not exactly/);
  assert.match(check({ issuer: ISS + '/' }).problem, /OIDC issuer is not exactly/, 'a prefix/suffix is not the issuer');
  assert.match(check({ identity: ID_A + '.evil' }).problem, /identity is not exactly/); assert.match(check({ identity: ID_A.replace('refs/heads/exp/sigstore-lab', 'refs/heads/main') }).problem, /identity is not exactly/, 'same workflow file on another ref');
});

test('transparency evidence is required: no entry, an entry without inclusion proof, or without its signed checkpoint, are all refused', () => {
  assert.match(check({ bundleFile: edit(A, 'notlog.json', (j) => { j.verificationMaterial.tlogEntries = []; }) }).problem, /no transparency log entry/);
  assert.match(check({ bundleFile: edit(A, 'nokey.json', (j) => { delete j.verificationMaterial.tlogEntries; }) }).problem, /no transparency log entry/);
  assert.match(check({ bundleFile: edit(A, 'noproof.json', (j) => { delete j.verificationMaterial.tlogEntries[0].inclusionProof; }) }).problem, /inclusion proof/, 'a promise alone is not enough');
  assert.match(check({ bundleFile: edit(A, 'nockpt.json', (j) => { delete j.verificationMaterial.tlogEntries[0].inclusionProof.checkpoint; }) }).problem, /inclusion proof/);
  assert.match(check({ bundleFile: edit(A, 'nohashes.json', (j) => { j.verificationMaterial.tlogEntries[0].inclusionProof.hashes = 'x'; }) }).problem, /inclusion proof/);
});

test('malformed or foreign-shaped bundles fail closed: not JSON, no message signature (DSSE), wrong digest algorithm, no certificate, unreadable certificate', () => {
  const junk = join(tmp, 'junk.json'); writeFileSync(junk, 'not json'); assert.match(check({ bundleFile: junk }).problem, /not valid JSON/);
  assert.match(check({ bundleFile: edit(A, 'dsse.json', (j) => { delete j.messageSignature; j.dsseEnvelope = {}; }) }).problem, /no SHA-256 message signature/);
  assert.match(check({ bundleFile: edit(A, 'alg.json', (j) => { j.messageSignature.messageDigest.algorithm = 'SHA2_512'; }) }).problem, /no SHA-256 message signature/);
  assert.match(check({ bundleFile: edit(A, 'nocert.json', (j) => { delete j.verificationMaterial.certificate; }) }).problem, /no signing certificate/);
  assert.match(check({ bundleFile: edit(A, 'badcert.json', (j) => { j.verificationMaterial.certificate.rawBytes = 'AAAA'; }) }).problem, /certificate is unreadable/);
});

test('what this check is NOT: a certificate swapped in from another workflow is caught here by the identity it names, but a bundle whose certificate is genuine and whose signature bytes were altered passes the binding and is stopped only by cosign', () => {
  assert.match(check({ bundleFile: edit(A, 'swap.json', (j) => { j.verificationMaterial.certificate.rawBytes = JSON.parse(readFileSync(B, 'utf8')).verificationMaterial.certificate.rawBytes; }) }).problem, /identity is not exactly/);
  const flipped = edit(A, 'flip.json', (j) => { const s = Buffer.from(j.messageSignature.signature, 'base64'); s[s.length - 3] ^= 1; j.messageSignature.signature = s.toString('base64'); });
  assert.deepEqual(check({ bundleFile: flipped }), { ok: true }, 'binding is not a signature check: that is why cosign runs first and its failure is final');
});
