// Static invariants of .github/workflows/backup.yml and the trust file: what the workflow may touch, which identity signs, and what it must never reference.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { sigstorePolicyError } from '../tools/backup_anchor.mjs';

const wf = readFileSync(new URL('../../.github/workflows/backup.yml', import.meta.url), 'utf8'), trust = JSON.parse(readFileSync(new URL('../environments/backup-trust.json', import.meta.url), 'utf8'));

test('the pinned Sigstore identity is exactly this workflow on main and passes the strict policy; the Ed25519 freeze point is recorded', () => {
  assert.equal(trust.sigstore.identity, `https://github.com/${trust.sigstore.repository}/.github/workflows/backup.yml@refs/heads/main`); assert.equal(sigstorePolicyError(trust.sigstore, trust.ed25519.max_sequence), null);
  assert.equal(trust.ed25519.max_sequence, 1); assert.match(trust.ed25519.public_key, /^ssh-ed25519 [A-Za-z0-9+/]{43,}$/); assert.match(trust.age_recipient, /^age1[a-z0-9]{50,}$/); assert.ok(!/AGE-SECRET-KEY|PRIVATE KEY/.test(JSON.stringify(trust)));
});

test('the workflow runs only from main, in the backup environment, with id-token only on the signing job and nothing else writable', () => {
  assert.match(wf, /if: github\.ref == 'refs\/heads\/main'/); assert.equal((wf.match(/environment: macguard-backup-production/g) ?? []).length, 2);
  assert.equal((wf.match(/id-token: write/g) ?? []).length, 2, 'the backup job and the credential-free selftest only'); assert.ok(!/contents: write|actions: write|packages: write|pull-requests: write/.test(wf)); assert.match(wf, /^permissions: \{\}$/m);
  assert.ok(!/pull_request|push:|workflow_run/.test(wf.split('\njobs:')[0]), 'only manual and scheduled triggers');
});

test('it never references the retired signing key or the age identity, never deletes or overwrites, and every action is pinned by commit SHA', () => {
  assert.ok(!/MACGUARD_BACKUP_SIGNING_KEY|ssh-keygen|signing-key|AGE-SECRET-KEY|BACKUP_AGE_IDENTITY|age -d|--identity/.test(wf));
  assert.ok(!/ rm -|--force|push --force|s3 rm|delete-object|lifecycle|DeleteObject/.test(wf));
  for (const m of wf.matchAll(/uses: ([^\s@]+)@(\S+)/g)) assert.match(m[2], /^[0-9a-f]{40}$/, `${m[1]} must be pinned by SHA`);
});

test('the selftest job holds no environment and no secret and cannot run from the schedule or another ref', () => {
  const st = wf.slice(wf.indexOf('\n  selftest:'), wf.indexOf('\n  verify-providers:')); assert.ok(st.length > 100);
  assert.ok(!/environment:|secrets\./.test(st)); assert.match(st, /github\.ref == 'refs\/heads\/main' && github\.event_name == 'workflow_dispatch' && inputs\.mode == 'selftest'/);
});

test('provider credentials reach only the steps that talk to the destinations; the Cloudflare token only the export; the verification job gets one provider each', () => {
  const steps = wf.split(/\n      - /); const withSecret = (name) => steps.filter((s) => new RegExp(`secrets\\.${name}\\b`).test(s));
  assert.equal(withSecret('CLOUDFLARE_API_TOKEN').length, 2, 'presence check + export'); assert.ok(withSecret('CLOUDFLARE_API_TOKEN').every((s) => /Trust anchors|Export D1/.test(s)));
  for (const n of ['MG_B2_SECRET', 'MG_SCW_SECRET', 'MG_R2_SECRET']) assert.ok(withSecret(n).every((s) => /Trust anchors|predecessor|Plan, then copy|Re-read|Download the newest backup/.test(s)), n);
  assert.match(wf, /MG_B2_SECRET: \$\{\{ matrix\.provider == 'b2' && secrets\.MG_B2_SECRET \|\| '' \}\}/); assert.match(wf, /MG_R2_SECRET: \$\{\{ matrix\.provider == 'r2' && secrets\.MG_R2_SECRET \|\| '' \}\}/);
});
