// Static invariants of .github/workflows/backup.yml and the trust file: one GitHub environment per provider and per direction, what each job may touch, which identity signs, and what must never appear.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { sigstorePolicyError } from '../tools/backup_anchor.mjs';

const wf = readFileSync(new URL('../../.github/workflows/backup.yml', import.meta.url), 'utf8'), trust = JSON.parse(readFileSync(new URL('../environments/backup-trust.json', import.meta.url), 'utf8')), dest = JSON.parse(readFileSync(new URL('../environments/backup-destinations.json', import.meta.url), 'utf8'));
const body = wf.slice(wf.indexOf('\njobs:') + 6), names = [...body.matchAll(/^  ([a-z-]+):\n/gm)].map((m) => m[1]);
const job = (n) => { const i = body.indexOf(`\n  ${n}:\n`); const rest = body.slice(i + 1); const m = rest.slice(1).search(/\n  [a-z-]+:\n/); return m < 0 ? rest : rest.slice(0, m + 1); };

test('the pinned Sigstore identity is exactly this workflow on main and passes the strict policy; the Ed25519 freeze point is recorded', () => {
  assert.equal(trust.sigstore.identity, `https://github.com/${trust.sigstore.repository}/.github/workflows/backup.yml@refs/heads/main`); assert.equal(sigstorePolicyError(trust.sigstore, trust.ed25519.max_sequence), null);
  assert.equal(trust.ed25519.max_sequence, 1); assert.match(trust.ed25519.public_key, /^ssh-ed25519 [A-Za-z0-9+/]{43,}$/); assert.match(trust.age_recipient, /^age1[a-z0-9]{50,}$/); assert.ok(!/AGE-SECRET-KEY|PRIVATE KEY/.test(JSON.stringify(trust)));
});

test('jobs and environments: one environment per job, per provider and direction; the export job holds no storage credential; redundancy and selftest hold no environment', () => {
  assert.deepEqual(names, ['fetch', 'export', 'write', 'read', 'redundancy', 'record', 'selftest']);
  assert.match(job('fetch'), /environment: archive-\$\{\{ matrix\.provider \}\}-read/); assert.match(job('write'), /environment: archive-\$\{\{ matrix\.provider \}\}-write/); assert.match(job('read'), /environment: archive-\$\{\{ matrix\.provider \}\}-read/);
  assert.match(job('export'), /environment: macguard-backup-production/); assert.ok(!/environment:/.test(job('redundancy') + job('record') + job('selftest')));
  for (const j of ['fetch', 'write', 'read']) assert.match(job(j), /provider: \[b2, scaleway, r2\]/);
  assert.deepEqual(Object.keys(dest.destinations).sort(), ['b2', 'r2', 'scaleway'].sort());
  assert.ok(!/ARCHIVE_|MG_ARCHIVE_PROVIDER/.test(job('export') + job('redundancy') + job('record') + job('selftest')), 'no storage credential outside the provider jobs');
});

test('secrets reach only the jobs that need them: storage keys only in the matrix jobs of their own environment, the Cloudflare token only in the export job', () => {
  const secretsIn = (n) => [...job(n).matchAll(/secrets\.([A-Z0-9_]+)/g)].map((m) => m[1]);
  for (const j of ['fetch', 'write', 'read']) assert.deepEqual([...new Set(secretsIn(j))].sort(), ['ARCHIVE_ACCESS_KEY_ID', 'ARCHIVE_SECRET_ACCESS_KEY'], j);
  assert.deepEqual([...new Set(secretsIn('export'))].sort(), ['CLOUDFLARE_API_TOKEN']); assert.deepEqual(secretsIn('redundancy').concat(secretsIn('selftest'), secretsIn('record')), []);
  assert.ok(!/needs\.[a-z-]+\.outputs\.[a-z_]*(key|secret|token)/i.test(wf), 'no secret travels through outputs'); assert.deepEqual([...wf.matchAll(/^      ([a-z]+): \$\{\{ steps\./gm)].map((m) => m[1]).sort(), ['sequence', 'stamp']);
});

test('the workflow runs only from main with minimal permissions: id-token only on export and selftest, nothing writable, only manual and scheduled triggers', () => {
  assert.match(wf, /^permissions: \{\}$/m); assert.equal((wf.match(/id-token: write/g) ?? []).length, 2); assert.ok(/id-token: write/.test(job('export')) && /id-token: write/.test(job('selftest')));
  assert.equal((wf.match(/contents: write/g) ?? []).length, 1, 'only the record job writes, and only the repository'); assert.ok(/contents: write/.test(job('record'))); assert.ok(!/actions: write|packages: write|pull-requests: write/.test(wf)); assert.ok(!/pull_request|push:|workflow_run/.test(wf.split('\njobs:')[0]));
  for (const j of ['fetch', 'export', 'selftest']) assert.match(job(j), /github\.ref == 'refs\/heads\/main'/);
});

test('artifacts: only ciphertext and public statements, kept one day (the repository is public); the selftest artifact is synthetic', () => {
  const arts = [...wf.matchAll(/name: ((?:prev|read)-\$\{\{ matrix\.provider \}\}|package|sigstore-selftest)\n\s+path: ([^\n]+)\n\s+retention-days: (\d+)/g)].map((m) => ({ name: m[1], path: m[2], days: +m[3] }));
  assert.deepEqual(arts.map((a) => a.name).sort(), ['package', 'prev-${{ matrix.provider }}', 'read-${{ matrix.provider }}', 'sigstore-selftest'].sort());
  for (const a of arts) assert.ok(a.days <= (a.name === 'sigstore-selftest' ? 30 : 1), `${a.name} retention`);
  assert.match(job('export'), /not age ciphertext/); assert.match(job('export'), /plaintext or configuration found in the package/); assert.ok(!/\*\.sql\b[^\n]*upload|path: [^\n]*\.sql/.test(wf));
});

test('it never references the retired signing key or the age identity, never deletes or overwrites, never skips a hook, and every action is pinned by commit SHA', () => {
  assert.ok(!/MACGUARD_BACKUP_SIGNING_KEY|ssh-keygen|signing-key|AGE-SECRET-KEY|BACKUP_AGE_IDENTITY|age -d|--identity/.test(wf));
  assert.ok(!/ rm -|--force|push --force|s3 rm|delete-object|lifecycle|DeleteObject|--no-verify/.test(wf));
  for (const m of wf.matchAll(/uses: ([^\s@]+)@(\S+)/g)) assert.match(m[2], /^[0-9a-f]{40}$/, `${m[1]} must be pinned by SHA`);
});

test('the selftest job is credential-free and cannot run from the schedule or another ref', () => {
  const st = job('selftest'); assert.ok(st.length > 100 && !/environment:|secrets\./.test(st)); assert.match(st, /github\.event_name == 'workflow_dispatch' && inputs\.mode == 'selftest'/);
});

test('the record job writes only the evidence file, under the shared lock, with no environment and no secret; the restore recorder needs an admin, passes inputs through env (plus its own per-run concurrency group), never inline', () => {
  const rec = job('record'); assert.match(rec, /group: macguard-log/); assert.ok(!/environment:|secrets\./.test(rec)); assert.match(rec, /commit_evidence\.sh/); assert.match(rec, /backup_record\.mjs backup/);
  const rr = readFileSync(new URL('../../.github/workflows/record-restore.yml', import.meta.url), 'utf8'); assert.match(rr, /^permissions: \{\}$/m); assert.match(rr, /\[ "\$P" = admin \]/); assert.ok(!/secrets\.|environment:|id-token/.test(rr));
  // The ONLY other place an input may appear is the concurrency group (a name, never a shell): exactly this line, nothing else. (PR #56 replaced the shared queue.)
  const GROUP = 'group: record-restore-${{ inputs.run_id }}-${{ inputs.provider }}';
  assert.equal(rr.split('\n').filter((l) => l.trim() === GROUP).length, 1, 'one concurrency group per backup run and provider');
  assert.ok(!/\$\{\{ *inputs\./.test(rr.replace(/^\s+(RUN_ID|PROVIDER|SHA|DUR|MODE|RESTORED_AT): \$\{\{ inputs\.[a-z_0-9]+ \}\}$/gm, '').replace(/^\s+group: record-restore-\$\{\{ inputs\.run_id \}\}-\$\{\{ inputs\.provider \}\}$/m, '')), 'inputs reach the shell only through env: lines (and the concurrency group name)');
  for (const m of rr.matchAll(/uses: ([^\s@]+)@(\S+)/g)) assert.match(m[2], /^[0-9a-f]{40}$/);
  assert.match(rr, /cancel-in-progress: false/); assert.ok(!/group: macguard-log/.test(rr), 'a restore record must not queue behind (and be cancelled by) the shared log group');
  assert.match(rr, /evidence_retry\.sh/, 'evidence is written by the retry that regenerates on a rejected push'); assert.ok(!/commit_evidence\.sh/.test(rr.replace(/evidence_retry\.sh/g, '')), 'no bare commit_evidence.sh (it rebases and loses concurrent appends)');
});
