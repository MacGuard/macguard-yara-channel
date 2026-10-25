// Evidence records: what a run writes, what a restore needs to be recorded, and that a merely downloaded copy never becomes "restored". Synthetic package; a throw-away certificate stands in for Fulcio's.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildBackupRecord, buildRestoreRecord, append, readRecords, readBundle } from '../tools/backup_record.mjs';
import { buildRecoveryStatus } from '../../admin/worker/src/restore.js';

const ID = 'https://github.com/MacGuard/macguard-yara-channel/.github/workflows/backup.yml@refs/heads/main', sha = (b) => createHash('sha256').update(b).digest('hex'), PT = 'ab'.repeat(32);
function pkg(root, { stamp = '20261026T032300Z', bundle = true } = {}) {
  const key = join(root, 'k.pem'), crt = join(root, 'c.pem'), cnf = join(root, 'o.cnf'); writeFileSync(cnf, `[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nCN=sigstore-intermediate\n[v3]\nsubjectAltName=URI:${ID}\n`);
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-config', cnf, '-keyout', key, '-out', crt], { stdio: 'ignore' });
  const der = execFileSync('openssl', ['x509', '-in', crt, '-outform', 'der']); const d = join(root, 'pkg', 'backups', stamp); mkdirSync(d, { recursive: true }); mkdirSync(join(root, 'pkg', 'checkpoint'), { recursive: true });
  writeFileSync(join(d, 'd1-export.sql.age'), 'age-encryption.org/v1\nciphertext'); writeFileSync(join(d, 'manifest.json'), JSON.stringify({ schema: 'macguard.gateway-backup/2', plaintext_sha256: PT })); writeFileSync(join(d, 'SHA256SUMS'), 'x  d1-export.sql.age\n');
  writeFileSync(join(d, 'ANCHOR.json'), JSON.stringify({ previous_head_sha256: 'cd'.repeat(32), schema: 'macguard.backup-anchor/1', sequence: 2, stamp }) + '\n');
  if (bundle) writeFileSync(join(d, 'ANCHOR.json.sigstore.json'), JSON.stringify({ verificationMaterial: { certificate: { rawBytes: der.toString('base64') }, tlogEntries: [{ logIndex: '3465351221', integratedTime: '1793000000' }] } }));
  writeFileSync(join(root, 'pkg', 'checkpoint', 'CHECKPOINT.json'), JSON.stringify({ sequence: 2, stamp }) + '\n'); return join(root, 'pkg');
}
const ALL = { b2: { write: 'success', read: 'success', read_at: '2026-10-26T03:40:00Z' }, scaleway: { write: 'success', read: 'success' }, r2: { write: 'success', read: 'failure' } };

test('a backup record carries the package facts, the signer identity and the Rekor index read from the bundle itself, and each provider\'s result', () => {
  const root = mkdtempSync(join(tmpdir(), 'mg-rec-')); try {
    const p = pkg(root), r = buildBackupRecord({ pkg: p, runId: '40224590918', runUrl: 'https://github.com/x/actions/runs/40224590918', providers: ALL, at: '2026-10-26T03:45:00Z' });
    assert.deepEqual([r.kind, r.run_id, r.stamp, r.sequence, r.schema_version, r.plaintext_sha256], ['backup', 40224590918, '20261026T032300Z', 2, 'macguard.gateway-backup/2', PT]);
    assert.equal(r.signer.identity, ID); assert.equal(r.signer.tlog_index, 3465351221); assert.equal(r.head_sha256, sha(readFileSync(join(p, 'backups', r.stamp, 'ANCHOR.json')))); assert.equal(r.files['d1-export.sql.age'].bytes, 'age-encryption.org/v1\nciphertext'.length);
    assert.deepEqual([r.providers.r2.write, r.providers.r2.read, r.providers.b2.read_at], ['success', 'failure', '2026-10-26T03:40:00Z']); assert.equal(r.checkpoint.sequence, 2); assert.equal(readBundle(readFileSync(join(p, 'backups', r.stamp, 'ANCHOR.json.sigstore.json'))).identity, ID);
    assert.throws(() => buildBackupRecord({ pkg: p, runId: 1, runUrl: 'u', providers: { b2: { write: 'maybe' } } }), /invalid state/);
    const nb = pkg(mkdtempSync(join(tmpdir(), 'mg-rec-')), { bundle: false }); assert.throws(() => buildBackupRecord({ pkg: nb, runId: 1, runUrl: 'u', providers: ALL }), /no Sigstore bundle/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('append-only and idempotent per run; a restore is recorded only for a known backup, a provider that wrote and read back, and the hash the signed manifest announced', () => {
  const root = mkdtempSync(join(tmpdir(), 'mg-rec-')); try {
    const file = join(root, 'evidence', 'backups.jsonl'), r = buildBackupRecord({ pkg: pkg(root), runId: 7, runUrl: 'u', providers: ALL });
    assert.equal(append(file, r).added, true); assert.equal(append(file, r).added, false); assert.equal(readRecords(file).length, 1);
    const rs = (over = {}) => buildRestoreRecord({ file, runId: 7, provider: 'b2', plaintextSha256: PT, durationS: 412.4, mode: 'drill', by: 'dmuino', at: '2026-10-26T09:00:00Z', ...over });
    const ok = rs(); assert.deepEqual([ok.kind, ok.stamp, ok.provider, ok.ok, ok.duration_s, ok.by], ['restore', '20261026T032300Z', 'b2', true, 412, 'dmuino']);
    assert.throws(() => rs({ plaintextSha256: 'cd'.repeat(32) }), /NOT the one the signed manifest announced/); assert.throws(() => rs({ runId: 99 }), /no backup record/); assert.throws(() => rs({ provider: 'r2' }), /did not write and read back/);
    assert.throws(() => rs({ provider: 'gcs' }), /unknown provider/); assert.throws(() => rs({ by: 'a b; rm' }), /invalid GitHub login/); assert.throws(() => rs({ mode: 'prod' }), /drill or real/); assert.throws(() => rs({ durationS: -1 }), /duration/); assert.throws(() => rs({ plaintextSha256: 'xyz' }), /64 hex/);
    assert.equal(append(file, ok).added, true); assert.equal(append(file, ok).added, false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('the panel: a downloaded copy is AUTHENTICATED, only the provider with a matching restore record is PROVEN, and the record feeds sequence, hash, tlog and last restore', () => {
  const root = mkdtempSync(join(tmpdir(), 'mg-rec-')); try {
    const file = join(root, 'e.jsonl'); append(file, buildBackupRecord({ pkg: pkg(root), runId: 7, runUrl: 'u', providers: { b2: ALL.b2, scaleway: ALL.scaleway, r2: ALL.b2 } })); append(file, buildRestoreRecord({ file, runId: 7, provider: 'scaleway', plaintextSha256: PT, durationS: 300, mode: 'drill', by: 'dmuino', at: '2026-10-26T09:00:00Z' }));
    const now = Date.parse('2026-10-26T12:00:00Z'), job = (n, c, at = '2026-10-26T04:00:00Z') => ({ name: n, status: 'completed', conclusion: c, completed_at: at, steps: n === 'export' ? [{ name: 'Sign ANCHOR.json and CHECKPOINT.json with Sigstore keyless', conclusion: 'success' }] : [] });
    const jobs = [job('export', 'success'), ...['b2', 'scaleway', 'r2'].flatMap((p) => [job(`fetch (${p})`, 'success'), job(`write (${p})`, 'success'), job(`read (${p})`, 'success')]), job('redundancy', 'success'), job('selftest', 'skipped')];
    const st = buildRecoveryStatus({ runs: [{ id: 7, html_url: 'u', event: 'workflow_dispatch', status: 'completed', conclusion: 'success', created_at: '2026-10-26T03:50:00Z', updated_at: '2026-10-26T04:00:00Z' }], jobs: { 7: jobs }, evidence: readRecords(file), trust: null }, now);
    const row = (p) => st.inventory.find((r) => r.provider === p); assert.equal(row('b2').recoverable, 'AUTHENTICATED'); assert.equal(row('r2').recoverable, 'AUTHENTICATED'); assert.equal(row('scaleway').recoverable, 'PROVEN');
    assert.deepEqual([row('b2').sequence, row('b2').sha256 === sha('age-encryption.org/v1\nciphertext'), row('b2').transparency_log.index], [2, true, 3465351221]); assert.equal(st.indicators.find((i) => i.id === 'last_restore').state, 'VERIFIED'); assert.equal(st.indicators.find((i) => i.id === 'rto_observed').value, 300);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('CLI: a refusal exits 1 and writes nothing; a valid call appends one line', () => {
  const root = mkdtempSync(join(tmpdir(), 'mg-rec-')); try {
    const CLI = new URL('../tools/backup_record.mjs', import.meta.url).pathname, file = join(root, 'e.jsonl'), run = (args) => spawnSync(process.execPath, [CLI, ...args, '--file', file], { encoding: 'utf8' });
    const bad = run(['restore', '--run-id', '1', '--provider', 'b2', '--plaintext-sha256', PT, '--duration-s', '5', '--mode', 'drill', '--by', 'x']); assert.equal(bad.status, 1); assert.match(bad.stderr, /no backup record/); assert.equal(readRecords(file).length, 0);
    const good = run(['backup', '--package', pkg(root), '--run-id', '9', '--run-url', 'u', '--providers', JSON.stringify(ALL)]); assert.equal(good.status, 0, good.stderr); assert.equal(readRecords(file).length, 1);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
