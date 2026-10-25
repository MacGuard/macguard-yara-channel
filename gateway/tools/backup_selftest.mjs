// Keyless self-test, run by backup.yml (mode selftest) with the workflow's OIDC identity: builds a SYNTHETIC predecessor and backup (fixed text, stamp 20000101T000000Z, never real data), signs ANCHOR.json and CHECKPOINT.json
// with Sigstore keyless, verifies them against the pinned policy of backup-trust.json and leaves the public statements in <out>/public. It touches no provider and uses no credential.
//   node tools/backup_selftest.mjs OUT_DIR TRUST_JSON
import { mkdirSync, readFileSync, writeFileSync, copyFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { buildAnchor, signBackupSigstore, signCheckpointSigstore, verifyAnchor, verifyCheckpoint } from './backup_anchor.mjs';

const [out, trustFile] = process.argv.slice(2).map((x) => resolve(x ?? '')); if (!out || !trustFile) { console.error('usage: backup_selftest.mjs OUT_DIR TRUST_JSON'); process.exit(2); }
const trust = JSON.parse(readFileSync(trustFile, 'utf8')), policy = { identity: trust.sigstore.identity, repository: trust.sigstore.repository }, max = trust.ed25519.max_sequence;
const dirs = { prev: join(out, 'backups', '19991231T000000Z'), next: join(out, 'backups', '20000101T000000Z') };
for (const d of Object.values(dirs)) { mkdirSync(d, { recursive: true }); for (const f of ['d1-export.sql.age', 'manifest.json', 'SHA256SUMS']) writeFileSync(join(d, f), `SYNTHETIC SELFTEST ${f}\n`); }
// the predecessor only needs to exist as a statement whose hash the next one names (sequence = the frozen maximum)
writeFileSync(join(dirs.prev, 'ANCHOR.json'), buildAnchor({ stamp: '19991231T000000Z', files: Object.fromEntries(['d1-export.sql.age', 'manifest.json', 'SHA256SUMS'].map((f) => [f, readFileSync(join(dirs.prev, f))])), sequence: max, previousHeadSha256: max === 1 ? null : 'f'.repeat(64), createdAt: '1999-12-31T00:00:00Z' }));
const signed = signBackupSigstore({ dir: dirs.next, sigstore: policy, ed25519MaxSequence: max, previousDir: dirs.prev });
const cp = signCheckpointSigstore({ backupDir: dirs.next, outDir: join(out, 'checkpoint'), sigstore: policy, ed25519MaxSequence: max });
const load = (d, names) => Object.fromEntries(names.map((f) => [f, readFileSync(join(d, f))])), a = verifyAnchor({ files: load(dirs.next, [...readdirSync(dirs.next)]), sigstore: policy, ed25519MaxSequence: max }), c = verifyCheckpoint({ files: load(join(out, 'checkpoint'), readdirSync(join(out, 'checkpoint'))), sigstore: policy, ed25519MaxSequence: max });
if (!a.ok || !c.ok || a.scheme !== 'sigstore' || c.scheme !== 'sigstore') { console.error('SELFTEST FAILED: ' + (a.reason ?? c.reason ?? 'wrong scheme')); process.exit(1); }
mkdirSync(join(out, 'public'), { recursive: true }); for (const [d, fs] of [[dirs.next, ['ANCHOR.json', 'ANCHOR.json.sigstore.json', 'manifest.json']], [join(out, 'checkpoint'), ['CHECKPOINT.json', 'CHECKPOINT.json.sigstore.json']]]) for (const f of fs) copyFileSync(join(d, f), join(out, 'public', f));
console.log(JSON.stringify({ ok: true, anchor: signed, checkpoint: cp, identity: policy.identity }, null, 1));
