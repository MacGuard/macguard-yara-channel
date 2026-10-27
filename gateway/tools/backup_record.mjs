// Evidence records of backups, appended to evidence/backups.jsonl (one JSON object per line, append-only, read by the panel's Restauración tab). Two kinds are written here:
//   backup   made by backup.yml after a run: the facts of the signed package (stamp, sequence, hashes and sizes, signer identity and Rekor index read from the bundle) and the result of each provider's write and read-back.
//   restore  made by record-restore.yml when the owner reports a restore done on their own machine with the age identity. It is accepted only for a stamp that has a backup record AND only if the reported plaintext hash
//            equals the one the signed manifest announced: a copy that was merely downloaded is never recorded as restored.
// Nothing here reads a secret or the SQL; it holds hashes, sizes, identities and states.
//   node tools/backup_record.mjs backup  [--resource gateway|panel] --package DIR --run-id N --run-url URL --providers JSON [--file evidence/backups.jsonl]
//   node tools/backup_record.mjs restore --run-id N --provider P --plaintext-sha256 H --duration-s N --mode drill|real --by LOGIN [--restored-at ISO8601Z] [--file ...]
import { createHash, X509Certificate } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';

const sha = (b) => createHash('sha256').update(b).digest('hex'), PROVIDERS = ['b2', 'scaleway', 'r2'], STATES = ['success', 'failure', 'skipped', 'cancelled', null];
const iso = (d = new Date()) => d.toISOString().replace(/\.\d{3}Z$/, 'Z');

/** Identity (SAN URI) and Rekor entry of a Sigstore bundle, read from the bundle itself. */
export function readBundle(bytes) {
  const b = JSON.parse(bytes.toString('utf8')), vm = b.verificationMaterial || {}, raw = vm.certificate?.rawBytes || vm.x509CertificateChain?.certificates?.[0]?.rawBytes, tl = vm.tlogEntries?.[0] || {};
  let identity = null; if (raw) { const c = new X509Certificate(Buffer.from(raw, 'base64')); identity = (c.subjectAltName || '').split(',').map((s) => s.trim()).find((s) => s.startsWith('URI:'))?.slice(4) ?? null; }
  return { identity, tlog_index: tl.logIndex !== undefined ? Number(tl.logIndex) : null, integrated_time: tl.integratedTime !== undefined ? Number(tl.integratedTime) : null };
}

export function buildBackupRecord({ pkg, runId, runUrl, providers, resource = 'gateway', at = iso() }) {
  if (!/^[a-z]{3,20}$/.test(resource)) throw new Error('invalid resource');
  const stamps = readdirSync(join(pkg, 'backups')).filter((n) => /^\d{8}T\d{6}Z$/.test(n)); if (stamps.length !== 1) throw new Error('the package must hold exactly one backup');
  const stamp = stamps[0], dir = join(pkg, 'backups', stamp), files = {}; for (const f of readdirSync(dir)) { const b = readFileSync(join(dir, f)); files[f] = { sha256: sha(b), bytes: b.length }; }
  const anchorBytes = readFileSync(join(dir, 'ANCHOR.json')), anchor = JSON.parse(anchorBytes.toString('utf8')), manifest = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8'));
  if (anchor.stamp !== stamp) throw new Error('the anchor names another stamp');
  if (!existsSync(join(dir, 'ANCHOR.json.sigstore.json'))) throw new Error('the package carries no Sigstore bundle');
  const sig = readBundle(readFileSync(join(dir, 'ANCHOR.json.sigstore.json')));
  const prov = {}; for (const p of PROVIDERS) { const x = providers[p] || {}; if (!STATES.includes(x.write ?? null) || !STATES.includes(x.read ?? null)) throw new Error(`invalid state for ${p}`); prov[p] = { write: x.write ?? null, read: x.read ?? null, write_at: x.write_at ?? null, read_at: x.read_at ?? null }; }
  const cpFile = join(pkg, 'checkpoint', 'CHECKPOINT.json'), cp = existsSync(cpFile) ? { sequence: JSON.parse(readFileSync(cpFile, 'utf8')).sequence, sha256: sha(readFileSync(cpFile)) } : null;
  return { schema: 'macguard.backup-evidence/1', kind: 'backup', resource, at, run_id: Number(runId), run_url: runUrl, stamp, sequence: anchor.sequence, head_sha256: sha(anchorBytes), previous_head_sha256: anchor.previous_head_sha256, files,
    schema_version: manifest.schema, plaintext_sha256: manifest.plaintext_sha256, signer: { scheme: 'sigstore', identity: sig.identity, issuer: 'https://token.actions.githubusercontent.com', tlog_index: sig.tlog_index, integrated_time: sig.integrated_time }, checkpoint: cp, providers: prov };
}

export const readRecords = (file) => (existsSync(file) ? readFileSync(file, 'utf8').split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean) : []);
/** Is `b` a second report of the restoration that `a` already records? Identity is the RESTORATION, never the time the workflow ran (`at` differs on every dispatch, which is why the old key never matched):
 *  - both carry restored_at (the moment the restore itself happened, reported by restore_from_run.sh): same backup run, provider, mode, plaintext hash and restored_at;
 *  - otherwise (older or manual reports): same run, provider, mode, hash AND the same reported duration and reporter, i.e. the same report. A genuinely new restore has a new restored_at and is a new event. */
export const sameRestore = (a, b) => a.kind === 'restore' && b.kind === 'restore' && a.run_id === b.run_id && a.provider === b.provider && a.mode === b.mode && a.plaintext_sha256 === b.plaintext_sha256
  && (a.restored_at && b.restored_at ? a.restored_at === b.restored_at : a.duration_s === b.duration_s && a.by === b.by);
export function append(file, rec) {
  const have = readRecords(file);
  if (rec.kind === 'backup' && have.some((r) => r.kind === 'backup' && r.run_id === rec.run_id)) return { added: false, reason: 'this run is already recorded' };
  if (rec.kind === 'restore' && have.some((r) => sameRestore(r, rec))) return { added: false, reason: 'this restoration is already recorded' };
  mkdirSync(dirname(file), { recursive: true }); appendFileSync(file, JSON.stringify(rec) + '\n'); return { added: true };
}

/** A restore is recorded only for a known backup, a known provider, and when the reported plaintext hash is the one the signed manifest announced. */
export function buildRestoreRecord({ file, runId, provider, plaintextSha256, durationS, mode, by, restoredAt = null, at = iso() }) {
  if (!PROVIDERS.includes(provider)) throw new Error('unknown provider'); if (!['drill', 'real'].includes(mode)) throw new Error('mode must be drill or real');
  if (!/^[0-9a-f]{64}$/.test(plaintextSha256 || '')) throw new Error('plaintext-sha256 must be 64 hex characters'); if (!/^[A-Za-z0-9-]{1,39}$/.test(by || '')) throw new Error('invalid GitHub login'); if (!Number.isFinite(+durationS) || +durationS < 0 || +durationS > 86400 * 3) throw new Error('duration out of range');
  const b = readRecords(file).find((r) => r.kind === 'backup' && r.run_id === Number(runId)); if (!b) throw new Error('no backup record exists for that run: nothing to attest a restore against');
  const p = b.providers?.[provider]; if (!p || p.write !== 'success' || p.read !== 'success') throw new Error(`${provider} did not write and read back that backup in the run`);
  if (plaintextSha256 !== b.plaintext_sha256) throw new Error('the reported plaintext hash is NOT the one the signed manifest announced: not recorded as a restore');
  if (restoredAt) {   // when the restore itself happened (not when it was reported): well formed, not in the future, not before the backup it restores
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(restoredAt) || Number.isNaN(Date.parse(restoredAt))) throw new Error('restored-at must be an ISO-8601 UTC time like 2026-10-27T08:00:00Z');
    if (Date.parse(restoredAt) > Date.parse(at) + 5 * 60000) throw new Error('restored-at is in the future');
    if (b.at && Date.parse(restoredAt) < Date.parse(b.at)) throw new Error('restored-at is before the backup it claims to restore');
  }
  return { schema: 'macguard.backup-evidence/1', kind: 'restore', resource: b.resource ?? 'gateway', at, run_id: b.run_id, stamp: b.stamp, sequence: b.sequence, provider, ok: true, mode, plaintext_sha256: plaintextSha256, duration_s: Math.round(+durationS), by, ...(restoredAt ? { restored_at: restoredAt } : {}) };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [cmd] = process.argv.slice(2), arg = (n, d = null) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : d; }, file = arg('--file', 'evidence/backups.jsonl');
  try {
    if (cmd === 'backup') { const r = append(file, buildBackupRecord({ resource: arg('--resource', 'gateway'), pkg: arg('--package'), runId: arg('--run-id'), runUrl: arg('--run-url'), providers: JSON.parse(arg('--providers', '{}')) })); console.log(JSON.stringify(r)); }
    else if (cmd === 'restore') { const r = append(file, buildRestoreRecord({ file, runId: arg('--run-id'), provider: arg('--provider'), plaintextSha256: arg('--plaintext-sha256'), durationS: arg('--duration-s'), mode: arg('--mode'), by: arg('--by'), restoredAt: arg('--restored-at') || null })); console.log(JSON.stringify(r)); }
    else { console.error('usage: backup_record.mjs backup|restore ...'); process.exit(2); }
  } catch (e) { console.error('refused: ' + String(e.message).split('\n')[0]); process.exit(1); }
}
