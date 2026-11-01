// Off-machine copy and periodic restore drill for the encrypted gateway backups. Nothing here uploads anywhere or reads the Keychain: the destination is a directory you mount (external disk, a synced
// folder you control, a mounted bucket) and the key for the drill is a FILE you supply.
//   node tools/backup_offsite.mjs sync  --dest /Volumes/BACKUP/macguard [--root DIR]                  copy new encrypted backups (dry run unless --apply)
//   node tools/backup_offsite.mjs drill --dest /Volumes/BACKUP/macguard --identity KEYFILE [--root DIR]  restore the newest COPY in isolation and record the result
//   node tools/backup_offsite.mjs check [--root DIR]                                                    alarms: copy too old, drill too old (exit 1 if one fires)
// Rules: only ciphertext leaves the machine (a directory whose export is not an .age file is skipped and reported, never copied); an existing destination file is never overwritten (same bytes = skip,
// different bytes = a conflict that stops the run); every copied file is re-read and its checksum compared before the copy counts.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, relative, isAbsolute } from 'node:path';
import { ROOT_DEFAULT, isTemp } from './backup_flow.mjs';
import { verifyRestore } from './backup_lib.mjs';
import { ageDecryptFile, shaFile } from './stream_io.mjs';
import { privateDir } from './private_tmp.mjs';

const sha = (p) => createHash('sha256').update(readFileSync(p)).digest('hex'), STAMP = /^\d{8}T\d{6}Z$/, FILES = ['d1-export.sql.age', 'manifest.json', 'SHA256SUMS'], iso = (d) => d.toISOString().replace(/\.\d{3}Z$/, 'Z');
const stampsOf = (dir) => (existsSync(dir) ? readdirSync(dir).filter((n) => STAMP.test(n)).sort() : []);
const stateFile = (root, name) => join(resolve(root), name), readState = (root, name) => { try { return JSON.parse(readFileSync(stateFile(root, name), 'utf8')); } catch { return {}; } };

// A copy on the same volume as the backups is not a second copy: one disk failure, one theft or one wipe takes both. The nearest existing ancestor of the destination must live on a different device.
const deviceOf = (p) => { let d = resolve(p); while (!existsSync(d) && dirname(d) !== d) d = dirname(d); return statSync(d).dev; };
function checkDest(root, dest, allowSameVolume = false) {
  if (!dest || !isAbsolute(dest)) throw new Error('--dest must be an absolute path');
  const d = resolve(dest), r = resolve(root);
  if (isTemp(d)) throw new Error('refusing a temporary directory as the off-machine destination');
  if (d === r || !relative(r, d).startsWith('..') || !relative(d, r).startsWith('..')) throw new Error('the destination must be outside the backup folder (and not contain it): it would not be a second copy');
  if (!allowSameVolume && deviceOf(d) === deviceOf(r)) throw new Error('the destination is on the same volume as the backups (not off-machine); mount an external disk or network volume, or pass --allow-same-volume for a local rehearsal');
  return d;
}

export function offsiteSync({ root = ROOT_DEFAULT, dest, apply = false, clock = () => new Date(), allowSameVolume = false }) {
  root = resolve(root); dest = checkDest(root, dest, allowSameVolume); const report = { dest, copied: [], already_there: [], skipped_plaintext: [], conflicts: [], ok: true };
  for (const stamp of stampsOf(root)) {
    const src = join(root, stamp), missing = FILES.filter((f) => !existsSync(join(src, f)));
    if (missing.includes('d1-export.sql.age')) { report.skipped_plaintext.push({ stamp, reason: 'no encrypted export: plaintext never leaves the machine' }); continue; }
    if (missing.length) { report.conflicts.push({ stamp, reason: 'missing ' + missing.join(', ') }); continue; }
    const out = join(dest, stamp), dstExists = existsSync(out);
    if (dstExists && FILES.every((f) => existsSync(join(out, f)) && sha(join(out, f)) === sha(join(src, f)))) { report.already_there.push(stamp); continue; }
    if (dstExists && FILES.some((f) => existsSync(join(out, f)))) { report.conflicts.push({ stamp, reason: 'the destination already has different bytes for this backup; nothing is overwritten' }); continue; }
    if (!apply) { report.copied.push({ stamp, planned: true }); continue; }
    mkdirSync(out, { recursive: true, mode: 0o700 });
    for (const f of FILES) { copyFileSync(join(src, f), join(out, f)); try { chmodSync(join(out, f), 0o600); } catch { /* a filesystem without modes (exFAT) */ } }
    const bad = FILES.filter((f) => sha(join(out, f)) !== sha(join(src, f)));
    if (bad.length) report.conflicts.push({ stamp, reason: 'copy did not verify: ' + bad.join(', ') }); else report.copied.push({ stamp, files: FILES.length });
  }
  report.ok = report.conflicts.length === 0;
  if (apply && report.ok) writeFileSync(stateFile(root, 'offsite.json'), JSON.stringify({ last_sync_at: iso(clock()), dest, backups_there: stampsOf(dest).length }, null, 1) + '\n');
  return report;
}

// Restores the newest backup found in `dest` (the COPY, not the original) using a key file, in an isolated in-memory database. The result is appended to drills.json.
export async function restoreDrill({ root = ROOT_DEFAULT, dest, identityFile, clock = () => new Date(), ageBin = 'age', allowSameVolume = false }) {
  root = resolve(root); dest = checkDest(root, dest, allowSameVolume); const stamp = stampsOf(dest).at(-1), at = iso(clock());
  const record = (r) => { const s = readState(root, 'drills.json'); s.history = [...(s.history ?? []), r].slice(-24); if (r.ok) s.last_ok_at = r.at; writeFileSync(stateFile(root, 'drills.json'), JSON.stringify(s, null, 1) + '\n'); return r; };
  if (!stamp) return record({ at, ok: false, reason: 'no backup in the destination' });
  if (!identityFile || !existsSync(identityFile)) return record({ at, backup: stamp, ok: false, reason: 'the key file is missing' });
  const dir = join(dest, stamp);
  try {
    const sums = readFileSync(join(dir, 'SHA256SUMS'), 'utf8').trim().split('\n').map((l) => l.split(/\s+/)); for (const [h, f] of sums) if (sha(join(dir, f)) !== h) return record({ at, backup: stamp, ok: false, reason: `checksum mismatch in ${f}` });
    // Streaming: age decrypts into a private 0600 file, the hash comes from that file and sqlite3 loads it from there; the plaintext never passes through this process.
    const manifest = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8')), work = privateDir(tmpdir(), 'mg-offsite-'); const plain = join(work, 'plain.sql'); let v;
    try {
      await ageDecryptFile({ ageBin, identity: identityFile, src: join(dir, 'd1-export.sql.age'), dst: plain });
      if (await shaFile(plain) !== manifest.plaintext_sha256) return record({ at, backup: stamp, ok: false, reason: 'the decrypted bytes do not match the manifest' });
      v = await verifyRestore({ file: plain }, { manifest });
    } finally { rmSync(work, { recursive: true, force: true }); }
    return record({ at, backup: stamp, ok: v.ok, checks: v.checks.length, failed: v.checks.filter((c) => !c.ok).map((c) => c.name), reason: v.ok ? null : 'restore checks failed' });
  } catch (e) { return record({ at, backup: stamp, ok: false, reason: String(e?.message ?? e).split('\n')[0].slice(0, 160) }); }
}

// Alarms. They are opt-in in backup_check.mjs (`--custody`) because until the owner configures a destination they would fire permanently, which is the truth but would drown the daily alarm.
export function custodyCheck({ root = ROOT_DEFAULT, clock = () => new Date(), maxCopyAgeHours = 48, maxDrillAgeDays = 35 } = {}) {
  const at = iso(clock()), off = readState(root, 'offsite.json'), dr = readState(root, 'drills.json'), out = [];
  const A = (rule_id, state, value, threshold, message) => out.push({ schema: 'macguard.alert/1', rule_id, category: 'integrity', severity: 'high', state, value, threshold, message, dedupe_key: rule_id, evaluated_at: at, source: { kind: 'agent', id: 'backup-custody' } });
  const copyAge = off.last_sync_at ? (clock() - Date.parse(off.last_sync_at)) / 3600000 : null, drillAge = dr.last_ok_at ? (clock() - Date.parse(dr.last_ok_at)) / 86400000 : null;
  A('backup.offsite_stale', copyAge === null || copyAge > maxCopyAgeHours ? 'FIRING' : 'OK', copyAge === null ? null : +copyAge.toFixed(1), maxCopyAgeHours, copyAge === null ? 'No off-machine copy has ever been made: every backup, and the key, still live on one computer.' : `The last off-machine copy was ${copyAge.toFixed(1)} h ago.`);
  A('backup.drill_stale', drillAge === null || drillAge > maxDrillAgeDays ? 'FIRING' : 'OK', drillAge === null ? null : +drillAge.toFixed(1), maxDrillAgeDays, drillAge === null ? 'No restore drill from an off-machine copy has ever passed.' : `The last passing restore drill was ${drillAge.toFixed(1)} days ago.`);
  const last = (dr.history ?? []).at(-1); A('backup.drill_failed', last && !last.ok ? 'FIRING' : 'OK', null, null, last && !last.ok ? `The latest restore drill failed: ${last.reason}` : 'The latest restore drill did not fail.');
  return out;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [cmd] = process.argv.slice(2), arg = (n, d = null) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : d; }, root = arg('--root', ROOT_DEFAULT);
  try {
    if (cmd === 'sync') { const r = offsiteSync({ root, dest: arg('--dest'), apply: process.argv.includes('--apply'), allowSameVolume: process.argv.includes('--allow-same-volume') }); console.log(JSON.stringify(r, null, 1)); if (!process.argv.includes('--apply')) console.log('DRY RUN: add --apply to copy'); process.exit(r.ok ? 0 : 1); }
    else if (cmd === 'drill') { const r = await restoreDrill({ root, dest: arg('--dest'), identityFile: arg('--identity'), allowSameVolume: process.argv.includes('--allow-same-volume') }); console.log(JSON.stringify(r, null, 1)); process.exit(r.ok ? 0 : 1); }
    else if (cmd === 'check') { const a = custodyCheck({ root }); console.log(JSON.stringify(a, null, 1)); process.exit(a.some((x) => x.state === 'FIRING') ? 1 : 0); }
    else { console.error('usage: backup_offsite.mjs sync|drill|check ...'); process.exit(2); }
  } catch (e) { console.error('refused: ' + e.message); process.exit(2); }
}
