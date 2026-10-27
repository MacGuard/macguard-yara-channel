// Backup flow as testable functions (the CLI in d1_backup.mjs wires them to wrangler). Order: export -> verify the PLAINTEXT in an isolated restore -> encrypt with age (recipient = a public key the owner
// holds) -> write checksums and a manifest -> record the outcome in status.json (success AND failure). The plaintext lives only in a private temp directory that is removed afterwards.
// check() turns the state on disk into macguard.alert/1 alerts: missing, stale, failed, tampered, unencrypted.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { verifyRestore, rowCounts } from './backup_lib.mjs';

export const ROOT_DEFAULT = join(homedir(), 'macguard-backups', 'gateway');
const sha = (b) => createHash('sha256').update(b).digest('hex'), now = (d) => d.toISOString().replace(/\.\d{3}Z$/, 'Z'), stampOf = (d) => now(d).replace(/[-:]/g, '');
export const isTemp = (p) => /^(\/tmp|\/private\/tmp|\/var\/folders)|scratchpad/.test(resolve(p));

export async function runBackup({ exportFn, root = ROOT_DEFAULT, recipient = null, clock = () => new Date(), meta = {}, ageBin = 'age', verify = verifyRestore, counts = rowCounts, schema = 'macguard.gateway-backup/2' }) {   // verify/counts/schema: a different database brings its own isolated-restore check
  root = resolve(root); if (isTemp(root)) throw new Error('refusing to keep backups in a temporary directory');
  mkdirSync(root, { recursive: true, mode: 0o700 }); chmodSync(root, 0o700);
  const status = existsSync(join(root, 'status.json')) ? JSON.parse(readFileSync(join(root, 'status.json'), 'utf8')) : {}, started = clock();
  const fail = (stage, e) => { const st = { ...status, last_attempt_at: now(started), last_status: 'failed', last_failed_stage: stage, last_error: String(e?.message ?? e).slice(0, 200) }; writeFileSync(join(root, 'status.json'), JSON.stringify(st, null, 2) + '\n', { mode: 0o600 }); return { ok: false, stage, error: st.last_error }; };
  const tmp = mkdtempSync(join(homedir(), '.mg-backup-')); chmodSync(tmp, 0o700);
  try {
    const plain = join(tmp, 'd1-export.sql');
    try { await exportFn(plain); } catch (e) { return fail('export', e); }
    const sql = readFileSync(plain, 'utf8'), scratch = new DatabaseSync(':memory:'); scratch.exec('PRAGMA foreign_keys = OFF');
    try { scratch.exec(sql); } catch (e) { return fail('load', e); }
    const manifest = { schema, created_at: now(started), ...meta, plaintext_sha256: sha(sql), plaintext_bytes: Buffer.byteLength(sql), row_counts: counts(scratch), encrypted: !!recipient };
    const v = await verify(sql, { manifest }); if (!v.ok) return fail('verify', new Error(v.checks.filter((c) => !c.ok).map((c) => c.name).join('; ')));
    const dir = join(root, stampOf(started)); mkdirSync(dir, { mode: 0o700 }); chmodSync(dir, 0o700);
    let name = 'd1-export.sql';
    if (recipient) {
      if (!/^age1[a-z0-9]{50,}$/.test(recipient)) return fail('encrypt', new Error('the age recipient is not a public key'));
      try { writeFileSync(join(dir, 'd1-export.sql.age'), execFileSync(ageBin, ['-r', recipient], { input: readFileSync(plain), maxBuffer: 1 << 30 })); name = 'd1-export.sql.age'; } catch (e) { return fail('encrypt', e); }
    } else writeFileSync(join(dir, name), sql);
    manifest.stored_file = name; manifest.stored_sha256 = sha(readFileSync(join(dir, name))); manifest.stored_bytes = statSync(join(dir, name)).size;
    writeFileSync(join(dir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n'); writeFileSync(join(dir, 'SHA256SUMS'), [name, 'manifest.json'].map((f) => `${sha(readFileSync(join(dir, f)))}  ${f}`).join('\n') + '\n');
    for (const f of [name, 'manifest.json', 'SHA256SUMS']) chmodSync(join(dir, f), 0o600);
    writeFileSync(join(root, 'status.json'), JSON.stringify({ ...status, last_attempt_at: now(started), last_success_at: now(started), last_status: 'ok', last_dir: stampOf(started), last_failed_stage: null, last_error: null, encrypted: !!recipient }, null, 2) + '\n', { mode: 0o600 });
    return { ok: true, dir, name, manifest, checks: v.checks.length };
  } finally { rmSync(tmp, { recursive: true, force: true }); }
}

// Alerts about the backup state. Never reads the encrypted content: only checksums, manifest and status.
export function check({ root = ROOT_DEFAULT, clock = () => new Date(), maxAgeHours = 30, requireEncrypted = true } = {}) {
  root = resolve(root); const at = now(clock()), out = [];
  const A = (rule_id, severity, state, message, value = null, threshold = null) => out.push({ schema: 'macguard.alert/1', rule_id, category: 'integrity', severity, state, value, threshold, message, dedupe_key: rule_id, evaluated_at: at, source: { kind: 'agent', id: 'backup-check' } });
  const sp = join(root, 'status.json');
  if (!existsSync(sp)) { A('backup.missing', 'critical', 'FIRING', 'No backup has ever been recorded in ' + root); return out; }
  const st = JSON.parse(readFileSync(sp, 'utf8')), age = st.last_success_at ? (clock().getTime() - Date.parse(st.last_success_at)) / 3600000 : Infinity;
  A('backup.never_succeeded', 'critical', st.last_success_at ? 'OK' : 'FIRING', st.last_success_at ? 'A successful backup exists.' : 'No backup has ever succeeded.');
  A('backup.stale', 'high', age > maxAgeHours ? 'FIRING' : 'OK', Number.isFinite(age) ? `Last successful backup ${age.toFixed(1)} h ago.` : 'No successful backup.', Number.isFinite(age) ? +age.toFixed(1) : null, maxAgeHours);
  A('backup.last_attempt_failed', 'high', st.last_status === 'failed' ? 'FIRING' : 'OK', st.last_status === 'failed' ? `Last attempt failed at stage ${st.last_failed_stage}: ${st.last_error}` : 'Last attempt succeeded.');
  if (st.last_dir && existsSync(join(root, st.last_dir))) {
    const dir = join(root, st.last_dir); let bad = [];
    try { for (const l of readFileSync(join(dir, 'SHA256SUMS'), 'utf8').trim().split('\n')) { const [h, f] = l.split(/\s+/); if (!existsSync(join(dir, f)) || sha(readFileSync(join(dir, f))) !== h) bad.push(f); } } catch { bad = ['SHA256SUMS']; }
    A('backup.integrity', 'critical', bad.length ? 'FIRING' : 'OK', bad.length ? `Checksum mismatch or missing file: ${bad.join(', ')}` : 'Stored files match their checksums.');
    if (requireEncrypted) A('backup.unencrypted', 'high', st.encrypted ? 'OK' : 'FIRING', st.encrypted ? 'The latest backup is encrypted.' : 'The latest backup is stored unencrypted.');
  } else A('backup.integrity', 'critical', 'FIRING', 'The latest backup directory recorded in status.json does not exist.');
  return out;
}

// Retention: keep the newest N daily, M weekly and K monthly backups. Returns what WOULD be removed; removal needs apply=true and only touches directories named like a backup stamp inside the root.
export function retentionPlan(names, { daily = 7, weekly = 4, monthly = 12 } = {}) {
  const dirs = names.filter((n) => /^\d{8}T\d{6}Z$/.test(n)).sort().reverse(), keep = new Set(), seen = { d: new Set(), w: new Set(), m: new Set() };
  const week = (n) => { const d = new Date(Date.UTC(+n.slice(0, 4), +n.slice(4, 6) - 1, +n.slice(6, 8))); const j = new Date(Date.UTC(d.getUTCFullYear(), 0, 1)); return d.getUTCFullYear() + '-' + Math.floor(((d - j) / 86400000 + j.getUTCDay()) / 7); };
  for (const n of dirs) { const day = n.slice(0, 8), wk = week(n), mo = n.slice(0, 6);
    if (seen.d.size < daily && !seen.d.has(day)) { seen.d.add(day); keep.add(n); } if (seen.w.size < weekly && !seen.w.has(wk)) { seen.w.add(wk); keep.add(n); } if (seen.m.size < monthly && !seen.m.has(mo)) { seen.m.add(mo); keep.add(n); } }
  if (dirs[0]) keep.add(dirs[0]);                                                // the newest is never removed
  return { keep: dirs.filter((n) => keep.has(n)), remove: dirs.filter((n) => !keep.has(n)) };
}
export function prune({ root = ROOT_DEFAULT, apply = false, ...policy } = {}) {
  root = resolve(root); const plan = retentionPlan(readdirSync(root), policy), st = existsSync(join(root, 'status.json')) ? JSON.parse(readFileSync(join(root, 'status.json'), 'utf8')) : {};
  const protectedNames = existsSync(join(root, 'protected.json')) ? Object.keys(JSON.parse(readFileSync(join(root, 'protected.json'), 'utf8'))) : [];           // backups the owner pinned (for example the first verified export)
  plan.remove = plan.remove.filter((n) => n !== st.last_dir && !protectedNames.includes(n)); plan.protected = protectedNames.filter((n) => existsSync(join(root, n))); if (apply) for (const n of plan.remove) rmSync(join(root, n), { recursive: true });
  return { ...plan, applied: !!apply };
}

// Re-encrypts an age backup for a NEW recipient (key rotation, or moving from the interim key to one the owner keeps offline). The old directory is never modified or removed: a new directory is written
// only after the old ciphertext decrypts to exactly the verified plaintext, the plaintext restores in isolation, and the new ciphertext decrypts back to the same bytes.
export async function rekeyBackup({ dir, identityFile, newRecipient, newIdentityFile = null, root = resolve(dir, '..'), clock = () => new Date(), ageBin = 'age' }) {
  dir = resolve(dir); root = resolve(root); if (isTemp(root)) throw new Error('refusing to keep backups in a temporary directory');
  if (!/^age1[a-z0-9]{50,}$/.test(newRecipient ?? '')) throw new Error('the new recipient is not an age public key');
  const manifest = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8')); if (manifest.stored_file !== 'd1-export.sql.age') throw new Error('this backup is not age-encrypted');
  const tmp = mkdtempSync(join(homedir(), '.mg-rekey-')); chmodSync(tmp, 0o700);
  try {
    const cipher = readFileSync(join(dir, 'd1-export.sql.age')); if (sha(cipher) !== manifest.stored_sha256) throw new Error('the stored ciphertext does not match its recorded checksum');
    let plain; try { plain = execFileSync(ageBin, ['-d', '-i', identityFile], { input: cipher, maxBuffer: 1 << 30 }); } catch { throw new Error('the old identity cannot decrypt this backup'); }
    if (sha(plain) !== manifest.plaintext_sha256) throw new Error('the decrypted bytes differ from the verified plaintext');
    const v = await verifyRestore(plain.toString('utf8'), { manifest }); if (!v.ok) throw new Error('the decrypted export does not restore: ' + v.checks.filter((c) => !c.ok).map((c) => c.name).join('; '));
    const fresh = execFileSync(ageBin, ['-r', newRecipient], { input: plain, maxBuffer: 1 << 30 });
    if (newIdentityFile) { const back = execFileSync(ageBin, ['-d', '-i', newIdentityFile], { input: fresh, maxBuffer: 1 << 30 }); if (sha(back) !== manifest.plaintext_sha256) throw new Error('the new ciphertext does not decrypt to the same bytes'); }
    let stamp = stampOf(clock()); while (existsSync(join(root, stamp))) stamp = stampOf(new Date(Date.parse(now(clock())) + 1000 * (1 + Math.floor(Math.random() * 50))));
    const out = join(root, stamp); mkdirSync(out, { mode: 0o700 }); chmodSync(out, 0o700);
    const m2 = { ...manifest, rekeyed_from: dir.split('/').pop(), rekeyed_at: now(clock()), stored_sha256: sha(fresh), stored_bytes: fresh.length }; writeFileSync(join(out, 'd1-export.sql.age'), fresh);
    writeFileSync(join(out, 'manifest.json'), JSON.stringify(m2, null, 2) + '\n'); writeFileSync(join(out, 'SHA256SUMS'), ['d1-export.sql.age', 'manifest.json'].map((f) => `${sha(readFileSync(join(out, f)))}  ${f}`).join('\n') + '\n');
    for (const f of ['d1-export.sql.age', 'manifest.json', 'SHA256SUMS']) chmodSync(join(out, f), 0o600);
    return { ok: true, dir: out, verified_new_key: !!newIdentityFile };
  } finally { rmSync(tmp, { recursive: true, force: true }); }
}
