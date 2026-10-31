// Makes an ADDITIONAL age-encrypted copy of a backup that was taken in plaintext (before encryption was switched on), and proves it can be restored. The original is never modified, moved or deleted:
// retiring it is a separate, human decision once the encrypted copy has been restored from every destination (docs/analytics/BACKUP-OBJECT-STORES.md).
//   node tools/backup_encrypt_legacy.mjs encrypt --src DIR --recipient-file FILE [--out ROOT]      (ROOT defaults to ~/macguard-backups/gateway-legacy-encrypted; the copy goes to ROOT/<stamp>/)
//   node tools/backup_encrypt_legacy.mjs verify --copy DIR --src DIR (--identity-file KEYFILE | --identity-from-keychain)
// verify decrypts the COPY in isolation, compares it byte for byte with the original, and runs the same restore checks as a real backup. A key read from the Keychain goes into a mode-600 file in a private
// temporary directory that is removed immediately; it is never printed.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { isTemp } from './backup_flow.mjs';
import { verifyRestore } from './backup_lib.mjs';
import { privateDir } from './private_tmp.mjs';

const sha = (b) => createHash('sha256').update(b).digest('hex'), STAMP = /^\d{8}T\d{6}Z$/;
export const DEFAULT_OUT = join(homedir(), 'macguard-backups', 'gateway-legacy-encrypted');

function checkSource(src) {
  src = resolve(src); if (!STAMP.test(basename(src))) throw new Error('the source directory must be named like a backup (YYYYMMDDTHHMMSSZ)');
  if (existsSync(join(src, 'd1-export.sql.age'))) throw new Error('this backup is already encrypted: nothing to do');
  const sums = readFileSync(join(src, 'SHA256SUMS'), 'utf8').trim().split('\n').map((l) => l.split(/\s+/));
  for (const [h, f] of sums) if (sha(readFileSync(join(src, f))) !== h) throw new Error(`the source does not match its own SHA256SUMS (${f}): it is not copied`);
  if (!sums.some(([, f]) => f === 'd1-export.sql')) throw new Error('the source SHA256SUMS does not list d1-export.sql');
  return src;
}
export async function encryptLegacy({ src, recipient, out = DEFAULT_OUT, ageBin = 'age' }) {
  src = checkSource(src); out = resolve(out); if (isTemp(out)) throw new Error('refusing a temporary directory for backups');
  if (!/^age1[a-z0-9]{50,}$/.test(recipient)) throw new Error('the age recipient is not a public key');
  const stamp = basename(src), dir = join(out, stamp); if (existsSync(dir)) throw new Error(`${dir} already exists: nothing is overwritten`);
  const sql = readFileSync(join(src, 'd1-export.sql')), srcManifest = existsSync(join(src, 'manifest.json')) ? JSON.parse(readFileSync(join(src, 'manifest.json'), 'utf8')) : {};
  if (srcManifest.plaintext_sha256 && srcManifest.plaintext_sha256 !== sha(sql)) throw new Error('the plaintext does not match its manifest');
  const v = await verifyRestore(sql.toString('utf8'), { manifest: srcManifest.row_counts ? srcManifest : null }); if (!v.ok) throw new Error('the source does not restore: ' + v.checks.filter((c) => !c.ok).map((c) => c.name).join('; '));
  const enc = execFileSync(ageBin, ['-r', recipient], { input: sql, maxBuffer: 1 << 30 });
  mkdirSync(dir, { recursive: true, mode: 0o700 }); chmodSync(out, 0o700); chmodSync(dir, 0o700);
  const manifest = { ...srcManifest, schema: 'macguard.gateway-backup/2', encrypted: true, plaintext_sha256: sha(sql), plaintext_bytes: sql.length, stored_file: 'd1-export.sql.age', stored_sha256: sha(enc), stored_bytes: enc.length,
    encrypted_copy_of: { stamp, source_manifest_sha256: existsSync(join(src, 'manifest.json')) ? sha(readFileSync(join(src, 'manifest.json'))) : null, note: 'additional encrypted copy; the plaintext original was left untouched' } };
  writeFileSync(join(dir, 'd1-export.sql.age'), enc); writeFileSync(join(dir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  writeFileSync(join(dir, 'SHA256SUMS'), ['d1-export.sql.age', 'manifest.json'].map((f) => `${sha(readFileSync(join(dir, f)))}  ${f}`).join('\n') + '\n');
  for (const f of ['d1-export.sql.age', 'manifest.json', 'SHA256SUMS']) chmodSync(join(dir, f), 0o600);
  return { dir, stamp, plaintext_sha256: manifest.plaintext_sha256, stored_bytes: enc.length, restore_checks: v.checks.length };
}
export function withIdentity({ identityFile = null, fromKeychain = false, service = 'macguard-gateway-prod', account = 'BACKUP_AGE_IDENTITY' }, fn) {
  if (identityFile) return fn(identityFile);
  if (!fromKeychain) throw new Error('an identity file or --identity-from-keychain is required');
  const tmp = privateDir(homedir(), '.mg-legacy-');
  try { const f = join(tmp, 'id.txt'); writeFileSync(f, execFileSync('security', ['find-generic-password', '-s', service, '-a', account, '-w'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }), { mode: 0o600 }); return fn(f); }
  finally { rmSync(tmp, { recursive: true, force: true }); }
}
export async function verifyLegacyCopy({ copy, src, identityFile, fromKeychain = false, ageBin = 'age' }) {
  copy = resolve(copy); src = resolve(src); const sums = readFileSync(join(copy, 'SHA256SUMS'), 'utf8').trim().split('\n').map((l) => l.split(/\s+/)), checks = [];
  for (const [h, f] of sums) checks.push({ name: `checksum ${f}`, ok: sha(readFileSync(join(copy, f))) === h });
  const manifest = JSON.parse(readFileSync(join(copy, 'manifest.json'), 'utf8'));
  const plain = withIdentity({ identityFile, fromKeychain }, (id) => execFileSync(ageBin, ['-d', '-i', id, join(copy, 'd1-export.sql.age')], { maxBuffer: 1 << 30 }));
  checks.push({ name: 'decrypts with the identity', ok: true }, { name: 'plaintext hash matches the manifest', ok: sha(plain) === manifest.plaintext_sha256 }, { name: 'identical to the original, byte for byte', ok: Buffer.compare(plain, readFileSync(join(src, 'd1-export.sql'))) === 0 });
  const r = await verifyRestore(plain.toString('utf8'), { manifest: manifest.row_counts ? manifest : null }); checks.push(...r.checks.map((c) => ({ name: `restore: ${c.name}`, ok: c.ok })));
  return { ok: checks.every((c) => c.ok), checks, original_untouched: existsSync(join(src, 'd1-export.sql')) && statSync(join(src, 'd1-export.sql')).size === plain.length };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const arg = (n) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : null; };
  try {
    if (process.argv[2] === 'encrypt') { const r = await encryptLegacy({ src: arg('--src'), recipient: readFileSync(arg('--recipient-file'), 'utf8').trim(), out: arg('--out') ?? DEFAULT_OUT }); console.log(JSON.stringify(r, null, 1)); }
    else if (process.argv[2] === 'verify') { const r = await verifyLegacyCopy({ copy: arg('--copy'), src: arg('--src'), identityFile: arg('--identity-file'), fromKeychain: process.argv.includes('--identity-from-keychain') }); console.log(JSON.stringify({ ok: r.ok, original_untouched: r.original_untouched, checks: r.checks.map((c) => `${c.ok ? 'PASS' : 'FAIL'} ${c.name}`) }, null, 1)); process.exit(r.ok ? 0 : 1); }
    else { console.error('usage: backup_encrypt_legacy.mjs encrypt|verify ...'); process.exit(2); }
  } catch (e) { console.error('refused: ' + e.message); process.exit(2); }
}
