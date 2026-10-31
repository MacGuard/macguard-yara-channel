// Verifies a backup by restoring it into an isolated SQLite. Never touches Cloudflare. Usage: node tools/restore_verify.mjs EXPORT.sql|EXPORT.sql.age [MANIFEST.json] [--identity KEYFILE] [--resource gateway|panel|intel]
// Streaming: age decrypts into a private 0600 file (the plaintext never passes through this process), the SHA-256 is computed from that file and compared with the manifest, and sqlite3 loads it from the file.
// Memory stays flat with the size of the export. The private directory is removed on every exit path.
import { chmodSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { verifyRestore } from './backup_lib.mjs';
import { ageDecryptFile, shaFile } from './stream_io.mjs';
import { privateDir } from './private_tmp.mjs';
const args = process.argv.slice(2), idi = args.indexOf('--identity'), identity = idi >= 0 ? args.splice(idi, 2)[1] : null, ri = args.indexOf('--resource'), resource = ri >= 0 ? args.splice(ri, 2)[1] : 'gateway', [file, manifestFile] = args; if (!file) { console.error('usage: restore_verify.mjs EXPORT.sql|EXPORT.sql.age [MANIFEST.json] [--identity KEYFILE]'); process.exit(2); }
if (file.endsWith('.age') && !identity) { console.error('an .age file needs --identity KEYFILE'); process.exit(2); }
const manifest = manifestFile ? JSON.parse(readFileSync(manifestFile, 'utf8')) : null;
const verify = resource === 'panel' ? (await import('../../admin/worker/tools/panel_backup_verify.mjs')).verifyPanelRestore : resource === 'intel' ? (await import('../../admin/worker/tools/intel_backup_verify.mjs')).verifyIntelRestore : verifyRestore;   // each protected database has its own verifier
const work = privateDir(tmpdir(), 'mg-restore-');
async function main() {
  let plain = file;
  if (file.endsWith('.age')) {
    plain = join(work, 'plain.sql');
    try { await ageDecryptFile({ identity, src: file, dst: plain }); } catch (e) { console.log(`FAIL  the backup decrypts  (${String(e.message).slice(0, 160)})`); console.log('RESTORE FAILED'); return 1; }
    console.log('PASS  the backup decrypts (age authenticated every chunk)');
  }
  const checks = [];
  if (manifest && manifest.plaintext_sha256) { const got = await shaFile(plain), ok = got === manifest.plaintext_sha256; checks.push({ ok, name: 'the plaintext SHA-256 equals the manifest', detail: ok ? '' : 'differs' }); }
  const r = await verify({ file: plain }, { manifest });
  for (const c of [...checks, ...r.checks]) console.log(`${c.ok ? 'PASS' : 'FAIL'}  ${c.name}${c.detail ? '  (' + c.detail + ')' : ''}`);
  const ok = r.ok && checks.every((c) => c.ok);
  console.log(ok ? 'RESTORE VERIFIED (isolated copy)' : 'RESTORE FAILED'); return ok ? 0 : 1;
}
let code = 1;
try { code = await main(); } finally { rmSync(work, { recursive: true, force: true }); }
process.exit(code);
