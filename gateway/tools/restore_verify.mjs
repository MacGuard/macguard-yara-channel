// Verifies a gateway backup by restoring it into an isolated in-memory database. Never touches Cloudflare. Usage: node tools/restore_verify.mjs EXPORT.sql [MANIFEST.json]
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { verifyRestore } from './backup_lib.mjs';
const args = process.argv.slice(2), idi = args.indexOf('--identity'), identity = idi >= 0 ? args.splice(idi, 2)[1] : null, [file, manifestFile] = args; if (!file) { console.error('usage: restore_verify.mjs EXPORT.sql|EXPORT.sql.age [MANIFEST.json] [--identity KEYFILE]'); process.exit(2); }
const text = file.endsWith('.age') ? (identity ? execFileSync('age', ['-d', '-i', identity, file], { maxBuffer: 1 << 30 }).toString('utf8') : (console.error('an .age file needs --identity KEYFILE'), process.exit(2))) : readFileSync(file, 'utf8');
const r = await verifyRestore(text, { manifest: manifestFile ? JSON.parse(readFileSync(manifestFile, 'utf8')) : null });
for (const c of r.checks) console.log(`${c.ok ? 'PASS' : 'FAIL'}  ${c.name}${c.detail ? '  (' + c.detail + ')' : ''}`);
console.log(r.ok ? 'RESTORE VERIFIED (isolated copy)' : 'RESTORE FAILED'); process.exit(r.ok ? 0 : 1);
