// set_backup_secrets.sh against a STAND-IN for the GitHub CLI: the value travels only on stdin, never in an argument, output or log; unknown names and empty input are refused or skipped.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const SH = new URL('../tools/set_backup_secrets.sh', import.meta.url).pathname;
const GH = `#!/bin/sh
case "$1 $2" in
  "auth status") exit 0;;
  "secret list") exit 0;;
  "secret set") printf '%s\\n' "$*" >> "$GHLOG/argv"; cat >> "$GHLOG/stdin"; echo >> "$GHLOG/stdin"; exit 0;;
esac
exit 1
`;
test('the secret goes to gh on stdin only; the arguments, the output and stderr carry the name but never the value', () => {
  const root = mkdtempSync(join(tmpdir(), 'mg-setsec-')); try {
    writeFileSync(join(root, 'gh'), GH); chmodSync(join(root, 'gh'), 0o755);
    const run = (args, input) => spawnSync('sh', [SH, ...args], { input, encoding: 'utf8', env: { PATH: root + ':' + process.env.PATH, GHLOG: root } });
    const VALUE = 'S3cr3t-VALUE-0123456789';
    let r = run(['MG_B2_SECRET'], VALUE + '\n'); assert.equal(r.status, 0); assert.match(r.stdout, /OK: MG_B2_SECRET set in macguard-backup-production/);
    assert.ok(!(r.stdout + r.stderr).includes(VALUE)); assert.ok(!readFileSync(join(root, 'argv'), 'utf8').includes(VALUE)); assert.match(readFileSync(join(root, 'argv'), 'utf8'), /secret set MG_B2_SECRET --env macguard-backup-production/); assert.ok(readFileSync(join(root, 'stdin'), 'utf8').includes(VALUE));
    r = run(['MACGUARD_BACKUP_SIGNING_KEY'], VALUE + '\n'); assert.match(r.stdout, /REFUSED/); r = run(['AGE_IDENTITY'], VALUE + '\n'); assert.match(r.stdout, /REFUSED/);
    r = run(['MG_R2_SECRET'], '\n'); assert.match(r.stdout, /SKIPPED: MG_R2_SECRET/);
    assert.ok(!/MACGUARD_BACKUP_SIGNING_KEY|AGE_IDENTITY/.test(readFileSync(join(root, 'argv'), 'utf8')), 'the retired key and the age identity are never set');
  } finally { rmSync(root, { recursive: true, force: true }); }
});
