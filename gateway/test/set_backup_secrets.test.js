// set_backup_secrets.sh against a STAND-IN for the GitHub CLI: it reports the existing environments by name, never recreates what exists, asks only for what is missing, and the value travels on stdin only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const SH = new URL('../tools/set_backup_secrets.sh', import.meta.url).pathname;
// the stand-in knows a vault: which secrets/variables exist per environment (from $GHVAULT lines "env|kind|name")
const GH = `#!/bin/sh
case "$1 $2" in
  "auth status") exit 0;;
  "secret list"|"variable list") kind=$1; env=; repo=; shift 2; while [ $# -gt 0 ]; do case $1 in --env) env=$2; shift 2;; *) shift;; esac; done
    if [ -n "$env" ]; then grep "^$env|$kind|" "$GHVAULT" | cut -d'|' -f3 | sed 's/$/\\tx/'; else grep "^|$kind|" "$GHVAULT" | cut -d'|' -f3 | sed 's/$/\\tx/'; fi; exit 0;;
  "secret set") printf '%s\\n' "$*" >> "$GHLOG/argv"; cat >> "$GHLOG/stdin"; echo >> "$GHLOG/stdin"; exit 0;;
esac
exit 1
`;
const vault = (extra = []) => [...['b2', 'scaleway', 'r2'].flatMap((p) => ['read', 'write'].flatMap((d) => [`archive-${p}-${d}|secret|ARCHIVE_ACCESS_KEY_ID`, `archive-${p}-${d}|secret|ARCHIVE_SECRET_ACCESS_KEY`, `archive-${p}-${d}|variable|ARCHIVE_BUCKET`, `archive-${p}-${d}|variable|ARCHIVE_ENDPOINT`, `archive-${p}-${d}|variable|ARCHIVE_REGION`])), 'macguard-backup-production|secret|MACGUARD_BACKUP_SIGNING_KEY', ...extra].join('\n') + '\n';

function setup(lines) {
  const root = mkdtempSync(join(tmpdir(), 'mg-setsec-')); writeFileSync(join(root, 'gh'), GH); chmodSync(join(root, 'gh'), 0o755); writeFileSync(join(root, 'vault'), lines);
  const run = (args, input) => spawnSync('sh', [SH, ...args], { input, encoding: 'utf8', env: { PATH: root + ':' + process.env.PATH, GHLOG: root, GHVAULT: join(root, 'vault') } });
  return { root, run, done: () => rmSync(root, { recursive: true, force: true }) };
}

test('with the six archive environments present it recreates nothing: it reports names and asks only for the export token that is missing', () => {
  const w = setup(vault()); try {
    const VALUE = 'Tok3n-VALUE-0123456789', r = w.run([], VALUE + '\n');
    assert.match(r.stdout, /PRESENT: archive-b2-write/); assert.match(r.stdout, /PRESENT: archive-scaleway-read/); assert.match(r.stdout, /PRESENT: archive-r2-write/); assert.match(r.stdout, /RETIRED but still present: MACGUARD_BACKUP_SIGNING_KEY/);
    assert.match(r.stdout, /OK: CLOUDFLARE_API_TOKEN set in macguard-backup-production/); assert.ok(!(r.stdout + r.stderr).includes(VALUE));
    const argv = readFileSync(join(w.root, 'argv'), 'utf8'); assert.equal(argv.trim().split('\n').length, 1, 'exactly one secret was set'); assert.match(argv, /secret set CLOUDFLARE_API_TOKEN --env macguard-backup-production/); assert.ok(!argv.includes(VALUE) && !/ARCHIVE_|MACGUARD_BACKUP_SIGNING_KEY/.test(argv));
    assert.ok(readFileSync(join(w.root, 'stdin'), 'utf8').includes(VALUE));
  } finally { w.done(); }
});

test('nothing is asked when the export token already exists (environment or repository) and --report never writes; a missing archive credential is reported, not recreated', () => {
  let w = setup(vault(['macguard-backup-production|secret|CLOUDFLARE_API_TOKEN'])); try { const r = w.run([], 'x\n'); assert.match(r.stdout, /PRESENT: CLOUDFLARE_API_TOKEN in macguard-backup-production/); assert.equal(existsSync(join(w.root, 'argv')), false); } finally { w.done(); }
  w = setup(vault(['|secret|CLOUDFLARE_API_TOKEN'])); try { const r = w.run([], 'x\n'); assert.match(r.stdout, /PRESENT at repository level/); assert.equal(existsSync(join(w.root, 'argv')), false); } finally { w.done(); }
  w = setup(vault().split('\n').filter((l) => !l.startsWith('archive-r2-read|secret|ARCHIVE_SECRET')).join('\n')); try { const r = w.run(['--report']); assert.match(r.stdout, /MISSING in archive-r2-read: ARCHIVE_SECRET_ACCESS_KEY \(ask the owner/); assert.notEqual(r.status, 0); assert.equal(existsSync(join(w.root, 'argv')), false); } finally { w.done(); }
});
