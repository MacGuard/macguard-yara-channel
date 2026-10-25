// protect_signing_key.sh against a STAND-IN for the Bitwarden CLI (the real `bw` is locked here and was not used): adds a passphrase to a throw-away key without changing the pair, and never replaces the local file unless the
// stored note + stored passphrase were proved to unlock the same public key.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const SH = new URL('../tools/protect_signing_key.sh', import.meta.url).pathname;
const BW = `#!/bin/sh
D=$BWDIR; b64d() { base64 -d 2>/dev/null || base64 -D; }
case "$1 $2" in
  "get item") [ -f "$D/$3.json" ] && cat "$D/$3.json" || exit 1;;
  "get notes") jq -r .notes "$D/$3.json";;
  "get password") jq -r .login.password "$D/$3.json";;
  "get template") echo '{"type":1,"name":"","notes":null,"login":null}';;
  "create item") J=$(cat | b64d); N=$(printf '%s' "$J" | jq -r .name); printf '%s' "$J" | jq --arg n "$N" '.id=$n' > "$D/$N.json";;
  "edit item") n=$(cat "$D/.edits" 2>/dev/null || echo 0); echo $((n+1)) > "$D/.edits"; if [ -n "\${BW_CORRUPT_FIRST_EDIT:-}" ] && [ "$n" = 0 ]; then b64d | jq '.notes="garbage"' > "$D/$3.json"; else b64d > "$D/$3.json"; fi;;
  "encode "*|"encode") base64 | tr -d '\\n';;
  sync*) ;;
esac
`;
const bwEncode = `case "$1" in encode) base64 | tr -d '\\n'; exit 0;; sync) exit 0;; esac\n`;

function setup() {
  const root = mkdtempSync(join(tmpdir(), 'mg-prot-')), bin = join(root, 'bin'), vault = join(root, 'vault'), keys = join(root, 'keys'); for (const d of [bin, vault, keys]) mkdirSync(d);
  writeFileSync(join(bin, 'bw'), BW.replace('case "$1 $2" in', bwEncode + 'case "$1 $2" in')); chmodSync(join(bin, 'bw'), 0o755);
  const key = join(keys, 'sign'); execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'throwaway', '-f', key]);
  writeFileSync(join(vault, 'KeyItem.json'), JSON.stringify({ id: 'KeyItem', name: 'KeyItem', type: 2, notes: readFileSync(key, 'utf8') }));
  const run = (input, env = {}) => spawnSync('sh', [SH, key, 'KeyItem', 'PassItem'], { input, encoding: 'utf8', env: { ...process.env, PATH: bin + ':' + process.env.PATH, BWDIR: vault, BW_SESSION: 'x', TMPDIR: root, ...env } });
  return { root, key, vault, run, done: () => rmSync(root, { recursive: true, force: true }) };
}
const pubOf = (f) => execFileSync('ssh-keygen', ['-y', '-P', '', '-f', f], { stdio: ['ignore', 'pipe', 'ignore'] }).toString().split(' ').slice(0, 2).join(' ');

test('adds the passphrase without changing the pair, updates the note, stores the passphrase separately, proves the stored copy unlocks, then replaces the local file (mode 400)', () => {
  const s = setup(); try {
    const pub = readFileSync(s.key + '.pub', 'utf8').split(' ').slice(0, 2).join(' '), fp = execFileSync('ssh-keygen', ['-l', '-f', s.key + '.pub']).toString().split(' ')[1];
    const r = s.run('correct horse battery staple\ncorrect horse battery staple\n'); assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /the copy is passphrase-protected[\s\S]*matches the public key[\s\S]*local key replaced atomically/); assert.ok(r.stdout.includes(fp));
    assert.ok(!/correct horse|PRIVATE KEY/.test(r.stdout + r.stderr), 'neither the passphrase nor the key is printed');
    assert.throws(() => pubOf(s.key), 'the local key now needs its passphrase'); assert.equal((statSync(s.key).mode & 0o777).toString(8), '400');
    assert.match(readFileSync(s.key, 'utf8'), /BEGIN OPENSSH PRIVATE KEY/); assert.notEqual(JSON.parse(readFileSync(join(s.vault, 'KeyItem.json'))).notes, undefined);
    assert.equal(JSON.parse(readFileSync(join(s.vault, 'PassItem.json'))).login.password, 'correct horse battery staple');
    assert.deepEqual(readdirSync(join(s.root)).filter((f) => f.startsWith('mg-protect')), [], 'the temporary directory is gone');
    assert.deepEqual(readdirSync(join(s.root, 'keys')).sort(), ['sign', 'sign.pub'], 'no stray file next to the key');
  } finally { s.done(); }
});

test('refuses without touching anything: locked vault, mismatching passphrases, an already protected key, a missing item', () => {
  const s = setup(); try {
    const before = readFileSync(s.key), vaultBefore = readFileSync(join(s.vault, 'KeyItem.json'));
    assert.match(s.run('a\na\n', { BW_SESSION: '' }).stdout, /vault is locked/); assert.match(s.run('a\nb\n').stdout, /differ/); assert.match(s.run('\n\n').stdout, /empty passphrase/);
    rmSync(join(s.vault, 'KeyItem.json')); assert.match(s.run('a\na\n').stdout, /could not be read/); writeFileSync(join(s.vault, 'KeyItem.json'), vaultBefore);
    assert.deepEqual(readFileSync(s.key), before); assert.equal(existsSync(join(s.vault, 'PassItem.json')), false);
    assert.equal(s.run('pw1\npw1\n').status, 0); assert.match(s.run('pw2\npw2\n').stdout, /not an UNPROTECTED key/);
  } finally { s.done(); }
});

test('if the Bitwarden copy does not prove out, the note is put back and the local key is left exactly as it was', () => {
  const s = setup(); try {
    const before = readFileSync(s.key), note = JSON.parse(readFileSync(join(s.vault, 'KeyItem.json'))).notes;
    const r = s.run('pw1\npw1\n', { BW_CORRUPT_FIRST_EDIT: '1' }); assert.equal(r.status, 1); assert.match(r.stdout, /REVERTED[\s\S]*do NOT unlock/);
    assert.deepEqual(readFileSync(s.key), before); assert.equal(pubOf(s.key).startsWith('ssh-ed25519'), true, 'the local key is still the original, unprotected one');
    assert.equal(JSON.parse(readFileSync(join(s.vault, 'KeyItem.json'))).notes, note, 'the note is back to the previous key');
  } finally { s.done(); }
});
