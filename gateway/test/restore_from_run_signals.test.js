// restore_from_run.sh (owner machine) holds the age identity and decrypted exports in its work directory. Regressions:
//  - its trap removed the directory on Ctrl-C/SIGTERM but did NOT exit: the script went on, `gh run download -D` re-created the directory and decryption resumed;
//  - the three decrypted exports stayed on disk until the end of the run;
//  - a directory left by SIGKILL/power loss was anonymous (tmp.XXXXXX) and never mentioned again.
// Fakes: gh, security, recover_verify.sh and restore_verify.mjs; the script under test and age-keygen are real.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const SCRIPT = new URL('../tools/restore_from_run.sh', import.meta.url).pathname, MARK = 'PLAINTEXT-MARKER-RFR';
const HAVE = (() => { try { execFileSync('age-keygen', ['--version'], { stdio: 'ignore' }); execFileSync('jq', ['--version'], { stdio: 'ignore' }); return true; } catch { return false; } })();

function sandbox({ slow = '' } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'mg-rfr-test-')), tools = join(root, 'repo', 'gateway', 'tools'), bin = join(root, 'bin'), tmp = join(root, 'tmp');
  for (const d of [tools, bin, tmp, join(root, 'repo', 'gateway', 'environments')]) mkdirSync(d, { recursive: true });
  copyFileSync(SCRIPT, join(tools, 'restore_from_run.sh'));
  const key = join(root, 'id.txt'); execFileSync('age-keygen', ['-o', key], { stdio: 'ignore' }); const pub = execFileSync('age-keygen', ['-y', key], { encoding: 'utf8' }).trim();
  writeFileSync(join(root, 'repo', 'gateway', 'environments', 'backup-trust.json'), JSON.stringify({ age_recipient: pub, ed25519: { public_key: 'x', max_sequence: 1 }, sigstore: { identity: 'x', repository: 'x' } }));
  const sh = (f, body) => { writeFileSync(f, '#!/bin/sh\n' + body + '\n'); chmodSync(f, 0o755); };
  sh(join(bin, 'gh'), `[ "$1 $2" = "run download" ] || exit 1; while [ $# -gt 0 ]; do case "$1" in -n) n=$2; shift;; -D) d=$2; shift;; esac; shift; done
mkdir -p "$d"; case "$n" in read-*) mkdir -p "$d/20261031T032300Z"; echo '{"resource":"gateway"}' > "$d/20261031T032300Z/manifest.json"; echo cipher > "$d/20261031T032300Z/d1-export.sql.age";; esac`);
  sh(join(bin, 'security'), `cat "${key}"`);
  // recover_verify.sh: writes the plaintext to OUTPUT ($5), records how many plaintexts exist in the work dir at that moment, optionally hangs (to be interrupted)
  sh(join(tools, 'recover_verify.sh'), `T=$(dirname "$5"); echo "$(ls "$T" | grep -c '\\.sql$')" >> "${root}/count"; echo ${MARK} > "$5"; echo "$T" > "${root}/workdir"; ${slow}
echo "DECRYPTED OK"`);
  writeFileSync(join(tools, 'restore_verify.mjs'), "console.log('RESTORE VERIFIED (isolated copy)');\n");
  return { root, tmp, key, run: (args, env = {}) => { const p = spawn('sh', [join(tools, 'restore_from_run.sh'), ...args], { env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, TMPDIR: tmp, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = ''; p.stdout.on('data', (d) => (out += d)); p.stderr.on('data', (d) => (err += d)); return { p, done: new Promise((ok) => p.on('close', (code, signal) => ok({ code, signal, out, err }))) }; },
  done: () => rmSync(root, { recursive: true, force: true }) };
}
const waitFor = async (fn, ms = 8000) => { const t = Date.now(); while (Date.now() - t < ms) { const v = fn(); if (v) return v; await new Promise((r) => setTimeout(r, 25)); } return null; };

test('a full run (Keychain identity): PASS for the three providers, at most one plaintext at a time, nothing left in TMPDIR', { skip: !HAVE }, async () => {
  const s = sandbox(); try {
    const r = await s.run(['123']).done; assert.equal(r.code, 0, r.out + r.err); assert.match(r.out, /PASS {2}the three restored plaintexts are identical/);
    assert.deepEqual(readFileSync(join(s.root, 'count'), 'utf8').trim().split('\n'), ['0', '0', '0'], 'the previous provider plaintext was already deleted');
    assert.match(readFileSync(join(s.root, 'workdir'), 'utf8').trim(), /\/mg-restore-run\.[A-Za-z0-9]+$/, 'recognisable work directory');
    assert.deepEqual(readdirSync(s.tmp), []); assert.equal(r.err, '');
  } finally { s.done(); }
});
for (const [sig, code] of [['SIGTERM', 143], ['SIGINT', 130], ['SIGHUP', 129]]) {
  test(`${sig} during decryption: the script STOPS (status ${code}), no further provider is processed, identity and plaintext are gone`, { skip: !HAVE }, async () => {
    const s = sandbox({ slow: 'sleep 1' }); try {
      const c = s.run(['123']); await waitFor(() => existsSync(join(s.root, 'workdir')));
      c.p.kill(sig); const r = await c.done;
      assert.equal(r.code, code, `code=${r.code} signal=${r.signal} out=${r.out}`); assert.doesNotMatch(r.out, /scaleway|r2|PASS {2}the three/);
      assert.equal(readFileSync(join(s.root, 'count'), 'utf8').trim().split('\n').length, 1, 'only the first provider was started');
      assert.deepEqual(readdirSync(s.tmp), [], 'the work directory (identity, plaintext) was removed and not re-created');
    } finally { s.done(); }
  });
}
test('a directory left by a killed run is reported (not deleted); one of a running process, another user prefix or a plain tmp dir is not', { skip: !HAVE }, async () => {
  const s = sandbox(); try {
    const dead = join(s.tmp, 'mg-restore-run.DEAD01'), live = join(s.tmp, 'mg-restore-run.LIVE01'), other = join(s.tmp, 'tmp.ABC123'), nomark = join(s.tmp, 'mg-restore-run.NOMARK');
    for (const d of [dead, live, other, nomark]) { mkdirSync(d, { mode: 0o700 }); writeFileSync(join(d, 'id'), 'AGE-SECRET-KEY-FAKE'); }
    writeFileSync(join(dead, '.mg-origin'), 'pid=999999\nscript=restore_from_run.sh\n'); writeFileSync(join(live, '.mg-origin'), `pid=${process.pid}\n`);
    const r = await s.run(['123']).done; assert.equal(r.code, 0, r.out + r.err);
    assert.match(r.err, /WARNING: leftover of an interrupted restore.*mg-restore-run\.DEAD01/); assert.match(r.err, /mg-restore-run\.NOMARK/);
    assert.doesNotMatch(r.err, /LIVE01|tmp\.ABC123/); assert.doesNotMatch(r.err + r.out, /AGE-SECRET-KEY/, 'the contents are never printed');
    for (const d of [dead, live, other, nomark]) assert.ok(existsSync(join(d, 'id')), `${d} not deleted`);
  } finally { s.done(); }
});
