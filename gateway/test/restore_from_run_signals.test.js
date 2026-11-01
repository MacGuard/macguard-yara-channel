// restore_from_run.sh (owner machine) holds the age identity and decrypted exports in its work directory. Regressions:
//  - its trap removed the directory on Ctrl-C/SIGTERM but did NOT exit: the script went on, `gh run download -D` re-created the directory and decryption resumed;
//  - SIGHUP (closing the Terminal window / logging out) was not trapped at all: the identity and the plaintexts stayed in $TMPDIR;
//  - the three decrypted exports stayed on disk until the end of the run;
//  - a directory left by SIGKILL/power loss was anonymous (tmp.XXXXXX) and never mentioned again.
// SIGKILL is NOT an interceptable signal: its test only shows what is left and that the next run reports it.
// Fakes: gh, security, recover_verify.sh and restore_verify.mjs; the script under test, sh, age-keygen (throwaway keys), jq and shasum are real. Data is synthetic.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const SCRIPT = new URL('../tools/restore_from_run.sh', import.meta.url).pathname, MARK = 'PLAINTEXT-MARKER-RFR';
const HAVE = (() => { try { for (const [c, a] of [['age-keygen', '--version'], ['jq', '--version'], ['shasum', '--version']]) execFileSync(c, [a], { stdio: 'ignore' }); return true; } catch { return false; } })();
const sha = (s) => createHash('sha256').update(s).digest('hex');
const PLAIN = `${MARK} same\n`, OTHER = `${MARK} TAMPERED\n`;
const alive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };

// opts: slow (shell run inside the fake decryption), tmpName (TMPDIR folder name), differ (provider decrypting to other bytes),
//       refuse (provider whose decryption/verification is refused), failVerify (provider whose isolated restore check fails)
function sandbox({ slow = '', tmpName = 'tmp', differ = '', refuse = '', failVerify = '' } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'mg-rfr-test-')), tools = join(root, 'repo', 'gateway', 'tools'), bin = join(root, 'bin'), tmp = join(root, tmpName);
  for (const d of [tools, bin, tmp, join(root, 'repo', 'gateway', 'environments')]) mkdirSync(d, { recursive: true });
  copyFileSync(SCRIPT, join(tools, 'restore_from_run.sh'));
  const key = join(root, 'id.txt'); execFileSync('age-keygen', ['-o', key], { stdio: 'ignore' }); const pub = execFileSync('age-keygen', ['-y', key], { encoding: 'utf8' }).trim();
  writeFileSync(join(root, 'repo', 'gateway', 'environments', 'backup-trust.json'), JSON.stringify({ age_recipient: pub, ed25519: { public_key: 'x', max_sequence: 1 }, sigstore: { identity: 'x', repository: 'x' } }));
  writeFileSync(join(root, 'plain'), PLAIN); writeFileSync(join(root, 'other'), OTHER);
  const sh = (f, body) => { writeFileSync(f, '#!/bin/sh\n' + body + '\n'); chmodSync(f, 0o755); };
  sh(join(bin, 'gh'), `echo "gh $*" >> "${root}/args"; if [ "$1 $2" = "workflow run" ]; then echo "$*" >> "${root}/recorded"; exit 0; fi
[ "$1 $2" = "run download" ] || exit 1; while [ $# -gt 0 ]; do case "$1" in -n) n=$2; shift;; -D) d=$2; shift;; esac; shift; done
mkdir -p "$d"; case "$n" in read-*) mkdir -p "$d/20261031T032300Z"; echo '{"resource":"gateway"}' > "$d/20261031T032300Z/manifest.json"; echo cipher > "$d/20261031T032300Z/d1-export.sql.age";; esac`);
  sh(join(bin, 'security'), `cat "${key}"`);
  // fake recover_verify.sh (DIR KEY MINSEQ IDENTITY OUTPUT): logs its args, pid, the number of plaintexts already in the work dir and the modes; then refuses or "decrypts"
  sh(join(tools, 'recover_verify.sh'), `echo "recover $*" >> "${root}/args"; echo $$ >> "${root}/childpids"; T=$(dirname "$5"); p=$(basename "$5" .sql)
echo "$(ls "$T" | grep -c '\\.sql$')" >> "${root}/count"; echo "$T" > "${root}/workdir"; echo "$T" >> "${root}/workdirs"
if [ "$p" = "${refuse}" ]; then echo "REFUSED: the decrypted bytes do not match the manifest"; exit 1; fi
if [ "$p" = "${differ}" ]; then cp "${root}/other" "$5"; else cp "${root}/plain" "$5"; fi
ls -ld "$T" "$4" "$5" | cut -c1-10 | tr '\\n' ' ' >> "${root}/modes"; echo >> "${root}/modes"; ${slow}
echo "ANCHORED OK"; echo "DECRYPTED OK"`);
  // fake restore_verify.mjs: must get the ENCRYPTED copy, the manifest and the identity PATH (never the plaintext the script deletes early)
  writeFileSync(join(tools, 'restore_verify.mjs'), `import { appendFileSync } from 'node:fs'; const a = process.argv.slice(2); appendFileSync(${JSON.stringify(join(root, 'args'))}, 'verify ' + a.join(' ') + '\\n');
if (!a[0].endsWith('/d1-export.sql.age') || !a[1].endsWith('/manifest.json') || !a.includes('--identity')) { console.log('BAD ARGS'); process.exit(1); }
if (${JSON.stringify(failVerify)} && a[0].includes('read-${failVerify}/')) { console.log('FAIL  integrity_check'); console.log('RESTORE FAILED'); process.exit(1); } console.log('RESTORE VERIFIED (isolated copy)');\n`);
  const env0 = { ...process.env, PATH: `${bin}:${process.env.PATH}`, TMPDIR: tmp };
  return { root, tmp, key, read: (f) => (existsSync(join(root, f)) ? readFileSync(join(root, f), 'utf8') : ''),
    run: (args, env = {}, { group = false } = {}) => { const p = spawn('sh', [join(tools, 'restore_from_run.sh'), ...args], { env: { ...env0, ...env }, stdio: ['ignore', 'pipe', 'pipe'], detached: group });
      let out = '', err = ''; p.stdout.on('data', (d) => (out += d)); p.stderr.on('data', (d) => (err += d)); return { p, done: new Promise((ok) => p.on('close', (code, signal) => ok({ code, signal, out, err }))) }; },
    done: () => rmSync(root, { recursive: true, force: true }) };
}
const waitFor = async (fn, ms = 8000) => { const t = Date.now(); while (Date.now() - t < ms) { const v = fn(); if (v) return v; await new Promise((r) => setTimeout(r, 25)); } return null; };
const noSecretIn = (s, text) => { const k = readFileSync(s.key, 'utf8').match(/AGE-SECRET-KEY-[0-9A-Z]+/)[0]; assert.ok(!text.includes(k) && !text.includes('AGE-SECRET-KEY'), 'no identity in output or arguments'); };
const T = { skip: !HAVE };

// ---- the five original regressions ----
test('a full run (Keychain identity): PASS for the three providers, at most one plaintext at a time, nothing left in TMPDIR', T, async () => {
  const s = sandbox(); try {
    const r = await s.run(['123']).done; assert.equal(r.code, 0, r.out + r.err); assert.match(r.out, /PASS {2}the three restored plaintexts are identical/);
    assert.deepEqual(s.read('count').trim().split('\n'), ['0', '0', '0'], 'the previous provider plaintext was already deleted');
    assert.match(s.read('workdir').trim(), /\/mg-restore-run\.[A-Za-z0-9]+$/, 'recognisable work directory');
    assert.deepEqual(readdirSync(s.tmp), []); assert.equal(r.err, ''); noSecretIn(s, r.out + r.err + s.read('args'));
  } finally { s.done(); }
});
for (const [sig, code] of [['SIGTERM', 143], ['SIGINT', 130], ['SIGHUP', 129]]) {
  test(`${sig} to the script during decryption: it STOPS (status ${code}), no further provider is downloaded or decrypted, identity and plaintext are gone`, T, async () => {
    const s = sandbox({ slow: 'sleep 1' }); try {
      const c = s.run(['123'], { MG_RECORD: '1' }); await waitFor(() => s.read('workdir'));
      c.p.kill(sig); const r = await c.done;
      assert.equal(r.code, code, `code=${r.code} signal=${r.signal} out=${r.out}`); assert.doesNotMatch(r.out, /scaleway|r2|PASS {2}the three/);
      assert.equal(s.read('count').trim().split('\n').length, 1, 'only the first provider was started'); assert.doesNotMatch(s.read('args'), /read-scaleway|read-r2/, 'nothing more downloaded');
      assert.deepEqual(readdirSync(s.tmp), [], 'the work directory (identity, plaintext) was removed and not re-created'); assert.equal(s.read('recorded'), '');
      for (const pid of s.read('childpids').trim().split('\n').map(Number)) assert.ok(await waitFor(() => !alive(pid), 3000), 'no child left running');
    } finally { s.done(); }
  });
}
test('leftover reporting: a dead run and an unmarked directory are reported; a live run, other prefixes and a symlink are not; nothing is deleted', T, async () => {
  const s = sandbox(); try {
    const dead = join(s.tmp, 'mg-restore-run.DEAD01'), live = join(s.tmp, 'mg-restore-run.LIVE01'), other = join(s.tmp, 'tmp.ABC123'), nomark = join(s.tmp, 'mg-restore-run.NOMARK');
    for (const d of [dead, live, other, nomark]) { mkdirSync(d, { mode: 0o700 }); writeFileSync(join(d, 'id'), 'AGE-SECRET-KEY-FAKE'); }
    writeFileSync(join(dead, '.mg-origin'), 'pid=999999\nscript=restore_from_run.sh\n'); writeFileSync(join(live, '.mg-origin'), `pid=${process.pid}\n`);
    execFileSync('ln', ['-s', other, join(s.tmp, 'mg-restore-run.LINK01')]);
    const r = await s.run(['123']).done; assert.equal(r.code, 0, r.out + r.err);
    assert.match(r.err, /WARNING: leftover of an interrupted restore.*mg-restore-run\.DEAD01/); assert.match(r.err, /mg-restore-run\.NOMARK/);
    assert.doesNotMatch(r.err, /LIVE01|tmp\.ABC123|LINK01/); assert.doesNotMatch(r.err + r.out, /AGE-SECRET-KEY/, 'the contents are never printed');
    for (const d of [dead, live, other, nomark]) assert.ok(existsSync(join(d, 'id')), `${d} not deleted`);
    assert.equal(statSync(dead).mode & 0o777, 0o700, 'not modified');
  } finally { s.done(); }
});

// ---- signals delivered to the whole process group (Ctrl-C in the terminal, closing the window / logging out) ----
for (const [sig, code] of [['SIGINT', 130], ['SIGHUP', 129]]) {
  test(`${sig} to the process group (terminal): the child decrypting dies at once, the script exits ${code}, nothing is left`, T, async () => {
    const s = sandbox({ slow: 'sleep 30' }); try {
      const c = s.run(['123'], {}, { group: true }); await waitFor(() => s.read('workdir')); const t0 = Date.now();
      process.kill(-c.p.pid, sig); const r = await c.done;
      assert.ok(Date.now() - t0 < 5000, 'did not wait for the 30 s child'); assert.equal(r.code, code, `code=${r.code} signal=${r.signal}`);
      assert.deepEqual(readdirSync(s.tmp), []); for (const pid of s.read('childpids').trim().split('\n').map(Number)) assert.ok(await waitFor(() => !alive(pid), 3000));
    } finally { try { execFileSync('pkill', ['-KILL', '-f', s.root]); } catch { /* none */ } s.done(); }
  });
}

// ---- SIGKILL: not interceptable ----
test('abrupt end (SIGKILL, as a power cut): nothing can clean up; the leftover is recognisable and the NEXT run reports it without deleting or printing it', T, async () => {
  const s = sandbox({ slow: '[ -f "$(dirname "$T")/../fast" ] || sleep 30' }); try {
    const c = s.run(['123']); await waitFor(() => s.read('workdir')); const wd = s.read('workdir').trim();
    c.p.kill('SIGKILL'); try { execFileSync('pkill', ['-KILL', '-f', `${s.root}/repo/gateway/tools/recover_verify.sh`]); } catch { /* already gone */ } await c.done;   // the orphaned child holds the pipes
    writeFileSync(join(s.root, 'fast'), '');
    assert.ok(existsSync(join(wd, 'id')) && existsSync(join(wd, 'b2.sql')), 'SIGKILL leaves the identity and the plaintext: no trap can run');
    assert.match(readFileSync(join(wd, '.mg-origin'), 'utf8'), /^pid=\d+\nscript=restore_from_run\.sh\nstarted=/);
    const r = await s.run(['124']).done; assert.equal(r.code, 0, r.out + r.err);
    assert.ok(r.err.includes('leftover of an interrupted restore') && r.err.includes(wd), r.err); assert.ok(!(r.err + r.out).includes(MARK)); noSecretIn(s, r.err + r.out);
    assert.ok(existsSync(join(wd, 'id')), 'reported, NOT deleted (its origin is for the owner to confirm)');
  } finally { s.done(); }
});

// ---- evidence, failures, isolation ----
test('early deletion does not change the evidence: the hash reported and recorded is that of the decrypted plaintext; MG_RECORD records the three', T, async () => {
  const s = sandbox(); try {
    const r = await s.run(['123'], { MG_RECORD: '1' }).done; assert.equal(r.code, 0, r.out + r.err);
    const h = sha(PLAIN); assert.match(r.out, new RegExp(`identical \\(sha256 ${h}\\)`));
    const rec = s.read('recorded').trim().split('\n'); assert.equal(rec.length, 3, r.out);
    for (const p of ['b2', 'scaleway', 'r2']) assert.ok(rec.some((l) => l.includes(`provider=${p}`) && l.includes(`plaintext_sha256=${h}`) && l.includes('run_id=123') && l.includes('mode=drill')), p);
    for (const p of ['b2', 'scaleway', 'r2']) assert.match(r.out, new RegExp(`^RECORDED: ${p}$`, 'm'), 'the output names each recorded provider'); noSecretIn(s, s.read('args'));
  } finally { s.done(); }
});
test('isolated restore: restore_verify gets the encrypted copy, its manifest and the identity path for every provider (never the deleted plaintext)', T, async () => {
  const s = sandbox(); try {
    const r = await s.run(['123']).done; assert.equal(r.code, 0, r.out + r.err); const v = s.read('args').split('\n').filter((l) => l.startsWith('verify '));
    assert.equal(v.length, 3); for (const l of v) assert.match(l, /read-(b2|scaleway|r2)\/20261031T032300Z\/d1-export\.sql\.age .*manifest\.json --identity .*\/mg-restore-run\.[A-Za-z0-9]+\/id --resource gateway$/);
  } finally { s.done(); }
});
test('a provider that decrypts to different bytes is a FAIL and nothing is recorded, even with MG_RECORD=1', T, async () => {
  const s = sandbox({ differ: 'scaleway' }); try {
    const r = await s.run(['123'], { MG_RECORD: '1' }).done; assert.equal(r.code, 1); assert.match(r.out, /FAIL {2}the three providers did not all restore to the same plaintext/);
    assert.equal(s.read('recorded'), '', 'no evidence for a failed restore'); assert.deepEqual(readdirSync(s.tmp), []);
  } finally { s.done(); }
});
test('a refused decryption (hash/manifest/signature) is a FAIL: no plaintext of that provider, nothing recorded, nothing left', T, async () => {
  const s = sandbox({ refuse: 'b2' }); try {
    const r = await s.run(['123'], { MG_RECORD: '1' }).done; assert.equal(r.code, 1); assert.match(r.out, /FAIL {2}b2: REFUSED/); assert.match(r.out, /FAIL {2}the three providers/);
    assert.equal(s.read('recorded'), ''); assert.deepEqual(readdirSync(s.tmp), []);
  } finally { s.done(); }
});
test('a corrupt export (the isolated SQLite restore fails) is a FAIL and nothing is recorded', T, async () => {
  const s = sandbox({ failVerify: 'r2' }); try {
    const r = await s.run(['123'], { MG_RECORD: '1' }).done; assert.equal(r.code, 1); assert.match(r.out, /FAIL {2}r2: isolated SQLite restore/); assert.equal(s.read('recorded'), '');
    assert.deepEqual(readdirSync(s.tmp), []);
  } finally { s.done(); }
});

// ---- concurrency, temporary paths, permissions ----
test('concurrency: two runs at the same time use separate directories, neither reports the other (still running), both finish clean', T, async () => {
  const s = sandbox({ slow: 'sleep 0.5' }); try {
    const a = s.run(['1']); await waitFor(() => s.read('workdir')); const b = s.run(['2']);
    const [ra, rb] = await Promise.all([a.done, b.done]);
    for (const r of [ra, rb]) { assert.equal(r.code, 0, r.out + r.err); assert.doesNotMatch(r.err, /leftover/); }
    assert.equal(new Set(s.read('workdirs').trim().split('\n')).size, 2, 'one private directory per run'); assert.deepEqual(readdirSync(s.tmp), []);
  } finally { s.done(); }
});
test('permissions: the work directory is 0700 and the identity and plaintext files are 0600 while they exist (umask of the caller ignored)', T, async () => {
  const s = sandbox(); try {
    const r = await new Promise((ok) => { const p = spawn('sh', ['-c', `umask 022; exec sh "${s.root}/repo/gateway/tools/restore_from_run.sh" 123`], { env: { ...process.env, PATH: `${s.root}/bin:${process.env.PATH}`, TMPDIR: s.tmp } }); p.on('close', ok); });
    assert.equal(r, 0); const lines = s.read('modes').trim().split('\n'); assert.equal(lines.length, 3);
    for (const line of lines) assert.deepEqual(line.trim().split(' '), ['drwx------', '-rw-------', '-rw-------'], line);
  } finally { s.done(); }
});
test('temporary paths: TMPDIR with a trailing slash and with spaces works and leaves nothing; another prefix or a plain tmp.* directory is never touched', T, async () => {
  for (const name of ['tmp dir with spaces', 'tmpx']) {
    const s = sandbox({ tmpName: name }); try {
      const other = join(s.tmp, 'tmp.ABC123'), alike = join(s.tmp, 'mg-restore-runX'); for (const d of [other, alike]) mkdirSync(d, { mode: 0o700 });
      const r = await s.run(['123'], { TMPDIR: s.tmp + '/' }).done; assert.equal(r.code, 0, r.out + r.err); assert.equal(r.err, '');
      assert.ok(s.read('workdir').startsWith(s.tmp + '/mg-restore-run.'), s.read('workdir')); assert.deepEqual(readdirSync(s.tmp).sort(), ['mg-restore-runX', 'tmp.ABC123']);
    } finally { s.done(); }
  }
});
