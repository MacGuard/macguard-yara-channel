// The evidence branch machinery: hash chain (tamper evidence + checkpoints), reconciliation, seeding, and the real commit/retry scripts in branch mode against a local bare repository
// (two writers racing, a dual-write that survives one side failing, and a bot that cannot touch code). No network, no secrets.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { appendFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { GENESIS, chainOf, check, checkpointOf, extend, verifyAgainstCheckpoint } from '../tools/evidence_chain.mjs';
import { reconcile } from '../tools/evidence_reconcile.mjs';

const T = join(dirname(fileURLToPath(import.meta.url)), '..', 'tools');
const B = (n, extra = {}) => JSON.stringify({ schema: 'macguard.backup-evidence/1', kind: 'backup', resource: 'gateway', at: '2026-10-27T03:56:52Z', run_id: n, stamp: 'S' + n, ...extra });
const R = (n, p = 'b2', extra = {}) => JSON.stringify({ schema: 'macguard.backup-evidence/1', kind: 'restore', resource: 'gateway', at: '2026-10-27T06:52:15Z', run_id: n, provider: p, mode: 'drill', plaintext_sha256: 'ab'.repeat(32), duration_s: 12, by: 'ada', ...extra });
const LOG = [B(1), B(2, { resource: 'panel' }), R(1), R(1, 'r2'), B(3)];
const text = (ls) => ls.join('\n') + '\n';
const git = (cwd, ...a) => execFileSync('git', a, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
const tmp = () => { const d = mkdtempSync(join(tmpdir(), 'mg-evb-')); return { d, done: () => rmSync(d, { recursive: true, force: true }) }; };

// ---- the chain ----
test('chain: deterministic, one value per record, each depends on everything before it', () => {
  const c = chainOf(LOG); assert.equal(c.length, 5); assert.deepEqual(chainOf(LOG), c);
  assert.deepEqual(chainOf(LOG.slice(0, 3)), c.slice(0, 3), 'a prefix has the prefix of the chain (appending never changes earlier values)');
  assert.notEqual(chainOf([LOG[1], LOG[0], ...LOG.slice(2)])[4], c[4], 'reordering changes the head');
  assert.equal(check('', '').head, GENESIS);
});

test('chain: extend is idempotent and appends only the missing lines; an altered, removed or reordered record is detected', () => {
  const side = extend(text(LOG), ''); assert.equal(side.trim().split('\n').length, 5); assert.equal(extend(text(LOG), side), side, 'idempotent');
  const grown = extend(text([...LOG, B(4)]), side); assert.ok(grown.startsWith(side) && grown.trim().split('\n').length === 6, 'only one line appended');
  const edit = (ls) => check(text(ls), grown.split('\n').slice(0, 6).join('\n'));
  const altered = LOG.slice(); altered[1] = B(2, { resource: 'panel', head_sha256: 'f'.repeat(64) });
  const a = edit([...altered, B(4)]); assert.equal(a.ok, false); assert.match(a.problems[0], /chain line 2 does not match record 2/);
  const removed = edit([LOG[0], ...LOG.slice(2), B(4)]); assert.equal(removed.ok, false);
  const reordered = edit([LOG[1], LOG[0], ...LOG.slice(2), B(4)]); assert.equal(reordered.ok, false);
  const shorter = check(text(LOG.slice(0, 3)), side); assert.equal(shorter.ok, false); assert.match(shorter.problems[0], /records were removed/);
  assert.throws(() => extend(text(altered), side), /does not match the log/, 'it never repairs a divergence by overwriting it');
});

test('checkpoints: valid while the log only grows; they catch a rewrite or a truncation of anything they cover', () => {
  const cp = checkpointOf(text(LOG.slice(0, 3)), '2026-10-28T00:00:00Z'); assert.deepEqual([cp.count, cp.schema], [3, 'macguard.evidence-checkpoint/1']);
  assert.equal(verifyAgainstCheckpoint(text(LOG), cp).ok, true, 'the log grew after the checkpoint: still consistent');
  assert.equal(verifyAgainstCheckpoint(text(LOG.slice(0, 3)), cp).ok, true);
  assert.match(verifyAgainstCheckpoint(text(LOG.slice(0, 2)), cp).problem, /records were removed/);
  const rewritten = LOG.slice(); rewritten[2] = R(1, 'b2', { duration_s: 1 }); assert.match(verifyAgainstCheckpoint(text(rewritten), cp).problem, /altered/);
  const lateEdit = LOG.slice(); lateEdit[4] = B(3, { stamp: 'other' }); assert.equal(verifyAgainstCheckpoint(text(lateEdit), cp).ok, true, 'records AFTER the checkpoint are not vouched for (documented limit)');
  assert.equal(verifyAgainstCheckpoint('', checkpointOf('')).ok, true); assert.equal(verifyAgainstCheckpoint(text(LOG), { ...cp, head: 'x' }).ok, false);
});

// ---- reconciliation ----
test('reconcile: adds only what is missing, in order; a record already present (even from a repeated report) is not duplicated; conflicts are reported, never overwritten; idempotent', () => {
  const dst0 = text([B(1), R(1)]); const r = reconcile(text(LOG), dst0);
  assert.deepEqual(r.missing, [LOG[1], LOG[3], LOG[4]]); assert.deepEqual(r.conflicts, []);
  const merged = dst0 + r.missing.join('\n') + '\n'; assert.deepEqual(reconcile(text(LOG), merged).missing, [], 'second run adds nothing');
  assert.deepEqual(reconcile(text([...LOG, LOG[0], LOG[0]]), merged).missing, [], 'duplicates inside the source are not added');
  const different = reconcile(text([B(1, { stamp: 'DIFFERENT' })]), dst0); assert.deepEqual(different.missing, []); assert.deepEqual(different.conflicts, [{ kind: 'backup', run_id: 1, resource: 'gateway' }]);
  assert.deepEqual(reconcile(text(['not json', B(9)]), '').unreadable, ['not json']);
  assert.deepEqual(reconcile(text([B(1)]), text([B(1, { resource: 'gateway' })])).missing, [], 'same run and resource');
  assert.deepEqual(reconcile(text([B(1, { resource: 'panel' })]), text([B(1)])).missing.length, 1, 'same run id on another resource is another record');
});

// ---- seeding, and the real scripts in branch mode against a bare repository ----
function world() {
  const t = tmp(), origin = join(t.d, 'origin.git'), code = join(t.d, 'code');
  git(t.d, 'init', '-q', '--bare', '-b', 'main', origin);
  const seed = join(t.d, 'seedmain'); mkdirSync(join(seed, 'evidence'), { recursive: true }); mkdirSync(join(seed, 'gateway', 'tools'), { recursive: true });
  writeFileSync(join(seed, 'evidence', 'backups.jsonl'), text(LOG)); writeFileSync(join(seed, 'gateway', 'tools', 'x.js'), '// code\n'); cpSync(T, join(seed, 'gateway', 'tools'), { recursive: true });
  git(t.d, 'init', '-q', '-b', 'main', seed); git(seed, 'config', 'user.email', 'a@b'); git(seed, 'config', 'user.name', 'a'); git(seed, 'add', '.'); git(seed, 'commit', '-qm', 'main'); git(seed, 'remote', 'add', 'origin', origin); git(seed, 'push', '-q', 'origin', 'main');
  git(t.d, 'clone', '-q', origin, code);
  return { ...t, origin, code, seedMain: seed };
}
const seedBranch = (w, name = 'evidence') => {   // seed the branch exactly as the runbook says, then push it
  const dir = join(w.d, 'seed-' + name); execFileSync('sh', [join(T, 'evidence_seed.sh'), dir, join(w.seedMain, 'evidence', 'backups.jsonl')], { stdio: 'pipe' });
  git(dir, 'remote', 'add', 'origin', w.origin); git(dir, 'push', '-q', 'origin', `HEAD:refs/heads/${name}`); return dir;
};
const checkout = (w, name, branch = 'evidence') => { const d = join(w.d, name); git(w.d, 'clone', '-q', '--branch', branch, w.origin, d); return d; };

test('seed: the first commit copies the existing records verbatim, starts a valid chain, never touches the source, refuses a non-empty directory', () => {
  const w = world(); try {
    const src = join(w.seedMain, 'evidence', 'backups.jsonl'), before = readFileSync(src, 'utf8'), dir = join(w.d, 's');
    execFileSync('sh', [join(T, 'evidence_seed.sh'), dir, src], { stdio: 'pipe' });
    assert.equal(readFileSync(join(dir, 'evidence', 'backups.jsonl'), 'utf8'), before, 'byte for byte'); assert.equal(readFileSync(src, 'utf8'), before);
    assert.equal(check(before, readFileSync(join(dir, 'evidence', 'backups.chain'), 'utf8')).ok, true); assert.equal(git(dir, 'rev-list', '--count', 'HEAD').trim(), '1');
    assert.deepEqual(git(dir, 'ls-files').trim().split('\n').sort(), ['README.md', 'evidence/backups.chain', 'evidence/backups.jsonl']);
    assert.notEqual(spawnSync('sh', [join(T, 'evidence_seed.sh'), dir, src]).status, 0, 'second run into the same directory is refused');
  } finally { w.done(); }
});

const record = (w, evDir, argsLine, env = {}) => spawnSync('sh', [join(w.code, 'gateway/tools/evidence_retry.sh'), 'rec', '--', 'sh', '-c', argsLine], { cwd: w.code, env: { ...process.env, MG_EVIDENCE_DIR: evDir, MG_EVIDENCE_BRANCH: 'evidence', ...env }, encoding: 'utf8' });

test('branch mode (the real evidence_retry.sh + commit_evidence.sh): appends to the evidence branch, extends the chain in the same commit, and leaves main and the code checkout untouched', () => {
  const w = world(); try {
    seedBranch(w); const ev = checkout(w, 'ev1'), mainBefore = git(w.origin, 'rev-parse', 'main').trim();
    const r = record(w, ev, `echo '${B(10)}' >> "$MG_EVIDENCE_DIR/evidence/backups.jsonl"`); assert.equal(r.status, 0, r.stderr);
    const check2 = checkout(w, 'verify'); const log = readFileSync(join(check2, 'evidence/backups.jsonl'), 'utf8');
    assert.equal(log.trim().split('\n').length, 6); const cc = check(log, readFileSync(join(check2, 'evidence/backups.chain'), 'utf8')); assert.deepEqual([cc.ok, cc.missing], [true, 0], 'chain extended in the same commit');
    assert.equal(git(w.origin, 'rev-parse', 'main').trim(), mainBefore, 'main did not move'); assert.equal(git(w.code, 'status', '--porcelain').trim(), '', 'the code checkout is untouched');
    assert.equal(git(check2, 'show', '--stat', '--format=%an', 'HEAD').split('\n')[0], 'macguard-evidence[bot]'); assert.deepEqual(git(check2, 'show', '--name-only', '--format=', 'HEAD').trim().split('\n').sort(), ['evidence/backups.chain', 'evidence/backups.jsonl']);
  } finally { w.done(); }
});

test('branch mode: six writers racing for the same branch all land exactly once (regenerate on the newest tip), the chain stays valid, and nothing is lost', async () => {
  const w = world(); try {
    seedBranch(w); const dirs = [1, 2, 3, 4, 5, 6].map((i) => checkout(w, 'w' + i));
    const run = (ev, i) => new Promise((ok) => { const p = spawn('sh', [join(w.code, 'gateway/tools/evidence_retry.sh'), 'rec ' + i, '--', 'sh', '-c', `echo '${B(100 + i)}' >> "$MG_EVIDENCE_DIR/evidence/backups.jsonl"`], { cwd: w.code, env: { ...process.env, MG_EVIDENCE_DIR: ev, MG_EVIDENCE_BRANCH: 'evidence' }, stdio: 'pipe' }); p.on('close', ok); });
    const codes = await Promise.all(dirs.map(run)); assert.deepEqual(codes, [0, 0, 0, 0, 0, 0]);
    const c = checkout(w, 'final'), log = readFileSync(join(c, 'evidence/backups.jsonl'), 'utf8').trim().split('\n');
    assert.equal(log.length, 11); assert.equal(new Set(log).size, 11, 'no duplicate'); const cc = check(log.join('\n') + '\n', readFileSync(join(c, 'evidence/backups.chain'), 'utf8')); assert.deepEqual([cc.ok, cc.missing], [true, 0]);
    assert.equal(git(c, 'log', '--format=%an', '--skip=1').split('\n').filter(Boolean).every((a) => a === 'macguard-evidence[bot]'), true);
  } finally { w.done(); }
});

test('defaults are today\'s behaviour: without the two variables the scripts stage only evidence/backups.jsonl on the current branch and push it (no chain file, no branch)', () => {
  const w = world(); try {
    const r = spawnSync('sh', [join(w.code, 'gateway/tools/evidence_retry.sh'), 'rec', '--', 'sh', '-c', `echo '${B(50)}' >> evidence/backups.jsonl; echo x > evidence/stray.txt`], { cwd: w.code, env: { ...process.env, MG_EVIDENCE_DIR: '', MG_EVIDENCE_BRANCH: '' }, encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr); assert.equal(git(w.origin, 'show', '--name-only', '--format=', 'main').trim(), 'evidence/backups.jsonl', 'the stray file was not committed'); assert.ok(!existsSync(join(w.code, 'evidence/backups.chain')));
  } finally { w.done(); }
});

test('dual write: if the evidence branch is unreachable the main copy is still written (nothing is lost), and reconciliation later brings the branch up to date; a later record is not duplicated', () => {
  const w = world(); try {
    seedBranch(w); const ev = checkout(w, 'ev1'), line = B(77);
    git(ev, 'remote', 'set-url', 'origin', join(w.d, 'unreachable.git'));   // the branch side cannot reach its remote
    const bad = record(w, ev, `echo '${line}' >> "$MG_EVIDENCE_DIR/evidence/backups.jsonl"`);
    assert.notEqual(bad.status, 0, 'the failure is reported, not hidden');
    const m = spawnSync('sh', [join(w.code, 'gateway/tools/evidence_retry.sh'), 'rec', '--', 'sh', '-c', `echo '${line}' >> evidence/backups.jsonl`], { cwd: w.code, env: { ...process.env, MG_EVIDENCE_DIR: '', MG_EVIDENCE_BRANCH: '' }, encoding: 'utf8' });
    assert.equal(m.status, 0, m.stderr); git(w.code, 'pull', '-q');
    const ev2 = checkout(w, 'ev2'), rec = spawnSync('node', [join(T, 'evidence_reconcile.mjs'), '--from', join(w.code, 'evidence/backups.jsonl'), '--to', join(ev2, 'evidence/backups.jsonl'), '--apply'], { encoding: 'utf8' });
    assert.equal(JSON.parse(rec.stdout).missing, 1); const again = spawnSync('node', [join(T, 'evidence_reconcile.mjs'), '--from', join(w.code, 'evidence/backups.jsonl'), '--to', join(ev2, 'evidence/backups.jsonl')], { encoding: 'utf8' });
    assert.equal(again.status, 0); assert.equal(JSON.parse(again.stdout).missing, 0, 'idempotent');
  } finally { w.done(); }
});

test('the CLI verifies: OK on a good branch, FAIL (exit 1) after a record is edited, and FAIL against a checkpoint taken before a truncation', () => {
  const w = world(); try {
    const dir = seedBranch(w), ev = join(dir, 'evidence'), cpFile = join(w.d, 'cp.json');
    const cli = (...a) => spawnSync('node', [join(T, 'evidence_chain.mjs'), ...a, '--dir', ev], { encoding: 'utf8' });
    assert.equal(cli('verify').status, 0); writeFileSync(cpFile, cli('checkpoint').stdout); assert.equal(cli('verify', '--checkpoint', cpFile, '--allow-unsigned').status, 0);
    const good = readFileSync(join(ev, 'backups.jsonl'), 'utf8');
    writeFileSync(join(ev, 'backups.jsonl'), good.replace('"run_id":1,', '"run_id":9,')); const e = cli('verify'); assert.equal(e.status, 1); assert.match(e.stderr, /does not match record/);
    writeFileSync(join(ev, 'backups.jsonl'), good.split('\n').slice(0, 2).join('\n') + '\n'); writeFileSync(join(ev, 'backups.chain'), readFileSync(join(ev, 'backups.chain'), 'utf8').split('\n').slice(0, 2).join('\n') + '\n');
    const t = cli('verify', '--checkpoint', cpFile, '--allow-unsigned'); assert.equal(t.status, 1, 'consistent with itself, but not with what was signed'); assert.match(t.stderr, /records were removed/);
  } finally { w.done(); }
});

// ---- the workflows: nothing changes until a person sets EVIDENCE_MODE ----
import { readFileSync as rf } from 'node:fs';
const WF = (n) => rf(join(T, '..', '..', '.github', 'workflows', n), 'utf8');
test('backup.yml and record-restore.yml: today\'s commands are kept for the default mode, the branch is reached only through evidence_write.sh under EVIDENCE_MODE, and permissions did not grow', () => {
  const b = WF('backup.yml'), r = WF('record-restore.yml');
  assert.match(b, /if \[ -z "\$\{EVIDENCE_MODE:-\}" \] \|\| \[ "\$EVIDENCE_MODE" = main \]; then[^\n]*\n\s+node gateway\/tools\/backup_record\.mjs backup[^\n]*\n\s+sh gateway\/tools\/commit_evidence\.sh "\$RESOURCE backup run \$RUN_ID"\n\s+else/);
  assert.match(r, /if \[ -z "\$\{EVIDENCE_MODE:-\}" \] \|\| \[ "\$EVIDENCE_MODE" = main \]; then[^\n]*\n\s+sh gateway\/tools\/evidence_retry\.sh "restore of run[^\n]*\\\n\s+node gateway\/tools\/backup_record\.mjs restore[^\n]*\n\s+else/);
  for (const w of [b, r]) {
    assert.equal((w.match(/EVIDENCE_MODE: \$\{\{ vars\.EVIDENCE_MODE \}\}/g) || []).length, 1, 'the mode comes only from a repository variable');
    assert.match(w, /name: Evidence branch \(only while EVIDENCE_MODE is dual or branch\)\n\s+if: \$\{\{ vars\.EVIDENCE_MODE == 'dual' \|\| vars\.EVIDENCE_MODE == 'branch' \}\}\n\s+continue-on-error: \$\{\{ vars\.EVIDENCE_MODE == 'dual' \}\}/);
    assert.match(w, /ref: evidence\n\s+path: evidence-wt/);
  }
  assert.doesNotMatch(b.split('\n  record:')[1].split('\n  selftest:')[0], /id-token|actions: write|contents: write\n\s+contents: write/, 'the record job keeps contents: write + actions: read and gains nothing');
  assert.match(r, /permissions: \{\}/); assert.equal((r.match(/contents: write/g) || []).length, 1);
});

test('evidence-checkpoint.yml: manual only, read-only token plus OIDC for the signature, never writes to the repository, no secrets', () => {
  const w = WF('evidence-checkpoint.yml');
  assert.match(w, /\non:\n  workflow_dispatch:\n\npermissions: \{\}/); assert.doesNotMatch(w, /schedule:|\n  push:|pull_request/);
  assert.match(w, /permissions:\n      contents: read\n      id-token: write/); assert.doesNotMatch(w, /contents: write|git push|secrets\./);
  assert.equal((w.match(/persist-credentials: false/g) || []).length, 2, 'neither checkout leaves a credential behind');
  assert.match(w, /cosign verify-blob[^\n]*evidence-checkpoint\.yml@refs\/heads\/main/);
});
