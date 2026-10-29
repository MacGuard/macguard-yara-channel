// Adversarial tests of the evidence machinery: reconciliation (missing, identical duplicate, contradictory duplicate), concurrent writers, network failure between the two writes and recovery,
// chain truncation, checkpoint tampering and signature identity, attempts to rewrite history, refusal to create the branch, and rollback without data loss. Local bare repositories only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { chmodSync, cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { OIDC_ISSUER, check, checkpointOf, extend, verifyAgainstCheckpoint } from '../tools/evidence_chain.mjs';
import { reconcile } from '../tools/evidence_reconcile.mjs';
import { append } from '../tools/backup_record.mjs';

const T = join(dirname(fileURLToPath(import.meta.url)), '..', 'tools');
const B = (n, extra = {}) => JSON.stringify({ schema: 'macguard.backup-evidence/1', kind: 'backup', resource: 'gateway', at: '2026-10-27T03:56:52Z', run_id: n, stamp: 'S' + n, ...extra });
const R = (n, p = 'b2', extra = {}) => JSON.stringify({ schema: 'macguard.backup-evidence/1', kind: 'restore', resource: 'gateway', at: '2026-10-27T06:52:15Z', run_id: n, provider: p, mode: 'drill', plaintext_sha256: 'ab'.repeat(32), duration_s: 12, by: 'ada', restored_at: '2026-10-27T06:50:00Z', ...extra });
const LOG = [B(1), B(2, { resource: 'panel' }), R(1), R(1, 'r2'), B(3)];
const text = (ls) => ls.join('\n') + '\n';
const git = (cwd, ...a) => execFileSync('git', a, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
const sha = (b) => createHash('sha256').update(b).digest('hex');
const lines = (f) => readFileSync(f, 'utf8').split('\n').filter(Boolean);

// a recorder that, like the real one, stamps `at` at BUILD time (unique per build) and refuses a record that is already there
const REC = (root) => { const f = join(root, 'rec.mjs'); writeFileSync(f, `import { append } from ${JSON.stringify(new URL('../tools/backup_record.mjs', import.meta.url).href)};
const arg = (n, d) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : d; };
const rec = JSON.parse(arg('--json')); rec.at = new Date().toISOString() + '#' + process.hrtime.bigint();
console.log(JSON.stringify(append(arg('--file', 'evidence/backups.jsonl'), rec)));\n`); return f; };

function world() {
  const root = mkdtempSync(join(tmpdir(), 'mg-evadv-')), origin = join(root, 'origin.git');
  git(root, 'init', '-q', '--bare', '-b', 'main', origin);
  const seed = join(root, 'seedmain'); mkdirSync(join(seed, 'evidence'), { recursive: true }); mkdirSync(join(seed, 'gateway', 'tools'), { recursive: true });
  writeFileSync(join(seed, 'evidence', 'backups.jsonl'), text(LOG)); cpSync(T, join(seed, 'gateway', 'tools'), { recursive: true });
  git(root, 'init', '-q', '-b', 'main', seed); git(seed, 'config', 'user.email', 'a@b'); git(seed, 'config', 'user.name', 'a'); git(seed, 'add', '.'); git(seed, 'commit', '-qm', 'main'); git(seed, 'remote', 'add', 'origin', origin); git(seed, 'push', '-q', 'origin', 'main');
  const sd = join(root, 'seed-ev'); execFileSync('sh', [join(T, 'evidence_seed.sh'), sd, join(seed, 'evidence', 'backups.jsonl')], { stdio: 'pipe' }); git(sd, 'remote', 'add', 'origin', origin); git(sd, 'push', '-q', 'origin', 'HEAD:refs/heads/evidence');
  const w = { root, origin, rec: REC(root), done: () => rmSync(root, { recursive: true, force: true }) };
  w.clone = (name, branch) => { const d = join(root, name); git(root, 'clone', '-q', '--branch', branch, origin, d); return d; };
  w.code = w.clone('code', 'main'); w.ev = w.clone('ev', 'evidence'); return w;
}
const remoteLines = (w, branch, tag = 'chk') => { const d = join(w.root, tag + Math.random().toString(36).slice(2)); git(w.root, 'clone', '-q', '--branch', branch, w.origin, d); return { dir: d, lines: lines(join(d, 'evidence/backups.jsonl')) }; };
const ew = (w, mode, rec, { code = w.code, ev = w.ev, env = {} } = {}) => spawnSync('sh', [join(code, 'gateway/tools/evidence_write.sh'), mode, 'msg', '--', 'node', w.rec, '--json', JSON.stringify(rec)], { cwd: code, env: { ...process.env, EVIDENCE_WT: ev, EVIDENCE_BRANCH_NAME: 'evidence', ...env }, encoding: 'utf8' });
const status = (r) => (/EVIDENCE_STATUS=(\S+)/.exec(r.stdout) || [])[1];
const NEW = (n) => ({ schema: 'macguard.backup-evidence/1', kind: 'backup', resource: 'gateway', run_id: n, stamp: 'N' + n });
const recover = (w, from, to, fresh) => spawnSync('sh', [join(fresh, 'gateway/tools/evidence_retry.sh'), 'recover', '--', 'node', join(T, 'evidence_reconcile.mjs'), '--from', from, '--to', join(fresh, 'evidence/backups.jsonl'), '--apply'], { cwd: fresh, env: { ...process.env, MG_EVIDENCE_DIR: '', MG_EVIDENCE_BRANCH: '' }, encoding: 'utf8' });

// ---- reconciliation, as a unit ----
test('reconcile: missing record is added; identical duplicate is not; contradictory duplicates (backup AND restore) are conflicts; nothing is chosen for you', () => {
  assert.deepEqual(reconcile(text(LOG), text(LOG.slice(0, 4))).missing, [LOG[4]], 'missing');
  assert.deepEqual(reconcile(text([...LOG, LOG[2]]), text(LOG)), { missing: [], conflicts: [], unreadable: [] }, 'identical duplicate');
  const cb = reconcile(text([B(1, { stamp: 'OTHER' })]), text(LOG)); assert.deepEqual([cb.missing.length, cb.conflicts], [0, [{ kind: 'backup', run_id: 1, resource: 'gateway' }]]);
  const cr = reconcile(text([R(1, 'b2', { duration_s: 999 })]), text(LOG)); assert.deepEqual([cr.missing.length, cr.conflicts], [0, [{ kind: 'restore', run_id: 1, resource: 'gateway', provider: 'b2' }]], 'same restoration, other content');
});

test('reconcile CLI: --apply never touches existing lines; on a conflict it writes NOTHING (not even the merely missing records) and exits 4; it is idempotent', () => {
  const w = world(); try {
    const src = join(w.root, 'src.jsonl'), dst = join(w.root, 'dst.jsonl');
    writeFileSync(dst, text(LOG.slice(0, 3))); writeFileSync(src, text(LOG)); const before = readFileSync(dst, 'utf8');
    const cli = (...a) => spawnSync('node', [join(T, 'evidence_reconcile.mjs'), '--from', src, '--to', dst, ...a], { encoding: 'utf8' });
    assert.equal(cli().status, 1, 'report mode: records are missing'); assert.equal(readFileSync(dst, 'utf8'), before, 'report mode writes nothing');
    assert.equal(cli('--apply').status, 0); assert.ok(readFileSync(dst, 'utf8').startsWith(before), 'history is a strict prefix: existing lines untouched'); assert.deepEqual(lines(dst), LOG);
    assert.equal(cli('--apply').status, 0); assert.deepEqual(lines(dst), LOG, 'idempotent');
    writeFileSync(src, text([...LOG, B(50), B(1, { stamp: 'CONTRADICTION' })])); const snap = readFileSync(dst, 'utf8'); const c = cli('--apply');
    assert.equal(c.status, 4); assert.match(c.stderr, /CONFLICT/); assert.equal(readFileSync(dst, 'utf8'), snap, 'B(50) was not added either: a contradiction resolves nothing');
  } finally { w.done(); }
});

// ---- network failure between the two writes, with recovery ----
test('dual write: CONFIRMED when both copies have the record, built ONCE (same bytes), and a re-run adds nothing anywhere', () => {
  const w = world(); try {
    const r = ew(w, 'dual', NEW(100)); assert.equal(r.status, 0, r.stderr + r.stdout); assert.equal(status(r), 'CONFIRMED');
    const br = remoteLines(w, 'evidence').lines, mn = remoteLines(w, 'main').lines; assert.equal(br.length, 6); assert.deepEqual(br, mn, 'identical bytes on both sides (so reconcile will never see a false conflict)');
    const heads = [git(w.origin, 'rev-parse', 'main'), git(w.origin, 'rev-parse', 'evidence')];
    const again = ew(w, 'dual', NEW(100), { code: w.clone('code2', 'main'), ev: w.clone('ev2', 'evidence') }); assert.equal(again.status, 0); assert.equal(status(again), 'CONFIRMED');
    assert.deepEqual([git(w.origin, 'rev-parse', 'main'), git(w.origin, 'rev-parse', 'evidence')], heads, 're-run: no new commit on either branch');
  } finally { w.done(); }
});

test('network failure AFTER the branch write: PENDING_SYNC (exit 3, loud), the record is on the branch only; recovery from a fresh checkout adds it to main exactly once', () => {
  const w = world(); try {
    git(w.code, 'remote', 'set-url', 'origin', join(w.root, 'down.git'));   // main's remote is unreachable
    const r = ew(w, 'dual', NEW(101)); assert.equal(r.status, 3); assert.equal(status(r), 'PENDING_SYNC'); assert.match(r.stdout, /::error::sync pending: the record is on the evidence branch only/);
    assert.equal(remoteLines(w, 'evidence').lines.length, 6); assert.equal(remoteLines(w, 'main').lines.length, 5, 'main does not have it yet');
    const fresh = w.clone('fresh', 'main'), rc = recover(w, join(remoteLines(w, 'evidence').dir, 'evidence/backups.jsonl'), '', fresh); assert.equal(rc.status, 0, rc.stderr);
    const mn = remoteLines(w, 'main').lines, br = remoteLines(w, 'evidence').lines; assert.deepEqual(mn, br); assert.equal(new Set(mn).size, 6, 'exactly once');
    assert.equal(recover(w, join(remoteLines(w, 'evidence').dir, 'evidence/backups.jsonl'), '', w.clone('fresh2', 'main')).status, 0); assert.equal(remoteLines(w, 'main').lines.length, 6, 'recovery is idempotent');
  } finally { w.done(); }
});

test('network failure BEFORE the branch write: the record is still written to main (never lost), PENDING_SYNC says the branch is behind, and reconciliation brings it up to date', () => {
  const w = world(); try {
    git(w.ev, 'remote', 'set-url', 'origin', join(w.root, 'down.git'));
    const r = ew(w, 'dual', NEW(102)); assert.equal(r.status, 3); assert.equal(status(r), 'PENDING_SYNC'); assert.match(r.stdout, /on main only/);
    assert.equal(remoteLines(w, 'main').lines.length, 6); assert.equal(remoteLines(w, 'evidence').lines.length, 5);
    const ev2 = w.clone('ev-fresh', 'evidence'), rc = spawnSync('sh', [join(w.code, 'gateway/tools/evidence_retry.sh'), 'recover', '--', 'node', join(T, 'evidence_reconcile.mjs'), '--from', join(remoteLines(w, 'main').dir, 'evidence/backups.jsonl'), '--to', join(ev2, 'evidence/backups.jsonl'), '--apply'], { cwd: w.code, env: { ...process.env, MG_EVIDENCE_DIR: ev2, MG_EVIDENCE_BRANCH: 'evidence' }, encoding: 'utf8' });
    assert.equal(rc.status, 0, rc.stderr); const c = remoteLines(w, 'evidence'); assert.deepEqual(c.lines, remoteLines(w, 'main').lines); const k = check(readFileSync(join(c.dir, 'evidence/backups.jsonl'), 'utf8'), readFileSync(join(c.dir, 'evidence/backups.chain'), 'utf8')); assert.deepEqual([k.ok, k.missing], [true, 0]);
  } finally { w.done(); }
});

test('both sides down: ERROR (exit 1) and nothing is claimed as written', () => {
  const w = world(); try {
    git(w.ev, 'remote', 'set-url', 'origin', join(w.root, 'down.git')); git(w.code, 'remote', 'set-url', 'origin', join(w.root, 'down.git'));
    const r = ew(w, 'dual', NEW(103)); assert.equal(r.status, 1); assert.equal(status(r), 'ERROR'); assert.match(r.stdout, /NOT written anywhere/);
    assert.equal(remoteLines(w, 'main').lines.length, 5); assert.equal(remoteLines(w, 'evidence').lines.length, 5);
  } finally { w.done(); }
});

test('contradictory copies: ERROR, nothing is resolved by picking a side, main is left exactly as it was', () => {
  const w = world(); try {
    const alt = join(w.code, 'evidence/backups.jsonl'); writeFileSync(alt, readFileSync(alt, 'utf8').replace('"stamp":"S1"', '"stamp":"TAMPERED"')); git(w.code, 'config', 'user.email', 'a@b'); git(w.code, 'config', 'user.name', 'a'); git(w.code, 'commit', '-qam', 'main diverges'); git(w.code, 'push', '-q', 'origin', 'main');
    const mainBefore = git(w.origin, 'rev-parse', 'main');
    const r = ew(w, 'dual', NEW(104)); assert.equal(r.status, 1); assert.equal(status(r), 'ERROR'); assert.match(r.stdout, /contradict each other/);
    assert.equal(git(w.origin, 'rev-parse', 'main'), mainBefore, 'main untouched'); assert.ok(remoteLines(w, 'main').lines.some((l) => l.includes('TAMPERED'))); assert.equal(remoteLines(w, 'evidence').lines.length, 6, 'the branch kept its own, confirmed, record');
  } finally { w.done(); }
});

// ---- concurrency ----
test('three dual writers at once (separate runners): every record lands exactly once on BOTH sides, the two copies are identical and the chain is valid', async () => {
  const w = world(); try {
    const runs = [1, 2, 3].map((i) => ({ code: w.clone('c' + i, 'main'), ev: w.clone('e' + i, 'evidence'), i }));
    const codes = await Promise.all(runs.map(({ code, ev, i }) => new Promise((ok) => { const p = spawn('sh', [join(code, 'gateway/tools/evidence_write.sh'), 'dual', 'msg', '--', 'node', w.rec, '--json', JSON.stringify(NEW(200 + i))], { cwd: code, env: { ...process.env, EVIDENCE_WT: ev, EVIDENCE_BRANCH_NAME: 'evidence' }, stdio: 'pipe' }); p.on('close', ok); })));
    assert.deepEqual(codes, [0, 0, 0]);
    const mn = remoteLines(w, 'main'), br = remoteLines(w, 'evidence'); assert.equal(mn.lines.length, 8); assert.equal(new Set(mn.lines).size, 8); assert.equal(new Set(br.lines).size, 8);
    assert.deepEqual(mn.lines.map((l) => JSON.parse(l).run_id).sort(), br.lines.map((l) => JSON.parse(l).run_id).sort(), 'same set of records on both sides');
    const k = check(text(br.lines), readFileSync(join(br.dir, 'evidence/backups.chain'), 'utf8')); assert.deepEqual([k.ok, k.missing], [true, 0]);
  } finally { w.done(); }
});

// ---- rewriting history, creating the branch ----
test('an attempt to rewrite a historical record is refused before anything is pushed, and the recorder never overwrites an existing record', () => {
  const w = world(); try {
    const f = join(w.ev, 'evidence/backups.jsonl'), tip = git(w.origin, 'rev-parse', 'evidence');
    writeFileSync(f, readFileSync(f, 'utf8').replace('"stamp":"S1"', '"stamp":"REWRITTEN"'));
    const r = spawnSync('sh', [join(w.code, 'gateway/tools/evidence_retry.sh'), 'x', '--', 'node', w.rec, '--json', JSON.stringify(NEW(300)), '--file', f], { cwd: w.code, env: { ...process.env, MG_EVIDENCE_DIR: w.ev, MG_EVIDENCE_BRANCH: 'evidence' }, encoding: 'utf8' });
    assert.equal(r.status, 2); assert.match(r.stderr, /chain does not match the log/); assert.match(r.stderr, /not retrying/); assert.doesNotMatch(r.stderr, /push rejected/, 'a refusal is not reported as a push conflict'); assert.equal(git(w.origin, 'rev-parse', 'evidence'), tip, 'nothing reached the remote');
    const g = join(w.root, 'g.jsonl'); writeFileSync(g, text(LOG)); const res = append(g, JSON.parse(B(1, { stamp: 'OVERWRITE' }))); assert.equal(res.added, false); assert.deepEqual(lines(g), LOG, 'the existing record is kept as it was');
  } finally { w.done(); }
});

test('the evidence branch is never created by a producer: a missing branch is refused with nothing committed or pushed', () => {
  const w = world(); try {
    const r = spawnSync('sh', [join(w.code, 'gateway/tools/evidence_retry.sh'), 'x', '--', 'node', w.rec, '--json', JSON.stringify(NEW(400)), '--file', join(w.ev, 'evidence/backups.jsonl')], { cwd: w.code, env: { ...process.env, MG_EVIDENCE_DIR: w.ev, MG_EVIDENCE_BRANCH: 'evidence-typo' }, encoding: 'utf8' });
    assert.equal(r.status, 2); assert.match(r.stderr, /creating it is a manual, authorised step/); assert.equal(git(w.origin, 'branch', '--list').includes('evidence-typo'), false);
    assert.equal(git(w.ev, 'log', '--oneline', 'origin/evidence..HEAD').trim(), '', 'no local commit was made either');
  } finally { w.done(); }
});

// ---- chain truncation ----
test('truncation: the log AND the chain cut together are consistent with themselves (NOT detected without a checkpoint: a stated limit); with a checkpoint it is; cutting only one of them is detected', () => {
  const full = text(LOG), cp = checkpointOf(full), side = check(full, '').head;   // side: head of the full chain
  const cut = text(LOG.slice(0, 3));
  assert.equal(check(cut, '').ok, true, 'a self-consistent shorter log looks fine on its own');
  assert.match(verifyAgainstCheckpoint(cut, cp).problem, /records were removed/, 'but not against what was signed');
  const chainFull = ((l) => l)(check(full, '').head); assert.ok(chainFull === side);
  const sidecar = full.split('\n').filter(Boolean).map((_, i) => `${i + 1} ${'0'.repeat(64)}`).join('\n') + '\n';
  assert.equal(check(full, sidecar).ok, false, 'a sidecar with forged values is detected'); assert.match(check(cut, text(['1 ' + '0'.repeat(64), '2 ' + '0'.repeat(64), '3 ' + '0'.repeat(64), '4 ' + '0'.repeat(64)])).problems.join(), /records were removed|does not match/);
});

// ---- checkpoint tampering and signature identity (cosign replaced by a stub that binds signature = hash of the bytes + identity) ----
function cosignStub() {   // stands in for cosign's CRYPTOGRAPHIC verdict only (the real one is exercised in the Actions lab); it is as strict as it can be without keys: file digest, identity and issuer must all match
  const dir = mkdtempSync(join(tmpdir(), 'mg-cosign-')), log = join(dir, 'argv.log');
  writeFileSync(join(dir, 'cosign'), `#!${process.execPath}
const fs = require('node:fs'), crypto = require('node:crypto'), a = process.argv.slice(2);
fs.appendFileSync(${JSON.stringify(log)}, a.join(' ') + '\\n');
if (a[0] !== 'verify-blob') process.exit(2);
const opt = (n) => a[a.indexOf(n) + 1], b = JSON.parse(fs.readFileSync(opt('--bundle'), 'utf8'));
const digest = Buffer.from(b.messageSignature.messageDigest.digest, 'base64').toString('hex');
process.exit(opt('--certificate-oidc-issuer') === ${JSON.stringify(OIDC_ISSUER)} && opt('--certificate-identity') === process.env.STUB_ID && crypto.createHash('sha256').update(fs.readFileSync(a[a.length - 1])).digest('hex') === digest ? 0 : 1);
`); chmodSync(join(dir, 'cosign'), 0o755); return { dir, log };
}
test('checkpoint (real Sigstore bundle as fixture, cosign verdict simulated): identity, issuer and bytes must match; an altered file, a foreign identity, a foreign issuer, a missing bundle, a missing cosign, and a correctly signed checkpoint that does not match the log are all refused', () => {
  const c = cosignStub(), tdir = mkdtempSync(join(tmpdir(), 'mg-cp-')), FX = join(T, '..', 'test', 'fixtures', 'evidence-checkpoint-lab');
  const ID = 'https://github.com/MacGuard/macguard-yara-channel/.github/workflows/sigstore-lab.yml@refs/heads/exp/sigstore-lab', cpf = join(FX, 'checkpoint.json'), bundle = join(FX, 'a.sigstore.json'), ev = join(FX, 'log');
  const verify = (extra, { pathDirs = [c.dir], dir = ev } = {}) => spawnSync(process.execPath, [join(T, 'evidence_chain.mjs'), 'verify', '--dir', dir, ...extra], { encoding: 'utf8', env: { ...process.env, STUB_ID: ID, PATH: pathDirs.concat(['/usr/bin', '/bin']).join(delimiter) } });
  try {
    const ok = verify(['--checkpoint', cpf, '--bundle', bundle, '--identity', ID]); assert.equal(ok.status, 0, ok.stderr);
    assert.match(readFileSync(c.log, 'utf8'), new RegExp(`--certificate-identity ${ID.replace(/[/.@]/g, '\\$&')} --certificate-oidc-issuer ${OIDC_ISSUER.replace(/[/.]/g, '\\$&')}`), 'cosign got the pinned identity and issuer');
    const altered = join(tdir, 'cp.json'); writeFileSync(altered, readFileSync(cpf, 'utf8').replace('"count":3', '"count":2')); const a1 = verify(['--checkpoint', altered, '--bundle', bundle, '--identity', ID]); assert.equal(a1.status, 1); assert.match(a1.stderr, /signature does not verify/);
    const foreign = verify(['--checkpoint', cpf, '--bundle', bundle]); assert.equal(foreign.status, 1, 'default identity is the production workflow, which did not sign this'); assert.match(foreign.stderr, /authorised identity/);
    const iss = verify(['--checkpoint', cpf, '--bundle', bundle, '--identity', ID, '--issuer', 'https://accounts.google.com']); assert.equal(iss.status, 1);
    const unsigned = verify(['--checkpoint', cpf, '--identity', ID]); assert.equal(unsigned.status, 1); assert.match(unsigned.stderr, /unsigned checkpoint is not accepted/);
    assert.equal(verify(['--checkpoint', cpf, '--bundle', bundle, '--identity', ID], { pathDirs: [] }).status, 1, 'no cosign on PATH: fail closed');
    assert.equal(verify(['--checkpoint', cpf, '--allow-unsigned'], { pathDirs: [] }).status, 0, 'an unsigned check is possible only by asking for it explicitly');
    const other = join(tdir, 'log'); mkdirSync(other); writeFileSync(join(other, 'backups.jsonl'), text(LOG)); writeFileSync(join(other, 'backups.chain'), extend(text(LOG), ''));
    const mism = verify(['--checkpoint', cpf, '--bundle', bundle, '--identity', ID], { dir: other }); assert.equal(mism.status, 1, 'even a correctly signed checkpoint must match THIS log'); assert.match(mism.stderr, /altered|removed/);
    const notlog = join(tdir, 'notlog.json'); const j = JSON.parse(readFileSync(bundle, 'utf8')); j.verificationMaterial.tlogEntries = []; writeFileSync(notlog, JSON.stringify(j));
    const nt = verify(['--checkpoint', cpf, '--bundle', notlog, '--identity', ID]); assert.equal(nt.status, 1, 'cosign said yes, the bundle itself carries no transparency evidence: refused anyway'); assert.match(nt.stderr, /transparency log entry/);
  } finally { rmSync(c.dir, { recursive: true, force: true }); rmSync(tdir, { recursive: true, force: true }); }
});

// ---- rollback ----
test('rollback: leaving the transition keeps every record and every reference; from branch-only mode the branch is reconciled into main first, nothing is deleted or rewritten', () => {
  const w = world(); try {
    assert.equal(ew(w, 'dual', NEW(500)).status, 0);
    const ev2 = w.clone('ev-b1', 'evidence'), code2 = w.clone('code-b1', 'main');
    for (const n of [501, 502]) assert.equal(ew(w, 'branch', NEW(n), { code: code2, ev: (git(ev2, 'pull', '-q'), ev2) }).status, 0);   // branch-only period
    const mainOnlyBefore = remoteLines(w, 'main').lines, branch = remoteLines(w, 'evidence'); assert.equal(mainOnlyBefore.length, 6); assert.equal(branch.lines.length, 8);
    const fresh = w.clone('rollback', 'main'), rc = recover(w, join(branch.dir, 'evidence/backups.jsonl'), '', fresh); assert.equal(rc.status, 0, rc.stderr);
    const after = remoteLines(w, 'main').lines; assert.deepEqual(after.slice(0, 6), mainOnlyBefore, 'main\'s history is an untouched prefix'); assert.deepEqual(after, branch.lines, 'and now holds everything the branch holds');
    assert.deepEqual(after.slice(0, 5), LOG, 'the original records are byte for byte what they were'); assert.equal(remoteLines(w, 'evidence').lines.length, 8, 'the branch keeps its data');
  } finally { w.done(); }
});
