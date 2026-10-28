// A restoration is recorded ONCE however many times it is reported, even when the workflow runs at a different time; a genuinely new restoration is a new event; the existing history is never touched.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { append, buildRestoreRecord, readRecords, sameRestore } from '../tools/backup_record.mjs';

const PT = 'ab'.repeat(32), BACKUP = { schema: 'macguard.backup-evidence/1', kind: 'backup', resource: 'intel', at: '2026-10-27T07:50:00Z', run_id: 777, stamp: '20261027T074636Z', sequence: 1, plaintext_sha256: PT, providers: { b2: { write: 'success', read: 'success' }, scaleway: { write: 'success', read: 'success' }, r2: { write: 'success', read: 'success' } } };
const sb = () => { const root = mkdtempSync(join(tmpdir(), 'mg-idem-')), file = join(root, 'evidence', 'backups.jsonl'); mkdirSync(join(root, 'evidence')); writeFileSync(file, JSON.stringify(BACKUP) + '\n'); return { root, file, done: () => rmSync(root, { recursive: true, force: true }) }; };
const rec = (file, over = {}) => buildRestoreRecord({ file, runId: 777, provider: 'b2', plaintextSha256: PT, durationS: 230, mode: 'drill', by: 'MacGuard', at: '2026-10-27T08:06:57Z', ...over });

test('the same restoration reported twice is ONE record even when the workflow runs at a different time (with and without restored_at)', () => {
  const s = sb(); try {
    for (const restoredAt of [undefined, '2026-10-27T08:00:00Z']) {
      const file = s.file + (restoredAt ? '.with' : '.without'); writeFileSync(file, JSON.stringify(BACKUP) + '\n');
      const first = rec(file, { restoredAt, at: '2026-10-27T08:06:57Z' }), again = rec(file, { restoredAt, at: '2026-10-27T19:44:02Z' });   // a different execution time
      assert.notEqual(first.at, again.at);
      assert.equal(append(file, first).added, true); const r = append(file, again);
      assert.deepEqual([r.added, r.reason], [false, 'this restoration is already recorded']); assert.equal(readRecords(file).filter((x) => x.kind === 'restore').length, 1);
    }
  } finally { s.done(); }
});

test('a genuinely new restoration of the same copy is a NEW event: a different restored_at is kept, and the earlier lines are byte-identical afterwards', () => {
  const s = sb(); try {
    append(s.file, rec(s.file, { restoredAt: '2026-10-27T08:00:00Z' })); const before = readFileSync(s.file, 'utf8');
    assert.equal(append(s.file, rec(s.file, { restoredAt: '2026-10-28T08:00:00Z', at: '2026-10-28T08:05:00Z' })).added, true, 'the next day\'s drill is legitimate history');
    const after = readFileSync(s.file, 'utf8'); assert.ok(after.startsWith(before), 'append-only: nothing before was modified'); assert.equal(readRecords(s.file).filter((x) => x.kind === 'restore').length, 2);
  } finally { s.done(); }
});

test('anything that makes it a different restoration is never merged: provider, mode, run or hash', () => {
  const s = sb(); try {
    const base = rec(s.file, { restoredAt: '2026-10-27T08:00:00Z' }); append(s.file, base);
    for (const over of [{ provider: 'scaleway' }, { mode: 'real' }]) assert.equal(append(s.file, rec(s.file, { restoredAt: '2026-10-27T08:00:00Z', ...over })).added, true, JSON.stringify(over));
    assert.equal(sameRestore(base, { ...base, run_id: 778 }), false); assert.equal(sameRestore(base, { ...base, plaintext_sha256: 'cd'.repeat(32) }), false); assert.equal(sameRestore(base, { ...base, kind: 'backup' }), false);
  } finally { s.done(); }
});

test('legacy reports (no restored_at) are matched by content, and a legacy line still matches a new report of the same content; different duration or reporter is a different event', () => {
  const s = sb(); try {
    const legacy = rec(s.file); append(s.file, legacy);
    assert.equal(append(s.file, rec(s.file, { at: '2026-10-28T01:00:00Z' })).added, false, 'identical report content');
    assert.equal(append(s.file, rec(s.file, { restoredAt: '2026-10-27T08:00:00Z' })).added, false, 'new-style report of the same content as a legacy line');
    assert.equal(append(s.file, rec(s.file, { durationS: 231 })).added, true, 'different duration'); assert.equal(append(s.file, rec(s.file, { by: 'someone-else' })).added, true, 'different reporter');
  } finally { s.done(); }
});

test('restored_at is validated: malformed, in the future, or before the backup it claims to restore are refused', () => {
  const s = sb(); try {
    for (const bad of ['yesterday', '2026-10-27 08:00:00', '2026-10-27T08:00:00+01:00', '2026-13-45T99:99:99Z']) assert.throws(() => rec(s.file, { restoredAt: bad }), /restored-at must be an ISO-8601 UTC time/, bad);
    assert.throws(() => rec(s.file, { restoredAt: '2026-10-27T09:00:00Z', at: '2026-10-27T08:00:00Z' }), /in the future/);
    assert.throws(() => rec(s.file, { restoredAt: '2026-10-27T07:00:00Z' }), /before the backup it claims to restore/);
    assert.equal(rec(s.file, { restoredAt: '2026-10-27T08:04:00Z', at: '2026-10-27T08:00:00Z' }).restored_at, '2026-10-27T08:04:00Z', 'a small clock skew (< 5 min) is tolerated');
  } finally { s.done(); }
});

// ---- end to end: the real CLI, a real git origin, two writers racing to report the SAME restoration ----
const git = (cwd, ...a) => execFileSync('git', a, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
function world(n) {
  const root = mkdtempSync(join(tmpdir(), 'mg-idem-git-')), origin = join(root, 'origin.git'); git(root, 'init', '-q', '--bare', '-b', 'main', origin);
  const seed = join(root, 'seed'); git(root, 'clone', '-q', origin, seed); git(seed, 'config', 'user.email', 'a@b'); git(seed, 'config', 'user.name', 'a');
  mkdirSync(join(seed, 'evidence')); writeFileSync(join(seed, 'evidence/backups.jsonl'), JSON.stringify(BACKUP) + '\n'); mkdirSync(join(seed, 'gateway/tools'), { recursive: true });
  for (const f of ['backup_record.mjs', 'commit_evidence.sh', 'evidence_retry.sh']) copyFileSync(new URL(`../tools/${f}`, import.meta.url), join(seed, 'gateway/tools', f));
  git(seed, 'add', '-A'); git(seed, 'commit', '-q', '-m', 'seed'); git(seed, 'push', '-q', 'origin', 'main');
  return { root, origin, clones: Array.from({ length: n }, (_, i) => { const c = join(root, 'c' + i); git(root, 'clone', '-q', origin, c); return c; }), done: () => rmSync(root, { recursive: true, force: true }) };
}
const report = (cwd, delayMs, restoredAt) => new Promise((ok) => setTimeout(() => {
  const p = spawn('sh', [join(cwd, 'gateway/tools/evidence_retry.sh'), 'restore recorded', '--', 'node', 'gateway/tools/backup_record.mjs', 'restore', '--run-id', '777', '--provider', 'b2', '--plaintext-sha256', PT, '--duration-s', '230', '--mode', 'drill', '--by', 'MacGuard', ...(restoredAt ? ['--restored-at', restoredAt] : [])], { cwd, stdio: 'pipe' });
  let e = ''; p.stderr.on('data', (d) => (e += d)); p.on('close', (code) => ok({ code, e }));
}, delayMs));

test('end to end: the same restoration reported by two racing dispatches (different execution seconds) leaves exactly ONE restore record in the shared log, and the history before it is untouched', async () => {
  const w = world(2); try {
    const out = await Promise.all([report(w.clones[0], 0, '2026-10-27T08:00:00Z'), report(w.clones[1], 1300, '2026-10-27T08:00:00Z')]);
    assert.deepEqual(out.map((r) => r.code), [0, 0], JSON.stringify(out.map((r) => r.e)));
    const check = join(w.root, 'check'); git(w.root, 'clone', '-q', w.origin, check); const lines = readFileSync(join(check, 'evidence/backups.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    assert.equal(lines.length, 2, 'the backup record plus ONE restore'); assert.deepEqual(lines[0], BACKUP); assert.equal(lines[1].kind, 'restore'); assert.equal(lines[1].restored_at, '2026-10-27T08:00:00Z');
  } finally { w.done(); }
});

test('end to end: two DIFFERENT restorations racing are both kept (no lost evidence, no false merge)', async () => {
  const w = world(2); try {
    const out = await Promise.all([report(w.clones[0], 0, '2026-10-27T08:00:00Z'), report(w.clones[1], 1300, '2026-10-27T09:30:00Z')]);
    assert.deepEqual(out.map((r) => r.code), [0, 0], JSON.stringify(out.map((r) => r.e)));
    const check = join(w.root, 'check'); git(w.root, 'clone', '-q', w.origin, check); const restores = readFileSync(join(check, 'evidence/backups.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l)).filter((r) => r.kind === 'restore');
    assert.deepEqual(restores.map((r) => r.restored_at).sort(), ['2026-10-27T08:00:00Z', '2026-10-27T09:30:00Z']);
  } finally { w.done(); }
});
