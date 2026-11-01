// Issue #82: a restore report that the evidence cannot tell apart from an existing line is REFUSED explicitly (RESTORE_AMBIGUOUS, CLI exit 3), never
// dropped silently and never recorded twice. Works on temp copies of the real evidence log; the real file is only read and its hash is checked.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { append, buildRestoreRecord, classifyRestore, readRecords } from '../tools/backup_record.mjs';

const REAL = new URL('../../evidence/backups.jsonl', import.meta.url), TOOL = new URL('../tools/backup_record.mjs', import.meta.url).pathname;
const sha = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');
const sandbox = () => { const root = mkdtempSync(join(tmpdir(), 'mg-amb-')), file = join(root, 'backups.jsonl'); copyFileSync(REAL, file); return { file, done: () => rmSync(root, { recursive: true, force: true }) }; };
const legacyOf = (file) => readRecords(file).find((r) => r.kind === 'restore' && !r.restored_at);
const report = (file, l, over = {}) => buildRestoreRecord({ file, runId: l.run_id, provider: l.provider, plaintextSha256: l.plaintext_sha256, durationS: l.duration_s, mode: l.mode, by: l.by, at: '2026-11-02T09:05:00Z', ...over });
const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');

test('#82: a new drill WITHOUT restored_at that matches a legacy line is refused with RESTORE_AMBIGUOUS and nothing is written (it used to be dropped silently)', () => {
  const realBefore = sha(REAL), s = sandbox(); try {
    const l = legacyOf(s.file), before = readFileSync(s.file, 'utf8');
    assert.throws(() => append(s.file, report(s.file, l)), (e) => e.code === 'RESTORE_AMBIGUOUS' && /--restored-at/.test(e.message));
    assert.equal(readFileSync(s.file, 'utf8'), before, 'byte-identical: no silent drop, no duplicate');
    assert.equal(append(s.file, report(s.file, l, { restoredAt: '2026-11-02T09:00:00Z' })).added, true, 'the same drill reported WITH restored_at is recorded');
  } finally { s.done(); }
  assert.equal(sha(REAL), realBefore, 'evidence/backups.jsonl untouched');
});

test('#82: a report without restored_at matching a line that HAS restored_at is refused too (the old guard was always true there)', () => {
  const s = sandbox(); try {
    const l = legacyOf(s.file); append(s.file, report(s.file, l, { restoredAt: '2026-11-02T09:00:00Z' }));
    assert.throws(() => append(s.file, report(s.file, l, { at: '2026-11-02T10:00:00Z' })), (e) => e.code === 'RESTORE_AMBIGUOUS');
  } finally { s.done(); }
});

test('#82: what stays unambiguous keeps its behaviour — exact replay is idempotent, different numbers are new events, restored_at decides', () => {
  const s = sandbox(); try {
    const l = legacyOf(s.file), first = report(s.file, l, { durationS: l.duration_s + 7 });
    assert.equal(append(s.file, first).added, true, 'different duration: a different restoration');
    assert.deepEqual(append(s.file, first), { added: false, reason: 'this restoration is already recorded' }, 'the very same report (same at) replayed: idempotent, no error');
    assert.equal(append(s.file, report(s.file, l, { by: 'someone-else' })).added, true, 'different reporter: a different restoration');
    const late = report(s.file, l, { restoredAt: iso(Date.parse(l.at) - 60000) });
    assert.equal(append(s.file, late).added, false, 'a late re-report of the legacy restoration (restored before it was reported) is the same restoration');
  } finally { s.done(); }
});

test('#82: the clock-skew window and a legacy line without a parseable `at` are ambiguous, outside the window is a new restoration', () => {
  const l = { kind: 'restore', run_id: 1, provider: 'b2', mode: 'drill', plaintext_sha256: 'ab'.repeat(32), duration_s: 5, by: 'MacGuard', at: '2026-10-27T06:52:15Z' };
  const at = Date.parse(l.at), with_ = (ms) => ({ ...l, at: '2026-11-02T00:00:00Z', restored_at: iso(ms) });
  assert.equal(classifyRestore(l, with_(at)), 'same', 'restored exactly when reported');
  assert.equal(classifyRestore(l, with_(at + 2 * 60000)), 'ambiguous', 'inside the 5 min skew buildRestoreRecord tolerates');
  assert.equal(classifyRestore(l, with_(at + 6 * 60000)), 'different');
  assert.equal(classifyRestore({ ...l, at: undefined }, with_(at + 86400000)), 'ambiguous', 'legacy line without at: cannot be ordered');
  assert.equal(classifyRestore({ ...l, at: 'not a date' }, with_(at + 86400000)), 'ambiguous');
  assert.equal(classifyRestore(l, { ...l, provider: 'r2' }), 'different'); assert.equal(classifyRestore(l, { ...l, kind: 'backup' }), 'different');
});

test('#82 CLI: an ambiguous report exits 3 with a diagnostic on stderr and writes nothing', () => {
  const s = sandbox(); try {
    const l = legacyOf(s.file), before = readFileSync(s.file, 'utf8');
    const r = spawnSync(process.execPath, [TOOL, 'restore', '--file', s.file, '--run-id', String(l.run_id), '--provider', l.provider, '--plaintext-sha256', l.plaintext_sha256, '--duration-s', String(l.duration_s), '--mode', l.mode, '--by', l.by], { encoding: 'utf8' });
    assert.equal(r.status, 3, r.stderr); assert.match(r.stderr, /^refused: RESTORE_AMBIGUOUS/); assert.equal(readFileSync(s.file, 'utf8'), before);
    writeFileSync(s.file + '.unused', '');   // keep the sandbox shape identical to the other tests
  } finally { s.done(); }
});
