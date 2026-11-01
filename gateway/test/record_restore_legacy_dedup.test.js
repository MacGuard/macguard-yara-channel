// Regression: a NEW restoration (reported with restored_at) must not be discarded as a duplicate of a historical line that has no restored_at just because
// run, provider, mode, hash, rounded duration and reporter coincide. Every historical restore in evidence/backups.jsonl lacks restored_at, lasts 4–6 s and was
// reported by the same login, so the next drill of the same copy would very likely collide. The real evidence file is only READ (copied to a temp dir), never written.
import test from 'node:test';
import assert from 'node:assert/strict';
import { copyFileSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { append, buildRestoreRecord, readRecords, sameRestore } from '../tools/backup_record.mjs';

const REAL = new URL('../../evidence/backups.jsonl', import.meta.url);
const sha = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');
const sandbox = () => { const root = mkdtempSync(join(tmpdir(), 'mg-legacy-')), file = join(root, 'backups.jsonl'); copyFileSync(REAL, file); return { file, done: () => rmSync(root, { recursive: true, force: true }) }; };

test('a new drill (restored_at AFTER the legacy report) with the same duration and reporter as a legacy line is a NEW event (real history)', () => {
  const realBefore = sha(REAL), s = sandbox(); try {
    const legacy = readRecords(s.file).find((r) => r.kind === 'restore' && !r.restored_at);
    assert.ok(legacy, 'the real history has restore lines without restored_at');
    const before = readFileSync(s.file, 'utf8'), n = readRecords(s.file).filter((r) => r.kind === 'restore').length;
    const fresh = buildRestoreRecord({ file: s.file, runId: legacy.run_id, provider: legacy.provider, plaintextSha256: legacy.plaintext_sha256, durationS: legacy.duration_s, mode: legacy.mode, by: legacy.by,
      restoredAt: '2026-10-31T09:00:00Z', at: '2026-10-31T09:05:00Z' });   // days after the legacy report: it cannot be the same restoration
    assert.equal(sameRestore(legacy, fresh), false); assert.equal(sameRestore(fresh, legacy), false, 'symmetric');
    const r = append(s.file, fresh); assert.equal(r.added, true, JSON.stringify(r));
    assert.equal(readRecords(s.file).filter((x) => x.kind === 'restore').length, n + 1); assert.ok(readFileSync(s.file, 'utf8').startsWith(before), 'append-only');
    assert.equal(append(s.file, { ...fresh, at: '2026-10-31T10:00:00Z' }).added, false, 'still idempotent: the same new restoration reported again is one record');
  } finally { s.done(); }
  assert.equal(sha(REAL), realBefore, 'evidence/backups.jsonl untouched');
});

test('a late re-report (restored_at at or BEFORE the legacy report) of the same content is still the same restoration', () => {
  const s = sandbox(); try {
    const legacy = readRecords(s.file).find((r) => r.kind === 'restore' && !r.restored_at);
    const late = { ...legacy, restored_at: new Date(Date.parse(legacy.at) - 60000).toISOString().replace(/\.\d{3}Z$/, 'Z'), at: '2026-10-31T09:05:00Z' };
    assert.equal(sameRestore(legacy, late), true); assert.equal(sameRestore(late, legacy), true);
    assert.equal(sameRestore(legacy, { ...late, restored_at: legacy.at }), true, 'boundary: restored exactly at the report time');
    assert.equal(sameRestore(legacy, { ...late, duration_s: legacy.duration_s + 1 }), false, 'different duration is still a different event');
  } finally { s.done(); }
});
