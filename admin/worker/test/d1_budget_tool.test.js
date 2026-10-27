// The budget tool that guards every command touching the productive D1: estimates, decisions, alert levels and the analytics reader (with a fake fetch; nothing here touches Cloudflare).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { estimateImport, decide, level, usageToday, FREE } from '../tools/d1_budget.mjs';

test('an import of the size that caused the incident is refused by estimate, a small fixture is allowed', () => {
  const big = Array.from({ length: 75_148 }, (_, i) => `INSERT INTO "intel_records" VALUES ('r${i}');`).join('\n'), est = estimateImport(big);
  assert.equal(est.rows, 75_148); assert.ok(est.writes >= 75_148 * 5, 'every row costs a write per secondary index'); const d = decide({ reads: 0, writes: est.writes }); assert.equal(d.ok, false); assert.match(d.why.join(' '), /write at most/);
  const small = estimateImport(Array.from({ length: 1500 }, (_, i) => `INSERT INTO "intel_records" VALUES ('r${i}');`).join('\n')); assert.equal(decide({ writes: small.writes }).ok, true);
});
test('limits per operation and per day: a read-heavy export is refused, and nothing planned may take the day above 60%', () => {
  assert.equal(decide({ reads: 600_000 }).ok, false, 'one operation above 10% of the read quota'); assert.equal(decide({ reads: 400_000 }).ok, true);
  assert.equal(decide({ reads: 400_000 }, { rowsRead: 2_700_000, rowsWritten: 0 }).ok, false, '2.7M + 0.4M passes 60%'); assert.equal(decide({ writes: 20_000 }, { rowsRead: 0, rowsWritten: 45_000 }).ok, false);
  assert.equal(decide({}, { rowsRead: 4_984_852, rowsWritten: 376_012 }).ok, false, 'on a day like 2026-10-26 nothing planned runs'); assert.equal(decide({}, { rowsRead: 0, rowsWritten: 0 }).ok, true);
});
test('alert levels follow the worse of reads and writes', () => {
  assert.equal(level({ rowsRead: 1000, rowsWritten: 10 }), 'ok'); assert.equal(level({ rowsRead: FREE.rowsRead * 0.5, rowsWritten: 0 }), 'warn'); assert.equal(level({ rowsRead: 0, rowsWritten: FREE.rowsWritten * 0.85 }), 'critical');
});
test('usageToday sums the analytics groups by database and fails loudly when analytics is unreachable (an unknown budget blocks the operation)', async () => {
  const fake = async () => ({ ok: true, json: async () => ({ data: { viewer: { accounts: [{ d1AnalyticsAdaptiveGroups: [{ dimensions: { databaseId: 'a' }, sum: { rowsRead: 10, rowsWritten: 1, readQueries: 2, writeQueries: 1 } }, { dimensions: { databaseId: 'a' }, sum: { rowsRead: 5, rowsWritten: 0, readQueries: 1, writeQueries: 0 } }, { dimensions: { databaseId: 'b' }, sum: { rowsRead: 7, rowsWritten: 2, readQueries: 1, writeQueries: 1 } }] }] } } }) });
  const u = await usageToday('t', 'acc', fake, '2026-10-26'); assert.equal(u.total.rowsRead, 22); assert.equal(u.byDb.a.rowsRead, 15); assert.equal(u.byDb.b.rowsWritten, 2);
  await assert.rejects(() => usageToday('t', 'acc', async () => ({ ok: false, status: 403 })), /HTTP 403/);
});
test('the scripts that touch D1 call the preflight and refuse to run without it', () => {
  for (const f of ['local_backup.sh', 'migration_trial2.sh']) { const s = readFileSync(new URL(`../tools/${f}`, import.meta.url), 'utf8'); assert.match(s, /d1_budget\.mjs/, `${f} uses the budget tool`); assert.match(s, /\$BUDGET preflight/, `${f} checks the budget first`); assert.match(s, /\$BUDGET record/, `${f} records the real cost`); assert.ok(s.indexOf('$BUDGET preflight') < Math.min(...['mk $', 'd1 export macguard'].map((x) => (s.indexOf(x) < 0 ? Infinity : s.indexOf(x)))), `${f}: the check comes before the first D1 command`); }
  const t = readFileSync(new URL('../tools/migration_trial2.sh', import.meta.url), 'utf8'); assert.doesNotMatch(t, /d1 export macguard-intel --remote/, 'the trial never exports the productive INTEL again: it uses a deterministic fixture'); assert.match(t, /intel_trial_fixture\.mjs/);
});
