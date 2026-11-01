// QA D3: the panel and intel export verifiers remove the loaded plaintext database even when a check throws (as verifyRestore in gateway backup_lib).
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { verifyIntelRestore } from '../tools/intel_backup_verify.mjs';
import { verifyPanelRestore } from '../tools/panel_backup_verify.mjs';
import { _open } from '../../../gateway/tools/private_tmp.mjs';

for (const [name, fn, sql, opts] of [
  ['intel', verifyIntelRestore, 'CREATE TABLE intel_records(id TEXT); CREATE TABLE intel_runs(id TEXT); CREATE TABLE intel_sources(id TEXT); CREATE TABLE intel_events(id INTEGER);', {}],
  ['panel', verifyPanelRestore, 'CREATE TABLE "odd""name"(x);', { manifest: { row_counts: { audit: 1 } } }]]) {   // panelRowCounts quotes table names naively: a name with a double quote makes it throw
  test(`${name}: a check that throws on a malformed export leaves no loaded database open or on disk`, async () => {
    const root = mkdtempSync(join(tmpdir(), 'mg-d3-')), f = join(root, 'export.sql'); writeFileSync(f, sql);
    try {
      const before = _open().length; let threw = false;
      try { const r = await fn({ file: f }, opts); assert.equal(r.ok, false, 'if it does not throw it must at least fail'); } catch { threw = true; }
      assert.ok(threw, `${name}: this export makes a check throw (the case under test)`);
      assert.equal(_open().length, before, `${name}: the private directory was released (${threw ? 'after a throw' : 'after a failed verification'})`);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
}
