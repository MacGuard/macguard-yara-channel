// A verification that THROWS half way must still close the restored database and remove its private directory: since O1 the export is loaded into a
// restore.db FILE (plaintext of the backup) under mg-load-*, and the process-exit hook does not run on a signal or a crash, so cleanup cannot wait for exit.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { loadExport } from '../tools/stream_io.mjs';
import { verifyRestore } from '../tools/backup_lib.mjs';

test('verifyRestore: an exception during the checks (unparseable policy document) still removes the plaintext restore directory', async () => {
  const d = mkdtempSync(join(homedir(), '.mg-vrc-')), root = join(d, 'tmp'); mkdirSync(root);
  try {
    const f = join(d, 'e.sql');
    writeFileSync(f, "CREATE TABLE policy_versions(version INTEGER, doc TEXT, doc_sha256 TEXT, prev_sha256 TEXT);\nINSERT INTO policy_versions VALUES(1,'{not json','x','0');\n");
    const L = await loadExport({ file: f }, { tmpRoot: root }); assert.equal(L.error, undefined, String(L.error));
    assert.equal(readdirSync(root).filter((n) => n.startsWith('mg-load-')).length, 1, 'the restore database lives on disk while open');
    // the checks themselves no longer throw on a missing table (they fail); an unreadable reference schema still throws inside the try, which is the path under test
    await assert.rejects(verifyRestore(L, { schemaFile: new URL('file:///nonexistent-mg-schema/schema.sql') }));
    assert.deepEqual(readdirSync(root).filter((n) => n.startsWith('mg-load-')), [], 'no plaintext restore directory is left behind');
    const L2 = await loadExport({ file: f }, { tmpRoot: root }); const r = await verifyRestore(L2);
    assert.equal(r.ok, false, 'the unparseable document and the missing tables are FAILED checks'); assert.deepEqual(readdirSync(root).filter((n) => n.startsWith('mg-load-')), [], 'and cleaned up as well');
  } finally { rmSync(d, { recursive: true, force: true }); }
});
