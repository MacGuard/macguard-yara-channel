// A failed load must never copy exported DATA into an error (status.json, CI logs). Review of PR #57 (MEDIUM, pre-existing): a truncated export produced
// `unrecognized token: "'{"marker":…` with up to 160 characters of data. (Table/column NAMES may still appear: they are schema, already public in the repo, not row data.) Both load paths are tested: the sqlite3 CLI (streamed file) and the in-memory fallback.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadExport } from '../tools/stream_io.mjs';

const MARK = 'DATA-MARKER-QX7';
const exportsThatFail = {
  'truncated inside a string literal': `CREATE TABLE t(a TEXT);\nINSERT INTO t VALUES('{"marker":"${MARK}","pad":"${'p'.repeat(200)}`,
  'garbage token after data': `CREATE TABLE t(a TEXT);\nINSERT INTO t VALUES('${MARK}') ${MARK}"oops;`,
  'syntax error next to data': `CREATE TABLE t(a TEXT);\nINSERT INTO t VALUES('${MARK}' '${MARK}');`,
};
for (const [name, sql] of Object.entries(exportsThatFail)) {
  test(`load error carries no exported data: ${name} (sqlite3 CLI and in-memory)`, async () => {
    const root = mkdtempSync(join(tmpdir(), 'mg-redact-')), f = join(root, 'export.sql'); writeFileSync(f, sql);
    try {
      for (const L of [await loadExport({ file: f }, { tmpRoot: root }), await loadExport(sql)]) {
        assert.ok(L.error, 'the load fails'); assert.ok(!L.error.includes(MARK), `no data in: ${L.error}`); assert.ok(!/pppp/.test(L.error)); assert.ok(L.error.length <= 160); L.close();
      }
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
}
test('the error still says what kind of failure it was', async () => {
  const L = await loadExport('CREATE TABLE t(a); INSERT INTO t VALUES(1) xyz;'); assert.match(L.error, /syntax error|near/); L.close();
});
