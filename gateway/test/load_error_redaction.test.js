// A failed load must never copy exported DATA into an error (status.json, CI logs). Review of PR #57 (MEDIUM, pre-existing): a truncated export produced
// `unrecognized token: "'{"marker":…` with up to 160 characters of data. A quote-based cut was not enough: SQLite also prints offending tokens UNQUOTED
// (`no such column: <token>`, `no such function: <token>`, `CHECK constraint failed: <expr>`), so the error is rebuilt from an allowlist. Both load paths are
// tested (sqlite3 CLI on a streamed file, in-memory fallback), plus the end-to-end sink (runBackup -> status.json) and negative controls.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadExport, scrub } from '../tools/stream_io.mjs';
import { runBackup } from '../tools/backup_flow.mjs';

const MARK = 'DATAMARKERQX7', LOW = MARK.toLowerCase();
const failing = {
  'truncated inside a string literal': `CREATE TABLE t(a TEXT);\nINSERT INTO t VALUES('{"marker":"${MARK}","pad":"${'p'.repeat(200)}`,
  'garbage token after data': `CREATE TABLE t(a TEXT);\nINSERT INTO t VALUES('${MARK}') ${MARK}"oops;`,
  'syntax error next to data': `CREATE TABLE t(a TEXT);\nINSERT INTO t VALUES('${MARK}' '${MARK}');`,
  'unquoted token (no such column)': `CREATE TABLE t(a TEXT);\nINSERT INTO t VALUES(${MARK});`,
  'unquoted qualified token': `CREATE TABLE t(a TEXT);\nINSERT INTO t VALUES(${MARK}.x);`,
  'unquoted call (no such function)': `CREATE TABLE t(a TEXT);\nINSERT INTO t VALUES(${MARK}(1));`,
  'CHECK constraint whose expression quotes a literal': `CREATE TABLE t(a TEXT CHECK (a <> '${MARK}'));\nINSERT INTO t VALUES('${MARK}');`,
  'statement that starts with data': `CREATE TABLE t(a TEXT);\n${MARK};`,
  'data right after a newline inside the literal': `CREATE TABLE t(a TEXT);\nINSERT INTO t VALUES('\n${MARK}`,
  'backtick-quoted data': `CREATE TABLE t(a TEXT);\nINSERT INTO t VALUES(\`${MARK}\` \`${MARK}\`);`,
  'blob literal with data': `CREATE TABLE t(a BLOB);\nINSERT INTO t VALUES(X'${MARK}');`,
  'non-ASCII data': `CREATE TABLE t(a TEXT);\nINSERT INTO t VALUES(ñ${MARK}ü);`,
  'lower-case data': `CREATE TABLE t(a TEXT);\nINSERT INTO t VALUES(${LOW});`,
};
const clean = (e) => { assert.ok(e, 'the load fails'); assert.ok(!e.includes(MARK) && !e.toLowerCase().includes(LOW), `no data in: ${e}`); assert.ok(!/pppp/.test(e)); assert.ok(e.length <= 80, e); };
for (const [name, sql] of Object.entries(failing)) {
  test(`load error carries no exported data: ${name} (sqlite3 CLI and in-memory)`, async () => {
    const root = mkdtempSync(join(tmpdir(), 'mg-redact-')), f = join(root, 'export.sql'); writeFileSync(f, sql);
    try { for (const L of [await loadExport({ file: f }, { tmpRoot: root }), await loadExport(sql)]) { clean(L.error); L.close(); } } finally { rmSync(root, { recursive: true, force: true }); }
  });
}

test('end to end: a backup whose export fails to load records no data in status.json or in its result', async () => {
  const root = mkdtempSync(join(homedir(), '.mg-redact-bk-'));   // runBackup refuses temporary directories (as in backup_flow.test.js)
  try {
    for (const sql of Object.values(failing)) {
      const r = await runBackup({ exportFn: async (p) => writeFileSync(p, sql), root, clock: () => new Date('2026-10-31T00:00:00Z') });
      assert.equal(r.ok, false); assert.equal(r.stage, 'load'); clean(r.error);
      const st = readFileSync(join(root, 'status.json'), 'utf8'); assert.ok(!st.includes(MARK) && !st.toLowerCase().includes(LOW), st);
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
});

// ---- negative controls: the diagnosis that IS useful survives, a valid export still loads, and scrub copies nothing it does not know ----
test('the error still says what kind of failure it was, and where (CLI)', async () => {
  const root = mkdtempSync(join(tmpdir(), 'mg-redact-')), f = join(root, 'e.sql');
  try {
    const cases = [['CREATE TABLE t(a);\n\nINSERT INTO t VALUES(1) xyz;', /^sqlite: syntax error near line 3$/], ['CREATE TABLE t(a);\nINSERT INTO t VALUES(\'abc', /^sqlite: (unrecognized token|incomplete input)/],
      ['CREATE TABLE t(a UNIQUE);\nINSERT INTO t VALUES(1);\nINSERT INTO t VALUES(1);', /^sqlite: constraint failed near line 3$/], ['INSERT INTO nope VALUES(1);', /^sqlite: no such table near line 1$/]];
    for (const [sql, re] of cases) { writeFileSync(f, sql); const L = await loadExport({ file: f }, { tmpRoot: root }); assert.match(L.error, re); L.close(); }
    const mem = await loadExport('CREATE TABLE t(a); INSERT INTO t VALUES(1) xyz;'); assert.match(mem.error, /^sqlite: syntax error$/); mem.close();
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test('a valid export (with quotes, newlines and the marker in its data) still loads without error', async () => {
  const root = mkdtempSync(join(tmpdir(), 'mg-redact-')), f = join(root, 'ok.sql'), sql = `CREATE TABLE t(a TEXT);\nINSERT INTO t VALUES('${MARK} it''s "q" \`b\`\nline2');`;
  writeFileSync(f, sql);
  try { for (const L of [await loadExport({ file: f }, { tmpRoot: root }), await loadExport(sql)]) { assert.equal(L.error, undefined); assert.match(L.db.prepare('SELECT a FROM t').get().a, new RegExp(MARK)); L.close(); } }
  finally { rmSync(root, { recursive: true, force: true }); }
});
test('scrub: only fixed phrases and a line number leave; its own messages pass; unknown text becomes "unclassified"', () => {
  assert.equal(scrub('sqlite3 killed by SIGTERM'), 'sqlite3 killed by SIGTERM'); assert.equal(scrub('sqlite3 exited 1'), 'sqlite3 exited 1');
  assert.equal(scrub(`sqlite3 exited 1 ${MARK}`), 'sqlite: unclassified error', 'a look-alike with extra text is not passed through');
  assert.equal(scrub(`Parse error near line 7: ${MARK}`), 'sqlite: unclassified error near line 7');
  assert.equal(scrub(`Parse error near line ${MARK}: x`), 'sqlite: unclassified error');
  assert.equal(scrub(`Runtime error near line 2: CHECK constraint failed: a <> '${MARK}' (19)`), 'sqlite: constraint failed near line 2');
  assert.equal(scrub(''), 'sqlite: unclassified error');
});
