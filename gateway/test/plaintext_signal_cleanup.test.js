// Regression: a restore interrupted by a signal must not leave the restored database (plaintext) on disk. Real child processes, real signals, a fake
// sqlite3 that writes a marker into the private directory and then hangs (the state in which the old code left `mg-load-*/restore.db` behind).
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const TOOLS = new URL('../tools/', import.meta.url).pathname, MARK = 'PLAINTEXT-SECRET-MARKER';
const sandbox = () => { const root = mkdtempSync(join(tmpdir(), 'mg-sigtest-')); return { root, done: () => rmSync(root, { recursive: true, force: true }) }; };
const alive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };
const waitFor = async (fn, ms = 8000) => { const t = Date.now(); while (Date.now() - t < ms) { const v = fn(); if (v) return v; await new Promise((r) => setTimeout(r, 25)); } return null; };
const leftovers = (root) => readdirSync(root).filter((n) => /^(mg-load-|\.mg-|mg-restore-|mg-offsite-|\.drill-)/.test(n));

function fakeSqlite(root, { dirAsDb = false } = {}) {   // writes the marker where the restored DB would be, records its pid, then hangs (or exits 0 leaving a directory as the "db")
  const f = join(root, 'fake-sqlite3');
  writeFileSync(f, `#!/bin/sh\nfor a; do db="$a"; done\n${dirAsDb ? 'mkdir "$db"; echo ' + MARK + ' > "$db/x"; exit 0' : 'echo ' + MARK + ' > "$db"; echo $$ > "' + join(root, 'fake.pid') + '"; exec sleep 60'}\n`); chmodSync(f, 0o755); return f;
}
function child(code, root) {
  const p = spawn(process.execPath, ['--input-type=module', '-e', code], { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] }); let out = '', err = '';
  p.stdout.on('data', (d) => (out += d)); p.stderr.on('data', (d) => (err += d));
  return { p, done: new Promise((ok) => p.on('close', (code, signal) => ok({ code, signal, out, err }))) };
}
const loadScript = (root, sqlite, extra = '') => `import { loadExport } from '${TOOLS}stream_io.mjs'; ${extra}
const sql = '${join(root, 'export.sql')}'; await loadExport({ file: sql }, { sqliteBin: '${sqlite}', tmpRoot: '${root}' }); setInterval(() => {}, 1000);`;

for (const sig of ['SIGTERM', 'SIGINT', 'SIGHUP']) {
  test(`${sig} during loadExport: the child writing plaintext is killed, mg-load-* is removed, and the process still dies by ${sig}`, async () => {
    const s = sandbox(); try {
      writeFileSync(join(s.root, 'export.sql'), 'CREATE TABLE t(x);'); const c = child(loadScript(s.root, fakeSqlite(s.root)), s.root);
      const dir = await waitFor(() => readdirSync(s.root).find((n) => n.startsWith('mg-load-') && existsSync(join(s.root, n, 'restore.db'))));
      assert.ok(dir, 'the private directory with the restored DB appeared'); assert.match(readFileSync(join(s.root, dir, 'restore.db'), 'utf8'), new RegExp(MARK));
      const pid = Number(readFileSync(join(s.root, 'fake.pid'), 'utf8'));
      c.p.kill(sig); const r = await c.done;
      assert.equal(r.signal, sig, `default status preserved (got code=${r.code} signal=${r.signal}) ${r.err}`);
      assert.deepEqual(leftovers(s.root), [], 'no plaintext directory left behind');
      assert.ok(await waitFor(() => !alive(pid), 3000), 'the sqlite3 child is not left running');
    } finally { s.done(); }
  });
}

test('a program that installs its own SIGTERM handler (after loading) keeps control: the plaintext is already gone when its handler runs', async () => {
  const s = sandbox(); try {
    writeFileSync(join(s.root, 'export.sql'), 'CREATE TABLE t(x);');
    const code = `import { readdirSync } from 'node:fs'; import { loadExport } from '${TOOLS}stream_io.mjs';
const p = loadExport({ file: '${join(s.root, 'export.sql')}' }, { sqliteBin: '${fakeSqlite(s.root)}', tmpRoot: '${s.root}' });
process.on('SIGTERM', () => { console.log('LEFT=' + readdirSync('${s.root}').filter((n) => n.startsWith('mg-load-')).length); process.exit(7); });
await p; setInterval(() => {}, 1000);`;
    const c = child(code, s.root);
    assert.ok(await waitFor(() => readdirSync(s.root).find((n) => n.startsWith('mg-load-') && existsSync(join(s.root, n, 'restore.db')))));
    c.p.kill('SIGTERM'); const r = await c.done;
    assert.equal(r.code, 7, r.err); assert.match(r.out, /LEFT=0/, 'the sweep ran before the program handler'); assert.deepEqual(leftovers(s.root), []);
  } finally { s.done(); }
});

test('an uncaught exception after the restore still removes the plaintext (exit path)', async () => {
  const s = sandbox(); try {
    const c = child(`import { privateDir } from '${TOOLS}private_tmp.mjs'; import { writeFileSync } from 'node:fs'; const d = privateDir('${s.root}', '.mg-restore-'); writeFileSync(d + '/plain.sql', '${MARK}'); throw new Error('verifier crashed');`, s.root);
    const r = await c.done; assert.notEqual(r.code, 0); assert.match(r.err, /verifier crashed/); assert.deepEqual(leftovers(s.root), []);
  } finally { s.done(); }
});

test('if the restored file cannot be opened as a database, loadExport removes it immediately (not at process exit)', async () => {
  const s = sandbox(); try {
    writeFileSync(join(s.root, 'export.sql'), 'CREATE TABLE t(x);');
    const { loadExport } = await import(`${TOOLS}stream_io.mjs`);
    const L = await loadExport({ file: join(s.root, 'export.sql') }, { sqliteBin: fakeSqlite(s.root, { dirAsDb: true }), tmpRoot: s.root });
    assert.ok(L.error, 'reported as an error'); assert.ok(!L.error.includes(MARK), 'no data in the error'); assert.deepEqual(leftovers(s.root), [], 'removed before close()'); L.close();
  } finally { s.done(); }
});

test('privateDir directories are 0700 and are registered until released', async () => {
  const s = sandbox(); try {
    const { privateDir, releaseDir, _open } = await import(`${TOOLS}private_tmp.mjs`);
    const d = privateDir(s.root, 'mg-restore-'); mkdirSync(join(d, 'x'));
    assert.equal((await import('node:fs')).statSync(d).mode & 0o777, 0o700); assert.ok(_open().includes(d));
    releaseDir(d); assert.ok(!existsSync(d)); assert.ok(!_open().includes(d));
  } finally { s.done(); }
});
