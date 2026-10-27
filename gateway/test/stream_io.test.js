import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { loadExport, ageDecryptFile, ageEncryptFile, shaFile } from '../tools/stream_io.mjs';

const HAVE_AGE = existsSync('/usr/local/bin/age') || existsSync('/opt/homebrew/bin/age') || (() => { try { execFileSync('age', ['--version'], { stdio: 'ignore' }); return true; } catch { return false; } })();
const sandbox = () => { const d = mkdtempSync(join(homedir(), '.mg-sio-')); return { d, done: () => rmSync(d, { recursive: true, force: true }) }; };
const TRICKY = "PRAGMA foreign_keys=OFF;\nCREATE TABLE t(id INTEGER PRIMARY KEY, a TEXT);\nCREATE TABLE log(n INTEGER);\nCREATE TRIGGER trg AFTER INSERT ON t BEGIN INSERT INTO log VALUES (new.id); END;\nINSERT INTO t VALUES(1,'it''s; a \"row\"\n.shell touch should-not-exist\nline3 -- not a comment');\nINSERT INTO t VALUES(2,'x');\n";
const tmpLeft = (root) => readdirSync(root).filter((n) => n.startsWith('mg-load-'));

test('loadExport: a file load gives exactly what the in-memory load gives (trigger, quotes, semicolons, a line starting with a dot inside a string) and close() removes the private directory', async () => {
  const sb = sandbox();
  try {
    const f = join(sb.d, 'e.sql'); writeFileSync(f, TRICKY); const root = join(sb.d, 'tmp'); mkdirSync(root);   // an own temp root: other test files run in parallel
    const a = await loadExport(TRICKY), b = await loadExport({ file: f }, { tmpRoot: root });
    assert.equal(a.error, undefined); assert.equal(b.error, undefined);
    const dump = (db) => JSON.stringify([db.prepare('SELECT * FROM t ORDER BY id').all(), db.prepare('SELECT * FROM log ORDER BY n').all(), db.prepare("SELECT name,type FROM sqlite_master ORDER BY name").all()]);
    assert.equal(dump(b.db), dump(a.db)); assert.equal(b.db.prepare('SELECT COUNT(*) n FROM log').get().n, 2, 'the trigger fired');
    assert.ok(!existsSync(join(sb.d, 'should-not-exist')), 'a dot line inside a string is data, never a command');
    assert.equal(tmpLeft(root).length, 1, 'one private directory while open'); assert.equal((statSync(join(root, tmpLeft(root)[0])).mode & 0o777).toString(8), '700'); b.close(); a.close(); assert.equal(tmpLeft(root).length, 0, 'removed on close');
  } finally { sb.done(); }
});

test('loadExport: SAFE mode refuses a hostile export (.shell, ATTACH, writefile) and nothing is created outside the private directory', async () => {
  const sb = sandbox(), hostile = {
    shell: `CREATE TABLE a(x);\n.shell touch ${join(sb.d, 'pwn1')}\n`,
    attach: `ATTACH DATABASE '${join(sb.d, 'pwn2.db')}' AS e;\nCREATE TABLE e.b(y);\n`,
    writefile: `SELECT writefile('${join(sb.d, 'pwn3')}', 'x');\n`,
  };
  try {
    for (const [name, sql] of Object.entries(hostile)) {
      const f = join(sb.d, name + '.sql'); writeFileSync(f, sql); const r = await loadExport({ file: f });
      assert.ok(r.error, name + ' must be refused'); assert.equal(r.db, undefined); r.close();
    }
    assert.deepEqual(readdirSync(sb.d).filter((n) => n.startsWith('pwn')), [], 'no side effect');
  } finally { sb.done(); }
});

test('loadExport: a syntax error is reported without copying SQL text, and without a sqlite3 binary it falls back to memory with the same result', async () => {
  const sb = sandbox();
  try {
    const f = join(sb.d, 'bad.sql'); writeFileSync(f, "CREATE TABLE t(a);\nINSERT INTO t VALUES ('SECRET-VALUE-123' 'oops');\n");
    const bad = await loadExport({ file: f }); assert.ok(bad.error); assert.doesNotMatch(bad.error, /SECRET-VALUE-123/); bad.close();
    const mem = await loadExport("CREATE TABLE t(a);\nINSERT INTO t VALUES ('SECRET-VALUE-123' 'oops');\n"); assert.ok(mem.error); assert.doesNotMatch(mem.error, /SECRET-VALUE-123/);
    const g = join(sb.d, 'good.sql'); writeFileSync(g, TRICKY);
    const fb = await loadExport({ file: g }, { sqliteBin: join(sb.d, 'no-such-sqlite3') }); assert.equal(fb.error, undefined); assert.equal(fb.db.prepare('SELECT COUNT(*) n FROM t').get().n, 2); fb.close();
  } finally { sb.done(); }
});

test('loadExport: an already loaded database is reused, not loaded twice', async () => {
  const a = await loadExport(TRICKY); assert.equal(await loadExport(a), a); a.close();
});

test('ageDecryptFile: round trip is exact with mode 0600; a wrong identity, an altered or a truncated ciphertext fail with a non-zero exit and leave NO output file', { skip: !HAVE_AGE }, async () => {
  const sb = sandbox();
  try {
    const key = join(sb.d, 'k'), key2 = join(sb.d, 'k2'); execFileSync('age-keygen', ['-o', key], { stdio: 'ignore' }); execFileSync('age-keygen', ['-o', key2], { stdio: 'ignore' });
    const pub = execFileSync('age-keygen', ['-y', key], { encoding: 'utf8' }).trim(), src = join(sb.d, 'p.sql'), enc = join(sb.d, 'p.age'); writeFileSync(src, TRICKY.repeat(20000));
    await ageEncryptFile({ recipient: pub, src, dst: enc });
    const out = join(sb.d, 'out.sql'); await ageDecryptFile({ identity: key, src: enc, dst: out });
    assert.equal(await shaFile(out), createHash('sha256').update(readFileSync(src)).digest('hex')); assert.equal((statSync(out).mode & 0o777).toString(8), '600');
    const cipher = readFileSync(enc), cases = { 'wrong identity': [key2, enc], 'truncated': [key, (() => { const p = join(sb.d, 't.age'); writeFileSync(p, cipher.subarray(0, cipher.length - 40)); return p; })()], 'altered': [key, (() => { const p = join(sb.d, 'a.age'); const b = Buffer.from(cipher); b[b.length - 100] ^= 0xff; writeFileSync(p, b); return p; })()] };
    for (const [name, [id, file]] of Object.entries(cases)) { const dst = join(sb.d, name.replace(/ /g, '_') + '.out'); await assert.rejects(() => ageDecryptFile({ identity: id, src: file, dst }), /age exited|age killed/, name); assert.ok(!existsSync(dst) && !existsSync(dst + '.partial'), name + ': nothing left behind'); }
  } finally { sb.done(); }
});

// ---- memory regression: the point of streaming is that RAM does not grow with the export ----
import { spawnSync } from 'node:child_process';
import { createWriteStream } from 'node:fs';
const HAVE_SQLITE3 = (() => { try { execFileSync('sqlite3', ['--version'], { stdio: 'ignore' }); return true; } catch { return false; } })();
const MIB = 1048576;
async function makeExport(file, mib) {
  await new Promise((ok, ko) => {
    const w = createWriteStream(file, { mode: 0o600 }); w.on('error', ko).on('finish', ok);
    w.write("CREATE TABLE t(id INTEGER PRIMARY KEY, a TEXT, b TEXT);\nCREATE TABLE log(n INTEGER);\nCREATE TRIGGER trg AFTER INSERT ON t BEGIN INSERT INTO log VALUES (new.id); END;\n");
    let bytes = 0, id = 0; const pad = 'x'.repeat(700);
    (function pump() { let go = true; while (bytes < mib * MIB && go) { id++; const row = `INSERT INTO t VALUES(${id},'it''s; a "row"\nline2 -- not a comment ${id}','${pad}${id}');\n`; bytes += row.length; go = w.write(row); } if (bytes < mib * MIB) w.once('drain', pump); else w.end(); })();
  });
}
const CHILD = `
import { ageDecryptFile, loadExport, shaFile } from ${JSON.stringify(new URL('../tools/stream_io.mjs', import.meta.url).href)};
const [enc, id, plain] = process.argv.slice(1);
await ageDecryptFile({ identity: id, src: enc, dst: plain }); const sha = await shaFile(plain);
const L = await loadExport({ file: plain }); if (L.error) throw new Error(L.error);
const rows = L.db.prepare('SELECT COUNT(*) n FROM t').get().n, logs = L.db.prepare('SELECT COUNT(*) n FROM log').get().n; L.close();
console.log(JSON.stringify({ sha, rows, logs, rssMiB: process.resourceUsage().maxRSS / 1024 }));   // maxRSS is in KiB
`;
test('memory: decrypt + hash + load of a 100 MiB export stays far below the export size (the in-memory path needs ~4.8x)', { skip: !(HAVE_AGE && HAVE_SQLITE3) }, async () => {
  const sb = sandbox();
  try {
    const key = join(sb.d, 'k'); execFileSync('age-keygen', ['-o', key], { stdio: 'ignore' }); const pub = execFileSync('age-keygen', ['-y', key], { encoding: 'utf8' }).trim();
    const src = join(sb.d, 'e.sql'), enc = join(sb.d, 'e.age'); await makeExport(src, 100); await ageEncryptFile({ recipient: pub, src, dst: enc });
    const size = statSync(src).size, want = await shaFile(src); rmSync(src);
    const r = spawnSync(process.execPath, ['--input-type=module', '-e', CHILD, enc, key, join(sb.d, 'plain.sql')], { encoding: 'utf8', timeout: 300000 });
    assert.equal(r.status, 0, r.stderr); const out = JSON.parse(r.stdout.trim().split('\n').pop());
    assert.equal(out.sha, want, 'exact plaintext'); assert.ok(out.rows > 100000 && out.rows === out.logs, 'every row loaded and the trigger fired for each');
    assert.ok(out.rssMiB < size / MIB, `peak RSS ${out.rssMiB.toFixed(0)} MiB for a ${(size / MIB).toFixed(0)} MiB export (holding the whole export alone would cost at least its size; the in-memory path measured ~478 MiB)`);
  } finally { sb.done(); }
});
