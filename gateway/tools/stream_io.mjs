// Streaming building blocks for backup and restore: nothing here holds a whole export in memory. age reads and writes through file descriptors, hashes are computed while reading, and an export is loaded
// into SQLite by the sqlite3 CLI straight from the file (in SAFE mode). Every function either returns a complete, verified result or leaves nothing behind.
import { spawn } from 'node:child_process';
import { open } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { chmodSync, closeSync, mkdtempSync, openSync, readFileSync, readSync, renameSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { privateDir, releaseDir, trackChild } from './private_tmp.mjs';   // plaintext dirs survive no exit, exception or signal

export const AGE_MAGIC = 'age-encryption.org/v1';

/** SHA-256 of a file without loading it. One 1 MiB buffer is reused for every read: a createReadStream allocates a new 64 KiB buffer per chunk, and the garbage it leaves made the peak RSS grow with the file
 *  (measured: 36 -> 50 -> 67 MiB for 2 -> 25 -> 100 MiB; flat at 35 MiB with a reused buffer, same digest). */
export const shaFile = async (file) => {
  const h = createHash('sha256'), fh = await open(file, 'r'), buf = Buffer.allocUnsafe(1 << 20);
  try { for (;;) { const { bytesRead } = await fh.read(buf, 0, buf.length, null); if (!bytesRead) break; h.update(buf.subarray(0, bytesRead)); } } finally { await fh.close(); }
  return h.digest('hex');
};

// age's stderr is the only text carried into an error (trimmed). It never contains the plaintext.
const failText = (code, sig, err) => `age ${sig ? 'killed by ' + sig : 'exited ' + code}${err ? ': ' + err.replace(/\s+/g, ' ').trim().slice(0, 200) : ''}`;
function runAge(args, inFd, outFd, signal, ageBin) {
  return new Promise((ok, ko) => {
    const c = trackChild(spawn(ageBin, args, { stdio: [inFd, outFd, 'pipe'], signal })); let e = '';
    c.stderr.on('data', (d) => { if (e.length < 400) e += d; }); c.on('error', ko);
    c.on('close', (code, sig) => (code === 0 ? ok() : ko(new Error(failText(code, sig, e)))));
  });
}

/** Encrypts SRC to DST. DST appears only when age exited 0 AND the result looks complete (age header, strictly larger than the plaintext); otherwise the partial file is removed. `signal` cancels the child. */
export async function ageEncryptFile({ ageBin = 'age', recipient, src, dst, signal }) {
  const part = dst + '.partial', inFd = openSync(src, 'r'); let outFd;
  try {
    outFd = openSync(part, 'wx', 0o600);
    await runAge(['-r', recipient], inFd, outFd, signal, ageBin);
    closeSync(outFd); outFd = undefined;
    const size = statSync(part).size, head = Buffer.alloc(AGE_MAGIC.length), fd = openSync(part, 'r'); try { readSync(fd, head, 0, head.length, 0); } finally { closeSync(fd); }
    if (head.toString('latin1') !== AGE_MAGIC) throw new Error('the encrypted output has no age header (incomplete or not age)');
    if (size <= statSync(src).size) throw new Error('the encrypted output is not larger than the plaintext (incomplete)');
    renameSync(part, dst); return { bytes: size };
  } catch (e) { rmSync(part, { force: true }); throw e; } finally { closeSync(inFd); if (outFd !== undefined) closeSync(outFd); }
}

/** Decrypts SRC (age) to DST, mode 0600, without passing the plaintext through this process. age authenticates every chunk and the final one, so a truncated or altered ciphertext exits non-zero and DST is never created. */
export async function ageDecryptFile({ ageBin = 'age', identity, src, dst, signal }) {
  const part = dst + '.partial', inFd = openSync(src, 'r'); let outFd;
  try {
    outFd = openSync(part, 'wx', 0o600);
    await runAge(['-d', '-i', identity], inFd, outFd, signal, ageBin);
    closeSync(outFd); outFd = undefined; renameSync(part, dst); return { bytes: statSync(dst).size };
  } catch (e) { rmSync(part, { force: true }); throw e; } finally { closeSync(inFd); if (outFd !== undefined) closeSync(outFd); }
}

// A failed load must not copy DATA into an error: it ends up in status.json and the (public) CI log. SQLite puts the offending text into its messages in
// many forms, quoted (near "…", unrecognized token: "'…") and unquoted (no such column: <token>, no such function: <token>, CHECK constraint failed:
// <expr with literals>), so nothing is copied from the message: the error is REBUILT from an allowlist of fixed phrases plus the line number.
// Private directories still open when the process ends (an exception in a verifier) are removed so a failed run never leaves restored data behind.
// (registry, exit and signal handling: private_tmp.mjs)
const KINDS = ['incomplete input', 'unrecognized token', 'syntax error', 'no such column', 'no such table', 'no such function', 'constraint failed', 'datatype mismatch',
  'malformed JSON', 'database disk image is malformed', 'file is not a database', 'unable to open database', 'not authorized', 'too big', 'out of memory',
  'database or disk is full', 'disk I/O error', 'readonly', 'interrupted'];
export const scrub = (s) => {
  const t = String(s).trim().split('\n')[0], own = /^sqlite3 (killed by SIG[A-Z0-9]+|exited -?\d+)$/.exec(t.trim());   // produced by this module, no external text
  if (own) return own[0];
  const kind = KINDS.find((k) => t.includes(k)) || 'unclassified error', line = /^(?:Parse|Runtime) error near line (\d+)/.exec(t);   // first line only: the CLI repeats the failing SQL (data) below it
  return `sqlite: ${kind}${line ? ' near line ' + line[1] : ''}`;
};

// journal_mode/synchronous OFF: the database is throwaway (created empty, only read afterwards), and without them the CLI commits and fsyncs every statement (measured: 249 s instead of 16 s for a 129 MB export).  (locking_mode and cache_size were tried: no measurable effect on the whole run, so they are not set.)
/** Loads an export into an isolated SQLite and returns { db, close() } or { error, close() }.
 *  - `sql` is a string (tests, small exports): loaded into :memory: as before.
 *  - `sql` is { file }: streamed from disk by `sqlite3 -safe -bail` into a database file inside a private 0700 directory. SAFE mode refuses .shell, ATTACH, writefile(), readfile() and dot-commands that touch the system:
 *    stricter than db.exec(), which allows ATTACH. If the CLI is not installed it falls back to reading the file into memory.
 *  The caller must call close(): it closes the database and removes the private directory. */
export async function loadExport(sql, { sqliteBin = 'sqlite3', signal, tmpRoot = tmpdir() } = {}) {
  if (sql && sql.db && sql.close) return sql;   // already loaded (runBackup loads once and shares it)
  if (typeof sql === 'string') return loadMemory(sql);
  const { file } = sql, dir = privateDir(tmpRoot, 'mg-load-');
  const dbFile = join(dir, 'restore.db'), done = (extra) => ({ close() { try { extra.db && extra.db.close(); } catch { /* already closed */ } releaseDir(dir); }, ...extra });
  const fd = openSync(file, 'r');
  try {
    const res = await new Promise((ok) => {
      const c = trackChild(spawn(sqliteBin, ['-safe', '-bail', '-cmd', 'PRAGMA foreign_keys = OFF', '-cmd', 'PRAGMA journal_mode = OFF', '-cmd', 'PRAGMA synchronous = OFF', dbFile], { stdio: [fd, 'ignore', 'pipe'], signal, cwd: dir })); let e = '';
      c.stderr.on('data', (d) => { if (e.length < 600) e += d; });
      c.on('error', (err) => ok({ spawnError: err }));
      c.on('close', (code, sig) => ok({ code, sig, e }));
    });
    if (res.spawnError) {
      if (res.spawnError.code !== 'ENOENT') return done({ error: `sqlite3 could not start (${/^[A-Z0-9_]+$/.test(String(res.spawnError.code)) ? res.spawnError.code : 'error'})` });
      releaseDir(dir); return loadMemory(readFileSync(file, 'utf8'));   // no sqlite3 CLI: same result, whole file in memory
    }
    if (res.code !== 0) return done({ error: scrub(res.sig ? 'sqlite3 killed by ' + res.sig : res.e || `sqlite3 exited ${res.code}`) });
    let db; try { db = new DatabaseSync(dbFile); db.exec('PRAGMA foreign_keys = OFF'); } catch (e) { try { db && db.close(); } catch { /* not open */ } releaseDir(dir); return { error: scrub(e.message), close() {} }; }   // the restored file is removed NOW, not at process exit
    return done({ db });
  } finally { closeSync(fd); }
}
function loadMemory(text) {
  const db = new DatabaseSync(':memory:'); db.exec('PRAGMA foreign_keys = OFF');
  try { db.exec(text); } catch (e) { const error = scrub(e.message); db.close(); return { error, close() {} }; }
  return { db, close() { try { db.close(); } catch { /* already closed */ } } };
}
