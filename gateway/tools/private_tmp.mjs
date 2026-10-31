// Private working directories for PLAINTEXT (decrypted exports, restored databases, age identities) and the child processes that write into them.
// `finally` blocks do not run when the process is killed by a signal, so a Ctrl-C or a runner cancellation (SIGTERM) during a restore or a drill used to leave
// a restored database in clear on disk. Every such directory is registered here and removed on normal exit, on an uncaught exception (which exits) and on
// SIGINT/SIGTERM/SIGHUP: children are killed first (so nothing keeps writing), the directories are removed, then the signal is re-raised so the process
// still ends with the default status for that signal (unless the program installed its own handler, which then decides). SIGKILL cannot be intercepted by
// anyone: the 0700 directory mode is the remaining protection, and the runner's workspace is discarded.
import { spawn } from 'node:child_process';
import { chmodSync, mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';

const OPEN = new Set(), CHILDREN = new Set(), SIGNALS = ['SIGINT', 'SIGTERM', 'SIGHUP'];
let installed = false;

/** Kills tracked children and removes every registered directory. Synchronous and idempotent. */
export function sweep() {
  for (const c of CHILDREN) { try { c.kill('SIGKILL'); } catch { /* already gone */ } }
  CHILDREN.clear();
  for (const d of OPEN) { try { rmSync(d, { recursive: true, force: true, maxRetries: 5, retryDelay: 20 }); } catch { /* best effort, keep going */ } }   // retries: a just-killed child may still be closing a file
  OPEN.clear();
}
function uninstall() { for (const s of SIGNALS) process.removeListener(s, onSignal); installed = false; }
function onSignal(sig) {
  sweep(); uninstall();
  if (process.listenerCount(sig) === 0) process.kill(process.pid, sig);   // default action, as if this module were not there
}
// Listeners exist ONLY while something is registered: Node defers a signal that has a JS listener while the thread is blocked in a synchronous call
// (execFileSync, spawnSync), and if nothing asynchronous is pending afterwards the process exits 0 without ever running the handler. Outside the
// windows in which plaintext exists, the default signal behaviour is untouched; inside them, children must be run with runTracked() (async).
let exitHooked = false;
function install() {
  if (!exitHooked) { exitHooked = true; process.once('exit', sweep); }
  if (installed) return; installed = true;
  for (const s of SIGNALS) process.on(s, onSignal);
}
const maybeUninstall = () => { if (installed && !OPEN.size && !CHILDREN.size) uninstall(); };

/** mkdtemp(root/prefix) with mode 0700, registered for removal on exit and on signals. The caller still removes it (releaseDir) when done. */
export function privateDir(root, prefix) { install(); const d = mkdtempSync(join(root, prefix)); chmodSync(d, 0o700); OPEN.add(d); return d; }
export function releaseDir(d) { rmSync(d, { recursive: true, force: true }); OPEN.delete(d); maybeUninstall(); }
/** A child that writes plaintext into a private directory: killed before the directories are removed. */
export function trackChild(c) { install(); CHILDREN.add(c); const done = () => { CHILDREN.delete(c); maybeUninstall(); }; c.once('close', done); c.once('error', done); return c; }
/** Asynchronous replacement for execFileSync while plaintext exists: the signal handler can run (and kill this child) while it works.
 *  Resolves with captured stdout (when stdio is 'pipe') or ''; rejects with an Error carrying `status`/`signal` on a non-zero exit, like execFileSync. */
export function runTracked(cmd, args, { env, cwd, stdio = 'inherit', timeout = 0 } = {}) {
  return new Promise((ok, ko) => {
    const c = trackChild(spawn(cmd, args, { env, cwd, stdio: stdio === 'inherit' ? 'inherit' : ['ignore', 'pipe', 'pipe'], timeout: timeout || undefined }));
    let out = ''; if (c.stdout) c.stdout.on('data', (d) => { out += d; });
    c.on('error', ko);
    c.on('close', (status, signal) => (status === 0 ? ok(out) : ko(Object.assign(new Error(`${cmd} ${signal ? 'killed by ' + signal : 'exited ' + status}`), { status, signal }))));
  });
}
export const _open = () => [...OPEN];   // tests only
export const _listening = () => installed;   // tests only
