// Private working directories for PLAINTEXT (decrypted exports, restored databases, age identities) and the child processes that write into them.
// `finally` blocks do not run when the process is killed by a signal, so a Ctrl-C or a runner cancellation (SIGTERM) during a restore or a drill used to leave
// a restored database in clear on disk. Every such directory is registered here and removed on normal exit, on an uncaught exception (which exits) and on
// SIGINT/SIGTERM/SIGHUP: children are killed first (so nothing keeps writing), the directories are removed, then the signal is re-raised so the process
// still ends with the default status for that signal (unless the program installed its own handler, which then decides). SIGKILL cannot be intercepted by
// anyone: the 0700 directory mode is the remaining protection, and the runner's workspace is discarded.
import { chmodSync, mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';

const OPEN = new Set(), CHILDREN = new Set(), SIGNALS = ['SIGINT', 'SIGTERM', 'SIGHUP'];
let installed = false;

/** Kills tracked children and removes every registered directory. Synchronous and idempotent. */
export function sweep() {
  for (const c of CHILDREN) { try { c.kill('SIGKILL'); } catch { /* already gone */ } }
  CHILDREN.clear();
  for (const d of OPEN) { try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort, keep going */ } }
  OPEN.clear();
}
function onSignal(sig) {
  sweep();
  for (const s of SIGNALS) process.removeListener(s, onSignal);
  if (process.listenerCount(sig) === 0) process.kill(process.pid, sig);   // default action, as if this module were not there
}
function install() {
  if (installed) return; installed = true;
  process.once('exit', sweep);
  for (const s of SIGNALS) process.on(s, onSignal);
}

/** mkdtemp(root/prefix) with mode 0700, registered for removal on exit and on signals. The caller still removes it (releaseDir) when done. */
export function privateDir(root, prefix) { install(); const d = mkdtempSync(join(root, prefix)); chmodSync(d, 0o700); OPEN.add(d); return d; }
export function releaseDir(d) { rmSync(d, { recursive: true, force: true }); OPEN.delete(d); }
/** A child that writes plaintext into a private directory: killed before the directories are removed. */
export function trackChild(c) { install(); CHILDREN.add(c); c.once('close', () => CHILDREN.delete(c)); return c; }
export const _open = () => [...OPEN];   // tests only
