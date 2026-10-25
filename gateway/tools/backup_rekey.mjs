// Re-encrypts one backup for a new age recipient (see rekeyBackup). Usage: node tools/backup_rekey.mjs --dir ~/macguard-backups/gateway/<stamp> --identity OLD_KEYFILE --recipient age1... [--new-identity NEW_KEYFILE]
// The old backup is left untouched; delete it yourself (or via backup_prune) only after you have restored from the new one. Pass --new-identity to prove the new key decrypts it right now.
import { rekeyBackup } from './backup_flow.mjs';
const arg = (n, d = null) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : d; };
if (!arg('--dir') || !arg('--identity') || !arg('--recipient')) { console.error('usage: backup_rekey.mjs --dir DIR --identity OLD_KEYFILE --recipient age1... [--new-identity NEW_KEYFILE]'); process.exit(2); }
try { const r = await rekeyBackup({ dir: arg('--dir'), identityFile: arg('--identity'), newRecipient: arg('--recipient'), newIdentityFile: arg('--new-identity') }); console.log(`REKEYED ${r.dir}${r.verified_new_key ? ' (new key verified)' : ' (new key NOT yet verified: restore from it before relying on it)'}`); } catch (e) { console.error('FAILED: ' + e.message); process.exit(1); }
