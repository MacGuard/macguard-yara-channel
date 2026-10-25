// Exports the gateway secrets from the macOS Keychain into ONE file encrypted with `age` for a recipient (public key) the owner holds, so the secrets do not depend on a single machine or a
// temporary folder. Values are never printed. Restore: `age -d -i KEYFILE FILE`, then `security add-generic-password -U -s macguard-gateway-prod -a NAME -w VALUE` per entry, and
// `wrangler secret put` for the three Worker secrets. Values must be printable ASCII (macOS `security -w` returns anything else as hex); the gateway's generated secrets are. Usage: node tools/secrets_backup.mjs --recipient age1... --out FILE [--service macguard-gateway-prod]
import { execFileSync } from 'node:child_process';
import { chmodSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const arg = (n, d = null) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : d; };
const recipient = arg('--recipient'), out = arg('--out') && resolve(arg('--out')), service = arg('--service', 'macguard-gateway-prod');
const NAMES = (arg('--names') ?? 'KEY_PEPPER,ADMIN_PEPPER,TOTP_SEAL_KEY,ADMIN_KEY,ADMIN_TOTP_SEED,ADMIN_ID').split(',');
if (!/^age1[a-z0-9]{50,}$/.test(recipient ?? '') || !out) { console.error('usage: secrets_backup.mjs --recipient age1... --out FILE'); process.exit(2); }
if (/^(\/tmp|\/private\/tmp|\/var\/folders)|scratchpad/.test(out)) { console.error('refusing to write the encrypted backup into a temporary directory'); process.exit(2); }
const got = {}; for (const n of NAMES) { try { got[n] = execFileSync('security', ['find-generic-password', '-s', service, '-a', n, '-w'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch { console.error('missing in the Keychain: ' + n); process.exit(1); } }
const enc = execFileSync('age', ['-r', recipient], { input: JSON.stringify({ schema: 'macguard.secrets-backup/1', service, created_at: new Date().toISOString(), secrets: got }) });
writeFileSync(out, enc, { mode: 0o600 }); chmodSync(out, 0o600); console.log(`encrypted ${NAMES.length} secrets for the recipient -> ${out} (${enc.length} bytes); no value was printed`);
