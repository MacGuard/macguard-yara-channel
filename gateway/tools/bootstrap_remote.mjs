// First-time bootstrap of a NEW gateway database: installs the seed commercial policy (FREE_LAUNCH) and the first administrator, on a scratch SQLite file, and exports exactly those rows as SQL
// for `wrangler d1 execute --remote --file`. The administrator's key and TOTP seed are written ONLY to --secret-out (mode 0600) for the caller to move into a secret store; nothing secret is printed.
// `--admin-only` emits ONLY the administrator row (no policy, no audit): for a staging database restored from a production copy, which already has the policy and the audit chain but whose administrators were
// sealed with the production peppers and cannot sign in under the new staging ones.
// Usage: ADMIN_PEPPER=... TOTP_SEAL_KEY=... node tools/bootstrap_remote.mjs --out FILE.sql --secret-out FILE.json [--admin-name owner] [--admin-only]
import { readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { openDb } from './sqlite_d1.mjs';
import { seedPolicy } from '../src/policy.js';
import { createAdmin } from '../src/admin.js';

const arg = (n, d = null) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : d; };
const out = arg('--out'), secretOut = arg('--secret-out'); if (!out || !secretOut) { console.error('usage: bootstrap_remote.mjs --out FILE.sql --secret-out FILE.json'); process.exit(2); }
const env = { ADMIN_PEPPER: process.env.ADMIN_PEPPER, TOTP_SEAL_KEY: process.env.TOTP_SEAL_KEY };
if (!env.ADMIN_PEPPER || env.ADMIN_PEPPER.length < 32 || !env.TOTP_SEAL_KEY || env.TOTP_SEAL_KEY.length < 32) { console.error('ADMIN_PEPPER and TOTP_SEAL_KEY (>= 32 chars) are required in the environment'); process.exit(2); }
const db = openDb(':memory:'), clock = () => new Date();
await seedPolicy(db, clock, JSON.parse(readFileSync(new URL('../../config/commercial/policy.seed.json', import.meta.url), 'utf8')));
const admin = await createAdmin(db, env, clock, { name: arg('--admin-name', 'owner') });
const q = (v) => (v === null || v === undefined ? 'NULL' : typeof v === 'number' || typeof v === 'bigint' ? String(v) : `'${String(v).replace(/'/g, "''")}'`);
const dump = (table) => db.raw.prepare(`SELECT * FROM ${table}`).all().map((r) => `INSERT INTO ${table}(${Object.keys(r).join(',')}) VALUES (${Object.values(r).map(q).join(',')});`);
const tables = process.argv.includes('--admin-only') ? ['admins'] : ['policy_versions', 'policy_pointer', 'admins', 'audit'];
writeFileSync(out, tables.flatMap(dump).join('\n') + '\n');
writeFileSync(secretOut, JSON.stringify({ admin_id: admin.id, admin_key: admin.key, totp_seed_base32: admin.totp_seed_base32 }), { mode: 0o600 }); chmodSync(secretOut, 0o600);
console.log(`bootstrap SQL written (${dump('policy_versions').length} policy, ${dump('admins').length} admin, ${dump('audit').length} audit rows); secrets written to the 0600 file, not printed`);
