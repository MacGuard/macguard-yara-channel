import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { dumpSql } from '../tools/backup_lib.mjs';
import { runBackup, check, retentionPlan, prune, isTemp, ageEncryptFile, shaFile } from '../tools/backup_flow.mjs';
import { world } from './helpers.js';
import { audit } from '../src/audit.js';

const HAVE_AGE = existsSync('/usr/local/bin/age') && process.platform === 'darwin';
const sha = (b) => createHash('sha256').update(b).digest('hex');
async function sample() { const w = await world({ now: '2026-10-24T05:00:00Z' }); await w.tenant('t1'); await audit(w.db, w.clock, 't1', 'x.y', { a: 1 }); return w; }
function sandbox() { const root = mkdtempSync(join(homedir(), '.mg-bk-test-')); return { root, done: () => rmSync(root, { recursive: true, force: true }) }; }
const byRule = (alerts) => Object.fromEntries(alerts.map((a) => [a.rule_id, a.state]));
const T = (h) => () => new Date(Date.parse('2026-10-24T06:00:00Z') + h * 3600000);

test('an unencrypted backup is verified, recorded, and flagged as unencrypted; an unknown directory is refused if it is temporary', async () => {
  const w = await sample(), sb = sandbox();
  try {
    const r = await runBackup({ exportFn: async (p) => writeFileSync(p, dumpSql(w.db.raw)), root: sb.root, clock: T(0), meta: { database: 'test' } });
    assert.equal(r.ok, true); assert.ok(existsSync(join(r.dir, 'd1-export.sql')) && existsSync(join(r.dir, 'SHA256SUMS')));
    const st = byRule(check({ root: sb.root, clock: T(1) })); assert.equal(st['backup.stale'], 'OK'); assert.equal(st['backup.integrity'], 'OK'); assert.equal(st['backup.unencrypted'], 'FIRING');
    assert.equal(byRule(check({ root: sb.root, clock: T(1), requireEncrypted: false }))['backup.unencrypted'], undefined);
    await assert.rejects(runBackup({ exportFn: async () => {}, root: '/private/tmp/x-backups' }), /temporary/); assert.equal(isTemp('/var/folders/ab/cd'), true);
  } finally { sb.done(); }
});
test('an age-encrypted backup leaves no plaintext behind, decrypts to exactly what was verified, and passes every alarm', { skip: !HAVE_AGE }, async () => {
  const w = await sample(), sb = sandbox(), keyDir = mkdtempSync(join(homedir(), '.mg-bk-key-')), key = join(keyDir, 'k.txt');
  try {
    execFileSync('age-keygen', ['-o', key], { stdio: 'ignore' }); const pub = execFileSync('age-keygen', ['-y', key], { encoding: 'utf8' }).trim();
    const r = await runBackup({ exportFn: async (p) => writeFileSync(p, dumpSql(w.db.raw)), root: sb.root, recipient: pub, clock: T(0) });
    assert.equal(r.ok, true); assert.equal(r.name, 'd1-export.sql.age'); assert.ok(!readdirSync(r.dir).includes('d1-export.sql'), 'no plaintext file');
    const all = []; const walk = (d) => { for (const f of readdirSync(d, { withFileTypes: true })) f.isDirectory() ? walk(join(d, f.name)) : all.push(join(d, f.name)); }; walk(sb.root);
    assert.ok(all.every((f) => !readFileSync(f).includes('CREATE TABLE')), 'no readable schema anywhere under the backup root');
    const dec = execFileSync('age', ['-d', '-i', key, join(r.dir, 'd1-export.sql.age')]); assert.equal(sha(dec), r.manifest.plaintext_sha256, 'decrypts to exactly the verified plaintext');
    const st = byRule(check({ root: sb.root, clock: T(2) })); assert.deepEqual(Object.entries(st).filter(([, v]) => v !== 'OK'), [], JSON.stringify(st));
    const { verifyRestore } = await import('../tools/backup_lib.mjs'); assert.equal((await verifyRestore(dec.toString('utf8'))).ok, true, 'the decrypted export restores in isolation');
    writeFileSync(join(r.dir, 'd1-export.sql.age'), Buffer.concat([readFileSync(join(r.dir, 'd1-export.sql.age')), Buffer.from('x')])); assert.equal(byRule(check({ root: sb.root, clock: T(2) }))['backup.integrity'], 'FIRING', 'a modified ciphertext is detected');
  } finally { sb.done(); rmSync(keyDir, { recursive: true, force: true }); }
});
test('an age-encrypted backup larger than the default child-process buffer (1 MiB) is still encrypted and decrypts to the verified plaintext', { skip: !HAVE_AGE }, async () => {
  const w = await sample(), sb = sandbox(), keyDir = mkdtempSync(join(homedir(), '.mg-bk-key-')), key = join(keyDir, 'k.txt');
  try {
    execFileSync('age-keygen', ['-o', key], { stdio: 'ignore' }); const pub = execFileSync('age-keygen', ['-y', key], { encoding: 'utf8' }).trim();
    const big = '-- ' + createHash('sha512').update('pad').digest('hex').repeat(32768) + '\n';   // ~4 MiB of comment: restores to nothing, but the ciphertext is far above 1 MiB
    const r = await runBackup({ exportFn: async (p) => writeFileSync(p, big + dumpSql(w.db.raw)), root: sb.root, recipient: pub, clock: T(0) });
    assert.equal(r.ok, true, r.error); assert.ok(r.manifest.stored_bytes > (1 << 20), 'the ciphertext exceeds the default 1 MiB buffer');
    const dec = execFileSync('age', ['-d', '-i', key, join(r.dir, 'd1-export.sql.age')], { maxBuffer: 1 << 30 }); assert.equal(sha(dec), r.manifest.plaintext_sha256);
  } finally { sb.done(); rmSync(keyDir, { recursive: true, force: true }); }
});

// ---- streaming age: failure modes (fake age binaries) and a large real file ----
const PUB = 'age1' + 'q'.repeat(58);
function fakeAge(dir, body) { const f = join(dir, 'age-fake'); writeFileSync(f, '#!/usr/bin/env node\n' + body); chmodSync(f, 0o755); return f; }
const PRE = "const fs=require('fs');";
test('streaming age: every incomplete or failed encryption is refused, leaves no partial/ciphertext behind and never puts plaintext in the error', async () => {
  const sb = sandbox(), src = join(sb.root, 'plain.sql'); writeFileSync(src, 'SECRET-PLAINTEXT-MARKER '.repeat(1000));
  const cases = {
    'exit code 1 after partial output': PRE + "fs.writeSync(1,'age-encryption.org/v1\\n'+'x'.repeat(100));process.stderr.write('boom');process.exit(1)",
    'killed by a signal': PRE + "fs.writeSync(1,'age-encryption.org/v1\\n');process.kill(process.pid,'SIGKILL')",
    'exit 0 with empty output': 'process.exit(0)',
    'exit 0 without an age header': PRE + "fs.writeSync(1,'z'.repeat(40000))",
    'exit 0 but not larger than the plaintext (truncated)': PRE + "fs.writeSync(1,'age-encryption.org/v1\\n'+'x'.repeat(50))",
  };
  try {
    for (const [name, body] of Object.entries(cases)) {
      const bin = fakeAge(sb.root, body), dst = join(sb.root, 'out.age');
      await assert.rejects(() => ageEncryptFile({ ageBin: bin, recipient: PUB, src, dst }), (e) => !/SECRET-PLAINTEXT-MARKER/.test(e.message), name);
      assert.ok(!existsSync(dst) && !existsSync(dst + '.partial'), `${name}: nothing left behind`);
    }
  } finally { sb.done(); }
});

test('streaming age: a failed encryption inside runBackup records the failure, removes the backup directory, keeps the previous good backup and exits no plaintext', async () => {
  const w = await sample(), sb = sandbox(), keyDir = mkdtempSync(join(homedir(), '.mg-bk-key-'));
  try {
    const good = await runBackup({ exportFn: async (p) => writeFileSync(p, dumpSql(w.db.raw)), root: sb.root, clock: T(0) }); assert.equal(good.ok, true);
    const bin = fakeAge(keyDir, PRE + "fs.writeSync(1,'age-encryption.org/v1\\n'+'x'.repeat(5000));process.stderr.write('disk full');process.exit(1)");
    const r = await runBackup({ exportFn: async (p) => writeFileSync(p, dumpSql(w.db.raw)), root: sb.root, recipient: PUB, ageBin: bin, clock: T(5) });
    assert.equal(r.ok, false); assert.equal(r.stage, 'encrypt'); assert.match(r.error, /disk full/);
    const st = JSON.parse(readFileSync(join(sb.root, 'status.json'), 'utf8')); assert.equal(st.last_status, 'failed'); assert.equal(st.last_failed_stage, 'encrypt'); assert.equal(st.last_dir, good.dir.split('/').pop());
    assert.deepEqual(readdirSync(sb.root).filter((n) => /^\d{8}T/.test(n)), [good.dir.split('/').pop()], 'no directory for the failed attempt');
  } finally { sb.done(); rmSync(keyDir, { recursive: true, force: true }); }
});

test('streaming age: a cancelled encryption (AbortSignal) kills age and leaves nothing behind', async () => {
  const sb = sandbox(), src = join(sb.root, 'plain.sql'); writeFileSync(src, 'x'.repeat(1000));
  try {
    const bin = fakeAge(sb.root, "setTimeout(()=>{},60000)"), ac = new AbortController(), dst = join(sb.root, 'o.age');
    const p = ageEncryptFile({ ageBin: bin, recipient: PUB, src, dst, signal: ac.signal }); setTimeout(() => ac.abort(), 150);
    await assert.rejects(p); assert.ok(!existsSync(dst) && !existsSync(dst + '.partial'));
  } finally { sb.done(); }
});

test('streaming age: a 48 MiB export is encrypted with permissions 0600, the stored hash matches the file, and decryption returns the exact plaintext; a truncated copy fails to decrypt', { skip: !HAVE_AGE }, async () => {
  const w = await sample(), sb = sandbox(), keyDir = mkdtempSync(join(homedir(), '.mg-bk-key-')), key = join(keyDir, 'k.txt');
  try {
    execFileSync('age-keygen', ['-o', key], { stdio: 'ignore' }); const pub = execFileSync('age-keygen', ['-y', key], { encoding: 'utf8' }).trim();
    const pad = '-- ' + createHash('sha512').update('pad').digest('hex').repeat(8) + '\n';   // 1 KiB line, repeated below
    const r = await runBackup({ exportFn: async (p) => { writeFileSync(p, pad.repeat(48 * 1024) + dumpSql(w.db.raw)); }, root: sb.root, recipient: pub, clock: T(0) });
    assert.equal(r.ok, true, r.error); const f = join(r.dir, 'd1-export.sql.age');
    assert.ok(r.manifest.plaintext_bytes > 48 * 1024 * 1024 && r.manifest.stored_bytes > r.manifest.plaintext_bytes);
    assert.equal((statSync(f).mode & 0o777).toString(8), '600'); assert.equal(await shaFile(f), r.manifest.stored_sha256);
    assert.equal(readdirSync(r.dir).some((n) => n.endsWith('.partial')), false);
    const dec = execFileSync('age', ['-d', '-i', key, f], { maxBuffer: 1 << 30 }); assert.equal(sha(dec), r.manifest.plaintext_sha256);
    const cut = join(keyDir, 'cut.age'); writeFileSync(cut, readFileSync(f).subarray(0, r.manifest.stored_bytes - 100));
    assert.throws(() => execFileSync('age', ['-d', '-i', key, cut], { maxBuffer: 1 << 30, stdio: 'pipe' }), 'a truncated ciphertext does not decrypt');
  } finally { sb.done(); rmSync(keyDir, { recursive: true, force: true }); }
});

test('a failed export or a failed verification is recorded, raises alarms, creates no backup and never damages the previous good one', async () => {
  const w = await sample(), sb = sandbox();
  try {
    const good = await runBackup({ exportFn: async (p) => writeFileSync(p, dumpSql(w.db.raw)), root: sb.root, clock: T(0) }); assert.equal(good.ok, true);
    const e = await runBackup({ exportFn: async () => { throw new Error('wrangler: network down'); }, root: sb.root, clock: T(24) }); assert.equal(e.ok, false); assert.equal(e.stage, 'export');
    let st = byRule(check({ root: sb.root, clock: T(25) })); assert.equal(st['backup.last_attempt_failed'], 'FIRING'); assert.equal(st['backup.stale'], 'OK', '25 h since the last good one is inside the 30 h limit'); assert.equal(byRule(check({ root: sb.root, clock: T(31) }))['backup.stale'], 'FIRING');
    const bad = dumpSql(w.db.raw).replace("'x.y'", "'x.forged'"); const v = await runBackup({ exportFn: async (p) => writeFileSync(p, bad), root: sb.root, clock: T(26) }); assert.equal(v.ok, false); assert.equal(v.stage, 'verify');
    assert.equal(readdirSync(sb.root).filter((n) => /^\d{8}T/.test(n)).length, 1, 'only the good backup exists'); assert.ok(existsSync(join(good.dir, 'd1-export.sql')));
    assert.equal(JSON.parse(readFileSync(join(sb.root, 'status.json'), 'utf8')).last_dir, good.dir.split('/').pop(), 'status still points at the last good backup');
    assert.equal(byRule(check({ root: sb.root, clock: T(26) }))['backup.integrity'], 'OK');
  } finally { sb.done(); }
});
test('staleness and absence raise their own alarms', async () => {
  const w = await sample(), sb = sandbox();
  try {
    assert.equal(byRule(check({ root: join(sb.root, 'never') }))['backup.missing'], 'FIRING');
    await runBackup({ exportFn: async (p) => writeFileSync(p, dumpSql(w.db.raw)), root: sb.root, clock: T(0) });
    assert.equal(byRule(check({ root: sb.root, clock: T(29) }))['backup.stale'], 'OK'); assert.equal(byRule(check({ root: sb.root, clock: T(31) }))['backup.stale'], 'FIRING');
    const never = mkdtempSync(join(homedir(), '.mg-bk-test-')); writeFileSync(join(never, 'status.json'), JSON.stringify({ last_status: 'failed', last_failed_stage: 'export', last_error: 'x' })); assert.equal(byRule(check({ root: never, clock: T(0) }))['backup.never_succeeded'], 'FIRING'); rmSync(never, { recursive: true });
  } finally { sb.done(); }
});
test('retention keeps the newest daily / weekly / monthly backups, never the newest-removal, ignores foreign names, and removes nothing without apply', () => {
  const names = []; for (let i = 0; i < 120; i++) { const d = new Date(Date.UTC(2026, 9, 24) - i * 86400000); names.push(d.toISOString().slice(0, 10).replace(/-/g, '') + 'T060000Z'); }
  const plan = retentionPlan([...names, 'status.json', 'notes.txt', 'README', '2026-10-24']); assert.ok(plan.keep.includes(names[0]), 'the newest is kept'); assert.ok(names.slice(0, 7).every((n) => plan.keep.includes(n)), 'the last 7 daily are kept');
  assert.ok(plan.remove.length > 60 && plan.keep.length < 40); assert.ok(![...plan.keep, ...plan.remove].some((n) => !/^\d{8}T\d{6}Z$/.test(n)), 'foreign names are never considered');
  const sb = sandbox(); try { for (const n of names.slice(0, 20)) mkdirSync(join(sb.root, n)); writeFileSync(join(sb.root, 'status.json'), JSON.stringify({ last_dir: names[19] })); writeFileSync(join(sb.root, 'keep-me.txt'), 'x');
    const dry = prune({ root: sb.root }); assert.equal(dry.applied, false); assert.equal(readdirSync(sb.root).length, 22, 'a dry run removes nothing'); assert.ok(!dry.remove.includes(names[19]), 'the directory status.json points at is protected');
    const done = prune({ root: sb.root, apply: true, daily: 3, weekly: 1, monthly: 1 }); const left = readdirSync(sb.root); assert.ok(left.includes('keep-me.txt') && left.includes('status.json') && left.includes(names[0]) && left.includes(names[19])); assert.equal(left.filter((n) => /^\d{8}T/.test(n)).length, done.keep.length + (done.keep.includes(names[19]) ? 0 : 1));
  } finally { sb.done(); }
});

test('a pinned backup (protected.json) and the status target are never removed even by an applied prune', () => {
  const sb = sandbox(); try {
    const names = Array.from({ length: 30 }, (_, i) => new Date(Date.UTC(2026, 9, 24) - i * 86400000).toISOString().slice(0, 10).replace(/-/g, '') + 'T060000Z'); for (const n of names) mkdirSync(join(sb.root, n));
    writeFileSync(join(sb.root, 'protected.json'), JSON.stringify({ [names[25]]: 'pinned' })); writeFileSync(join(sb.root, 'status.json'), JSON.stringify({ last_dir: names[0] }));
    const r = prune({ root: sb.root, apply: true, daily: 2, weekly: 1, monthly: 1 }); const left = readdirSync(sb.root); assert.ok(left.includes(names[25]), 'pinned'); assert.ok(left.includes(names[0])); assert.deepEqual(r.protected, [names[25]]); assert.ok(r.remove.length > 10 && !left.includes(r.remove[0]));
  } finally { sb.done(); }
});

test('restore_to_staging refuses production and unconfirmed targets and defaults to a dry run', async () => {
  const w = await sample(), sb = sandbox(), run = (...a) => { try { return { code: 0, out: execFileSync('node', [new URL('../tools/restore_to_staging.mjs', import.meta.url).pathname, ...a], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }) }; } catch (e) { return { code: e.status, out: String(e.stderr) + String(e.stdout) }; } };
  try {
    const f = join(sb.root, 'x.sql'); writeFileSync(f, dumpSql(w.db.raw));
    for (const bad of ['macguard-gateway', 'macguard-gateway-prod', 'staging', 'x']) assert.equal(run('--export', f, '--staging', bad).code, 2, bad);
    const dry = run('--export', f, '--staging', 'macguard-gateway-staging'); assert.equal(dry.code, 0); assert.match(dry.out, /DRY RUN \(nothing executed\)/); assert.match(dry.out, /d1 create macguard-gateway-staging/);
    assert.equal(run('--export', f, '--staging', 'macguard-gateway-staging', '--apply').code, 2, 'apply without confirmation'); assert.equal(run('--export', f, '--staging', 'macguard-gateway-staging', '--apply', '--confirm-database', 'other-staging').code, 2);
    writeFileSync(f, dumpSql(w.db.raw).replace("'x.y'", "'forged'")); assert.equal(run('--export', f, '--staging', 'macguard-gateway-staging').code, 1, 'an export that does not verify is never restored');
  } finally { sb.done(); }
});
