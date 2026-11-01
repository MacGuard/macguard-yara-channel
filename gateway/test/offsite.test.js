// Off-machine copy and restore drill. Local: the "off-machine" destination is a second directory; no network, no Keychain.
import test from 'node:test';
import { HAVE_AGE } from './tools_available.js';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, readdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { dumpSql } from '../tools/backup_lib.mjs';
import { runBackup } from '../tools/backup_flow.mjs';
import { offsiteSync, restoreDrill, custodyCheck } from '../tools/backup_offsite.mjs';
import { world } from './helpers.js';
import { audit } from '../src/audit.js';

const keypair = (dir, name) => { const f = join(dir, name); execFileSync('age-keygen', ['-o', f], { stdio: 'ignore' }); return { file: f, pub: execFileSync('age-keygen', ['-y', f], { encoding: 'utf8' }).trim() }; };
async function setup() {
  const w = await world({ now: '2026-10-24T05:00:00Z' }); await w.tenant('t1'); await audit(w.db, w.clock, 't1', 'x.y', {});
  const mk = (p) => mkdtempSync(join(homedir(), p)), root = mk('.mg-os-root-'), dest = mk('.mg-os-dest-'), keys = mk('.mg-os-keys-'), k = keypair(keys, 'k.txt'), other = keypair(keys, 'other.txt');
  const backup = (iso) => runBackup({ exportFn: async (p) => writeFileSync(p, dumpSql(w.db.raw)), root, recipient: k.pub, clock: () => new Date(iso) });
  return { w, root, dest, keys, k, other, backup, done: () => [root, dest, keys].forEach((d) => rmSync(d, { recursive: true, force: true })) };
}

test('sync: a dry run copies nothing; --apply copies only ciphertext, verified; a second run copies nothing; the original is untouched', { skip: !HAVE_AGE }, async () => {
  const s = await setup();
  try {
    const b1 = await s.backup('2026-10-24T06:00:00Z'), b2 = await s.backup('2026-10-25T06:00:00Z');
    const dry = offsiteSync({ allowSameVolume: true, root: s.root, dest: s.dest }); assert.equal(dry.copied.length, 2); assert.ok(dry.copied.every((c) => c.planned)); assert.equal(readdirSync(s.dest).length, 0, 'a dry run writes nothing');
    const r = offsiteSync({ allowSameVolume: true, root: s.root, dest: s.dest, apply: true, clock: () => new Date('2026-10-25T07:00:00Z') }); assert.equal(r.ok, true); assert.equal(r.copied.length, 2);
    for (const b of [b1, b2]) assert.deepEqual(readFileSync(join(s.dest, b.dir.split('/').pop(), 'd1-export.sql.age')), readFileSync(join(b.dir, 'd1-export.sql.age')));
    const again = offsiteSync({ allowSameVolume: true, root: s.root, dest: s.dest, apply: true, clock: () => new Date('2026-10-26T07:00:00Z') }); assert.equal(again.copied.length, 0); assert.equal(again.already_there.length, 2);
    assert.equal(JSON.parse(readFileSync(join(s.root, 'offsite.json'), 'utf8')).last_sync_at, '2026-10-26T07:00:00Z', 'a run that verifies the copy is up to date counts as a sync');
  } finally { s.done(); }
});

test('sync: a plaintext backup is never copied off the machine, and an existing different file is never overwritten', { skip: !HAVE_AGE }, async () => {
  const s = await setup();
  try {
    mkdirSync(join(s.root, '20261023T200122Z'), { mode: 0o700 }); writeFileSync(join(s.root, '20261023T200122Z', 'd1-export.sql'), 'PLAINTEXT-MUST-STAY'); writeFileSync(join(s.root, '20261023T200122Z', 'manifest.json'), '{}');
    const b = await s.backup('2026-10-24T06:00:00Z'), stamp = b.dir.split('/').pop();
    const r = offsiteSync({ allowSameVolume: true, root: s.root, dest: s.dest, apply: true }); assert.equal(r.skipped_plaintext.length, 1); assert.ok(!existsSync(join(s.dest, '20261023T200122Z')), 'nothing of the plaintext directory exists at the destination');
    assert.ok(!readdirSync(s.dest).some((n) => readFileSync(join(s.dest, n, 'manifest.json'), 'utf8') === '{}'));
    writeFileSync(join(s.dest, stamp, 'd1-export.sql.age'), 'tampered at the destination'); const c = offsiteSync({ allowSameVolume: true, root: s.root, dest: s.dest, apply: true });
    assert.equal(c.ok, false); assert.equal(c.conflicts.length, 1); assert.equal(readFileSync(join(s.dest, stamp, 'd1-export.sql.age'), 'utf8'), 'tampered at the destination', 'never overwritten');
  } finally { s.done(); }
});

test('sync refuses a destination that is temporary, relative, the backup folder, inside it, or containing it', { skip: !HAVE_AGE }, async () => {
  const s = await setup();
  try {
    for (const dest of ['/private/tmp/x', '/tmp/x', 'relative/dir', s.root, join(s.root, 'sub'), homedir()]) assert.throws(() => offsiteSync({ root: s.root, dest }), /destination|absolute|temporary/, dest);
  } finally { s.done(); }
});

test('a destination on the same volume as the backups is refused (it is not an off-machine copy), unless explicitly allowed for a rehearsal', { skip: !HAVE_AGE }, async () => {
  const s = await setup();
  try { await s.backup('2026-10-24T06:00:00Z'); assert.throws(() => offsiteSync({ root: s.root, dest: s.dest }), /same volume/); assert.throws(() => offsiteSync({ root: s.root, dest: '/Volumes/Muky HD/anything' }), /same volume|destination|absolute/); assert.equal(offsiteSync({ allowSameVolume: true, root: s.root, dest: s.dest }).ok, true); }
  finally { s.done(); }
});

test('drill: restores the COPY with a key file (no Keychain), records it, and still passes when the original is gone; a wrong key or a tampered copy fails and is recorded', { skip: !HAVE_AGE }, async () => {
  const s = await setup();
  try {
    const b = await s.backup('2026-10-24T06:00:00Z'); offsiteSync({ allowSameVolume: true, root: s.root, dest: s.dest, apply: true });
    rmSync(b.dir, { recursive: true, force: true });                                                       // the original is lost: the drill must not need it
    const ok = await restoreDrill({ allowSameVolume: true, root: s.root, dest: s.dest, identityFile: s.k.file, clock: () => new Date('2026-10-26T00:00:00Z') }); assert.equal(ok.ok, true, JSON.stringify(ok)); assert.ok(ok.checks > 0);
    const bad = await restoreDrill({ allowSameVolume: true, root: s.root, dest: s.dest, identityFile: s.other.file, clock: () => new Date('2026-10-27T00:00:00Z') }); assert.equal(bad.ok, false);
    const noKey = await restoreDrill({ allowSameVolume: true, root: s.root, dest: s.dest, identityFile: join(s.keys, 'missing.txt') }); assert.equal(noKey.ok, false); assert.match(noKey.reason, /key file/);
    const stamp = readdirSync(s.dest)[0]; writeFileSync(join(s.dest, stamp, 'd1-export.sql.age'), 'x'); const t = await restoreDrill({ allowSameVolume: true, root: s.root, dest: s.dest, identityFile: s.k.file }); assert.equal(t.ok, false); assert.match(t.reason, /checksum/);
    const st = JSON.parse(readFileSync(join(s.root, 'drills.json'), 'utf8')); assert.equal(st.last_ok_at, '2026-10-26T00:00:00Z', 'only a passing drill moves last_ok_at'); assert.equal(st.history.length, 4);
    assert.ok(!JSON.stringify(st).includes('AGE-SECRET-KEY'), 'no key material in the record');
  } finally { s.done(); }
});

test('alarms: nothing copied or drilled fires; after a copy and a passing drill they clear; they fire again when stale, and a failed drill fires', { skip: !HAVE_AGE }, async () => {
  const s = await setup();
  try {
    const at = (iso) => () => new Date(iso), firing = (a) => a.filter((x) => x.state === 'FIRING').map((x) => x.rule_id).sort();
    assert.deepEqual(firing(custodyCheck({ root: s.root, clock: at('2026-10-25T00:00:00Z') })), ['backup.drill_stale', 'backup.offsite_stale']);
    await s.backup('2026-10-24T06:00:00Z'); offsiteSync({ allowSameVolume: true, root: s.root, dest: s.dest, apply: true, clock: at('2026-10-24T07:00:00Z') }); await restoreDrill({ allowSameVolume: true, root: s.root, dest: s.dest, identityFile: s.k.file, clock: at('2026-10-24T08:00:00Z') });
    assert.deepEqual(firing(custodyCheck({ root: s.root, clock: at('2026-10-25T00:00:00Z') })), []);
    assert.deepEqual(firing(custodyCheck({ root: s.root, clock: at('2026-10-27T00:00:00Z') })), ['backup.offsite_stale'], 'the copy is older than 48 h');
    assert.deepEqual(firing(custodyCheck({ root: s.root, clock: at('2026-12-01T00:00:00Z') })), ['backup.drill_stale', 'backup.offsite_stale']);
    await restoreDrill({ allowSameVolume: true, root: s.root, dest: s.dest, identityFile: s.other.file, clock: at('2026-10-25T01:00:00Z') });
    assert.ok(firing(custodyCheck({ root: s.root, clock: at('2026-10-25T02:00:00Z') })).includes('backup.drill_failed'));
    assert.ok(custodyCheck({ root: s.root }).every((a) => a.schema === 'macguard.alert/1'));
  } finally { s.done(); }
});
