// Node-side run records and outbox: the same guarantees as intel/telemetry.py. Backups emit one witness record per destination and operation without ever changing their own result.
import test from 'node:test';
import { HAVE_AGE } from './tools_available.js';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { Outbox, makeRecord, classify, scrub, httpSender, outboxFromEnv } from '../tools/telemetry.mjs';
import { DEFAULT_CONFIG, PROVIDERS, syncAll, verifyAll, drillOne } from '../tools/backup_objstore.mjs';
import { dumpSql } from '../tools/backup_lib.mjs';
import { runBackup } from '../tools/backup_flow.mjs';
import { world } from './helpers.js';
import { audit } from '../src/audit.js';

const CFG = { ...DEFAULT_CONFIG, destinations: { ...DEFAULT_CONFIG.destinations, scaleway: { ...DEFAULT_CONFIG.destinations.scaleway, bucket: 'macguard-archive-scw' } } };
const tmp = (p) => mkdtempSync(join(homedir(), p));
const store = ({ failPut = null, failGet = null } = {}) => { const m = new Map(); return { m, async head(k) { return m.has(k); }, async get(k) { if (failGet) throw new Error(failGet); return m.get(k) ?? null; }, async put(k, d) { if (failPut) throw new Error(failPut); m.set(k, Buffer.from(d)); } }; };
const keypair = (dir) => { const f = join(dir, 'k.txt'); execFileSync('age-keygen', ['-o', f], { stdio: 'ignore' }); return { file: f, pub: execFileSync('age-keygen', ['-y', f], { encoding: 'utf8' }).trim() }; };
const records = (dir) => readdirSync(dir).filter((n) => n.endsWith('.json')).map((n) => JSON.parse(readFileSync(join(dir, n), 'utf8')));

test('classification uses the HTTP status first and the words of the error second; secrets never survive; records are well formed', () => {
  assert.deepEqual(classify(new Error('PUT 403')), { error_class: 'AUTH', http_status: 403 }); assert.equal(classify(new Error('GET 429')).error_class, 'RATE_LIMIT'); assert.equal(classify(new Error('PUT 503')).error_class, 'HTTP');
  assert.equal(classify(new Error('the object read back differs from what was sent')).error_class, 'INTEGRITY'); assert.equal(classify(new Error('The operation was aborted due to timeout')).error_class, 'TIMEOUT'); assert.equal(classify(new Error('getaddrinfo ENOTFOUND x')).error_class, 'DNS');
  assert.doesNotMatch(scrub('failed Bearer abcdefghijklmnopqrstuv token=ABCDEFGHIJKLMN'), /abcdefghijklmnop|ABCDEFGHIJKLMN/);
  const r = makeRecord({ source_id: 'backup:b2', operation: 'upload', started: 1000, finished: 3500, counters: { files_attempted: 3, files_downloaded: 3, bytes_downloaded: 10 } });
  assert.deepEqual([r.schema, r.status, r.error_class, r.duration_ms, r.started_at], ['macguard.source-run/1', 'ok', null, 2500, '1970-01-01T00:00:01Z']); assert.match(r.run_id, /^[0-9a-f]{32}$/);
  assert.equal(makeRecord({ source_id: 's', started: 0, status: 'failed' }).error_class, 'OTHER', 'a failed record always has a class');
});

test('outbox: the record is on disk before any send; a failed send keeps it with a scrubbed note; flush after an outage delivers once; a restart loses nothing; an unwritable outbox never throws', async () => {
  const dir = tmp('.mg-tel-'), seen = [];
  try {
    let up = false; const send = async (rec) => { seen.push(existsSync(join(dir, `${rec.run_id}.json`))); if (!up) throw new Error('panel down token=ABCDEFGHIJKLMNOP'); };
    const a = new Outbox(dir, send); for (let i = 0; i < 3; i++) assert.equal(await a.emit(makeRecord({ source_id: 'backup:b2', started: i, run_id: `r${i}aaaaaaaa` })), false);
    assert.deepEqual(seen, [true, true, true]); assert.equal(a.pending().length, 3); const note = readFileSync(join(dir, 'r0aaaaaaaa.error'), 'utf8'); assert.doesNotMatch(note, /ABCDEFGHIJKLMNOP/);
    const b = new Outbox(dir, send); assert.deepEqual(await b.flush(), { sent: 0, failed: 3 }); up = true; assert.deepEqual(await b.flush(), { sent: 3, failed: 0 }); assert.deepEqual(await b.flush(), { sent: 0, failed: 0 }); assert.equal(readdirSync(join(dir, 'sent')).length, 3);
    rmSync(dir, { recursive: true }); writeFileSync(dir, 'a file where the directory was'); assert.equal(await new Outbox(dir, send).emit(makeRecord({ source_id: 's', started: 0 })), false, 'no throw');
  } finally { rmSync(dir, { recursive: true, force: true }); }
  assert.throws(() => httpSender('http://example.com/x'), /HTTPS/); assert.equal(outboxFromEnv({}), null);
});

async function backupWorld() {
  const w = await world({ now: '2026-10-24T05:00:00Z' }); await w.tenant('t1'); await audit(w.db, w.clock, 't1', 'x.y', {});
  const root = tmp('.mg-tel-root-'), keys = tmp('.mg-tel-keys-'), box = tmp('.mg-tel-box-'), k = keypair(keys);
  const b = await runBackup({ exportFn: async (p) => writeFileSync(p, dumpSql(w.db.raw)), root, recipient: k.pub, clock: () => new Date('2026-10-24T06:00:00Z') });
  return { root, keys, box, k, stamp: b.dir.split('/').pop(), done: () => [root, keys, box].forEach((d) => rmSync(d, { recursive: true, force: true })) };
}

test('backups emit one witness record per destination: upload ok / failed (AUTH) / conflict (INTEGRITY), verify, restore drill; counts are exact and the result of the operation is unchanged', { skip: !HAVE_AGE }, async () => {
  const s = await backupWorld();
  try {
    const ok = store(), denied = store({ failPut: 'PUT 403' }), r2 = store(); const stores = { b2: ok, scaleway: denied, r2 }; r2.m.set(`gateway-d1/${s.stamp}/d1-export.sql.age`, Buffer.from('tampered'));
    const ob = new Outbox(s.box), base = { root: s.root, config: CFG, clientOverride: stores };
    const withT = await syncAll({ ...base, apply: true, telemetry: ob }); const without = await syncAll({ ...base, apply: true });
    assert.deepEqual(Object.fromEntries(PROVIDERS.map((n) => [n, withT.destinations[n].ok])), { b2: true, scaleway: false, r2: false }, 'the report is what it always was');
    assert.deepEqual(without.destinations.b2.already_there, [s.stamp], 'a second run finds the copy already there');
    const rec = Object.fromEntries(records(s.box).map((r) => [r.source_id + (r.status === 'not_modified' ? ':nm' : ''), r]));
    assert.equal(rec['backup:b2'].status, 'ok'); assert.deepEqual([rec['backup:b2'].operation, rec['backup:b2'].files_attempted, rec['backup:b2'].files_downloaded, rec['backup:b2'].error_class], ['upload', 3, 3, null]); assert.equal(rec['backup:b2'].bytes_downloaded, ['d1-export.sql.age', 'manifest.json', 'SHA256SUMS'].reduce((a, f) => a + readFileSync(join(s.root, s.stamp, f)).length, 0), 'the bytes uploaded are exactly the size of the three files');
    assert.deepEqual([rec['backup:scaleway'].status, rec['backup:scaleway'].error_class, rec['backup:scaleway'].http_status, rec['backup:scaleway'].files_downloaded], ['failed', 'AUTH', 403, 0]);
    assert.deepEqual([rec['backup:r2'].status, rec['backup:r2'].error_class, rec['backup:r2'].files_downloaded], ['partial', 'INTEGRITY', 2], 'the tampered object is a conflict (never overwritten); the two other files did arrive: a partial copy is not a success'); assert.equal(records(s.box).length, 3, 'one record per destination for the run that emitted; the run without a sink emitted none');
    const ob2 = new Outbox(tmp('.mg-tel-box2-')); await syncAll({ ...base, apply: true, telemetry: ob2, only: ['b2'] }); assert.equal(records(ob2.dir)[0].status, 'not_modified', 'nothing new to upload is a success with no new file'); rmSync(ob2.dir, { recursive: true, force: true });
    const dry = new Outbox(tmp('.mg-tel-box3-')); await syncAll({ ...base, telemetry: dry }); assert.equal(records(dry.dir).length, 0, 'a dry run is not a run'); rmSync(dry.dir, { recursive: true, force: true });
    const vb = new Outbox(tmp('.mg-tel-box4-')); await verifyAll({ ...base, telemetry: vb }); const v = Object.fromEntries(records(vb.dir).map((x) => [x.source_id, x])); assert.deepEqual([v['backup:b2'].operation, v['backup:b2'].status, v['backup:r2'].status, v['backup:scaleway'].status], ['verify', 'ok', 'failed', 'failed']); rmSync(vb.dir, { recursive: true, force: true });
    const db = new Outbox(tmp('.mg-tel-box5-')); const d1 = await drillOne({ ...base, name: 'b2', identityFile: s.k.file, telemetry: db }); assert.equal(d1.ok, true); const dr = records(db.dir)[0]; assert.deepEqual([dr.operation, dr.status, dr.tests_state, dr.source_id], ['restore_drill', 'ok', 'ok', 'backup:b2']);
    const bad = await drillOne({ ...base, name: 'b2', identityFile: join(s.keys, 'nope'), telemetry: db }); assert.equal(bad.ok, false); assert.ok(records(db.dir).some((x) => x.status === 'failed' && x.tests_state === 'failed')); rmSync(db.dir, { recursive: true, force: true });
  } finally { s.done(); }
});

test('an unconfigured destination emits no record; a telemetry sink that throws, hangs its disk or loses its directory changes nothing about the backup', { skip: !HAVE_AGE }, async () => {
  const s = await backupWorld();
  try {
    const stores = { b2: store(), scaleway: store(), r2: store() }, NOBUCKET = { ...DEFAULT_CONFIG, destinations: { ...DEFAULT_CONFIG.destinations, scaleway: { ...DEFAULT_CONFIG.destinations.scaleway, bucket: null } } }, base = { root: s.root, config: NOBUCKET, clientOverride: stores };   // a configuration with no Scaleway bucket
    const ob = new Outbox(s.box); const r = await syncAll({ ...base, apply: true, telemetry: ob, clientOverride: { b2: stores.b2, r2: stores.r2 } }); assert.equal(r.destinations.scaleway.state, 'UNCONFIGURED'); assert.deepEqual(records(s.box).map((x) => x.source_id).sort(), ['backup:b2', 'backup:r2']);
    const boom = { async emit() { throw new Error('disk full'); } }; const again = await syncAll({ ...base, config: CFG, apply: true, telemetry: boom }); assert.equal(again.destinations.b2.ok, true, 'a throwing sink is swallowed');
    rmSync(s.box, { recursive: true }); writeFileSync(s.box, 'x'); const third = await syncAll({ ...base, config: CFG, apply: true, telemetry: new Outbox(s.box) }); assert.equal(third.destinations.r2.ok, true);
  } finally { s.done(); }
});
