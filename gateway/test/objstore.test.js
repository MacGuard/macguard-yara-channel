// Replication of the encrypted backups to three independent object stores. Local: each "provider" is an in-memory S3-like store (or a local HTTP server for the real signing client); nothing leaves the machine.
import test from 'node:test';
import { HAVE_AGE } from './tools_available.js';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { dumpSql } from '../tools/backup_lib.mjs';
import { runBackup } from '../tools/backup_flow.mjs';
import { signBackup, signCheckpoint } from '../tools/backup_anchor.mjs';
import { loadCheckpoint } from '../tools/backup_objstore.mjs';
import { execFileSync as sshExec } from 'node:child_process';
import { headsAll } from '../tools/backup_objstore.mjs';
import { DEFAULT_CONFIG, PROVIDERS, loadConfig, s3Client, signV4, syncAll, verifyAll, drillOne, objstoreCheck } from '../tools/backup_objstore.mjs';
import { world } from './helpers.js';
import { audit } from '../src/audit.js';

const CFG = { ...DEFAULT_CONFIG, destinations: { ...DEFAULT_CONFIG.destinations, scaleway: { ...DEFAULT_CONFIG.destinations.scaleway, bucket: 'macguard-archive-scw' } } };   // all three configured for the tests
const keypair = (dir, name) => { const f = join(dir, name); execFileSync('age-keygen', ['-o', f], { stdio: 'ignore' }); return { file: f, pub: execFileSync('age-keygen', ['-y', f], { encoding: 'utf8' }).trim() }; };
const store = ({ failPut = false } = {}) => { const m = new Map(); return { m, async head(k) { return m.has(k); }, async get(k) { return m.get(k) ?? null; }, async put(k, d) { if (failPut) throw new Error('PUT 403'); m.set(k, Buffer.from(d)); } }; };
async function setup() {
  const w = await world({ now: '2026-10-24T05:00:00Z' }); await w.tenant('t1'); await audit(w.db, w.clock, 't1', 'x.y', {});
  const mk = (p) => mkdtempSync(join(homedir(), p)), root = mk('.mg-obj-root-'), keys = mk('.mg-obj-keys-'), k = keypair(keys, 'k.txt'), other = keypair(keys, 'other.txt');
  const backup = (iso) => runBackup({ exportFn: async (p) => writeFileSync(p, dumpSql(w.db.raw)), root, recipient: k.pub, clock: () => new Date(iso) });
  const stores = { b2: store(), scaleway: store(), r2: store() };
  return { w, root, keys, k, other, backup, stores, done: () => [root, keys].forEach((d) => rmSync(d, { recursive: true, force: true })) };
}
const sha = (b) => createHash('sha256').update(b).digest('hex');

test('signV4 reproduces the published AWS Signature V4 test-suite vector (get-vanilla)', () => {
  const auth = signV4({ method: 'GET', path: '/', headers: { host: 'example.amazonaws.com', 'x-amz-date': '20150830T123600Z' }, payloadHash: sha(''), region: 'us-east-1', service: 'service', accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', amz: '20150830T123600Z' });
  assert.match(auth, /Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31$/);
});

test('sync: a dry run uploads nothing; --apply puts identical ciphertext in all three destinations, verified; a second run uploads nothing; plaintext never leaves', { skip: !HAVE_AGE }, async () => {
  const s = await setup();
  try {
    mkdirSync(join(s.root, '20261023T200122Z'), { mode: 0o700 }); writeFileSync(join(s.root, '20261023T200122Z', 'd1-export.sql'), 'PLAINTEXT-MUST-STAY'); writeFileSync(join(s.root, '20261023T200122Z', 'manifest.json'), '{}');
    const b = await s.backup('2026-10-24T06:00:00Z'), stamp = b.dir.split('/').pop(), over = { clientOverride: s.stores, config: CFG, root: s.root };
    const dry = await syncAll({ ...over }); assert.equal(dry.skipped_plaintext.length, 1); for (const n of PROVIDERS) { assert.equal(dry.destinations[n].uploaded[0].planned, true); assert.equal(s.stores[n].m.size, 0); }
    const r = await syncAll({ ...over, apply: true, clock: () => new Date('2026-10-24T07:00:00Z') });
    for (const n of PROVIDERS) { assert.equal(r.destinations[n].ok, true); assert.equal(s.stores[n].m.size, 3); }
    const local = readFileSync(join(b.dir, 'd1-export.sql.age')); for (const n of PROVIDERS) assert.deepEqual(s.stores[n].m.get(`gateway-d1/${stamp}/d1-export.sql.age`), local);
    for (const n of PROVIDERS) assert.ok(![...s.stores[n].m.keys()].some((k) => k.includes('20261023T200122Z')), 'the plaintext directory is never uploaded');
    const again = await syncAll({ ...over, apply: true }); for (const n of PROVIDERS) { assert.equal(again.destinations[n].uploaded.length, 0); assert.deepEqual(again.destinations[n].already_there, [stamp]); }
    const state = readFileSync(join(s.root, 'objstore.json'), 'utf8'); assert.doesNotMatch(state, /AGE-SECRET-KEY|secret|KEY_ID/i, 'no credential or key material in the state file');
  } finally { s.done(); }
});

test('independence: a destination that fails, conflicts or is not configured never stops or alters the others, and "three copies" is only claimed when all three verified', { skip: !HAVE_AGE }, async () => {
  const s = await setup();
  try {
    const b = await s.backup('2026-10-24T06:00:00Z'), stamp = b.dir.split('/').pop(); s.stores.scaleway = store({ failPut: true });
    s.stores.r2.m.set(`gateway-d1/${stamp}/d1-export.sql.age`, Buffer.from('tampered at the destination'));
    const over = { clientOverride: s.stores, config: CFG, root: s.root }, r = await syncAll({ ...over, apply: true, clock: () => new Date('2026-10-24T07:00:00Z') });
    assert.equal(r.destinations.b2.ok, true); assert.equal(s.stores.b2.m.size, 3);
    assert.equal(r.destinations.scaleway.ok, false); assert.match(r.destinations.scaleway.errors[0].error, /PUT 403/); assert.equal(s.stores.scaleway.m.size, 0);
    assert.equal(r.destinations.r2.ok, false); assert.equal(r.destinations.r2.conflicts.length, 1); assert.equal(s.stores.r2.m.get(`gateway-d1/${stamp}/d1-export.sql.age`).toString(), 'tampered at the destination', 'never overwritten');
    await verifyAll({ ...over, clock: () => new Date('2026-10-24T07:05:00Z') });
    const al = objstoreCheck({ root: s.root, config: CFG, clock: () => new Date('2026-10-24T08:00:00Z') }), by = Object.fromEntries(al.map((a) => [a.rule_id, a]));
    assert.equal(by['backup.b2.copy_stale'].state, 'OK'); assert.equal(by['backup.scaleway.copy_stale'].state, 'FIRING'); assert.equal(by['backup.r2.copy_stale'].state, 'FIRING');
    assert.equal(by['backup.three_copies'].state, 'FIRING'); assert.equal(by['backup.three_copies'].value, 1);
    const NOBUCKET = { ...DEFAULT_CONFIG, destinations: { ...DEFAULT_CONFIG.destinations, scaleway: { ...DEFAULT_CONFIG.destinations.scaleway, bucket: null } } }, un = await syncAll({ root: s.root, config: NOBUCKET, env: {} }); assert.equal(un.destinations.scaleway.state, 'UNCONFIGURED', 'no bucket named: reported, never guessed'); assert.equal(DEFAULT_CONFIG.destinations.scaleway.bucket, 'macguard-archive-scw', 'the destinations file names the verified Scaleway bucket'); assert.equal(un.destinations.b2.state, 'UNCONFIGURED', 'no credentials in the environment: nothing attempted');
  } finally { s.done(); }
});

test('verify catches a corrupted or missing object at one destination only', { skip: !HAVE_AGE }, async () => {
  const s = await setup();
  try {
    const b = await s.backup('2026-10-24T06:00:00Z'), stamp = b.dir.split('/').pop(), over = { clientOverride: s.stores, config: CFG, root: s.root };
    await syncAll({ ...over, apply: true }); s.stores.r2.m.set(`gateway-d1/${stamp}/manifest.json`, Buffer.from('{"corrupt":1}')); s.stores.scaleway.m.delete(`gateway-d1/${stamp}/SHA256SUMS`);
    const v = await verifyAll(over); assert.equal(v.destinations.b2.ok, true); assert.equal(v.destinations.r2.ok, false); assert.match(v.destinations.r2.reason, /manifest\.json/); assert.equal(v.destinations.scaleway.ok, false); assert.match(v.destinations.scaleway.reason, /SHA256SUMS/);
  } finally { s.done(); }
});

test('restore drill from EACH destination decrypts in isolation; losing one provider leaves the others restorable; a wrong key fails', { skip: !HAVE_AGE }, async () => {
  const s = await setup();
  try {
    await s.backup('2026-10-24T06:00:00Z'); const over = { clientOverride: s.stores, config: CFG, root: s.root }; await syncAll({ ...over, apply: true });
    for (const n of PROVIDERS) { const d = await drillOne({ ...over, name: n, identityFile: s.k.file, clock: () => new Date('2026-10-24T09:00:00Z') }); assert.equal(d.ok, true, `${n}: ${d.reason}`); assert.ok(d.checks > 0); }
    s.stores.b2 = store();                                                                      // the account of one provider is lost
    assert.equal((await drillOne({ ...over, name: 'b2', identityFile: s.k.file })).ok, false);
    for (const n of ['scaleway', 'r2']) assert.equal((await drillOne({ ...over, name: n, identityFile: s.k.file })).ok, true, `${n} still restores`);
    assert.equal((await drillOne({ ...over, name: 'r2', identityFile: s.other.file })).ok, false, 'a key that is not the recipient cannot restore');
    assert.equal((await drillOne({ ...over, name: 'r2', identityFile: join(s.keys, 'nope') })).ok, false);
    const al = Object.fromEntries(objstoreCheck({ root: s.root, config: CFG, clock: () => new Date('2026-10-24T10:00:00Z') }).map((a) => [a.rule_id, a]));
    assert.equal(al['backup.scaleway.drill_stale'].state, 'OK'); assert.equal(al['backup.r2.drill_failed'].state, 'FIRING'); assert.equal(al['backup.b2.drill_failed'].state, 'FIRING');
  } finally { s.done(); }
});

test('the real signing client talks S3 over HTTP: signed headers, signed payload hash, write-once semantics, 404 handling, and no credential in the request line', async () => {
  const objects = new Map(), seen = [], srv = http.createServer((req, res) => {
    const chunks = []; req.on('data', (c) => chunks.push(c)); req.on('end', () => {
      const body = Buffer.concat(chunks); seen.push({ method: req.method, url: req.url, auth: req.headers.authorization, hash: req.headers['x-amz-content-sha256'], date: req.headers['x-amz-date'], sha: sha(body) });
      if (req.method === 'PUT') { objects.set(req.url, body); res.writeHead(200).end(); } else if (objects.has(req.url)) { res.writeHead(200).end(req.method === 'GET' ? objects.get(req.url) : undefined); } else res.writeHead(404).end();
    });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r)); const port = srv.address().port;
  try {
    const c = s3Client({ endpoint: `http://127.0.0.1:${port}`, region: 'eu-central-003', bucket: 'b', accessKeyId: 'AKIDTEST', secretAccessKey: 'SECRETTEST', now: () => new Date('2026-10-24T06:00:00Z') });
    assert.equal(await c.head('p/a b.age'), false); assert.equal(await c.get('p/a b.age'), null);
    await c.put('p/a b.age', Buffer.from('ciphertext')); assert.equal(await c.head('p/a b.age'), true); assert.deepEqual(await c.get('p/a b.age'), Buffer.from('ciphertext'));
    const put = seen.find((x) => x.method === 'PUT'); assert.equal(put.hash, put.sha, 'the signed payload hash is the real hash of the body'); assert.match(put.auth, /^AWS4-HMAC-SHA256 Credential=AKIDTEST\/20261024\/eu-central-003\/s3\/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=[0-9a-f]{64}$/);
    assert.ok(seen.every((x) => !x.url.includes('SECRETTEST') && !(x.auth ?? '').includes('SECRETTEST')), 'the secret never travels');
  } finally { srv.close(); }
});

test('the destinations file names the three providers, holds no secret, and refuses anything that looks like one', () => {
  assert.deepEqual(Object.keys(DEFAULT_CONFIG.destinations).sort(), ['b2', 'r2', 'scaleway']); assert.ok(DEFAULT_CONFIG.destinations.b2.endpoint.includes('eu-central-003'));
  const d = mkdtempSync(join(homedir(), '.mg-obj-cfg-'));
  try {
    const f = join(d, 'c.json'); writeFileSync(f, JSON.stringify({ ...DEFAULT_CONFIG, destinations: { ...DEFAULT_CONFIG.destinations, b2: { ...DEFAULT_CONFIG.destinations.b2, note: 'AGE-SECRET-KEY-1ABC' } } })); assert.throws(() => loadConfig(f), /secrets/);
    writeFileSync(f, JSON.stringify({ ...DEFAULT_CONFIG, destinations: { gcs: {} } })); assert.throws(() => loadConfig(f), /unknown destination/);
    assert.equal(loadConfig(null).prefix, 'gateway-d1');
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test('restore drill: a different but self-consistent backup planted in one bucket is caught by the local anchor; without a local copy the drill passes but says it is not anchored', { skip: !HAVE_AGE }, async () => {
  const s = await setup();
  try {
    const b1 = await s.backup('2026-10-24T06:00:00Z'), stamp = b1.dir.split('/').pop(), over = { clientOverride: s.stores, config: CFG, root: s.root }; await syncAll({ ...over, apply: true });
    const honest = await drillOne({ ...over, name: 'r2', identityFile: s.k.file }); assert.equal(honest.ok, true); assert.equal(honest.anchored, true);
    const b2 = await s.backup('2026-10-24T07:00:00Z');                                        // a second, perfectly valid backup (same key, internally consistent)
    for (const f of ['d1-export.sql.age', 'manifest.json', 'SHA256SUMS']) s.stores.r2.m.set(`gateway-d1/${stamp}/${f}`, readFileSync(join(b2.dir, f)));
    const forged = await drillOne({ ...over, name: 'r2', identityFile: s.k.file }); assert.equal(forged.ok, false); assert.match(forged.reason, /different SHA256SUMS than the local record/);
    assert.equal((await drillOne({ ...over, name: 'b2', identityFile: s.k.file })).ok, true, 'the untouched destinations still restore');
    rmSync(join(s.root, stamp, 'SHA256SUMS')); const noLocal = await drillOne({ ...over, name: 'b2', identityFile: s.k.file }); assert.equal(noLocal.ok, true); assert.equal(noLocal.anchored, false, 'a restore with no local record is reported as not anchored');
  } finally { s.done(); }
});

// ---- the signed anchor through the real sync / verify / drill code -------------------------------------------------------------------------------------------------------
const sshKey = (dir, n) => { const f = join(dir, n); sshExec('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', n, '-f', f]); return { file: f, pub: readFileSync(f + '.pub', 'utf8').trim() }; };
test('anchored backups: the signed statement travels to every destination, verify covers it, and a restore is authenticated with only the public key even when the original machine is gone', { skip: !HAVE_AGE }, async () => {
  const s = await setup();
  try {
    const owner = sshKey(s.root, 'owner'), b1 = await s.backup('2026-10-24T06:00:00Z'), stamp = b1.dir.split('/').pop(); signBackup({ dir: b1.dir, signingKey: owner.file }); const over = { clientOverride: s.stores, config: CFG, root: s.root };
    const sy = await syncAll({ ...over, apply: true }); for (const n of PROVIDERS) assert.equal(sy.destinations[n].ok, true, n);
    for (const n of PROVIDERS) { assert.ok(s.stores[n].m.has(`gateway-d1/${stamp}/ANCHOR.json`) && s.stores[n].m.has(`gateway-d1/${stamp}/ANCHOR.json.sig`), `${n} holds the signed statement`); }
    assert.equal((await verifyAll(over)).destinations.r2.ok, true);
    const trust = { publicKey: owner.pub, minSequence: 1 };
    for (const n of PROVIDERS) { const d = await drillOne({ ...over, name: n, identityFile: s.k.file, trust }); assert.equal(d.ok, true, `${n}: ${d.reason}`); assert.equal(d.anchor, 'signature'); assert.equal(d.sequence, 1); }
    rmSync(join(s.root, stamp), { recursive: true });                                              // the Mac is lost: no local record of this backup remains
    const lost = await drillOne({ ...over, name: 'scaleway', identityFile: s.k.file, trust }); assert.equal(lost.ok, true, lost.reason); assert.equal(lost.anchor, 'signature'); assert.equal(lost.anchored, true);
    const weak = await drillOne({ ...over, name: 'scaleway', identityFile: s.k.file }); assert.equal(weak.ok, true); assert.equal(weak.anchor, 'none'); assert.equal(weak.anchored, false, 'without the trusted key and without a local record nothing authenticates the backup, and it says so');
  } finally { s.done(); }
});

test('anchored backups: a forged self-consistent backup, a rollback, a missing statement and a lost provider, with the original machine gone', { skip: !HAVE_AGE }, async () => {
  const s = await setup();
  try {
    const owner = sshKey(s.root, 'owner'), attacker = sshKey(s.root, 'attacker');
    const b1 = await s.backup('2026-10-24T06:00:00Z'); signBackup({ dir: b1.dir, signingKey: owner.file, clock: () => new Date('2026-10-24T06:00:00Z') });
    const b2 = await s.backup('2026-10-25T06:00:00Z'); signBackup({ dir: b2.dir, signingKey: owner.file, previousDir: b1.dir, clock: () => new Date('2026-10-25T06:00:00Z') });
    const over = { clientOverride: s.stores, config: CFG, root: s.root }; await syncAll({ ...over, apply: true });
    const st1 = b1.dir.split('/').pop(), st2 = b2.dir.split('/').pop(), trust = { publicKey: owner.pub, minSequence: 2 };
    rmSync(join(s.root, st1), { recursive: true }); rmSync(join(s.root, st2), { recursive: true });         // the original machine is gone
    // rollback: r2 serves the older genuine backup under the newest stamp's keys
    for (const f of ['d1-export.sql.age', 'manifest.json', 'SHA256SUMS', 'ANCHOR.json', 'ANCHOR.json.sig']) s.stores.r2.m.set(`gateway-d1/${st2}/${f}`, s.stores.r2.m.get(`gateway-d1/${st1}/${f}`));
    const rb = await drillOne({ ...over, name: 'r2', identityFile: s.k.file, trust }); assert.equal(rb.ok, false); assert.match(rb.reason, /signed anchor does not authenticate|is for|rollback/);
    // forgery: b2 (Scaleway) is replaced by a perfectly consistent backup whose statement is signed by the attacker
    const evil = await s.backup('2026-10-25T07:00:00Z'); signBackup({ dir: evil.dir, signingKey: attacker.file, clock: () => new Date('2026-10-25T07:00:00Z') });
    for (const f of ['d1-export.sql.age', 'manifest.json', 'SHA256SUMS', 'ANCHOR.json', 'ANCHOR.json.sig']) s.stores.scaleway.m.set(`gateway-d1/${st2}/${f}`, readFileSync(join(evil.dir, f)));
    const fg = await drillOne({ ...over, name: 'scaleway', identityFile: s.k.file, trust }); assert.equal(fg.ok, false); assert.match(fg.reason, /signature does not verify/);
    const weak = await drillOne({ ...over, name: 'scaleway', identityFile: s.k.file }); assert.equal(weak.ok, true, 'the same forgery passes WITHOUT the trusted key and without a local record: this is exactly why the key must be kept outside');
    // a statement removed from a destination that is trusted-checked
    s.stores.b2.m.delete(`gateway-d1/${st2}/ANCHOR.json.sig`); const ms = await drillOne({ ...over, name: 'b2', identityFile: s.k.file, trust }); assert.equal(ms.ok, false); assert.match(ms.reason, /no signed anchor/);
  } finally { s.done(); }
});

test('heads: the three destinations are compared by their signed statements with no local copy; a stale, a conflicting, a forged and a lost destination are each reported', { skip: !HAVE_AGE }, async () => {
  const s = await setup();
  try {
    const owner = sshKey(s.root, 'owner'), attacker = sshKey(s.root, 'attacker'), b1 = await s.backup('2026-10-24T06:00:00Z'); signBackup({ dir: b1.dir, signingKey: owner.file, clock: () => new Date('2026-10-24T06:00:00Z') });
    const over = { clientOverride: s.stores, config: CFG }, stamp = b1.dir.split('/').pop(), trust = { publicKey: owner.pub }; await syncAll({ ...over, root: s.root, apply: true });
    let h = await headsAll({ ...over, stamp, trust }); assert.deepEqual(h.current.sort(), ['b2', 'r2', 'scaleway']); assert.equal(h.newest, 1); assert.deepEqual([h.stale, h.conflicts, h.failed, h.gone], [[], [], [], []]);
    s.stores.b2.m.clear();                                                                           // one provider lost
    h = await headsAll({ ...over, stamp, trust }); assert.deepEqual(h.gone, ['b2']); assert.deepEqual(h.current.sort(), ['r2', 'scaleway']);
    const evil = await s.backup('2026-10-24T07:00:00Z'); signBackup({ dir: evil.dir, signingKey: attacker.file });
    for (const f of ['d1-export.sql.age', 'manifest.json', 'SHA256SUMS', 'ANCHOR.json', 'ANCHOR.json.sig']) s.stores.r2.m.set(`gateway-d1/${stamp}/${f}`, readFileSync(join(evil.dir, f)));      // r2 now serves a forgery signed by someone else
    h = await headsAll({ ...over, stamp, trust }); assert.equal(h.failed.length, 1); assert.equal(h.failed[0].name, 'r2'); assert.deepEqual(h.current, ['scaleway']);
    h = await headsAll({ ...over, stamp, trust: { ...trust, minSequence: 2 } }); assert.deepEqual(h.current, [], 'a newest-known sequence of 2 makes every sequence-1 copy a rollback'); assert.ok(h.failed.length >= 1);
  } finally { s.done(); }
});

test('anchored restore drill with an external checkpoint: the confirmed newest passes; a drill that would restore an older backup than the one confirmed is refused', { skip: !HAVE_AGE }, async () => {
  const s = await setup();
  try {
    const owner = sshKey(s.root, 'owner'), b1 = await s.backup('2026-10-24T06:00:00Z'); signBackup({ dir: b1.dir, signingKey: owner.file, clock: () => new Date('2026-10-24T06:00:00Z') });
    const b2 = await s.backup('2026-10-25T06:00:00Z'); signBackup({ dir: b2.dir, signingKey: owner.file, previousDir: b1.dir, clock: () => new Date('2026-10-25T06:00:00Z') });
    const over = { clientOverride: s.stores, config: CFG, root: s.root }; await syncAll({ ...over, apply: true });                       // the providers hold sequences 1 and 2; the newest is 2
    signCheckpoint({ backupDir: b2.dir, outDir: join(s.root, 'cp2'), signingKey: owner.file });
    const cp2 = loadCheckpoint([join(s.root, 'cp2')], owner.pub); assert.equal(cp2.ok, true);
    for (const n of PROVIDERS) { const d = await drillOne({ ...over, name: n, identityFile: s.k.file, trust: { publicKey: owner.pub, checkpoint: cp2.checkpoint } }); assert.equal(d.ok, true, `${n}: ${d.reason}`); assert.equal(d.sequence, 2); }
    // later a third backup is made and confirmed, but the providers are rolled back to sequence 2 (or never got it): the checkpoint of sequence 3 exposes it in every provider
    const b3 = await s.backup('2026-10-26T06:00:00Z'); signBackup({ dir: b3.dir, signingKey: owner.file, previousDir: b2.dir, clock: () => new Date('2026-10-26T06:00:00Z') });
    signCheckpoint({ backupDir: b3.dir, outDir: join(s.root, 'cp3'), signingKey: owner.file }); rmSync(b3.dir, { recursive: true });
    const cp3 = loadCheckpoint([join(s.root, 'cp3'), join(s.root, 'cp2')], owner.pub); assert.equal(cp3.checkpoint.sequence, 3);
    for (const n of PROVIDERS) { const d = await drillOne({ ...over, name: n, identityFile: s.k.file, trust: { publicKey: owner.pub, checkpoint: cp3.checkpoint } }); assert.equal(d.ok, false, n); assert.match(d.reason, /against the external checkpoint: rollback or loss: this copy is sequence 2 but sequence 3 was confirmed/); }
    const blind = await drillOne({ ...over, name: 'r2', identityFile: s.k.file, trust: { publicKey: owner.pub } }); assert.equal(blind.ok, true, 'with the public key alone the same old copy passes: the checkpoint is what closes this');
  } finally { s.done(); }
});
