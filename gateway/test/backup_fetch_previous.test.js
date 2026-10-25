// fetchPrevious: how the workflow learns the predecessor of the next backup from the destinations themselves, and the signed ListObjectsV2 request it relies on. Throw-away keys, in-memory stores.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, createHmac } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { signBackup, chooseHead } from '../tools/backup_anchor.mjs';
import { fetchPrevious, probeReadOnly, s3Client, DEFAULT_CONFIG } from '../tools/backup_objstore.mjs';

let HAVE = true; try { execFileSync('ssh-keygen', ['-Y', 'find-principals'], { stdio: 'pipe' }); } catch (e) { HAVE = !/unknown option|illegal option|usage: ssh-keygen/i.test(String(e.stderr)) || /find-principals/.test(String(e.stderr)); }
const skip = { skip: !HAVE && 'ssh-keygen with -Y support is needed' };
const CFG = { ...DEFAULT_CONFIG };

function ws() {
  const root = mkdtempSync(join(tmpdir(), 'mg-fetchprev-')), key = (n) => { const f = join(root, n); execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', n, '-f', f]); return { file: f, pub: readFileSync(f + '.pub', 'utf8').trim() }; };
  const backup = (stamp, signer, body = stamp) => { const dir = join(root, 'src', body, stamp); mkdirSync(dir, { recursive: true }); for (const f of ['d1-export.sql.age', 'manifest.json', 'SHA256SUMS']) writeFileSync(join(dir, f), f + body); signBackup({ dir, signingKey: signer.file, publicKey: signer.pub }); return Object.fromEntries(readdirSync(dir).map((f) => [f, readFileSync(join(dir, f))])); };
  const store = (objs = {}) => { const m = new Map(Object.entries(objs)); return { m, async bucket() { return 'EXISTS'; }, async head(k) { return m.has(k); }, async get(k) { return m.get(k) ?? null; }, async put(k, b) { m.set(k, b); }, async list(p) { return [...m.keys()].filter((k) => k.startsWith(p)); } }; };
  const put = (st, stamp, files) => { for (const [f, b] of Object.entries(files)) st.m.set(`${CFG.prefix}/${stamp}/${f}`, b); return st; };
  return { root, key, backup, store, put, out: () => join(root, 'out-' + Math.random().toString(16).slice(2)), done: () => rmSync(root, { recursive: true, force: true }) };
}

test('the predecessor is the newest statement that VERIFIES: a forged newer stamp is skipped, a lagging destination is reported, files are written exactly', skip, async () => {
  const w = ws(); try {
    const owner = w.key('owner'), attacker = w.key('attacker'), trust = { publicKey: owner.pub }, good = w.backup('20261024T050235Z', owner), forged = w.backup('20261099T000000Z', attacker);
    const stores = { b2: w.put(w.store(), '20261024T050235Z', good), scaleway: w.put(w.put(w.store(), '20261024T050235Z', good), '20261099T000000Z', forged), r2: w.store() };
    const out = w.out(), r = await fetchPrevious({ trust, outDir: out, clientOverride: stores });
    assert.equal(r.stamp, '20261024T050235Z'); assert.equal(r.sequence, 1); assert.deepEqual(r.current.sort(), ['b2', 'scaleway']); assert.match(r.detail.r2, /no signed backup/); assert.match(r.detail.scaleway, /20261024T050235Z/);
    for (const [f, b] of Object.entries(good)) assert.deepEqual(readFileSync(join(out, r.stamp, f)), b); assert.equal(existsSync(join(out, '20261099T000000Z')), false);
    await assert.rejects(() => fetchPrevious({ trust, outDir: out, clientOverride: stores }), /already exists: nothing is overwritten/);
  } finally { w.done(); }
});

test('refuses when nothing verifies, when the key is not the trusted one, and when two destinations hold different statements for the same sequence', skip, async () => {
  const w = ws(); try {
    const owner = w.key('owner'), other = w.key('other'), a = w.backup('20261024T050235Z', owner, 'A'), b = w.backup('20261024T050235Z', owner, 'B');
    await assert.rejects(() => fetchPrevious({ trust: { publicKey: owner.pub }, outDir: w.out(), clientOverride: { b2: w.store(), scaleway: w.store(), r2: w.store() } }), /no destination holds a signed backup/);
    await assert.rejects(() => fetchPrevious({ trust: { publicKey: other.pub }, outDir: w.out(), clientOverride: { b2: w.put(w.store(), '20261024T050235Z', a) } }), /no destination holds a signed backup/);
    await assert.rejects(() => fetchPrevious({ trust: { publicKey: owner.pub }, outDir: w.out(), clientOverride: { b2: w.put(w.store(), '20261024T050235Z', a), r2: w.put(w.store(), '20261024T050235Z', b) } }), /equivocation/);
  } finally { w.done(); }
});

test('ListObjectsV2 is signed over a sorted, RFC 3986 encoded query that matches the URL, follows pagination and reads keys', async () => {
  const calls = []; const pages = [`<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>tok/en+1</NextContinuationToken><Contents><Key>gateway-d1/20261024T050235Z/manifest.json</Key></Contents></ListBucketResult>`, `<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>gateway-d1/20261025T050235Z/a&amp;b</Key></Contents></ListBucketResult>`];
  const fetchImpl = async (url, init) => { calls.push({ url, init }); return { status: 200, ok: true, arrayBuffer: async () => Buffer.from(pages[calls.length - 1]) }; };
  const c = s3Client({ endpoint: 'https://s3.example.test', region: 'eu-test-1', bucket: 'bkt', accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 'SECRETEXAMPLE', fetchImpl, now: () => new Date('2026-10-25T12:00:00Z') });
  const keys = await c.list('gateway-d1/'); assert.deepEqual(keys, ['gateway-d1/20261024T050235Z/manifest.json', 'gateway-d1/20261025T050235Z/a&b']);
  assert.equal(calls[0].url, 'https://s3.example.test/bkt?list-type=2&prefix=gateway-d1%2F'); assert.equal(calls[1].url, 'https://s3.example.test/bkt?continuation-token=tok%2Fen%2B1&list-type=2&prefix=gateway-d1%2F');
  // independent re-computation of the SigV4 signature of the second request
  const sha = (x) => createHash('sha256').update(x).digest('hex'), hm = (k, s) => createHmac('sha256', k).update(s).digest(), amz = '20261025T120000Z', day = '20261025', payload = sha('');
  const canon = ['GET', '/bkt', 'continuation-token=tok%2Fen%2B1&list-type=2&prefix=gateway-d1%2F', `x-amz-content-sha256:${payload}\nx-amz-date:${amz}\n`, 'x-amz-content-sha256;x-amz-date', payload].join('\n').replace(/^GET\n\/bkt\n/, 'GET\n/bkt\n');
  const hostCanon = ['GET', '/bkt', 'continuation-token=tok%2Fen%2B1&list-type=2&prefix=gateway-d1%2F', `host:s3.example.test\nx-amz-content-sha256:${payload}\nx-amz-date:${amz}\n`, 'host;x-amz-content-sha256;x-amz-date', payload].join('\n');
  const sts = ['AWS4-HMAC-SHA256', amz, `${day}/eu-test-1/s3/aws4_request`, sha(hostCanon)].join('\n'), sig = createHmac('sha256', hm(hm(hm(hm('AWS4SECRETEXAMPLE', day), 'eu-test-1'), 's3'), 'aws4_request')).update(sts).digest('hex');
  assert.ok(calls[1].init.headers.authorization.endsWith(`Signature=${sig}`), 'the Authorization header equals an independent computation'); assert.ok(canon.length > 0);
});

test('statement-only fetch leaves the ciphertext behind; chooseHead takes the highest valid statement, ignores forgeries and refuses equivocation', skip, async () => {
  const w = ws(); try {
    const owner = w.key('owner'), attacker = w.key('attacker'), trust = { publicKey: owner.pub }, good = w.backup('20261024T050235Z', owner), forged = w.backup('20261025T050235Z', attacker, 'forged'), other = w.backup('20261024T050235Z', owner, 'OTHER');
    const out = w.out(), r = await fetchPrevious({ trust, outDir: out, keep: 'statement', clientOverride: { b2: w.put(w.store(), '20261024T050235Z', good) } });
    assert.deepEqual(readdirSync(join(out, r.stamp)).sort(), ['ANCHOR.json', 'ANCHOR.json.sig']);
    const dirOf = (name, files) => { const d = join(w.root, 'cand', name); mkdirSync(d, { recursive: true }); for (const [f, b] of Object.entries(files)) if (f.startsWith('ANCHOR')) writeFileSync(join(d, f), b); return { name, dir: d }; };
    const c = chooseHead({ candidates: [dirOf('a', good), dirOf('forged', forged)], publicKey: owner.pub }); assert.equal(c.stamp, '20261024T050235Z'); assert.equal(c.rejected.length, 1); assert.match(c.rejected[0].reason, /does not verify/);
    assert.throws(() => chooseHead({ candidates: [dirOf('a2', good), dirOf('b2', other)], publicKey: owner.pub }), /equivocation/); assert.throws(() => chooseHead({ candidates: [dirOf('f2', forged)], publicKey: owner.pub }), /no candidate statement verifies/);
  } finally { w.done(); }
});

test('a READ credential must read and must not write: a refused PUT passes, an accepted PUT fails, an unreadable bucket fails', async () => {
  const mk = (writable, bucket = 'EXISTS') => ({ async bucket() { return bucket; }, async list() { return ['gateway-d1/x/y']; }, async put() { if (!writable) throw new Error('PUT 403'); } });
  const r = await probeReadOnly({ clientOverride: { b2: mk(false), scaleway: mk(true), r2: mk(false, 'DENIED') } });
  assert.deepEqual([r.b2.ok, r.scaleway.ok, r.r2.ok], [true, false, false]); assert.match(r.scaleway.reason, /could write/); assert.match(r.r2.reason, /DENIED/);
});

test('a GitHub environment holds ONE provider under generic names: they are used for that provider only', async () => {
  const seen = []; const fetchImpl = async (url, init) => { seen.push(init.headers.authorization.match(/Credential=([^/]+)/)[1]); return { status: 200, ok: true, arrayBuffer: async () => Buffer.from('<ListBucketResult></ListBucketResult>') }; };
  const env = { MG_ARCHIVE_PROVIDER: 'scaleway', ARCHIVE_ACCESS_KEY_ID: 'SCWKEYID', ARCHIVE_SECRET_ACCESS_KEY: 'secretvalue' };
  const r = await probeReadOnly({ env, fetchImpl, only: ['b2', 'scaleway'] }); assert.match(r.b2.reason, /are not set/); assert.ok(seen.every((x) => x === 'SCWKEYID') && seen.length > 0, 'only the scaleway client was built, with the generic credential');
});
