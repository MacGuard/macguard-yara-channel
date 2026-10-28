import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { downloadObject } from '../tools/objstore_download.mjs';
import { s3Client } from '../tools/backup_objstore.mjs';

const CFG = { endpoint: 'https://s3.example.test', region: 'eu-test-1', bucket: 'bkt', accessKeyId: 'AKIDEXAMPLE0000', secretAccessKey: 'SECRET-KEY-DO-NOT-LEAK-0123456789', now: () => new Date('2026-10-28T01:02:03Z') };
const sha = (b) => createHash('sha256').update(b).digest('hex');
const sandbox = () => { const d = mkdtempSync(join(homedir(), '.mg-dl-')); return { d, done: () => rmSync(d, { recursive: true, force: true }) }; };
const bodyOf = (chunks, { len, hold } = {}) => new Response(new ReadableStream({ start(c) { for (const ch of chunks) c.enqueue(ch); if (!hold) c.close(); } }), { status: 200, headers: len === undefined ? {} : { 'content-length': String(len) } });
const files = (d) => readdirSync(d).sort();

test('the request is signed exactly like s3Client signs a GET of the same key (same signV4, same headers), and a complete object lands with mode 0600 and the right hash', async () => {
  const sb = sandbox(); try {
    const data = Buffer.from('age-encryption.org/v1\n' + 'x'.repeat(5000)); let seen, ref;
    const r = await downloadObject({ ...CFG, key: 'macguard/20261028T010203Z/d1-export.sql.age', dest: join(sb.d, 'o.age'), fetchImpl: async (u, i) => { seen = { u, h: i.headers }; return bodyOf([data.subarray(0, 100), data.subarray(100)], { len: data.length }); } });
    await s3Client({ ...CFG, fetchImpl: async (u, i) => { ref = { u, h: i.headers }; return new Response(data); } }).get('macguard/20261028T010203Z/d1-export.sql.age');
    assert.deepEqual(seen, ref, 'identical URL and headers, including the Authorization signature');
    assert.deepEqual([r.bytes, r.sha256], [data.length, sha(data)]); assert.deepEqual(readFileSync(join(sb.d, 'o.age')), data);
    assert.equal((statSync(join(sb.d, 'o.age')).mode & 0o777).toString(8), '600'); assert.deepEqual(files(sb.d), ['o.age'], 'no partial file left');
  } finally { sb.done(); }
});

test('404 gives null and no file; any other status throws with the status only (never headers, keys or the signature) and leaves nothing', async () => {
  const sb = sandbox(); try {
    assert.equal(await downloadObject({ ...CFG, key: 'k', dest: join(sb.d, 'a'), fetchImpl: async () => new Response('nope', { status: 404 }) }), null);
    for (const status of [403, 500]) await assert.rejects(() => downloadObject({ ...CFG, key: 'k', dest: join(sb.d, 'a'), fetchImpl: async () => new Response('denied: ' + CFG.secretAccessKey, { status }) }), (e) => e.message === `GET ${status}` && !e.message.includes('SECRET'));
    assert.deepEqual(files(sb.d), []);
  } finally { sb.done(); }
});

test('an incomplete, oversized, mis-sized or altered object is refused and leaves no .partial and no destination file', async () => {
  const sb = sandbox(), dest = join(sb.d, 'o'), data = Buffer.alloc(4000, 7); try {
    const bad = {
      'fewer bytes than Content-Length': [() => bodyOf([data.subarray(0, 2500)], { len: 4000 }), {}, /incomplete download/],
      'larger than the cap (announced)': [() => bodyOf([data], { len: 4000 }), { maxBytes: 1000 }, /larger than the allowed maximum/],
      'larger than the cap (not announced, caught mid-stream)': [() => bodyOf([data, data, data]), { maxBytes: 5000 }, /larger than the allowed maximum/],
      'unexpected size': [() => bodyOf([data], { len: 4000 }), { expectedBytes: 3999 }, /unexpected object size/],
      'wrong SHA-256': [() => bodyOf([data], { len: 4000 }), { expectedSha256: sha(Buffer.from('other')) }, /does not match its expected SHA-256/],
    };
    for (const [name, [mk, opts, msg]] of Object.entries(bad)) { await assert.rejects(() => downloadObject({ ...CFG, key: 'k', dest, fetchImpl: async () => mk(), ...opts }), msg, name); assert.deepEqual(files(sb.d), [], name + ': nothing left behind'); }
    assert.equal((await downloadObject({ ...CFG, key: 'k', dest, fetchImpl: async () => bodyOf([data], { len: 4000 }), expectedBytes: 4000, expectedSha256: sha(data) })).bytes, 4000, 'the same object with correct expectations is accepted');
  } finally { sb.done(); }
});

test('a cancelled or timed-out transfer stops with a fixed message and leaves nothing', async () => {
  const sb = sandbox(), dest = join(sb.d, 'o'), keepAlive = setInterval(() => {}, 50); try {   // AbortSignal.timeout() is unref'd: without a socket (a real download has one) nothing would keep the loop alive until it fires
    const ac = new AbortController(), hang = async (_u, i) => new Promise((ok) => ok(new Response(new ReadableStream({ start(c) { c.enqueue(new Uint8Array(10)); i.signal.addEventListener('abort', () => c.error(i.signal.reason)); } }), { status: 200 })));
    const p = downloadObject({ ...CFG, key: 'k', dest, fetchImpl: hang, signal: ac.signal }); setTimeout(() => ac.abort(), 100); await assert.rejects(p, /the download was cancelled/);
    await assert.rejects(() => downloadObject({ ...CFG, key: 'k', dest, fetchImpl: hang, timeoutMs: 150 }), /the download timed out/); assert.deepEqual(files(sb.d), []);
  } finally { clearInterval(keepAlive); sb.done(); }
});

test('against a REAL local HTTP server (real fetch, real sockets): a complete object downloads; a connection cut mid-body is refused and leaves nothing', async () => {
  const sb = sandbox(), data = Buffer.alloc(8 * 1024 * 1024, 3); let seenAuth = '';
  const srv = createServer((req, res) => {
    seenAuth = req.headers.authorization || '';
    if (req.url.includes('whole')) { res.writeHead(200, { 'content-length': data.length }); res.end(data); }
    else { res.writeHead(200, { 'content-length': data.length }); res.write(data.subarray(0, 3 * 1024 * 1024), () => setTimeout(() => req.socket.destroy(), 20)); }
  });
  await new Promise((ok) => srv.listen(0, '127.0.0.1', ok)); const endpoint = `http://127.0.0.1:${srv.address().port}`;
  try {
    const r = await downloadObject({ ...CFG, endpoint, key: 'whole', dest: join(sb.d, 'whole') });
    assert.deepEqual([r.bytes, r.sha256], [data.length, sha(data)]); assert.match(seenAuth, /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE0000\//);
    await assert.rejects(() => downloadObject({ ...CFG, endpoint, key: 'cut', dest: join(sb.d, 'cut') })); assert.deepEqual(files(sb.d), ['whole'], 'the cut transfer left nothing');
  } finally { srv.closeAllConnections?.(); await new Promise((ok) => srv.close(ok)); sb.done(); }
});

// ---- memory: the point of this module ----
const MIB = 1048576;
const CHILD = `
import { downloadObject } from ${JSON.stringify(new URL('../tools/objstore_download.mjs', import.meta.url).href)};
const [dest, mib] = process.argv.slice(1), total = Number(mib) * ${MIB}, chunk = Buffer.alloc(65536, 9); let sent = 0;
const body = new ReadableStream({ pull(c) { if (sent >= total) return c.close(); sent += chunk.length; c.enqueue(chunk); } });   // produced lazily: only back-pressure keeps it from piling up
const r = await downloadObject({ endpoint: 'https://s3.example.test', region: 'r', bucket: 'b', accessKeyId: 'AKIDEXAMPLE0000', secretAccessKey: 'x'.repeat(30), key: 'big', dest, fetchImpl: async () => new Response(body, { status: 200, headers: { 'content-length': String(total) } }) });
console.log(JSON.stringify({ bytes: r.bytes, rssMiB: process.resourceUsage().maxRSS / 1024 }));   // maxRSS is in KiB
`;
test('memory: a 256 MiB object is written to disk with a peak RSS far below its size (an arrayBuffer() read would need at least 256 MiB)', () => {
  const sb = sandbox(); try {
    const dest = join(sb.d, 'big'), r = spawnSync(process.execPath, ['--input-type=module', '-e', CHILD, dest, '256'], { encoding: 'utf8', timeout: 240000 });
    assert.equal(r.status, 0, r.stderr); const out = JSON.parse(r.stdout.trim().split('\n').pop());
    assert.equal(out.bytes, 256 * MIB); assert.equal(statSync(dest).size, 256 * MIB); assert.ok(!existsSync(dest + '.partial'));
    assert.ok(out.rssMiB < 128, `peak RSS ${out.rssMiB.toFixed(0)} MiB for a 256 MiB object (reading it whole would cost at least 256 MiB)`);
  } finally { sb.done(); }
});
