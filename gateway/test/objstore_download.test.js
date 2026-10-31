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

// ---- adversarial: destination, partial file, symlinks, concurrency ----
import { lstatSync, symlinkSync } from 'node:fs';
const mustNotFetch = async () => { throw new Error('the network must not be touched'); };
const OBJ = Buffer.alloc(3000, 5), okBody = () => bodyOf([OBJ], { len: OBJ.length });

test('an existing destination (regular file, symlink, dangling symlink) is never overwritten or followed, and the network is not even touched', async () => {
  const sb = sandbox(); try {
    const victim = join(sb.d, 'victim'); writeFileSync(victim, 'PRECIOUS');
    const cases = { regular: join(sb.d, 'reg'), link: join(sb.d, 'lnk'), dangling: join(sb.d, 'dng') };
    writeFileSync(cases.regular, 'OLD'); symlinkSync(victim, cases.link); symlinkSync(join(sb.d, 'nowhere'), cases.dangling);
    for (const [name, dest] of Object.entries(cases)) await assert.rejects(() => downloadObject({ ...CFG, key: 'k', dest, fetchImpl: mustNotFetch }), /destination already exists/, name);
    assert.equal(readFileSync(cases.regular, 'utf8'), 'OLD'); assert.equal(readFileSync(victim, 'utf8'), 'PRECIOUS'); assert.ok(lstatSync(cases.link).isSymbolicLink() && lstatSync(cases.dangling).isSymbolicLink());
  } finally { sb.done(); }
});

test('a destination that appears DURING the download is not overwritten either (no rename-over), and our partial file is cleaned', async () => {
  const sb = sandbox(), dest = join(sb.d, 'o'); try {
    await assert.rejects(() => downloadObject({ ...CFG, key: 'k', dest, fetchImpl: async () => { writeFileSync(dest, 'RACED IN'); return okBody(); } }), /destination already exists/);
    assert.equal(readFileSync(dest, 'utf8'), 'RACED IN'); assert.deepEqual(files(sb.d), ['o']);
  } finally { sb.done(); }
});

test('a pre-existing .partial (a regular file, or a symlink to a victim) is refused, not truncated, not followed, and not deleted', async () => {
  const sb = sandbox(); try {
    const victim = join(sb.d, 'victim'); writeFileSync(victim, 'PRECIOUS'); writeFileSync(join(sb.d, 'a.partial'), 'SOMEONE ELSE'); symlinkSync(victim, join(sb.d, 'b.partial'));
    for (const n of ['a', 'b']) await assert.rejects(() => downloadObject({ ...CFG, key: 'k', dest: join(sb.d, n), fetchImpl: async () => okBody() }), /partial file already exists/, n);
    assert.equal(readFileSync(victim, 'utf8'), 'PRECIOUS'); assert.equal(readFileSync(join(sb.d, 'a.partial'), 'utf8'), 'SOMEONE ELSE'); assert.ok(lstatSync(join(sb.d, 'b.partial')).isSymbolicLink());
  } finally { sb.done(); }
});

test('two downloads to the same destination at once: one is refused and it does NOT delete the other one\'s partial file; the winner completes intact', async () => {
  const sb = sandbox(), dest = join(sb.d, 'o'); try {
    let release; const gate = new Promise((ok) => { release = ok; });
    const slow = async () => new Response(new ReadableStream({ async start(c) { c.enqueue(OBJ.subarray(0, 1000)); await gate; c.enqueue(OBJ.subarray(1000)); c.close(); } }), { status: 200, headers: { 'content-length': String(OBJ.length) } });
    const a = downloadObject({ ...CFG, key: 'k', dest, fetchImpl: slow }); await new Promise((ok) => setTimeout(ok, 100));
    await assert.rejects(() => downloadObject({ ...CFG, key: 'k', dest, fetchImpl: async () => okBody() }), /partial file already exists/);
    assert.ok(existsSync(dest + '.partial'), 'the first download\'s partial survived the refused second one'); release();
    assert.equal((await a).sha256, sha(OBJ)); assert.deepEqual(readFileSync(dest), OBJ); assert.deepEqual(files(sb.d), ['o']);
  } finally { sb.done(); }
});

// ---- adversarial: anomalous HTTP answers ----
test('anomalous answers are refused and leave nothing: redirects (never followed), partial content, content-encoding, malformed Content-Length, 200 without a body', async () => {
  const sb = sandbox(), dest = join(sb.d, 'o'); try {
    let calls = 0;
    const cases = {
      'redirect 301': [() => new Response(null, { status: 301, headers: { location: 'https://evil.example.test/x' } }), /GET 301$/],
      'redirect 307': [() => new Response(null, { status: 307, headers: { location: 'https://evil.example.test/x' } }), /GET 307$/],
      'partial content 206': [() => new Response(OBJ, { status: 206 }), /GET 206$/],
      'content-encoding gzip': [() => new Response(OBJ, { status: 200, headers: { 'content-encoding': 'gzip', 'content-length': String(OBJ.length) } }), /content-encoding/],
      'content-length abc': [() => new Response(OBJ, { status: 200, headers: { 'content-length': 'abc' } }), /Content-Length/],
      'content-length 1e3': [() => new Response(OBJ, { status: 200, headers: { 'content-length': '1e3' } }), /Content-Length/],
      'content-length -5': [() => new Response(OBJ, { status: 200, headers: { 'content-length': '-5' } }), /Content-Length/],
      '200 without a body': [() => new Response(null, { status: 200 }), /no body/],
    };
    for (const [name, [mk, msg]] of Object.entries(cases)) { calls = 0; await assert.rejects(() => downloadObject({ ...CFG, key: 'k', dest, fetchImpl: async (_u, i) => { calls++; assert.equal(i.redirect, 'manual', 'redirects are never followed'); return mk(); } }), msg, name); assert.equal(calls, 1, name + ': exactly one request'); assert.deepEqual(files(sb.d), [], name); }
  } finally { sb.done(); }
});

// ---- adversarial: nothing secret in an error, whatever the transport says ----
test('no secret reaches an error message, even when the transport itself echoes it (thrown by fetch, or injected mid-body)', async () => {
  const sb = sandbox(), dest = join(sb.d, 'o'); try {
    const echo = `boom key=${CFG.secretAccessKey} id=${CFG.accessKeyId}`;
    const errors = [];
    for (const impl of [async () => { throw new Error(echo); }, async (_u, i) => new Response(new ReadableStream({ start(c) { c.enqueue(new Uint8Array(5)); c.error(new Error(echo + ' auth=' + i.headers.authorization)); } }), { status: 200 })]) {
      await downloadObject({ ...CFG, key: 'k', dest, fetchImpl: impl }).catch((e) => errors.push(e.message));
    }
    assert.equal(errors.length, 2);
    for (const m of errors) for (const s of [CFG.secretAccessKey, CFG.accessKeyId, 'AWS4-HMAC', 'Signature=']) assert.ok(!m.includes(s), `"${s}" leaked: ${m}`);
    assert.deepEqual(files(sb.d), []);
  } finally { sb.done(); }
});

// ---- compatibility: the three real providers' endpoint shapes ----
test('B2, Scaleway and R2 endpoint shapes: same URL, host and signature as s3Client signs for the same key (path-style, region as configured; R2 uses region "auto")', async () => {
  const sb = sandbox(); try {
    const providers = { b2: ['https://s3.eu-central-003.backblazeb2.com', 'eu-central-003'], scaleway: ['https://s3.fr-par.scw.cloud', 'fr-par'], r2: ['https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com', 'auto'] };
    const data = Buffer.from('age-encryption.org/v1\nbody');
    for (const [name, [endpoint, region]] of Object.entries(providers)) {
      let seen, ref; const cfg = { ...CFG, endpoint, region };
      await downloadObject({ ...cfg, key: 'macguard/2026 10/d1 export.sql.age', dest: join(sb.d, name), fetchImpl: async (u, i) => { seen = { u, h: i.headers }; return bodyOf([data], { len: data.length }); } });
      await s3Client({ ...cfg, fetchImpl: async (u, i) => { ref = { u, h: i.headers }; return new Response(data); } }).get('macguard/2026 10/d1 export.sql.age');
      assert.deepEqual(seen, ref, name); assert.ok(seen.u.startsWith(endpoint + '/bkt/macguard/2026%2010/d1%20export.sql.age'), name + ' ' + seen.u);
      assert.match(seen.h.authorization, new RegExp(`Credential=AKIDEXAMPLE0000/20261028/${region}/s3/aws4_request`), name);
    }
  } finally { sb.done(); }
});
