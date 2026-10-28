// Streaming download of ONE object from an S3-compatible bucket into a file. backup_objstore.mjs reads a whole object with `Buffer.from(await r.arrayBuffer())`, which costs the object's size in RAM (a 130 MB
// Intelligence ciphertext today, more as the data grows). This writes the body to disk as it arrives, with back-pressure, hashing on the way:
//   - the request is signed with the SAME signV4 as s3Client (the test compares both signatures), payload hash = SHA-256 of the empty body;
//   - the body goes to DEST.partial (mode 0600, created exclusively) and is renamed to DEST only when it is complete and verified; ANY failure removes the partial file;
//   - verified: Content-Length (when the server sends one), an expected byte count and an expected SHA-256 (when given); a hard cap (maxBytes) stops a body that is bigger than expected;
//   - a total deadline and a caller's AbortSignal cancel the transfer; errors carry the HTTP status or a fixed phrase, never headers, keys or the signature.
import { createHash } from 'node:crypto';
import { closeSync, createWriteStream, openSync, renameSync, rmSync } from 'node:fs';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { signV4 } from './backup_objstore.mjs';

const EMPTY_SHA256 = createHash('sha256').update('').digest('hex');

/** Returns null when the object does not exist (404), otherwise { bytes, sha256 } and DEST holds the verified object. Throws otherwise, leaving no file behind. */
export async function downloadObject({ endpoint, region, bucket, accessKeyId, secretAccessKey, key, dest, fetchImpl = fetch, now = () => new Date(), expectedSha256 = null, expectedBytes = null, maxBytes = 2 * 1024 ** 3, timeoutMs = 600000, signal }) {
  const host = new URL(endpoint).host, amz = now().toISOString().replace(/[-:]|\.\d{3}/g, ''), path = `/${bucket}/${key.split('/').map(encodeURIComponent).join('/')}`;
  const headers = { host, 'x-amz-content-sha256': EMPTY_SHA256, 'x-amz-date': amz };
  const authorization = signV4({ method: 'GET', path, query: '', headers, payloadHash: EMPTY_SHA256, region, accessKeyId, secretAccessKey, amz }); delete headers.host;
  const signals = [AbortSignal.timeout(timeoutMs), ...(signal ? [signal] : [])], part = dest + '.partial';
  let fd, ok = false;
  try {
    const r = await fetchImpl(endpoint + path, { method: 'GET', headers: { ...headers, authorization }, signal: AbortSignal.any(signals) });
    if (r.status === 404) { await r.body?.cancel(); return null; }
    if (r.status !== 200) { await r.body?.cancel(); throw new Error(`GET ${r.status}`); }
    const declared = r.headers.get('content-length') === null ? null : Number(r.headers.get('content-length'));
    if (declared !== null && (!Number.isFinite(declared) || declared > maxBytes)) throw new Error('the object is larger than the allowed maximum');
    fd = openSync(part, 'wx', 0o600);
    const hash = createHash('sha256'); let bytes = 0;
    const meter = new Transform({ transform(chunk, _enc, cb) { bytes += chunk.length; if (bytes > maxBytes) return cb(new Error('the object is larger than the allowed maximum')); hash.update(chunk); cb(null, chunk); } });
    await pipeline(Readable.fromWeb(r.body), meter, createWriteStream(part, { fd, autoClose: true })); fd = undefined;
    if (declared !== null && bytes !== declared) throw new Error('incomplete download: fewer bytes than announced');
    if (expectedBytes !== null && bytes !== expectedBytes) throw new Error('unexpected object size');
    const sha256 = hash.digest('hex'); if (expectedSha256 !== null && sha256 !== expectedSha256) throw new Error('the downloaded object does not match its expected SHA-256');
    renameSync(part, dest); ok = true; return { bytes, sha256 };
  } catch (e) {
    throw new Error(e && e.name === 'TimeoutError' ? 'the download timed out' : e && e.name === 'AbortError' ? 'the download was cancelled' : String(e && e.message || e).split('\n')[0].slice(0, 160));
  } finally { if (fd !== undefined) { try { closeSync(fd); } catch { /* the stream already closed it */ } } if (!ok) rmSync(part, { force: true }); }
}
