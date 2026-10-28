// Streaming download of ONE object from an S3-compatible bucket into a file. backup_objstore.mjs reads a whole object with `Buffer.from(await r.arrayBuffer())`, which costs the object's size in RAM (a 130 MB
// Intelligence ciphertext today, more as the data grows). This writes the body to disk as it arrives, with back-pressure, hashing on the way:
//   - the request is signed with the SAME signV4 as s3Client (the test compares both signatures), payload hash = SHA-256 of the empty body;
//   - the body goes to DEST.partial (mode 0600, created exclusively with O_EXCL, so a planted file or symlink at that name is refused, never followed or truncated) and is placed at DEST only when it is
//     complete and verified, with link()+unlink() so an existing DEST (or a symlink, even a dangling one) is NEVER overwritten; a failure removes only the partial file THIS call created;
//   - verified: status 200 exactly (redirects are not followed), no content-encoding, a well-formed Content-Length (when the server sends one), an expected byte count and an expected SHA-256 (when given);
//     a hard cap (maxBytes) stops a body that is bigger than expected;
//   - a total deadline and a caller's AbortSignal cancel the transfer; errors carry the HTTP status or a fixed phrase, never headers, keys or the signature (and any key/id/authorization echoed by the transport is masked).
//   The directory of DEST is the caller's responsibility (a fresh 0700 temporary directory, as stream_io.mjs's tmpRoot gives).
import { createHash } from 'node:crypto';
import { closeSync, createWriteStream, linkSync, lstatSync, openSync, rmSync, unlinkSync } from 'node:fs';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { signV4 } from './backup_objstore.mjs';

const EMPTY_SHA256 = createHash('sha256').update('').digest('hex');
const taken = (p) => { try { lstatSync(p); return true; } catch (e) { if (e && e.code === 'ENOENT') return false; throw e; } };   // lstat: a symlink counts as taken, and is not followed
const mask = (text, secrets) => secrets.filter(Boolean).reduce((m, v) => m.split(v).join('[redacted]'), text);

/** Returns null when the object does not exist (404), otherwise { bytes, sha256 } and DEST holds the verified object. Throws otherwise, leaving no file behind. */
export async function downloadObject({ endpoint, region, bucket, accessKeyId, secretAccessKey, key, dest, fetchImpl = fetch, now = () => new Date(), expectedSha256 = null, expectedBytes = null, maxBytes = 2 * 1024 ** 3, timeoutMs = 600000, signal }) {
  const host = new URL(endpoint).host, amz = now().toISOString().replace(/[-:]|\.\d{3}/g, ''), path = `/${bucket}/${key.split('/').map(encodeURIComponent).join('/')}`;
  const headers = { host, 'x-amz-content-sha256': EMPTY_SHA256, 'x-amz-date': amz };
  const authorization = signV4({ method: 'GET', path, query: '', headers, payloadHash: EMPTY_SHA256, region, accessKeyId, secretAccessKey, amz }); delete headers.host;
  const signals = [AbortSignal.timeout(timeoutMs), ...(signal ? [signal] : [])], part = dest + '.partial';
  let fd, created = false;
  try {
    if (taken(dest)) throw new Error('the destination already exists');
    const r = await fetchImpl(endpoint + path, { method: 'GET', headers: { ...headers, authorization }, redirect: 'manual', signal: AbortSignal.any(signals) });
    if (r.status === 404) { await r.body?.cancel(); return null; }
    if (r.status !== 200) { await r.body?.cancel(); throw new Error(`GET ${r.status}`); }
    const enc = r.headers.get('content-encoding'); if (enc !== null && enc.trim().toLowerCase() !== 'identity') { await r.body?.cancel(); throw new Error('unexpected content-encoding'); }
    const cl = r.headers.get('content-length'); if (cl !== null && !/^\d{1,16}$/.test(cl)) { await r.body?.cancel(); throw new Error('malformed Content-Length'); }
    const declared = cl === null ? null : Number(cl);
    if (declared !== null && declared > maxBytes) { await r.body?.cancel(); throw new Error('the object is larger than the allowed maximum'); }
    if (!r.body) throw new Error('the response has no body');
    try { fd = openSync(part, 'wx', 0o600); created = true; } catch (e) { await r.body.cancel(); throw new Error(e && e.code === 'EEXIST' ? 'a partial file already exists for this destination' : 'could not create the partial file'); }
    const hash = createHash('sha256'); let bytes = 0;
    const meter = new Transform({ transform(chunk, _enc, cb) { bytes += chunk.length; if (bytes > maxBytes) return cb(new Error('the object is larger than the allowed maximum')); hash.update(chunk); cb(null, chunk); } });
    await pipeline(Readable.fromWeb(r.body), meter, createWriteStream(part, { fd, autoClose: true })); fd = undefined;
    if (declared !== null && bytes !== declared) throw new Error('incomplete download: fewer bytes than announced');
    if (expectedBytes !== null && bytes !== expectedBytes) throw new Error('unexpected object size');
    const sha256 = hash.digest('hex'); if (expectedSha256 !== null && sha256 !== expectedSha256) throw new Error('the downloaded object does not match its expected SHA-256');
    try { linkSync(part, dest); } catch (e) { throw new Error(e && e.code === 'EEXIST' ? 'the destination already exists' : 'could not place the downloaded file'); }   // link() never replaces an existing name
    unlinkSync(part); return { bytes, sha256 };
  } catch (e) {
    throw new Error(e && e.name === 'TimeoutError' ? 'the download timed out' : e && e.name === 'AbortError' ? 'the download was cancelled' : mask(String(e && e.message || e).split('\n')[0], [authorization, secretAccessKey, accessKeyId]).slice(0, 160));
  } finally { if (fd !== undefined) { try { closeSync(fd); } catch { /* the stream already closed it */ } } if (created) rmSync(part, { force: true }); }
}
