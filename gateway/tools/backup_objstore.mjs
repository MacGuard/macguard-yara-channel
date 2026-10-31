// Replication of the encrypted gateway backups to three independent object stores: Backblaze B2, Scaleway Object Storage and Cloudflare R2 (all S3-compatible). Only the age ciphertext, its manifest and
// SHA256SUMS leave the machine; credentials are read from the environment at the moment of use and never printed, logged or written to a state file.
//   node tools/backup_objstore.mjs plan   [--root DIR] [--config FILE]                        what each destination is missing, and which destinations are configured
//   node tools/backup_objstore.mjs sync   [--root DIR] [--config FILE] [--apply]              upload what is missing (dry run unless --apply); each destination is independent
//   node tools/backup_objstore.mjs verify [--root DIR] [--config FILE]                        re-read every object of the newest backup from each destination and compare checksums
//   node tools/backup_objstore.mjs drill  [--root DIR] [--config FILE] --identity KEYFILE [--trust-key PUBKEY_OR_FILE --min-sequence N]   per destination: download the newest backup, verify (with --trust-key: authenticate it by its signed anchor), decrypt in isolation, run the restore checks
//   node tools/backup_objstore.mjs check  [--root DIR]                                        per-destination alarms (exit 1 if one fires)
// Rules: write-once (an existing key with different bytes is a conflict, never overwritten; nothing is ever deleted here); a destination that fails does not stop the others and never touches their
// objects; "three copies" is claimed only when all three destinations have verified the same bytes recently.
import { createHash, createHmac } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { ROOT_DEFAULT } from './backup_flow.mjs';
import { verifyRestore } from './backup_lib.mjs';
import { ageDecryptFile, shaFile } from './stream_io.mjs';
import { makeRecord, classify, safeEmit, outboxFromEnv } from './telemetry.mjs';
import { ANCHOR_FILES, ANCHOR_BUNDLE, CHECKPOINT_BUNDLE, CHECKPOINT_FILES, anchorFiles, verifyAnchor, compareHeads, verifyCheckpoint, bestCheckpoint, checkAgainstCheckpoint } from './backup_anchor.mjs';
import { privateDir } from './private_tmp.mjs';

export const FILES = ['d1-export.sql.age', 'manifest.json', 'SHA256SUMS'], PROVIDERS = ['b2', 'scaleway', 'r2'];
const STAMP = /^\d{8}T\d{6}Z$/, sha = (b) => createHash('sha256').update(b).digest('hex'), iso = (d) => d.toISOString().replace(/\.\d{3}Z$/, 'Z'), hmac = (k, s) => createHmac('sha256', k).update(s).digest();
const stateFile = (root) => join(resolve(root), 'objstore.json'), readState = (root) => { try { return JSON.parse(readFileSync(stateFile(root), 'utf8')); } catch { return { destinations: {} }; } };
const stampsOf = (dir) => (existsSync(dir) ? readdirSync(dir).filter((n) => STAMP.test(n)).sort() : []);

// Non-secret description of the three destinations (environments/backup-destinations.json). A destination with a null bucket is UNCONFIGURED (reported, never guessed). The credential variables are NAMES; their values stay in the environment.
export const DEFAULT_CONFIG = JSON.parse(readFileSync(new URL('../environments/backup-destinations.json', import.meta.url), 'utf8'));   // the single description of the three destinations (also read by scripts/sources_inventory.py)
export function loadConfig(file) {
  const c = file ? JSON.parse(readFileSync(file, 'utf8')) : DEFAULT_CONFIG;
  if (c.schema !== DEFAULT_CONFIG.schema || !/^[a-z0-9-]+$/.test(c.prefix ?? '')) throw new Error('invalid destinations file');
  for (const [n, d] of Object.entries(c.destinations)) { if (!PROVIDERS.includes(n)) throw new Error(`unknown destination ${n}`); if (JSON.stringify(d).match(/AKIA|secret_access|-----BEGIN|AGE-SECRET-KEY/i)) throw new Error('the destinations file must not hold secrets'); }
  return c;
}

// AWS Signature V4 (pure function, checked against the published AWS test-suite vector in test/objstore.test.js).
export function signV4({ method, path, query = '', headers, payloadHash, region, service = 's3', accessKeyId, secretAccessKey, amz }) {
  const day = amz.slice(0, 8), names = Object.keys(headers).sort(), signed = names.join(';'), scope = `${day}/${region}/${service}/aws4_request`;
  const canon = [method, path, query, names.map((n) => `${n}:${headers[n]}\n`).join(''), signed, payloadHash].join('\n');
  const sts = ['AWS4-HMAC-SHA256', amz, scope, sha(canon)].join('\n'), k = hmac(hmac(hmac(hmac('AWS4' + secretAccessKey, day), region), service), 'aws4_request');
  return `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope}, SignedHeaders=${signed}, Signature=${createHmac('sha256', k).update(sts).digest('hex')}`;
}

// Minimal path-style S3 client: HEAD/GET/PUT of single objects, payload hash signed. No SDK.
export function s3Client({ endpoint, region, bucket, accessKeyId, secretAccessKey, fetchImpl = fetch, now = () => new Date() }) {
  const host = new URL(endpoint).host;
  async function call(method, key, body, query = '') {
    const amz = now().toISOString().replace(/[-:]|\.\d{3}/g, ''), payloadHash = sha(body ?? ''), path = key === null ? `/${bucket}` : `/${bucket}/${key.split('/').map(encodeURIComponent).join('/')}`;
    const headers = { host, 'x-amz-content-sha256': payloadHash, 'x-amz-date': amz };
    const authorization = signV4({ method, path, query, headers, payloadHash, region, accessKeyId, secretAccessKey, amz }); delete headers.host;
    const r = await fetchImpl(endpoint + path + (query ? '?' + query : ''), { method, headers: { ...headers, authorization }, body, signal: AbortSignal.timeout(120000) });
    return { status: r.status, bytes: method === 'GET' && r.ok ? Buffer.from(await r.arrayBuffer()) : (await r.arrayBuffer(), null) };
  }
  return {
    /** HEAD on the bucket itself: EXISTS (200), MISSING (404: a 404 on an object does NOT prove the bucket exists), DENIED (401/403: the key is valid for the provider but not for this bucket, or invalid). */
    async bucket() { const r = await call('HEAD', null); return r.status === 200 ? 'EXISTS' : r.status === 404 ? 'MISSING' : r.status === 401 || r.status === 403 ? 'DENIED' : `HTTP_${r.status}`; },
    async head(key) { const r = await call('HEAD', key); if (r.status === 404) return false; if (r.status !== 200) throw new Error(`HEAD ${r.status}`); return true; },
    async get(key) { const r = await call('GET', key); if (r.status === 404) return null; if (r.status !== 200) throw new Error(`GET ${r.status}`); return r.bytes; },
    /** Keys under a prefix (ListObjectsV2, read-only). */
    async list(prefix) {
      const enc = (x) => encodeURIComponent(x).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase()), keys = []; let token = null;
      do {
        const q = [['list-type', '2'], ['prefix', prefix], ...(token ? [['continuation-token', token]] : [])].sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([k, v]) => `${k}=${enc(v)}`).join('&');
        const r = await call('GET', null, undefined, q); if (r.status !== 200) throw new Error(`LIST ${r.status}`);
        const xml = r.bytes.toString('utf8'); for (const m of xml.matchAll(/<Key>([^<]+)<\/Key>/g)) keys.push(m[1].replace(/&amp;/g, '&'));
        token = /<IsTruncated>true<\/IsTruncated>/.test(xml) ? (xml.match(/<NextContinuationToken>([^<]+)<\/NextContinuationToken>/) ?? [])[1] ?? null : null;
      } while (token);
      return keys;
    },
    async put(key, data) { const r = await call('PUT', key, data); if (r.status !== 200) throw new Error(`PUT ${r.status}`); },
  };
}

// Credentials: from the environment variables the config names. Missing => the destination is reported as UNCONFIGURED, nothing is attempted.
function clientFor(name, cfg, { env = process.env, fetchImpl, clientOverride } = {}) {
  const d = cfg.destinations[name];
  if (!d) return { state: 'UNCONFIGURED', reason: 'not in the destinations file' };
  if (!d.bucket) return { state: 'UNCONFIGURED', reason: 'no bucket named for this destination' };
  const viaEnvironment = env.MG_ARCHIVE_PROVIDER === name;                                         // a GitHub environment holds ONE provider's credential under generic names (ARCHIVE_ACCESS_KEY_ID / ARCHIVE_SECRET_ACCESS_KEY)
  const id = env[d.key_id_env] ?? (viaEnvironment ? env.ARCHIVE_ACCESS_KEY_ID : undefined), secret = env[d.secret_env] ?? (viaEnvironment ? env.ARCHIVE_SECRET_ACCESS_KEY : undefined);
  if (clientOverride?.[name]) return { state: 'READY', client: clientOverride[name] };
  if (!id || !secret) return { state: 'UNCONFIGURED', reason: `${d.key_id_env}/${d.secret_env} are not set in this environment` };
  return { state: 'READY', client: s3Client({ endpoint: d.endpoint, region: d.region, bucket: d.bucket, accessKeyId: id, secretAccessKey: secret, fetchImpl }) };
}
const keyOf = (cfg, stamp, f) => `${cfg.prefix}/${stamp}/${f}`;
const record = (root, name, patch) => { const s = readState(root); s.destinations[name] = { ...(s.destinations[name] ?? {}), ...patch }; writeFileSync(stateFile(root), JSON.stringify(s, null, 1) + '\n'); };

// What must be uploaded: every encrypted backup (a directory without .age is plaintext and is reported, never sent).
function local(root) {
  const out = [], skipped = [];
  for (const stamp of stampsOf(root)) {
    const dir = join(root, stamp);
    if (!existsSync(join(dir, 'd1-export.sql.age'))) { skipped.push({ stamp, reason: 'no encrypted export: plaintext never leaves the machine' }); continue; }
    const miss = FILES.filter((f) => !existsSync(join(dir, f))); if (miss.length) { skipped.push({ stamp, reason: 'missing ' + miss.join(', ') }); continue; }
    const pair = anchorFiles((f) => existsSync(join(dir, f))), anchored = pair.every((f) => existsSync(join(dir, f)));       // the signed statement travels with the backup when it exists; half of it is ignored (and reported by the drill)
    out.push({ stamp, files: Object.fromEntries([...FILES, ...(anchored ? pair : [])].map((f) => [f, readFileSync(join(dir, f))])) });
  }
  return { backups: out, skipped };
}

export async function syncAll({ root = ROOT_DEFAULT, config = DEFAULT_CONFIG, apply = false, only = PROVIDERS, clock = () => new Date(), env, fetchImpl, clientOverride, telemetry = null } = {}) {
  root = resolve(root); const { backups, skipped } = local(root), report = { skipped_plaintext: skipped, destinations: {} };
  for (const name of only) {
    const c = clientFor(name, config, { env, fetchImpl, clientOverride }), r = report.destinations[name] = { state: c.state, uploaded: [], already_there: [], conflicts: [], errors: [] };
    if (c.state !== 'READY') { r.reason = c.reason; continue; }
    if (c.client.bucket) { const bs = await c.client.bucket().catch((e) => `ERROR_${String(e.message).slice(0, 40)}`); r.bucket = bs; if (bs !== 'EXISTS') { r.state = 'BUCKET_' + bs; r.reason = `the bucket answered ${bs}: nothing is attempted`; r.errors.push(r.reason); r.ok = false; continue; } }
    const t0 = clock().getTime(), real0 = Date.now(), fin = () => t0 + (Date.now() - real0); let nFiles = 0, nBytes = 0, firstErr = null, planned = 0;
    for (const b of backups) {
      try {
        let there = 0, put = 0, bad = 0;
        for (const f of Object.keys(b.files)) {
          const k = keyOf(config, b.stamp, f), existing = await c.client.get(k);
          if (existing) { if (sha(existing) === sha(b.files[f])) there++; else bad++; continue; }
          if (!apply) { put++; continue; }
          await c.client.put(k, b.files[f]);
          const back = await c.client.get(k); if (!back || sha(back) !== sha(b.files[f])) throw new Error(`${f}: the object read back differs from what was sent`); put++; nFiles++; nBytes += b.files[f].length;
        }
        planned += Object.keys(b.files).length;
        if (bad) r.conflicts.push({ stamp: b.stamp, reason: 'the destination holds different bytes under this key; nothing is overwritten' });
        else if (put) r.uploaded.push({ stamp: b.stamp, files: put, planned: !apply });
        else r.already_there.push(b.stamp);
      } catch (e) { firstErr ??= e; r.errors.push({ stamp: b.stamp, error: String(e.message).slice(0, 160) }); }   // this destination stops here; the others continue
    }
    r.ok = !r.conflicts.length && !r.errors.length;
    if (apply && backups.length) {   // one witness record per destination and run; telemetry can never change the outcome above
      const bad = firstErr ? classify(firstErr) : r.conflicts.length ? { error_class: 'INTEGRITY', http_status: null } : null;
      await safeEmit(telemetry, makeRecord({ source_id: `backup:${name}`, operation: 'upload', started: t0, finished: fin(), status: bad ? (nFiles ? 'partial' : 'failed') : nFiles ? 'ok' : 'not_modified', error: firstErr?.message ?? r.conflicts[0]?.reason ?? null, ...(bad ?? {}), counters: { files_attempted: planned, files_downloaded: nFiles, bytes_downloaded: nBytes, answers: nFiles * 3 }, stages: { validation_state: bad ? 'failed' : 'ok', manifest_state: bad ? 'failed' : 'ok' } }));
    }
    if (apply && r.ok && backups.length) record(root, name, { last_sync_at: iso(clock()), newest: backups.at(-1).stamp, bucket: config.destinations[name].bucket });
  }
  return report;
}

// Read every object of the newest backup back from each destination and compare it to the local bytes.
export async function verifyAll({ root = ROOT_DEFAULT, config = DEFAULT_CONFIG, only = PROVIDERS, clock = () => new Date(), env, fetchImpl, clientOverride, telemetry = null } = {}) {
  root = resolve(root); const { backups } = local(root), newest = backups.at(-1), report = { newest: newest?.stamp ?? null, destinations: {} };
  for (const name of only) {
    const c = clientFor(name, config, { env, fetchImpl, clientOverride }), r = report.destinations[name] = { state: c.state, ok: false };
    if (c.state !== 'READY') { r.reason = c.reason; continue; }
    if (!newest) { r.reason = 'no encrypted backup locally'; continue; }
    const t0 = clock().getTime(), real0 = Date.now(), fin = () => t0 + (Date.now() - real0); let verr = null;
    try {
      const bad = []; for (const f of Object.keys(newest.files)) { const b = await c.client.get(keyOf(config, newest.stamp, f)); if (!b || sha(b) !== sha(newest.files[f])) bad.push(f); }
      r.ok = !bad.length; if (bad.length) r.reason = 'missing or different: ' + bad.join(', ');
      if (r.ok) record(root, name, { last_verified_at: iso(clock()), verified: newest.stamp });
    } catch (e) { verr = e; r.reason = String(e.message).slice(0, 160); }
    await safeEmit(telemetry, makeRecord({ source_id: `backup:${name}`, operation: 'verify', started: t0, finished: fin(), status: r.ok ? 'ok' : 'failed', error: r.ok ? null : r.reason, ...(r.ok ? {} : verr ? classify(verr) : { error_class: 'INTEGRITY' }), counters: { files_attempted: FILES.length, files_downloaded: r.ok ? FILES.length : 0, answers: FILES.length }, stages: { validation_state: r.ok ? 'ok' : 'failed' } }));
  }
  return report;
}

// Restore drill from ONE destination at a time: the copy is downloaded, hash-checked, decrypted with the identity FILE and restored into an isolated in-memory database.
export async function drillOne({ root = ROOT_DEFAULT, config = DEFAULT_CONFIG, name, identityFile, ageBin = 'age', clock = () => new Date(), env, fetchImpl, clientOverride, telemetry = null, trust = null }) {
  const t0 = clock().getTime(), real0 = Date.now(); const out = await drillCore({ root, config, name, identityFile, ageBin, clock, env, fetchImpl, clientOverride, trust });
  if (!/not configured|UNCONFIGURED|are not set|no bucket/i.test(String(out.reason ?? '')) ) await safeEmit(telemetry, makeRecord({ source_id: `backup:${name}`, operation: 'restore_drill', started: t0, finished: t0 + (Date.now() - real0), status: out.ok ? 'ok' : 'failed', error: out.ok ? null : out.reason, ...(out.ok ? {} : { error_class: /checksum|do not match|differs/.test(String(out.reason)) ? 'INTEGRITY' : /not in the destination|nothing to restore/.test(String(out.reason)) ? 'STORAGE' : 'OTHER' }), counters: { files_attempted: FILES.length, files_downloaded: out.ok ? FILES.length : 0 }, stages: { tests_state: out.ok ? 'ok' : 'failed', validation_state: out.ok ? 'ok' : 'failed' } }));
  return out;
}
async function drillCore({ root = ROOT_DEFAULT, config = DEFAULT_CONFIG, name, identityFile, ageBin = 'age', clock = () => new Date(), env, fetchImpl, clientOverride, trust = null }) {
  root = resolve(root); const at = iso(clock()), c = clientFor(name, config, { env, fetchImpl, clientOverride }), res = (r) => { const s = readState(root), d = s.destinations[name] ?? {}; d.drills = [...(d.drills ?? []), { at, ...r }].slice(-12); if (r.ok) d.last_drill_ok_at = at; s.destinations[name] = d; writeFileSync(stateFile(root), JSON.stringify(s, null, 1) + '\n'); return { name, at, ...r }; };
  if (c.state !== 'READY') return res({ ok: false, reason: c.reason });
  if (!identityFile || !existsSync(identityFile)) return res({ ok: false, reason: 'the key file is missing' });
  try {
    const stamp = (readState(root).destinations[name] ?? {}).newest ?? stampsOf(root).at(-1); if (!stamp) return res({ ok: false, reason: 'nothing to restore' });
    const got = {}; for (const f of FILES) { const b = await c.client.get(keyOf(config, stamp, f)); if (!b) return res({ ok: false, backup: stamp, reason: `${f} is not in the destination` }); got[f] = b; }
    for (const l of got['SHA256SUMS'].toString('utf8').trim().split('\n')) { const [h, f] = l.split(/\s+/); if (got[f] && sha(got[f]) !== h) return res({ ok: false, backup: stamp, reason: `checksum mismatch in ${f}` }); }
    // `trust` = { publicKey, principal?, minSequence? } comes from OUTSIDE the buckets and the Mac (the recovery kit). With it the restore is authenticated by a signature over the whole backup, which works with no local copy at all;
    // a destination that does not carry a valid, current signed statement then fails. Without it, the weaker local-record anchor below is used.
    let signed = false;
    if (trust) {
      for (const f of [...ANCHOR_FILES, ANCHOR_BUNDLE]) { const b = await c.client.get(keyOf(config, stamp, f)); if (b) got[f] = b; }
      const v = verifyAnchor({ files: got, publicKey: trust.publicKey, principal: trust.principal, minSequence: trust.minSequence ?? 0, expectedStamp: stamp, sigstore: trust.sigstore ?? null, ed25519MaxSequence: trust.ed25519MaxSequence ?? null });
      if (!v.ok) return res({ ok: false, backup: stamp, anchor: 'signature', reason: 'the signed anchor does not authenticate this backup: ' + v.reason });
      if (trust.checkpoint) { const k = checkAgainstCheckpoint(v, trust.checkpoint); if (!k.ok) return res({ ok: false, backup: stamp, anchor: 'signature', reason: 'against the external checkpoint: ' + k.reason }); }
      signed = true;
    }
    // Anchor to the LOCAL record when it exists: the checksums, the manifest and the ciphertext all come from the same bucket, and age encrypts to a PUBLIC key, so whoever could write to one bucket could upload a different but
    // self-consistent backup. The local SHA256SUMS of the same stamp is the reference that bucket cannot forge. Without a local copy (disaster recovery) the drill still runs but reports `anchored: false`.
    const localSums = join(root, stamp, 'SHA256SUMS'), localRecord = existsSync(localSums), anchored = signed || localRecord;
    if (localRecord && sha(readFileSync(localSums)) !== sha(got['SHA256SUMS'])) return res({ ok: false, backup: stamp, anchored, reason: 'the destination holds a different SHA256SUMS than the local record of this backup' });
    // Streaming: the ciphertext goes to a private directory, age decrypts it into a 0600 file (the plaintext never passes through this process), the hash is computed from the file and sqlite3 loads it from the file.
    const work = privateDir(resolve(root), '.drill-'); const plain = join(work, 'plain.sql'), manifest = JSON.parse(got['manifest.json'].toString('utf8')); let v;
    try {
      writeFileSync(join(work, 'c.age'), got['d1-export.sql.age'], { mode: 0o600 });
      await ageDecryptFile({ ageBin, identity: identityFile, src: join(work, 'c.age'), dst: plain });
      if (await shaFile(plain) !== manifest.plaintext_sha256) return res({ ok: false, backup: stamp, reason: 'the decrypted bytes do not match the manifest' });
      v = await verifyRestore({ file: plain }, { manifest });
    } finally { rmSync(work, { recursive: true, force: true }); }
    return res({ ok: v.ok, backup: stamp, anchored, anchor: signed ? 'signature' : localRecord ? 'local-record' : 'none', sequence: signed ? JSON.parse(got['ANCHOR.json']).sequence : undefined, checks: v.checks.length, failed: v.checks.filter((x) => !x.ok).map((x) => x.name), reason: v.ok ? null : 'restore checks failed' });
  } catch (e) { return res({ ok: false, reason: String(e?.message ?? e).split('\n')[0].slice(0, 160) }); }
}

// The newest signed backup that the destinations hold, downloaded into `outDir/<stamp>/` (so that the next backup can name it as its predecessor and a sync heals any destination that is behind). Every candidate is
// verified with the pinned policy first; destinations that disagree at the same sequence are an error (equivocation); nothing is written to any destination.
export async function fetchPrevious({ config = DEFAULT_CONFIG, trust, outDir, only = PROVIDERS, keep = 'all', stamp: wanted = null, allowEmpty = false, env, fetchImpl, clientOverride } = {}) {
  const found = {}, detail = {};
  for (const name of only) {
    const c = clientFor(name, config, { env, fetchImpl, clientOverride });
    if (c.state !== 'READY') { detail[name] = 'UNCONFIGURED'; continue; }
    try {
      const stamps = [...new Set((await c.client.list(config.prefix + '/')).map((k) => (k.match(new RegExp(`^${config.prefix}/(\\d{8}T\\d{6}Z)/`)) ?? [])[1]).filter(Boolean))].sort();
      let best = null;
      if (wanted && !stamps.includes(wanted)) { detail[name] = `${wanted}: not held`; continue; }
      for (const stamp of wanted ? [wanted] : stamps.reverse()) {                                                                                  // newest first: the first one that verifies is the head of this destination
        const files = {}; for (const f of [...FILES, ...ANCHOR_FILES, ANCHOR_BUNDLE]) { const b = await c.client.get(keyOf(config, stamp, f)); if (b) files[f] = b; }
        const v = verifyAnchor({ files, publicKey: trust.publicKey, principal: trust.principal, minSequence: trust.minSequence ?? 0, expectedStamp: stamp, sigstore: trust.sigstore ?? null, ed25519MaxSequence: trust.ed25519MaxSequence ?? null });
        if (v.ok) { best = { stamp, files, v }; break; } detail[name] = `${stamp}: ${v.reason}`;
      }
      if (best) { found[name] = best; detail[name] = `sequence ${best.v.anchor.sequence} (${best.stamp})`; } else detail[name] ??= 'no signed backup';
    } catch (e) { detail[name] = 'unreachable: ' + String(e.message).slice(0, 80); }
  }
  const cmp = compareHeads(Object.fromEntries(Object.entries(found).map(([n, f]) => [n, f.v])));
  if (cmp.conflicts.length) throw new Error('destinations hold two different signed statements for the same sequence (equivocation)');
  if (!cmp.newest) {
    // an EMPTY resource (every destination answered and none holds a signed backup) may start its chain; anything else (a statement that fails verification, an unreachable or unconfigured destination) must stop the run, never be read as "empty"
    if (allowEmpty && Object.keys(detail).length === only.length && Object.values(detail).every((v) => v === 'no signed backup')) return { none: true, detail };
    throw new Error('no destination holds a signed backup that verifies: ' + JSON.stringify(detail));
  }
  const [name, top] = Object.entries(found).find(([, f]) => f.v.anchor.sequence === cmp.newest);
  const dir = join(resolve(outDir), top.stamp); if (existsSync(dir)) throw new Error('the previous backup directory already exists: nothing is overwritten');
  mkdirSync(dir, { recursive: true, mode: 0o700 }); for (const [f, b] of Object.entries(top.files)) if (keep === 'all' || f.startsWith('ANCHOR')) writeFileSync(join(dir, f), b, { mode: 0o600 });          // keep: 'statement' leaves the ciphertext behind
  return { stamp: top.stamp, sequence: cmp.newest, head_sha256: top.v.head_sha256, taken_from: name, current: cmp.current, behind: cmp.stale, detail };
}

// A READ credential must read and must NOT write. Reads the bucket and lists the prefix; then tries to PUT one tiny object under `_probe/` and expects the provider to refuse. If the provider accepts, the credential is
// too powerful (reported as a failure; the stray object is a few bytes and nothing is deleted here).
export async function probeReadOnly({ config = DEFAULT_CONFIG, only = PROVIDERS, env, fetchImpl, clientOverride, runId = 'probe' } = {}) {
  const out = {};
  for (const name of only) {
    const c = clientFor(name, config, { env, fetchImpl, clientOverride });
    if (c.state !== 'READY') { out[name] = { ok: false, reason: c.reason }; continue; }
    try {
      const bucket = await c.client.bucket(), listed = (await c.client.list(config.prefix + '/')).length;
      if (bucket !== 'EXISTS') { out[name] = { ok: false, reason: `the bucket answered ${bucket}` }; continue; }
      let wrote = true; try { await c.client.put(`_probe/readonly-check-${runId}`, Buffer.from('read-only credential probe')); } catch { wrote = false; }
      out[name] = wrote ? { ok: false, reason: 'the READ credential could write: it is not read-only', objects_listed: listed } : { ok: true, read: true, write_refused: true, objects_listed: listed };
    } catch (e) { out[name] = { ok: false, reason: String(e.message).slice(0, 100) }; }
  }
  return out;
}

// Which destinations hold the current signed head of `stamp`, which are behind, which disagree, which are gone. Needs only the trusted public key (no local copy); nothing is written.
export async function headsAll({ config = DEFAULT_CONFIG, stamp, trust, only = PROVIDERS, env, fetchImpl, clientOverride } = {}) {   // trust.checkpoint (from loadCheckpoint) adds the external check: every destination serving less than what was confirmed is a rollback
  const results = {}, detail = {};
  for (const name of only) {
    const c = clientFor(name, config, { env, fetchImpl, clientOverride });
    if (c.state !== 'READY') { results[name] = { ok: false, reason: c.reason }; detail[name] = 'UNCONFIGURED'; continue; }
    try {
      const files = {}; for (const f of [...FILES, ...ANCHOR_FILES, ANCHOR_BUNDLE]) { const b = await c.client.get(keyOf(config, stamp, f)); if (b) files[f] = b; }
      if (!Object.keys(files).length) { results[name] = null; detail[name] = 'nothing under this stamp'; continue; }
      results[name] = verifyAnchor({ files, publicKey: trust.publicKey, principal: trust.principal, minSequence: trust.minSequence ?? 0, expectedStamp: stamp, sigstore: trust.sigstore ?? null, ed25519MaxSequence: trust.ed25519MaxSequence ?? null });
      if (results[name].ok && trust.checkpoint) { const k = checkAgainstCheckpoint(results[name], trust.checkpoint); if (!k.ok) results[name] = { ok: false, reason: k.reason, sequence_seen: results[name].anchor.sequence }; }
      detail[name] = results[name].ok ? `sequence ${results[name].anchor.sequence}` : results[name].reason;
    } catch (e) { results[name] = { ok: false, reason: 'unreachable: ' + String(e.message).slice(0, 80) }; detail[name] = 'unreachable'; }
  }
  const cmp = compareHeads(results), seen = Object.values(results).filter((r) => r?.sequence_seen != null).map((r) => r.sequence_seen);
  const behind = trust.checkpoint && !cmp.current.length && seen.length > 0;           // every reachable destination is behind what was confirmed
  return { stamp, ...cmp, detail, checkpoint_sequence: trust.checkpoint?.sequence ?? null, rollback_everywhere: !!behind, best_available_sequence: seen.length ? Math.max(...seen) : cmp.newest };
}

// Reads one or more external copies of the checkpoint (directories holding CHECKPOINT.json and .sig), verifies each with the trusted key and keeps the newest authentic one.
export function loadCheckpoint(dirs, publicKey, { maxAgeDays = null, now, sigstore = null, ed25519MaxSequence = null } = {}) {
  const rs = dirs.map((d) => { try { return verifyCheckpoint({ files: Object.fromEntries([...CHECKPOINT_FILES, CHECKPOINT_BUNDLE].filter((f) => existsSync(join(d, f))).map((f) => [f, readFileSync(join(d, f))])), publicKey, maxAgeDays, now, sigstore, ed25519MaxSequence }); } catch (e) { return { ok: false, reason: String(e.message).slice(0, 80) }; } });
  return bestCheckpoint(rs);
}

// Alarms, one set per destination, plus the aggregate claim. Nothing is "OK" without a recorded success.
export function objstoreCheck({ root = ROOT_DEFAULT, clock = () => new Date(), maxCopyAgeHours = 48, maxDrillAgeDays = 35, config = DEFAULT_CONFIG } = {}) {
  const at = iso(clock()), st = readState(root).destinations, out = [];
  const A = (rule_id, state, value, threshold, message) => out.push({ schema: 'macguard.alert/1', rule_id, category: 'integrity', severity: 'high', state, value, threshold, message, dedupe_key: rule_id, evaluated_at: at, source: { kind: 'agent', id: 'backup-objstore' } });
  let fresh = 0;
  for (const n of PROVIDERS) {
    const d = st[n] ?? {}, copyAge = d.last_verified_at ? (clock() - Date.parse(d.last_verified_at)) / 3600000 : null, drillAge = d.last_drill_ok_at ? (clock() - Date.parse(d.last_drill_ok_at)) / 86400000 : null, unconf = !config.destinations[n]?.bucket;
    const copyBad = copyAge === null || copyAge > maxCopyAgeHours; if (!copyBad) fresh++;
    A(`backup.${n}.copy_stale`, copyBad ? 'FIRING' : 'OK', copyAge === null ? null : +copyAge.toFixed(1), maxCopyAgeHours, unconf ? `${n}: no bucket is configured.` : copyAge === null ? `${n}: no verified copy has ever been recorded.` : `${n}: the last verified copy is ${copyAge.toFixed(1)} h old.`);
    A(`backup.${n}.drill_stale`, drillAge === null || drillAge > maxDrillAgeDays ? 'FIRING' : 'OK', drillAge === null ? null : +drillAge.toFixed(1), maxDrillAgeDays, drillAge === null ? `${n}: no restore from this destination has ever passed.` : `${n}: the last passing restore was ${drillAge.toFixed(1)} days ago.`);
    const last = (d.drills ?? []).at(-1); A(`backup.${n}.drill_failed`, last && !last.ok ? 'FIRING' : 'OK', null, null, last && !last.ok ? `${n}: the latest restore failed: ${last.reason}` : `${n}: the latest restore did not fail.`);
  }
  A('backup.three_copies', fresh === PROVIDERS.length ? 'OK' : 'FIRING', fresh, PROVIDERS.length, `${fresh} of ${PROVIDERS.length} independent destinations hold a recently verified copy.`);
  return out;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [cmd] = process.argv.slice(2), arg = (n, d = null) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : d; }, root = arg('--root', ROOT_DEFAULT);
  try {
    const SS = () => arg('--sigstore-identity') ? { identity: arg('--sigstore-identity'), repository: arg('--sigstore-repo'), trustedRoot: arg('--trusted-root') } : null, ED = () => arg('--ed25519-max-sequence') != null ? +arg('--ed25519-max-sequence') : null;
    let config = loadConfig(arg('--config')); if (arg('--prefix')) { if (!/^[a-z0-9-]{3,40}$/.test(arg('--prefix'))) throw new Error('invalid --prefix'); config = { ...config, prefix: arg('--prefix') }; }   // one prefix per protected database: its stamps, chain and evidence never mix with another's
    const show = (r) => console.log(JSON.stringify(r, null, 1)), telemetry = outboxFromEnv();
    if (cmd === 'plan' || cmd === 'sync') { const r = await syncAll({ root, config, apply: cmd === 'sync' && process.argv.includes('--apply'), only: arg('--only') ? arg('--only').split(',') : PROVIDERS, telemetry }); show(r); if (cmd === 'sync' && !process.argv.includes('--apply')) console.log('DRY RUN: add --apply to upload'); process.exit(Object.values(r.destinations).every((d) => d.state === 'READY' ? d.ok !== false : true) ? 0 : 1); }
    else if (cmd === 'verify') { const r = await verifyAll({ root, config, telemetry }); show(r); process.exit(Object.values(r.destinations).every((d) => d.ok) ? 0 : 1); }
    else if (cmd === 'heads') { const tk = arg('--trust-key'); if (!tk || !arg('--stamp')) { console.error('heads needs --stamp and --trust-key'); process.exit(2); } const pk = existsSync(tk) ? readFileSync(tk, 'utf8').trim().split('\n')[0] : tk, cps = arg('--checkpoint-dir'), cp = cps ? loadCheckpoint(cps.split(','), pk, { maxAgeDays: arg('--max-age-days') ? +arg('--max-age-days') : null, sigstore: SS(), ed25519MaxSequence: ED() }) : null; if (cp && !cp.ok) { show(cp); process.exit(1); } const r = await headsAll({ config, stamp: arg('--stamp'), trust: { publicKey: pk, sigstore: SS(), ed25519MaxSequence: ED(), minSequence: +arg('--min-sequence', 0), checkpoint: cp?.checkpoint ?? null } }); show({ ...r, checkpoint_stale: cp?.stale ?? null }); process.exit(r.current.length && !r.stale.length && !r.conflicts.length && !r.failed.length && !r.rollback_everywhere ? 0 : 1); }
    else if (cmd === 'drill') { const tk = arg('--trust-key'), pk0 = tk ? (existsSync(tk) ? readFileSync(tk, 'utf8').trim().split('\n')[0] : tk) : null, cps0 = arg('--checkpoint-dir'), cp0 = tk && cps0 ? loadCheckpoint(cps0.split(','), pk0, { maxAgeDays: arg('--max-age-days') ? +arg('--max-age-days') : null, sigstore: SS(), ed25519MaxSequence: ED() }) : null; if (cp0 && !cp0.ok) { show(cp0); process.exit(1); } const trust = tk ? { publicKey: pk0, sigstore: SS(), ed25519MaxSequence: ED(), minSequence: +arg('--min-sequence', 0), checkpoint: cp0?.checkpoint ?? null } : null; const out = []; for (const n of PROVIDERS) out.push(await drillOne({ root, config, name: n, identityFile: arg('--identity'), telemetry, trust })); show(out); process.exit(out.every((x) => x.ok) ? 0 : 1); }
    else if (cmd === 'fetch-previous') { const tk = arg('--trust-key'); if (!tk || !arg('--out')) { console.error('fetch-previous needs --trust-key and --out'); process.exit(2); } const pk = existsSync(tk) ? readFileSync(tk, 'utf8').trim().split('\n')[0] : tk; show(await fetchPrevious({ config, only: arg('--only') ? arg('--only').split(',') : PROVIDERS, keep: process.argv.includes('--statement-only') ? 'statement' : 'all', stamp: arg('--stamp'), allowEmpty: process.argv.includes('--allow-empty'), outDir: arg('--out'), trust: { publicKey: pk, sigstore: SS(), ed25519MaxSequence: ED() } })); }
    else if (cmd === 'stamps') { const out = {}; for (const name of arg('--only') ? arg('--only').split(',') : PROVIDERS) { const c = clientFor(name, config, {}); if (c.state !== 'READY') { out[name] = { state: c.state, reason: c.reason }; continue; } try { out[name] = { state: 'READY', stamps: [...new Set((await c.client.list(config.prefix + '/')).map((k) => (k.match(new RegExp(`^${config.prefix}/(\\d{8}T\\d{6}Z)/`)) ?? [])[1]).filter(Boolean))].sort() }; } catch (e) { out[name] = { state: 'ERROR', reason: String(e.message).slice(0, 80) }; } } show(out); }
    else if (cmd === 'probe-readonly') { const r = await probeReadOnly({ config, only: arg('--only') ? arg('--only').split(',') : PROVIDERS, runId: process.env.GITHUB_RUN_ID ?? 'local' }); show(r); process.exit(Object.values(r).every((x) => x.ok) ? 0 : 1); }
    else if (cmd === 'check') { const a = objstoreCheck({ root, config }); show(a); process.exit(a.some((x) => x.state === 'FIRING') ? 1 : 0); }
    else { console.error('usage: backup_objstore.mjs plan|sync|verify|drill|check ...'); process.exit(2); }
  } catch (e) { console.error('refused: ' + e.message); process.exit(2); }
}
