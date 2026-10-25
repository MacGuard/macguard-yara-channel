// One published rule: its identity from the verified manifest, its content read from the signed release package (and checked against the manifest's SHA-256), what D1 knows about it,
// and the one way to register a rule the panel never saw so that the existing withdrawal engine (src/policies.js) can manage it. Nothing here edits a release.
import { sha256Hex } from './core.js';

const MAX_PACKAGE = 40_000_000, MAX_RULE = 2_000_000;
const stop = () => (typeof AbortSignal !== 'undefined' && AbortSignal.timeout ? AbortSignal.timeout(20_000) : undefined);
const dec = new TextDecoder('utf-8');
const octal = (b, o, n) => parseInt(dec.decode(b.subarray(o, o + n)).replace(/\0.*$/, '').trim() || '0', 8);
const cstr = (b, o, n) => dec.decode(b.subarray(o, o + n)).replace(/\0.*$/, '');

/** The bytes of `want` inside a gzip-compressed tar (ustar, GNU long names and pax `path` records), or null. Reads the decompressed stream once and stops at the entry. */
export async function tarEntry(gzBytes, want) {
  const stream = new Blob([gzBytes]).stream().pipeThrough(new DecompressionStream('gzip'));
  const reader = stream.getReader(); let buf = new Uint8Array(0), longName = null, paxPath = null;
  const need = async (n) => { while (buf.length < n) { const { done, value } = await reader.read(); if (done) return false; const m = new Uint8Array(buf.length + value.length); m.set(buf); m.set(value, buf.length); buf = m; } return true; };
  const take = async (n) => { if (!(await need(n))) return null; const out = buf.subarray(0, n); buf = buf.subarray(n); return out; };
  try {
    for (;;) {
      const h = await take(512); if (!h || h.every((x) => x === 0)) return null;
      const size = octal(h, 124, 12), type = String.fromCharCode(h[156] || 48), pad = (512 - (size % 512)) % 512;
      let name = cstr(h, 0, 100); const prefix = cstr(h, 345, 155); if (prefix && cstr(h, 257, 5) === 'ustar') name = `${prefix}/${name}`;
      if (type === 'L' || type === 'x') { const body = await take(size + pad); if (!body) return null; const txt = dec.decode(body.subarray(0, size));
        if (type === 'L') longName = txt.replace(/\0.*$/, ''); else { const m = txt.match(/(?:^|\n)\d+ path=([^\n]*)\n/); paxPath = m ? m[1] : null; } continue; }
      const full = longName || paxPath || name; longName = paxPath = null;
      if ((type === '0' || type === '\0') && full === want) { if (size > MAX_RULE) return null; const body = await take(size); return body ? new Uint8Array(body) : null; }
      let left = size + pad; while (left > 0) { const k = Math.min(left, 65536); if (!(await take(k))) return null; left -= k; }
    }
  } finally { try { await reader.cancel(); } catch { /* already closed */ } }
}

/** Reads the rule from the package of the release and checks it against the manifest. Never throws: the answer says what could be established. */
export async function loadRuleContent(env, deps, tag, path, expect) {
  const url = `https://github.com/${env.REPO}/releases/download/${tag}/rules-release.tar.gz`;
  const key = new Request(`${env.PUBLIC_URL}/__cache/rules-package-${tag}`);
  try {
    let bytes = null; const hit = deps.cache ? await deps.cache.match(key) : null; if (hit) bytes = new Uint8Array(await hit.arrayBuffer());
    if (!bytes) {
      const r = await deps.fetch(url, { headers: { 'User-Agent': 'macguard-admin' }, signal: stop() }); if (!r || !r.ok) return { status: 'UNAVAILABLE', error: `the release package answered ${r ? r.status : 'no response'}` };
      const buf = new Uint8Array(await r.arrayBuffer()); if (buf.length > MAX_PACKAGE) return { status: 'UNAVAILABLE', error: 'the release package is too large to read here' };
      bytes = buf; if (deps.cache) await deps.cache.put(key, new Response(bytes, { headers: { 'Content-Type': 'application/gzip', 'Cache-Control': 'max-age=900' } }));
    }
    const raw = await tarEntry(bytes, path); if (!raw) return { status: 'UNAVAILABLE', error: 'the file is not inside the release package' };
    if ((await sha256Hex(raw)) !== expect.sha256) return { status: 'MISMATCH', error: 'the package content does not match the SHA-256 of the signed manifest; it is not shown' };
    return { status: 'VERIFIED', content: dec.decode(raw), bytes: raw.length };
  } catch (e) { return { status: 'UNAVAILABLE', error: 'the release package could not be read' }; }
}

const pj = (s, d) => { try { return JSON.parse(s); } catch { return d; } };
/** Everything the detail shows, assembled from sources that each say where they come from; what no source provides is NO_DATA. */
export async function publishedRuleDetail(db, env, deps, inv, path) {
  const f = (inv.files || []).find(([p]) => p === path); if (!f) return { status: 404, error: 'that path is not in the current signed release' };
  const meta = f[1], m = inv.meta || {};
  const src = (m.sources || []).find((s) => s.id === meta.source) || null;
  const rec = await db.prepare("SELECT id, state, version, detected_at, reasons, metrics, release_tag, upstream_commit FROM candidates WHERE path = ? AND sha256 = ? AND archived_at IS NULL ORDER BY detected_at DESC LIMIT 1").bind(path, meta.sha256).first();
  const content = await loadRuleContent(env, deps, inv.tag, path, meta);
  const decisions = rec ? (await db.prepare('SELECT action, from_state, to_state, candidate_version, actor, role, reason, at FROM decisions WHERE candidate_id = ? ORDER BY id').bind(rec.id).all()).results : [];
  const newer = (await db.prepare("SELECT id, state, sha256, detected_at FROM candidates WHERE path = ? AND sha256 != ? AND archived_at IS NULL AND state != 'RELEASED' ORDER BY detected_at DESC LIMIT 5").bind(path, meta.sha256).all()).results;
  const base = `https://github.com/${env.REPO}/releases/download/${inv.tag}`;
  return { status: 200, release: { tag: inv.tag, url: `https://github.com/${env.REPO}/releases/tag/${inv.tag}`, published_at: inv.published_at, manifest_sha256: inv.manifest_sha256, rules_root: inv.rules_root, evidence: inv.evidence, created_at: m.created_at || null,
      signatures: { manifest: `${base}/manifest.sigstore.json`, checkpoint: `${base}/checkpoint.sigstore.json`, inclusion_proof: `${base}/inclusion-proof.json` }, publish_run_url: (m.evidence && m.evidence.publish_run_url) || null },
    file: { path, name: path.split('/').pop(), sha256: meta.sha256, bytes: meta.bytes, source: meta.source },
    provenance: src ? { source: src.id, repository: src.repository, commit: src.commit, license: src.license_check ? { detail: src.license_check.detail, redistribution: src.license_check.redistribution, spdx_reported: src.license_check.spdx_reported, ok: src.license_check.ok } : null } : { source: meta.source, repository: null, commit: null, license: null },
    content, set_validation: m.validation ? { engine: m.validation.engine, checked: m.validation.checked, scope: 'the whole release, not this rule alone' } : null, set_dynamic: m.evidence && m.evidence.dynamic ? { verdict: m.evidence.dynamic.verdict, canaries: `${m.evidence.dynamic.canaries_detected}/${m.evidence.dynamic.canaries_expected}`, engine: m.evidence.dynamic.engine, scope: 'canary rules of the whole release' } : null,
    record: rec ? { id: rec.id, state: rec.state, version: rec.version, detected_at: rec.detected_at, reasons: pj(rec.reasons, []), metrics: pj(rec.metrics, {}), release_tag: rec.release_tag, upstream_commit: rec.upstream_commit, decisions } : null,
    newer_versions: newer };
}

/** Registers a published rule the panel never saw as a RELEASED record (ADMIN, audited), so that it can be withdrawn through the engine of src/policies.js. The content must be verified against the manifest.
 *  Idempotent: the same path and bytes answer with the existing record. */
export async function adoptPublished(db, env, deps, inv, { path, request_id }, actor, now, newId) {
  const f = (inv.files || []).find(([p]) => p === path); if (!f) return { status: 404, error: 'that path is not in the current signed release' };
  const meta = f[1], known = await db.prepare('SELECT id, state FROM candidates WHERE sha256 = ? AND path = ?').bind(meta.sha256, path).first();
  if (known) return { status: 200, id: known.id, existing: true };
  const c = await loadRuleContent(env, deps, inv.tag, path, meta); if (c.status !== 'VERIFIED') return { status: 502, error: `the content could not be verified (${c.error}); nothing was registered` };
  const id = newId();
  await db.batch([
    db.prepare('INSERT OR IGNORE INTO blobs (sha256, content) VALUES (?,?)').bind(meta.sha256, c.content),
    db.prepare("INSERT INTO candidates (id, sha256, path, name, source, upstream_commit, bytes, detected_at, state, reasons, metrics, depends_on, related, version, previous_id, release_tag, updated_at) VALUES (?,?,?,?,?,?,?,?,'RELEASED','[]','{}','[]','[]',1,NULL,?,?)")
      .bind(id, meta.sha256, path, path.split('/').pop(), meta.source || 'unknown', null, meta.bytes || c.bytes, now, inv.tag, now)]);
  return { status: 200, id, existing: false, audit: { action: 'published.adopt', target: id, detail: { path, sha256: meta.sha256, tag: inv.tag, request_id: String(request_id || '').slice(0, 80) } } };
}
