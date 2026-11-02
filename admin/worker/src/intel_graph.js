// Canonical intelligence graph (INTEL D1, migration 0004): stable entity identities, evidence-backed relationships and an append-only confidence log.
// The database enforces the invariants (allowed endpoint types, CONFIRMED only with strong evidence, append-only evidence/assessments, state = latest assessment);
// this module adds what SQL cannot express: key normalisation per namespace, deterministic relationship ids, bounded reads and exposure filtering.
// Nothing here fetches anything, and no read scans a whole table: every query is keyed by id or by an indexed endpoint, with a hard LIMIT.

export const CONFIDENCE = ['CONFIRMED', 'REPORTED', 'INFERRED', 'DISPUTED', 'UNKNOWN'];
const RANK = { CONFIRMED: 4, REPORTED: 3, INFERRED: 2, DISPUTED: 1, UNKNOWN: 0 };
export const EXPOSURE = ['public', 'internal', 'restricted'];
const EXPOSURE_RANK = { public: 0, internal: 1, restricted: 2 };
export const MAX_PAGE = 200;
const STRONG = new Set(['test_run', 'human_review', 'signature', 'content_match']);

class GraphError extends Error { constructor(msg, code = 'invalid') { super(msg); this.code = code; } }
export { GraphError };

const CTRL = /[\u0000-\u001f\u007f-\u009f]/;
const HEX = { md5: 32, sha1: 40, sha256: 64, sha512: 128, 'x509-sha256': 64, 'x509-sha1': 40, ja3: 32 };

function ipv4(s) {
  const p = s.split('.'); if (p.length !== 4) throw new GraphError('ipv4: four decimal octets');
  for (const o of p) if (!/^(0|[1-9]\d{0,2})$/.test(o) || +o > 255) throw new GraphError('ipv4: octet out of range or with leading zeros (ambiguous octal)');
  return p.map(Number).join('.');
}
function ipv6(s) {
  let t = s.toLowerCase(); if (t.includes('%')) throw new GraphError('ipv6: zone ids are not indicators');
  const m4 = t.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (m4) { const v = ipv4(m4[2]).split('.').map(Number); t = m4[1] + ((v[0] << 8) | v[1]).toString(16) + ':' + ((v[2] << 8) | v[3]).toString(16); }
  const halves = t.split('::'); if (halves.length > 2) throw new GraphError('ipv6: more than one "::"');
  const part = (h) => (h === '' ? [] : h.split(':'));
  const a = part(halves[0]), b = halves.length === 2 ? part(halves[1]) : [];
  const missing = 8 - a.length - b.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) throw new GraphError('ipv6: wrong number of groups');
  const g = [...a, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...b];
  for (const x of g) if (!/^[0-9a-f]{1,4}$/.test(x)) throw new GraphError('ipv6: bad group');
  const n = g.map((x) => parseInt(x, 16).toString(16));
  let best = -1, len = 0; for (let i = 0; i < 8;) { if (n[i] !== '0') { i++; continue; } let j = i; while (j < 8 && n[j] === '0') j++; if (j - i > len) { best = i; len = j - i; } i = j; }
  if (len < 2) return n.join(':');                                  // RFC 5952: "::" only for two or more zero groups
  return n.slice(0, best).join(':') + '::' + n.slice(best + len).join(':');
}
function domain(s) {
  let d = s.toLowerCase(); if (d.endsWith('.')) d = d.slice(0, -1);
  if (!/^[\x21-\x7e]+$/.test(d)) throw new GraphError('domain: ASCII (punycode) only');
  if (d.length > 253) throw new GraphError('domain: longer than 253');
  const labels = d.split('.'); if (labels.length < 2) throw new GraphError('domain: at least two labels');
  for (const l of labels) if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(l)) throw new GraphError('domain: bad label');
  if (/^\d+$/.test(labels.at(-1))) throw new GraphError('domain: numeric TLD (is it an IP?)');
  return d;
}
function url(s) {
  let u; try { u = new URL(s); } catch { throw new GraphError('url: not parseable'); }
  if (!['http:', 'https:'].includes(u.protocol)) throw new GraphError('url: http(s) only');
  if (u.username || u.password) throw new GraphError('url: credentials are never stored');
  u.hash = ''; return u.toString();
}

/** Normalised key for (type, namespace). Throws GraphError on anything that cannot be an identifier. Idempotent: normalizeKey(t, n, normalizeKey(t, n, k)) === normalizeKey(t, n, k). */
export function normalizeKey(type, namespace, key) {
  if (typeof key !== 'string') throw new GraphError('key must be a string');
  const k = key.normalize('NFC').trim();
  if (!k || k.length > 512 || CTRL.test(k)) throw new GraphError('key: empty, too long or with control characters');
  if (HEX[namespace]) { const h = k.toLowerCase().replace(/:/g, ''); if (h.length !== HEX[namespace] || /[^0-9a-f]/.test(h)) throw new GraphError(`${namespace}: ${HEX[namespace]} hex characters`); return h; }
  switch (namespace) {
    case 'ipv4': return ipv4(k);
    case 'ipv6': return ipv6(k);
    case 'domain': return domain(k);
    case 'url': return url(k);
    case 'cve': { const c = k.toUpperCase(); if (!/^CVE-\d{4}-\d{4,}$/.test(c)) throw new GraphError('cve: CVE-YYYY-NNNN'); return c; }
    case 'ghsa': { const g = k.toLowerCase(); if (!/^ghsa(-[23456789cfghjmpqrvwx]{4}){3}$/.test(g)) throw new GraphError('ghsa: GHSA-xxxx-xxxx-xxxx'); return 'GHSA' + g.slice(4); }
    case 'euvd': { const e = k.toUpperCase(); if (!/^EUVD-\d{4}-\d+$/.test(e)) throw new GraphError('euvd: EUVD-YYYY-N'); return e; }
    // R1 (0005): GCVE ids keep their GNA (assigning authority); only GCVE-0 is defined as the CVE space (see gcveToCve). CWE is a weakness classification.
    case 'gcve': { const m = k.toUpperCase().match(/^GCVE-(\d{1,10})-(\d{4})-(\d{1,19})$/); if (!m) throw new GraphError('gcve: GCVE-<GNA>-YYYY-N'); return `GCVE-${+m[1]}-${m[2]}-${m[3]}`; }
    case 'cwe': { const m = k.toUpperCase().match(/^CWE-(\d{1,6})$/); if (!m) throw new GraphError('cwe: CWE-N'); return `CWE-${+m[1]}`; }
    case 'mitre-attack': { const a = k.toUpperCase(); if (!/^(T\d{4}(\.\d{3})?|TA\d{4}|S\d{4}|G\d{4}|M\d{4})$/.test(a)) throw new GraphError('mitre-attack: T1234, T1234.001, TA0001, S/G/M1234'); return a; }
    case 'suricata': case 'snort': { const m = k.match(/^(?:(\d{1,10}):)?(\d{1,10})$/); if (!m) throw new GraphError(`${namespace}: [gid:]sid`); return `${m[1] ? +m[1] : 1}:${+m[2]}`; }
    case 'sigma': { const s = k.toLowerCase(); if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(s)) throw new GraphError('sigma: rule UUID'); return s; }
    case 'cpe': { const c = k.toLowerCase(); if (!c.startsWith('cpe:2.3:') || c.split(/(?<!\\):/).length !== 13) throw new GraphError('cpe: CPE 2.3 formatted string with 13 components'); return c; }
    case 'purl': { const m = k.match(/^pkg:([A-Za-z.+-][A-Za-z0-9.+-]*)\/(.+)$/); if (!m) throw new GraphError('purl: pkg:type/name'); return `pkg:${m[1].toLowerCase()}/${m[2]}`; }
    default: return k;
  }
}
export const entityId = (type, namespace, key) => `${type}:${namespace}:${normalizeKey(type, namespace, key)}`;
/** GCVE-0 is the CVE namespace inside GCVE: GCVE-0-YYYY-N corresponds to CVE-YYYY-N. Any other GNA has NO CVE equivalent by definition (returns null);
 *  an equivalence for those exists only if a source asserts it (ALIAS_OF). Never extends the GCVE-0 rule to other assigners. */
export function gcveToCve(key) {
  const g = normalizeKey('vulnerability', 'gcve', key), m = g.match(/^GCVE-0-(\d{4})-(\d+)$/);
  return m && m[2].length >= 4 ? `CVE-${m[1]}-${m[2]}` : null;
}

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
/** Deterministic id: the same (type, endpoints, source, method) is the same relationship however many times it is imported. */
export async function relationshipId({ type, from, to, source_id, method }) {
  return hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(['macguard.rel/1', type, from, to, source_id, method]))));
}

/** Insert or refresh an entity. Identity columns never change (the database refuses it); display/attrs/record link may be refreshed. */
export async function putEntity(db, { type, namespace, key, display = null, record_id = null, attrs = {}, source_id = null }, now) {
  const k = normalizeKey(type, namespace, key), id = `${type}:${namespace}:${k}`;
  await db.prepare('INSERT INTO intel_entities (id,type,namespace,key,display,record_id,attrs,source_id,first_seen,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET display = excluded.display, record_id = COALESCE(excluded.record_id, intel_entities.record_id), attrs = excluded.attrs, source_id = COALESCE(excluded.source_id, intel_entities.source_id), updated_at = excluded.updated_at')
    .bind(id, type, namespace, k, display, record_id, JSON.stringify(attrs), source_id, now, now).run();
  return id;
}

const evidenceStmt = (db, relId, e, now) => {
  if (!e || !e.kind || !e.ref) throw new GraphError('evidence needs kind and ref');
  return db.prepare('INSERT INTO intel_relationship_evidence (relationship_id,kind,ref,sha256,source_id,observed_at,recorded_at,note) VALUES (?,?,?,?,?,?,?,?)').bind(relId, e.kind, e.ref, e.sha256 ?? null, e.source_id ?? null, e.observed_at ?? now, now, e.note ?? null);
};

/** Create (idempotently) a relationship and append its evidence in ONE transaction. A new relationship is UNKNOWN until assessed. */
export async function relate(db, { type, from, to, source_id, method, version = null, exposure = 'internal', observed_at, evidence = [] }, now) {
  if (!EXPOSURE.includes(exposure)) throw new GraphError('exposure must be public, internal or restricted');
  const id = await relationshipId({ type, from, to, source_id, method });
  // INSERT OR IGNORE inside the same batch as the evidence: two concurrent imports of the same relationship both succeed, and neither loses its evidence
  // (a separate existence check raced; Codex r1-canonical fix round, F1). The identity is content-derived, so the ignored row is identical.
  const stmts = [db.prepare('INSERT OR IGNORE INTO intel_relationships (id,type,from_id,to_id,source_id,method,version,exposure,observed_at,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)').bind(id, type, from, to, source_id, method, version, exposure, observed_at ?? now, now)];
  for (const e of evidence) stmts.push(evidenceStmt(db, id, e, now));
  const res = await db.batch(stmts);
  return { id, created: Number(res[0]?.meta?.changes ?? 0) > 0 };
}
export async function addEvidence(db, relId, e, now) { await evidenceStmt(db, relId, e, now).run(); }

/** Append an assessment. Beyond the database rules: an automatic correlation is confirmed only by a test run or a human review (a content match or signature is not enough for a correlation). */
export async function assess(db, relId, { confidence, verification = 'UNVERIFIED', reason, actor }, now) {
  if (!CONFIDENCE.includes(confidence)) throw new GraphError('unknown confidence');
  const rel = await db.prepare('SELECT method FROM intel_relationships WHERE id = ?').bind(relId).first(); if (!rel) throw new GraphError('no such relationship', 'not_found');
  if (confidence === 'CONFIRMED' && rel.method === 'correlated') {
    const ok = await db.prepare("SELECT 1 AS x FROM intel_relationship_evidence WHERE relationship_id = ? AND kind IN ('test_run','human_review') LIMIT 1").bind(relId).first();
    if (!ok) throw new GraphError('an automatic correlation is confirmed only by a test run or a human review', 'policy');
  }
  await db.prepare('INSERT INTO intel_relationship_assessments (relationship_id,confidence,verification,reason,actor,at) VALUES (?,?,?,?,?,?)').bind(relId, confidence, verification, reason, actor, now).run();
}

export async function getEntity(db, id) {
  const e = await db.prepare('SELECT id,type,namespace,key,display,record_id,attrs,source_id,first_seen,updated_at FROM intel_entities WHERE id = ?').bind(id).first();
  return e ? { ...e, attrs: JSON.parse(e.attrs) } : null;
}

/** Bounded neighbourhood of one entity: at most `limit` (<= MAX_PAGE) edges per call, keyset-paginated by (type, id), filtered by relationship type,
 *  minimum confidence and the caller's maximum exposure. Unknown confidence is returned as UNKNOWN, never upgraded. */
export async function neighbours(db, id, { direction = 'out', types = [], minConfidence = 'UNKNOWN', maxExposure = 'public', limit = 50, after = null } = {}) {
  if (!['out', 'in'].includes(direction)) throw new GraphError('direction is out or in');
  if (!(minConfidence in RANK) || !(maxExposure in EXPOSURE_RANK)) throw new GraphError('bad filter');
  const n = Math.max(1, Math.min(MAX_PAGE, Number(limit) | 0 || 50)), [mine, other] = direction === 'out' ? ['from_id', 'to_id'] : ['to_id', 'from_id'];
  if (types.length > 20) throw new GraphError('at most 20 relationship types per query');
  const conf = CONFIDENCE.filter((c) => RANK[c] >= RANK[minConfidence]), expo = EXPOSURE.filter((x) => EXPOSURE_RANK[x] <= EXPOSURE_RANK[maxExposure]);
  const where = [`r.${mine} = ?`, `s.confidence IN (${conf.map(() => '?').join(',')})`, `r.exposure IN (${expo.map(() => '?').join(',')})`], args = [id, ...conf, ...expo];
  if (types.length) { where.push(`r.type IN (${types.map(() => '?').join(',')})`); args.push(...types); }
  if (after) { const [t, i] = String(after).split('|'); where.push('(r.type > ? OR (r.type = ? AND r.id > ?))'); args.push(t, t, i); }
  const rows = (await db.prepare(`SELECT r.id, r.type, r.${other} AS other_id, r.source_id, r.method, r.exposure, r.observed_at, s.confidence, s.verification, s.evidence_count, e.type AS other_type, e.display AS other_display FROM intel_relationships r JOIN intel_relationship_state s ON s.relationship_id = r.id JOIN intel_entities e ON e.id = r.${other} WHERE ${where.join(' AND ')} ORDER BY r.type, r.id LIMIT ?`).bind(...args, n + 1).all()).results;
  const more = rows.length > n, page = rows.slice(0, n);
  return { edges: page, next: more ? `${page.at(-1).type}|${page.at(-1).id}` : null };
}

/** Evidence and assessment history of one relationship (bounded). */
export async function relationshipDetail(db, relId, { limit = 50 } = {}) {
  const n = Math.max(1, Math.min(MAX_PAGE, Number(limit) | 0 || 50));
  const rel = await db.prepare('SELECT r.*, s.confidence, s.verification, s.evidence_count FROM intel_relationships r JOIN intel_relationship_state s ON s.relationship_id = r.id WHERE r.id = ?').bind(relId).first();
  if (!rel) return null;
  const evidence = (await db.prepare('SELECT id,kind,ref,sha256,source_id,observed_at,recorded_at,note FROM intel_relationship_evidence WHERE relationship_id = ? ORDER BY id DESC LIMIT ?').bind(relId, n).all()).results;
  const assessments = (await db.prepare('SELECT id,confidence,verification,reason,actor,at FROM intel_relationship_assessments WHERE relationship_id = ? ORDER BY id DESC LIMIT ?').bind(relId, n).all()).results;
  return { ...rel, strong_evidence: evidence.some((e) => STRONG.has(e.kind)), evidence, assessments };
}
