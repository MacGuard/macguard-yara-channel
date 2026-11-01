// Vulnerability model (INTEL migration 0005) on the canonical graph of 0004 (src/intel_graph.js). The database enforces the invariants (append-only per-source
// assessments, CWE without CVSS, ALIAS_OF only asserted, no PoC in a package, validated detection only with a test run); this module adds input validation that
// SQL cannot express (CVSS vector grammar per version, dates), alias conflict handling, the "absence is not a state" reading of exploitation, and the bounded
// export record (contracts/v1/intel-vulnerability.schema.json). Nothing here fetches anything; every read is keyed and LIMITed.
import { GraphError, normalizeKey, entityId, putEntity, relate, assess, gcveToCve, MAX_PAGE } from './intel_graph.js';

export const NORMALISATION = 'macguard.norm/1';
export const EXPORT_SCHEMA = 'macguard.intel-vulnerability/1';
const VULN_NS = ['cve', 'euvd', 'gcve', 'ghsa'];
const DATE = /^\d{4}-\d{2}-\d{2}$/, TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;
const okDate = (s) => typeof s === 'string' && DATE.test(s) && !Number.isNaN(Date.parse(s + 'T00:00:00Z')) && new Date(s + 'T00:00:00Z').toISOString().startsWith(s);
const okTs = (s) => typeof s === 'string' && TS.test(s) && Number.isFinite(Date.parse(s));
const need = (c, m) => { if (!c) throw new GraphError(m); };

// ---- CVSS vectors: base metrics per version (mandatory, each once, allowed values). Extra (temporal/environmental/supplemental) metrics are allowed but validated. ----
const V3 = { AV: 'NALP', AC: 'LH', PR: 'NLH', UI: 'NR', S: 'UC', C: 'NLH', I: 'NLH', A: 'NLH' };
const V3X = { E: 'XUPFH', RL: 'XOTWU', RC: 'XURC', CR: 'XLMH', IR: 'XLMH', AR: 'XLMH', MAV: 'XNALP', MAC: 'XLH', MPR: 'XNLH', MUI: 'XNR', MS: 'XUC', MC: 'XNLH', MI: 'XNLH', MA: 'XNLH' };
const V4 = { AV: 'NALP', AC: 'LH', AT: 'NP', PR: 'NLH', UI: 'NPA', VC: 'HLN', VI: 'HLN', VA: 'HLN', SC: 'HLN', SI: 'HLN', SA: 'HLN' };
const V4X = { E: 'XAPU', CR: 'XHML', IR: 'XHML', AR: 'XHML', MAV: 'XNALP', MAC: 'XLH', MAT: 'XNP', MPR: 'XNLH', MUI: 'XNPA', MVC: 'XHLN', MVI: 'XHLN', MVA: 'XHLN', MSC: 'XHLN', MSI: 'XSHLN', MSA: 'XSHLN', S: 'XNP', AU: 'XNY', R: 'XAUI', V: 'XDC', RE: 'XLMH', U: 'XClearGreenAmberRed' };
const V2 = { AV: 'LAN', AC: 'HML', Au: 'MSN', C: 'NPC', I: 'NPC', A: 'NPC' };
const V2X = { E: ['U', 'POC', 'F', 'H', 'ND'], RL: ['OF', 'TF', 'W', 'U', 'ND'], RC: ['UC', 'UR', 'C', 'ND'], CDP: ['N', 'L', 'LM', 'MH', 'H', 'ND'], TD: ['N', 'L', 'M', 'H', 'ND'], CR: ['L', 'M', 'H', 'ND'], IR: ['L', 'M', 'H', 'ND'], AR: ['L', 'M', 'H', 'ND'] };
function metrics(parts, base, extra, multi = false) {
  const seen = new Set();
  for (const p of parts) {
    const [k, v, ...rest] = p.split(':'); if (!k || v === undefined || rest.length || seen.has(k)) return false; seen.add(k);
    const allowed = base[k] ?? extra[k]; if (!allowed) return false;
    if (Array.isArray(allowed) ? !allowed.includes(v) : (multi && k === 'U' ? !['X', 'Clear', 'Green', 'Amber', 'Red'].includes(v) : !(v.length === 1 && allowed.includes(v)))) return false;
  }
  return Object.keys(base).every((k) => seen.has(k));
}
/** true when `vector` is a syntactically complete CVSS vector of `version` (base metrics present once, known metrics only). */
export function validCvssVector(version, vector) {
  if (typeof vector !== 'string' || vector.length > 300) return false;
  if (version === '2.0') return metrics(vector.split('/'), V2, V2X);
  const m = vector.match(/^CVSS:(3\.0|3\.1|4\.0)\/(.+)$/); if (!m || m[1] !== version) return false;
  return version === '4.0' ? metrics(m[2].split('/'), V4, V4X, true) : metrics(m[2].split('/'), V3, V3X);
}

// ---- identities ----
/** Put a vulnerability entity for one identifier (cve/euvd/gcve/ghsa). It never creates OTHER identifiers: an EUVD/GCVE id without a source mapping gets no CVE. */
export async function putVulnerability(db, { namespace, key, display = null, attrs = {}, record_id = null, source_id = null }, now) {
  need(VULN_NS.includes(namespace), `vulnerability namespace must be one of ${VULN_NS}`);
  return putEntity(db, { type: 'vulnerability', namespace, key, display, attrs, record_id, source_id }, now);
}
export async function putWeakness(db, { key, name = null, description = null, category = null, mitigations = [] , source_id = 'mitre-cwe' }, now) {
  return putEntity(db, { type: 'weakness', namespace: 'cwe', key, display: name, attrs: { description, category, mitigations }, source_id }, now);
}

/** Record an identifier equivalence ASSERTED by a source (evidence: a source statement or document). It is REPORTED, never CONFIRMED automatically.
 *  If the identifier already has a non-disputed alias to a DIFFERENT identifier of the same namespace (e.g. one EUVD -> two CVEs), every conflicting alias
 *  is marked DISPUTED: they are kept, shown as conflicting, and never merged. */
export async function recordAlias(db, { from, to, source_id, evidence, observed_at, actor = 'ingest' }, now) {
  for (const id of [from, to]) { const e = await db.prepare('SELECT type FROM intel_entities WHERE id = ?').bind(id).first(); need(e && e.type === 'vulnerability', 'ALIAS_OF joins two existing vulnerability identifiers'); }
  need(evidence && ['source_statement', 'document'].includes(evidence.kind) && evidence.ref, 'an alias needs the source statement or document that asserts it');
  const { id } = await relate(db, { type: 'ALIAS_OF', from, to, source_id, method: 'asserted_by_source', version: NORMALISATION, exposure: 'public', observed_at, evidence: [{ ...evidence, source_id }] }, now);
  // A conflict is any OTHER alias of `from` to a different identifier of the same namespace, whatever its current state (a DISPUTED one included):
  // re-importing one side of a conflict must never turn it back into an equivalence (Codex r1-canonical F2). Only a manual decision resolves a dispute.
  const toNs = to.split(':')[1], cur = await db.prepare('SELECT confidence FROM intel_relationship_state WHERE relationship_id = ?').bind(id).first();
  if (cur?.confidence !== 'DISPUTED') await assess(db, id, { confidence: 'REPORTED', reason: `asserted by ${source_id}`, actor }, now);
  // Equivalence is bidirectional: look at the aliases of BOTH endpoints in BOTH directions. `from` may have only one alias in `to`'s namespace and `to` only one in
  // `from`'s namespace; any other is a conflict (Codex r1-canonical round 2, F1).
  const fromNs = from.split(':')[1];
  const aliasesIn = async (x, ns, except) => (await db.prepare("SELECT r.id, CASE WHEN r.from_id = ? THEN r.to_id ELSE r.from_id END AS other, s.confidence FROM intel_relationships r JOIN intel_relationship_state s ON s.relationship_id = r.id WHERE r.type = 'ALIAS_OF' AND (r.from_id = ? OR r.to_id = ?) ORDER BY r.id LIMIT ?").bind(x, x, x, MAX_PAGE).all()).results
    .filter((o) => o.id !== id && o.other.split(':')[1] === ns && o.other !== except);
  const clash = [...await aliasesIn(from, toNs, to), ...await aliasesIn(to, fromNs, from)];
  if (clash.length) for (const r of [{ id, confidence: (await db.prepare('SELECT confidence FROM intel_relationship_state WHERE relationship_id = ?').bind(id).first()).confidence }, ...clash])
    if (r.confidence !== 'DISPUTED') await assess(db, r.id, { confidence: 'DISPUTED', reason: `conflicting ${toNs} aliases for ${from}: kept separate, never merged`, actor: 'system' }, now);
  const st = await db.prepare('SELECT confidence FROM intel_relationship_state WHERE relationship_id = ?').bind(id).first();
  return { id, disputed: st.confidence === 'DISPUTED' };
}
/** GCVE-0-YYYY-N <-> CVE-YYYY-N by the GCVE definition (source 'gcve-spec'). Returns null for any other GNA: no CVE is invented. */
export async function linkGcve0(db, gcveKey, now) {
  const cve = gcveToCve(gcveKey); if (!cve) return null;
  const g = await putVulnerability(db, { namespace: 'gcve', key: gcveKey }, now), c = await putVulnerability(db, { namespace: 'cve', key: cve }, now);
  return recordAlias(db, { from: g, to: c, source_id: 'gcve-spec', evidence: { kind: 'document', ref: 'GCVE BCP-03: GCVE-0 is the CVE namespace' } }, now);
}
/** Aliases of one identifier (both directions), split into equivalent (REPORTED/CONFIRMED) and disputed/unknown. Bounded. */
export async function aliasesOf(db, id, { maxExposure = 'public' } = {}) {
  const expo = { public: ['public'], internal: ['public', 'internal'], restricted: ['public', 'internal', 'restricted'] }[maxExposure]; need(expo, 'maxExposure public/internal/restricted');
  const rows = (await db.prepare(`SELECT r.id, CASE WHEN r.from_id = ? THEN r.to_id ELSE r.from_id END AS other, r.source_id, r.observed_at, s.confidence FROM intel_relationships r JOIN intel_relationship_state s ON s.relationship_id = r.id WHERE r.type = 'ALIAS_OF' AND (r.from_id = ? OR r.to_id = ?) AND r.exposure IN (${expo.map(() => '?').join(',')}) ORDER BY r.id LIMIT ?`).bind(id, id, id, ...expo, MAX_PAGE).all()).results;
  const view = (r) => ({ id: r.other.split(':').slice(2).join(':'), namespace: r.other.split(':')[1], source: r.source_id, observed_at: r.observed_at, confidence: r.confidence });
  return { equivalent: rows.filter((r) => ['REPORTED', 'CONFIRMED'].includes(r.confidence)).map(view), disputed: rows.filter((r) => !['REPORTED', 'CONFIRMED'].includes(r.confidence)).map(view) };
}

// ---- assessments ----
const SEV = (v, s) => (v === '2.0' ? (s < 4 ? 'LOW' : s < 7 ? 'MEDIUM' : 'HIGH') : s === 0 ? 'NONE' : s < 4 ? 'LOW' : s < 7 ? 'MEDIUM' : s < 9 ? 'HIGH' : 'CRITICAL');
/** Append a CVSS assessment from one source. availability NOT_PROVIDED/WITHDRAWN records that the source has no score (never a guessed one). */
export async function addSeverity(db, vulnId, { source_id, cvss_version, vector = null, base_score = null, availability = 'AVAILABLE', assessed_at }, now) {
  need(['2.0', '3.0', '3.1', '4.0'].includes(cvss_version), 'unknown CVSS version'); need(okTs(assessed_at), 'assessed_at must be a UTC timestamp'); need(source_id, 'source_id required');
  let severity = null;
  if (availability === 'AVAILABLE') { need(validCvssVector(cvss_version, vector), `invalid CVSS ${cvss_version} vector`); need(typeof base_score === 'number' && base_score >= 0 && base_score <= 10 && Math.abs(Math.round(base_score * 10) - base_score * 10) < 1e-9, 'base_score 0.0-10.0'); severity = SEV(cvss_version, base_score); }
  else { need(vector === null && base_score === null, 'no vector or score when the source does not provide one'); }
  await db.prepare('INSERT OR IGNORE INTO intel_severity_assessments (vuln_id,source_id,cvss_version,availability,vector,base_score,severity,assessed_at,recorded_at) VALUES (?,?,?,?,?,?,?,?,?)').bind(vulnId, source_id, cvss_version, availability, vector, base_score, severity, assessed_at, now).run();
  return severity;
}
/** EPSS of one day: updates the latest (only forward in time) and, when `keepHistory`, appends the dated snapshot. */
export async function addEpss(db, vulnId, { source_id = 'first-epss', score_date, probability, percentile, model_version = null, keepHistory = false }, now) {
  need(okDate(score_date), 'score_date YYYY-MM-DD'); for (const v of [probability, percentile]) need(typeof v === 'number' && v >= 0 && v <= 1, 'probability and percentile are in [0,1]');
  // ONE atomic upsert (no read-then-write race between concurrent imports): it inserts, or updates only when this score is not older than the stored one.
  const stmts = [db.prepare('INSERT INTO intel_epss_latest (vuln_id,source_id,score_date,probability,percentile,model_version,recorded_at) VALUES (?,?,?,?,?,?,?) ON CONFLICT(vuln_id, source_id) DO UPDATE SET score_date = excluded.score_date, probability = excluded.probability, percentile = excluded.percentile, model_version = excluded.model_version, recorded_at = excluded.recorded_at WHERE excluded.score_date >= intel_epss_latest.score_date')
    .bind(vulnId, source_id, score_date, probability, percentile, model_version, now)];
  if (keepHistory) stmts.push(db.prepare('INSERT OR IGNORE INTO intel_epss_history (vuln_id,source_id,score_date,probability,percentile,model_version,recorded_at) VALUES (?,?,?,?,?,?,?)').bind(vulnId, source_id, score_date, probability, percentile, model_version, now));
  const res = await db.batch(stmts);
  return { latest_updated: Number(res[0]?.meta?.changes ?? 0) > 0 };
}
export async function recordSnapshot(db, { source_id, snapshot_at, item_count, sha256, complete = true }, now) {
  need(okTs(snapshot_at), 'snapshot_at must be a UTC timestamp');
  await db.prepare('INSERT OR IGNORE INTO intel_source_snapshots (source_id,snapshot_at,item_count,sha256,complete,recorded_at) VALUES (?,?,?,?,?,?)').bind(source_id, snapshot_at, item_count, sha256, complete ? 1 : 0, now).run();
  return (await db.prepare('SELECT id FROM intel_source_snapshots WHERE source_id = ? AND snapshot_at = ?').bind(source_id, snapshot_at).first()).id;
}
export async function addExploitation(db, vulnId, { source_id, kind, listed_at = null, due_date = null, required_action = null, ransomware_use = null, evidence_ref, snapshot_id = null, observed_at }, now) {
  for (const d of [listed_at, due_date]) need(d === null || okDate(d), 'dates are YYYY-MM-DD'); need(okTs(observed_at), 'observed_at must be a UTC timestamp');
  await db.prepare('INSERT OR IGNORE INTO intel_exploitation_evidence (vuln_id,source_id,kind,listed_at,due_date,required_action,ransomware_use,evidence_ref,snapshot_id,observed_at,recorded_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
    .bind(vulnId, source_id, kind, listed_at, due_date, required_action, ransomware_use, evidence_ref, snapshot_id, observed_at, now).run();
}
/** KEV status as of the latest COMPLETE snapshot of `kevSource`: LISTED / NOT_LISTED (as_of that snapshot) / UNKNOWN (no snapshot: the source is unavailable).
 *  Exploitation evidence is EVIDENCE_RECORDED or NO_EVIDENCE_RECORDED: there is no "not exploited" answer, by design. */
export async function exploitationStatus(db, vulnId, { kevSource = 'cisa-kev' } = {}) {
  const snap = await db.prepare('SELECT id, snapshot_at FROM intel_source_snapshots WHERE source_id = ? AND complete = 1 ORDER BY snapshot_at DESC LIMIT 1').bind(kevSource).first();
  const ev = (await db.prepare('SELECT source_id, kind, listed_at, due_date, required_action, ransomware_use, evidence_ref, observed_at FROM intel_exploitation_evidence WHERE vuln_id = ? ORDER BY observed_at DESC, id DESC LIMIT ?').bind(vulnId, MAX_PAGE).all()).results;
  // the most recently OBSERVED KEV event of that source, read on its own (never cut off by the page of other sources' evidence; a late historical import never wins)
  const last = await db.prepare("SELECT kind, listed_at, due_date, required_action, observed_at FROM intel_exploitation_evidence WHERE vuln_id = ? AND source_id = ? AND kind IN ('KEV_LISTED','KEV_DELISTED') ORDER BY observed_at DESC, id DESC LIMIT 1").bind(vulnId, kevSource).first();   // the most recently OBSERVED KEV event wins (not the last imported: a late historical import never overrides a newer observation)
  let kev;
  if (last && last.kind === 'KEV_LISTED') kev = { status: 'LISTED', source: kevSource, date_added: last.listed_at, due_date: last.due_date, required_action: last.required_action, as_of: snap && snap.snapshot_at >= last.observed_at ? snap.snapshot_at : last.observed_at };   // never attribute a listing to a snapshot older than the listing itself
  else if (snap) kev = { status: 'NOT_LISTED', source: kevSource, as_of: snap.snapshot_at, note: 'not in the KEV catalogue as of this snapshot; this is not evidence that it is not exploited' };
  else kev = { status: 'UNKNOWN', source: kevSource, as_of: null, note: 'no KEV snapshot available' };
  const inWild = ev.filter((e) => e.kind !== 'KEV_DELISTED');
  return { kev, evidence_status: inWild.length ? 'EVIDENCE_RECORDED' : 'NO_EVIDENCE_RECORDED', evidence: inWild.map((e) => ({ source: e.source_id, kind: e.kind, observed_at: e.observed_at, ref: e.evidence_ref })) };
}

// ---- products and ranges ----
const sha256hex = async (s) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))].map((b) => b.toString(16).padStart(2, '0')).join('');
/** A version range is its own identity (SHA-256 of its canonical fields), joined to its product and to the vulnerability that a source says affects it. */
export async function addAffectedRange(db, { vuln_id, product, scheme, ecosystem = null, introduced = null, fixed = null, last_affected = null, version_limit = null, source_id, observed_at, evidence }, now) {
  need(['SEMVER', 'ECOSYSTEM', 'CPE', 'GIT'].includes(scheme), 'scheme SEMVER/ECOSYSTEM/CPE/GIT'); need(!(fixed && last_affected), 'fixed and last_affected are exclusive');
  need(introduced || fixed || last_affected, 'a range needs at least one bound'); need(scheme !== 'ECOSYSTEM' || ecosystem, 'ECOSYSTEM ranges name their ecosystem');
  const productId = await putEntity(db, { type: 'product', namespace: product.namespace, key: product.key, display: product.display ?? null }, now);
  const key = await sha256hex(JSON.stringify(['macguard.range/1', productId, scheme, ecosystem, introduced, fixed, last_affected, version_limit]));
  const rangeId = await putEntity(db, { type: 'version_range', namespace: 'range', key, display: `${introduced ?? '*'}..${fixed ? '<' + fixed : last_affected ? '<=' + last_affected : '*'}` }, now);
  await db.prepare('INSERT OR IGNORE INTO intel_version_ranges (entity_id,product_id,scheme,ecosystem,introduced,fixed,last_affected,version_limit) VALUES (?,?,?,?,?,?,?,?)').bind(rangeId, productId, scheme, ecosystem, introduced, fixed, last_affected, version_limit).run();
  await relate(db, { type: 'RANGE_OF_PRODUCT', from: rangeId, to: productId, source_id, method: 'asserted_by_source', version: NORMALISATION, exposure: 'public', observed_at }, now);
  const rel = await relate(db, { type: 'VULN_AFFECTS_RANGE', from: vuln_id, to: rangeId, source_id, method: 'asserted_by_source', version: NORMALISATION, exposure: 'public', observed_at, evidence: evidence ? [{ ...evidence, source_id }] : [] }, now);
  if (evidence && ['source_statement', 'document'].includes(evidence.kind)) await assess(db, rel.id, { confidence: 'REPORTED', reason: `affected range from ${source_id}`, actor: 'ingest' }, now);
  return { productId, rangeId, relationship: rel.id };
}

// ---- packages ----
/** Record a published defensive package (immutable). The database refuses PoC content in a package; here we also refuse empty or unsigned descriptors. */
export async function putPackage(db, p, now) {
  need(p.items_count > 0 && p.size_bytes > 0, 'an empty package is never recorded'); need(Array.isArray(p.licences) && p.licences.length, 'a package declares its licences');
  const id = await putEntity(db, { type: 'package', namespace: p.family, key: `${p.name}@${p.version}`, display: `${p.name} ${p.version}` }, now);
  await db.prepare('INSERT INTO intel_packages (entity_id,family,tier,name,version,engine,engine_min_version,format,release_tag,items_count,size_bytes,manifest_sha256,artifact_sha256,signature_ref,log_index,licences,validation_state,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
    .bind(id, p.family, p.tier, p.name, p.version, p.engine, p.engine_min_version ?? null, p.format, p.release_tag ?? null, p.items_count, p.size_bytes, p.manifest_sha256, p.artifact_sha256, p.signature_ref ?? null, p.log_index ?? null, JSON.stringify(p.licences), p.validation_state, now).run();
  return id;
}

// ---- detection levels (rule <-> vulnerability), as shown to users ----
const LEVEL = { RULE_ASSOCIATED_WITH_CVE: 'related', RULE_APPLIES_TO_PRODUCT: 'compatible', RULE_DETECTS_CVE_BEHAVIOUR: 'detects-behaviour', RULE_DETECTS_CVE: 'claimed-detection' };
/** Level of a rule<->vulnerability edge. 'validated-detection' ONLY for RULE_DETECTS_CVE that is CONFIRMED and VERIFIED (the database requires a test run for that). */
export const detectionLevel = (type, confidence, verification) => (type === 'RULE_DETECTS_CVE' && confidence === 'CONFIRMED' && verification === 'VERIFIED' ? 'validated-detection' : LEVEL[type] ?? null);

// ---- export record (contracts/v1/intel-vulnerability.schema.json) ----
/** The public/premium view of one vulnerability, assembled from keyed reads only (each LIMIT <= MAX_PAGE). Missing data stays missing (null / []), never zero. */
export async function vulnerabilityRecord(db, vulnId, { maxExposure = 'public' } = {}) {
  const v = await db.prepare("SELECT id, namespace, key, display, attrs, first_seen, updated_at FROM intel_entities WHERE id = ? AND type = 'vulnerability'").bind(vulnId).first();
  if (!v) return null;
  const attrs = JSON.parse(v.attrs), expo = { public: ['public'], internal: ['public', 'internal'], restricted: ['public', 'internal', 'restricted'] }[maxExposure];
  need(expo, 'maxExposure public/internal/restricted');
  const ex = `r.exposure IN (${expo.map(() => '?').join(',')})`;
  const edges = async (dir, types) => (await db.prepare(`SELECT r.id, r.type, r.source_id, r.observed_at, ${dir === 'out' ? 'r.to_id' : 'r.from_id'} AS other, s.confidence, s.verification FROM intel_relationships r JOIN intel_relationship_state s ON s.relationship_id = r.id WHERE ${dir === 'out' ? 'r.from_id' : 'r.to_id'} = ? AND r.type IN (${types.map(() => '?').join(',')}) AND ${ex} ORDER BY r.type, r.id LIMIT ?`).bind(vulnId, ...types, ...expo, MAX_PAGE).all()).results;
  const key = (id) => id.split(':').slice(2).join(':'), ns = (id) => id.split(':')[1];
  const aliases = await aliasesOf(db, vulnId, { maxExposure });
  const sev = (await db.prepare('SELECT source_id, cvss_version, availability, vector, base_score, severity, assessed_at FROM intel_severity_current WHERE vuln_id = ? ORDER BY source_id, cvss_version LIMIT ?').bind(vulnId, MAX_PAGE).all()).results;
  const epss = await db.prepare('SELECT source_id, score_date, probability, percentile, model_version FROM intel_epss_latest WHERE vuln_id = ? ORDER BY score_date DESC LIMIT 1').bind(vulnId).first();
  const weak = await edges('out', ['VULN_HAS_WEAKNESS']), adv = await edges('out', ['CVE_HAS_ADVISORY']), poc = await edges('out', ['CVE_HAS_POC_REFERENCE']);
  const ranges = await edges('out', ['VULN_AFFECTS_RANGE']), rules = await edges('in', ['RULE_ASSOCIATED_WITH_CVE', 'RULE_DETECTS_CVE_BEHAVIOUR', 'RULE_DETECTS_CVE']), iocs = await edges('in', ['INDICATOR_ASSOCIATED_WITH_CVE']);
  const affected = [];
  for (const r of ranges) { const row = await db.prepare('SELECT product_id, scheme, ecosystem, introduced, fixed, last_affected FROM intel_version_ranges WHERE entity_id = ?').bind(r.other).first(); if (row) affected.push({ product: { namespace: ns(row.product_id), key: key(row.product_id) }, scheme: row.scheme, ecosystem: row.ecosystem, introduced: row.introduced, fixed: row.fixed, last_affected: row.last_affected, source: r.source_id, confidence: r.confidence }); }
  return {
    schema: EXPORT_SCHEMA, id: v.key, namespace: v.namespace, title: v.display ?? null, summary: attrs.summary ?? null, published: attrs.published ?? null, modified: attrs.modified ?? null,
    aliases: aliases.equivalent, disputed_aliases: aliases.disputed,
    weaknesses: weak.map((w) => ({ cwe: key(w.other), source: w.source_id, confidence: w.confidence })),
    severity: sev.map((s) => ({ source: s.source_id, cvss_version: s.cvss_version, availability: s.availability, vector: s.vector, base_score: s.base_score, severity: s.severity, assessed_at: s.assessed_at })),
    epss: epss ? { source: epss.source_id, score_date: epss.score_date, probability: epss.probability, percentile: epss.percentile, model_version: epss.model_version, meaning: 'estimated probability of exploitation activity in the next 30 days; not a severity' } : null,
    exploitation: await exploitationStatus(db, vulnId),
    affected,
    advisories: adv.map((a) => ({ id: key(a.other), source: a.source_id, confidence: a.confidence })),
    detections: rules.map((r) => ({ rule: key(r.other), family: ns(r.other), level: detectionLevel(r.type, r.confidence, r.verification), confidence: r.confidence, verification: r.verification })),
    indicators: iocs.map((i) => ({ type: ns(i.other), value: key(i.other), source: i.source_id, confidence: i.confidence })),
    poc_references: poc.map((p) => ({ ref: key(p.other), source: p.source_id, confidence: p.confidence, review: p.confidence === 'CONFIRMED' ? 'HUMAN_REVIEWED' : 'NOT_REVIEWED', executable_content: false })),
  };
}
export { normalizeKey, entityId };
