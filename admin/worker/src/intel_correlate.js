// Deterministic correlation rule engine (design: docs/design/CORRELATION-ENGINE.md §5, PR #87, NOT yet approved). PURE: no database, no network, no clock.
// Input: one snapshot of normalised source documents. Output: proposed relationships, a rejection report, retractions and conflicts. Same input, same bytes
// (serialize()). Nothing here writes the graph: toGraph() only describes how a proposal maps onto the CURRENT INTEL 0004/0005 schema.
//
// INPUT CONTRACT (macguard.correlation-input/0, defined here because no shared contract exists yet):
//   { kev: [{ source_id?, document }], rule_indexes: [{ source_id?, document }] }
//   * kev[].document: macguard.intel-kev/1 exactly as admin/worker/src/intel_ingest.js normalizeKev() writes it (branch feat/hub-ingest,
//     contracts/v1/intel-kev.schema.json). original_source_id = document.source.id. source_id defaults to the same; a republisher (an aggregator
//     that copies KEV) passes its own source_id, so its evidence counts as the SAME original source.
//   * rule_indexes[].document: macguard.search-index/1 from scripts/rule_index.py (contracts/v1/search-index.schema.json). source_id defaults to
//     YARA_SOURCE_ID, a PROVISIONAL id: config/intel/sources.registry.json has no entry for the MacGuard YARA release (gap, see the tests).
//   Several documents of one source_id are successive snapshots: the latest one is used; what only older ones stated is reported as retracted.
//
// RULES (versioned; a change of predicate is a new version):
//   R-KEV-CWE-1   KEV item cwes[]                       -> VULN_HAS_WEAKNESS        vulnerability:cve:X -> weakness:cwe:CWE-N    asserted (the KEV source)
//   R-YARA-HASH-1 rule meta SHA-256 in an allow-listed key -> RULE_REFERENCES_SAMPLE  rule:yara:P#N -> sample:sha256:H            asserted (rule author, signed release)
//   R-YARA-CVE-1  rule meta CVE in an allow-listed key    -> RULE_ASSOCIATED_WITH_CVE rule:yara:P#N -> vulnerability:cve:X       asserted; NEVER RULE_DETECTS_CVE*
//   The contract names RULE_META_MENTIONS_SAMPLE / RULE_META_REFERENCES_CVE; those types do not exist in 0004/0005, so the engine emits the existing
//   types (contract review input; see CONTRACT_TYPE_MISMATCHES). A rule never emits RULE_DETECTS_CVE or RULE_DETECTS_CVE_BEHAVIOUR.
//
// NEVER: text similarity, transitivity (no relation is derived from two others), alias merges (md5/sha1/sha256 of "the same sample" stay apart), CVSS or
// any severity, reading KEV notes/description/product/vendor, reading rule names. Malformed or non-canonical identifiers (scripts/intel_ids.py rules,
// ported in intel_ids.js) produce no relation and a rejection.
import { isCanonical } from './intel_ids.js';

export const OUTPUT_SCHEMA = 'macguard.correlation/0';
export const YARA_SOURCE_ID = 'macguard-yara-release';   // PROVISIONAL: not in the source registry
export const DB_KEY_MAX = 512;                           // intel_entities.key CHECK (0004); a valid rule identity key can be 529 characters

export const RULES = Object.freeze({
  'R-KEV-CWE-1': { version: 1, type: 'VULN_HAS_WEAKNESS', contract_type: 'VULN_HAS_WEAKNESS' },
  'R-YARA-HASH-1': { version: 1, type: 'RULE_REFERENCES_SAMPLE', contract_type: 'RULE_META_MENTIONS_SAMPLE' },
  'R-YARA-CVE-1': { version: 1, type: 'RULE_ASSOCIATED_WITH_CVE', contract_type: 'RULE_META_REFERENCES_CVE' },
});
export const CONTRACT_TYPE_MISMATCHES = Object.freeze([
  { contract: 'RULE_META_MENTIONS_SAMPLE', schema: null, emitted_as: 'RULE_REFERENCES_SAMPLE', note: 'not in 0004/0005; nearest existing type (0004, rule->sample)' },
  { contract: 'RULE_META_REFERENCES_CVE', schema: null, emitted_as: 'RULE_ASSOCIATED_WITH_CVE', note: 'not in 0004/0005; nearest existing type (0004, rule->vulnerability, "association only")' },
]);

// R-YARA-HASH-1 / R-YARA-CVE-1 exact meta-key allow-lists (lowercased key, full match). Only a WHOLE-VALUE identifier in one of these keys is asserted.
// An identifier embedded in free text (description, a reference URL, "sha256: <hex>" ...) or in any other key is at most a candidate (never public).
// Decision on references: `reference = "CVE-2023-3519"` (the whole value is a CVE) is asserted; `reference = "https://x/...cve-2023-3519..."` is a
// candidate, because the CVE is part of a third party's locator (a PoC repository name, a blog slug), not an identifier the rule author wrote as such.
// Contract v3 (docs/correlation-engine 88c60a8): keys are compared after ASCII lower-casing (a meta key is an ASCII identifier); the evidence locator keeps
// the original case. `hash` + digits covers hash0, hash1 ... hashN.
export const HASH_KEYS = /^(?:hash[0-9]*|sha256|sample|samples)$/;
export const CVE_KEYS = /^(?:cve|cves|vuln|vulnerability|reference)$/;
export const HASH_KIND_KEYS = { sha256: 'sha256', sha1: 'sha1', md5: 'md5' };
// Generic-rule guard: a rule that asserts more distinct values than this for one rule loses the asserted state for all of them (candidate,
// 'generic_rule_fanout'). Measured on rules-20261101-41271797671: max 140 distinct hashes, max 2 distinct CVEs per rule.
export const MAX_ASSERTED_PER_RULE = Object.freeze({ 'R-YARA-HASH-1': 256, 'R-YARA-CVE-1': 5 });

// Mapping onto the CURRENT schema (0004 vocabulary). candidate = proposed, never public: INFERRED/UNVERIFIED, method derived_from_content,
// evidence kind 'document' (0004 has no evidence kind that is neither strong nor REPORTED-enabling: see the gap tests).
export const STATE_MAP = Object.freeze({
  asserted: { method: 'asserted_by_source', evidence_kind: 'source_statement', confidence: 'REPORTED', verification: 'UNVERIFIED', exposure: 'internal' },
  candidate: { method: 'derived_from_content', evidence_kind: 'document', confidence: 'INFERRED', verification: 'UNVERIFIED', exposure: 'restricted' },
});

/** Total projection of the schema's assessment vocabulary onto contract states (contract v3 §4). `evidenceKinds` = kinds recorded for the relationship,
 *  `sourceApproved` = the relationship's source is APPROVED_PUBLIC in the registry. Engine 'asserted' = REPORTED/UNVERIFIED + source_statement evidence. */
export function projectState({ confidence, verification, evidenceKinds = [], sourceApproved = false }) {
  if (verification === 'FAILED') return 'rejected';
  if (confidence === 'DISPUTED') return 'disputed';
  if (confidence === 'CONFIRMED' && verification === 'VERIFIED') return 'verified';
  const stated = evidenceKinds.some((k) => k === 'source_statement' || k === 'document');
  if ((confidence === 'CONFIRMED' || confidence === 'REPORTED') && verification === 'UNVERIFIED' && stated && sourceApproved) return 'asserted';
  return 'candidate';
}

const SOURCE_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const HEX64 = /^[0-9a-f]{64}$/;
// Canonical forms only (Codex c4 r2 F2): a run number or a KEV version suffix with a leading zero (rules-20260101-01, 2026.10.30.01, 2026.10.30.0) would
// order equal to another spelling and let input order pick the latest snapshot.
const TAG = /^rules-([0-9]{8})-(0|[1-9][0-9]{0,19})$/;
const KEV_VERSION = /^([0-9]{4})\.([0-9]{2})\.([0-9]{2})(?:\.([1-9][0-9]{0,3}))?$/;
const TS = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;
const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const cmpBy = (...keys) => (x, y) => { for (const k of keys) { const c = cmp(k(x), k(y)); if (c) return c; } return 0; };
const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
// Every input value embedded in a report string goes through the SAME canonical serialisation as contentKey (sorted keys, sorted set-arrays, JSON number
// formatting), capped at MAX_REPORT code points (Codex c4 fix round MEDIUM: {"id":..,"name":..} and {"name":..,"id":..} are one content but printed
// differently, so input order chose the output bytes). The cap keeps the longest valid rule identity (534) intact.
export const MAX_REPORT = 600;
const str = (x) => {
  const t = typeof x === 'string' ? x : JSON.stringify(canonSet(x)) ?? String(x), cp = [...t];
  return cp.length > MAX_REPORT ? `${cp.slice(0, MAX_REPORT).join('')}...(${cp.length} code points)` : t;
};

/** Numeric, fixed-width sort key of a canonical KEV catalogue version (YYYY.MM.DD[.N]). */
function kevVersionKey(v) { const m = KEV_VERSION.exec(v); return [m[1], m[2], m[3], (m[4] ?? '0').padStart(4, '0')].join('.'); }

// ---- snapshot documents ---------------------------------------------------------------------------------------------------------------------------
function kevMeta(w) {
  const d = w?.document;
  if (!isObj(d) || d.schema !== 'macguard.intel-kev/1') return { error: 'not a macguard.intel-kev/1 document' };
  const s = d.source;
  if (!isObj(s) || !SOURCE_ID.test(s.id ?? '') || typeof s.url !== 'string' || !KEV_VERSION.test(s.catalog_version ?? '') || !TS.test(s.date_released ?? '') || !HEX64.test(s.upstream_sha256 ?? '')) return { error: 'source block incomplete' };
  if ('chunk' in d) return { error: 'partial snapshot (loader chunk): absence cannot be inferred from it' };
  if (!Array.isArray(d.items)) return { error: 'items is not an array' };
  const source_id = w.source_id ?? s.id;
  if (!SOURCE_ID.test(source_id)) return { error: 'bad source_id' };
  return { kind: 'kev', source_id, original_source_id: s.id, version: s.catalog_version, order: [s.date_released, kevVersionKey(s.catalog_version)], content_sha256: s.upstream_sha256, doc: d };
}
function indexMeta(w) {
  const d = w?.document;
  if (!isObj(d) || d.schema !== 'macguard.search-index/1') return { error: 'not a macguard.search-index/1 document' };
  const r = d.release, m = TAG.exec(r?.tag ?? '');
  if (!m || !HEX64.test(r.manifest_sha256 ?? '')) return { error: 'release block incomplete' };
  if (!Array.isArray(d.entities) || !Array.isArray(d.assertions)) return { error: 'entities/assertions are not arrays' };
  const source_id = w.source_id ?? YARA_SOURCE_ID;
  if (!SOURCE_ID.test(source_id)) return { error: 'bad source_id' };
  return { kind: 'rule_index', source_id, original_source_id: null, version: r.tag, order: [`${m[1]}-${m[2].padStart(20, '0')}`, `${m[1]}-${m[2].padStart(20, '0')}`], content_sha256: r.manifest_sha256, doc: d };
}

// ---- per-document rule evaluation: returns proposals [{rule_id, from, to, state, basis, evidence}] and rejections ------------------------------------
function evalKev(s) {
  const props = [], rej = [], seen = new Map();
  const reject = (input, reason, detail) => rej.push({ rule_id: 'R-KEV-CWE-1', source_id: s.source_id, version: s.version, input, reason, ...(detail ? { detail } : {}) });
  for (const it of s.doc.items) if (isObj(it) && typeof it.cve_id === 'string') seen.set(it.cve_id, (seen.get(it.cve_id) ?? 0) + 1);
  for (const it of s.doc.items) {
    const id = isObj(it) ? it.cve_id : undefined;
    if (!isCanonical('cve', id)) { reject(str(id), 'malformed_identifier', 'cve_id is not a canonical CVE id (intel_ids)'); continue; }
    if (seen.get(id) > 1) { reject(id, 'duplicate_item_in_snapshot'); continue; }
    if (!Array.isArray(it.cwes) || it.cwes.length === 0) { reject(id, 'no_cwes'); continue; }
    for (const c of new Set(it.cwes)) {
      if (!isCanonical('cwe', c)) { reject(`${id} ${str(c)}`, 'malformed_identifier', 'cwe is not a canonical CWE id (intel_ids)'); continue; }
      props.push({ rule_id: 'R-KEV-CWE-1', from: `vulnerability:cve:${id}`, to: `weakness:cwe:${c}`, state: 'asserted', basis: 'kev_cwes_field',
        evidence: { source_id: s.source_id, original_source_id: s.original_source_id, locator: `${s.doc.source.url}#catalogVersion=${s.version};cveID=${id};cwe=${c}`, content_sha256: s.content_sha256 } });
    }
  }
  return { props, rej };
}

function evalIndex(s) {
  const props = [], rej = [], tag = s.version, rules = new Map(), bad = new Map(), withAssertions = new Set();
  const reject = (rule_id, input, reason, detail) => rej.push({ rule_id, source_id: s.source_id, version: tag, input, reason, ...(detail ? { detail } : {}) });
  const ids = new Map();
  for (const e of s.doc.entities) if (isObj(e) && typeof e.id === 'string') ids.set(e.id, (ids.get(e.id) ?? 0) + 1);
  for (const e of s.doc.entities) {
    const id = isObj(e) ? e.id : undefined;
    let why = null;
    if (typeof id !== 'string' || !isObj(e) || e.kind !== 'rule') why = 'malformed_entity';
    else if (ids.get(id) > 1) why = 'duplicate_rule_id';
    else if (!isCanonical('yara_rule', id) || id !== `yara:${e.path}#${e.name}` || !HEX64.test(e.file_sha256 ?? '')) why = 'malformed_identifier';
    else if (`${e.path}#${e.name}`.length > DB_KEY_MAX) why = 'rule_key_exceeds_db_limit';
    if (why) { if (typeof id === 'string') bad.set(id, why); reject(null, str(id), why, why === 'rule_key_exceeds_db_limit' ? `rule key is ${`${e.path}#${e.name}`.length} characters; intel_entities.key allows ${DB_KEY_MAX} (refused, never truncated)` : undefined); continue; }
    rules.set(id, e);
  }
  for (const a of s.doc.assertions) {
    const rid = a?.type === 'rule_meta_mentions_hash' ? 'R-YARA-HASH-1' : a?.type === 'rule_meta_mentions_cve' ? 'R-YARA-CVE-1' : null;
    const input = isObj(a) ? `${str(a.subject)} ${str(a.meta_key)}=${str(a.value)} @${str(a.provenance?.line)}` : str(a);
    if (isObj(a) && typeof a.subject === 'string') withAssertions.add(a.subject);
    if (!rid) { reject(null, input, 'unknown_assertion_type'); continue; }
    if (a.status !== 'asserted_by_rule_metadata') { reject(rid, input, 'bad_status'); continue; }
    if (bad.has(a.subject)) { reject(rid, input, 'subject_rejected', bad.get(a.subject)); continue; }
    const e = rules.get(a.subject);
    if (!e) { reject(rid, input, 'subject_not_in_index'); continue; }
    const p = a.provenance;
    if (!isObj(p) || p.release_tag !== tag || p.path !== e.path || p.file_sha256 !== e.file_sha256 || !Number.isInteger(p.line) || p.line < 1) { reject(rid, input, 'provenance_mismatch'); continue; }
    if (typeof a.meta_key !== 'string' || !IDENT.test(a.meta_key)) { reject(rid, input, 'malformed_meta_key'); continue; }
    if (a.match !== 'whole_value' && a.match !== 'embedded') { reject(rid, input, 'malformed_match'); continue; }
    const kinds = rid === 'R-YARA-HASH-1' ? ['sha256', 'sha1', 'md5'] : ['cve'];
    if (!kinds.includes(a.value_kind)) { reject(rid, input, 'value_kind_mismatch'); continue; }
    if (!isCanonical(a.value_kind, a.value)) { reject(rid, input, 'malformed_identifier', `value is not a canonical ${a.value_kind} (intel_ids)`); continue; }
    if (a.value_kind === 'sha1' || a.value_kind === 'md5') { reject(rid, input, 'no_canonical_sample_identity_for_md5_sha1', 'the contract defines a sample only as sample:sha256:<hex>; md5/sha1 are never merged with it'); continue; }
    const key = a.meta_key.replace(/[A-Z]/g, (c) => c.toLowerCase());   // ASCII lower-casing only
    let state = 'candidate', basis;
    if (rid === 'R-YARA-HASH-1') {
      if (HASH_KIND_KEYS[key] && HASH_KIND_KEYS[key] !== a.value_kind) basis = 'meta_key_names_other_hash_kind';
      else if (!HASH_KEYS.test(key)) basis = 'hash_outside_allowlisted_key';
      else if (a.match !== 'whole_value') basis = 'hash_embedded_in_value';
      else { state = 'asserted'; basis = 'meta_hash_key_whole_value'; }
    } else {
      if (!CVE_KEYS.test(key)) basis = a.match === 'embedded' ? 'cve_embedded_in_free_text' : 'cve_outside_allowlisted_key';
      else if (a.match !== 'whole_value') basis = key === 'reference' ? 'cve_inside_reference_locator' : 'cve_embedded_in_value';
      else { state = 'asserted'; basis = 'meta_cve_key_whole_value'; }
    }
    const to = rid === 'R-YARA-HASH-1' ? `sample:sha256:${a.value}` : `vulnerability:cve:${a.value}`;
    props.push({ rule_id: rid, from: `rule:yara:${e.path}#${e.name}`, to, state, basis,
      evidence: { source_id: s.source_id, original_source_id: `yara-upstream:${typeof e.source === 'string' && SOURCE_ID.test(e.source) ? e.source : 'unknown'}`,
        locator: `${tag}/${p.path}:${p.line}#meta.${a.meta_key}`, content_sha256: p.file_sha256 } });
  }
  // generic-rule guard
  for (const rid of ['R-YARA-HASH-1', 'R-YARA-CVE-1']) {
    const per = new Map();
    for (const x of props) if (x.rule_id === rid && x.state === 'asserted') { if (!per.has(x.from)) per.set(x.from, new Set()); per.get(x.from).add(x.to); }
    for (const x of props) if (x.rule_id === rid && x.state === 'asserted' && per.get(x.from).size > MAX_ASSERTED_PER_RULE[rid]) { x.state = 'candidate'; x.basis = 'generic_rule_fanout'; }
  }
  for (const id of rules.keys()) if (!withAssertions.has(id)) reject(null, id, 'no_assertions');
  return { props, rej };
}

// ---- aggregation --------------------------------------------------------------------------------------------------------------------------------------
const relKey = (p) => `${p.rule_id}\u0000${p.from}\u0000${p.to}`;
function aggregate(props) {
  const by = new Map();
  for (const p of props) { const k = relKey(p); if (!by.has(k)) by.set(k, []); by.get(k).push(p); }
  const out = [];
  for (const list of by.values()) {
    const asserted = list.filter((p) => p.state === 'asserted'), use = asserted.length ? asserted : list, r = RULES[list[0].rule_id];
    const ev = new Map();
    for (const p of use) ev.set(JSON.stringify([p.evidence.source_id, p.evidence.locator, p.evidence.content_sha256, p.evidence.original_source_id]), p.evidence);
    const evidence = [...ev.values()].sort(cmpBy((e) => e.source_id, (e) => e.locator, (e) => e.content_sha256, (e) => e.original_source_id));
    out.push({ type: r.type, from: list[0].from, to: list[0].to, state: asserted.length ? 'asserted' : 'candidate', rule_id: list[0].rule_id, rule_version: r.version,
      basis: [...new Set(use.map((p) => p.basis))].sort(), evidence, independent_sources: new Set(evidence.map((e) => e.original_source_id)).size });
  }
  return out.sort(cmpBy((x) => x.type, (x) => x.from, (x) => x.to, (x) => x.rule_id));
}

/** Run every rule over one snapshot. Never throws on bad data: anything unusable is in `rejections` or `inputs[].reason`. */
export function correlate(snapshot = {}) {
  if (!isObj(snapshot)) snapshot = {};
  const inputs = [], groups = new Map(), rejections = [];
  const wrap = (list, meta, kind) => {
    for (const w of Array.isArray(list) ? list : []) {
      const m = meta(w);
      if (m.error) { inputs.push({ kind, source_id: str(w?.source_id ?? null), version: null, content_sha256: null, role: 'refused', reason: m.error }); continue; }
      const g = `${m.kind}\u0000${m.source_id}`; if (!groups.has(g)) groups.set(g, []); groups.get(g).push(m);
    }
  };
  wrap(snapshot.kev, kevMeta, 'kev'); wrap(snapshot.rule_indexes, indexMeta, 'rule_index');
  const current = [], retracted = [];
  for (const list of [...groups.values()]) {
    // Snapshots are compared by CONTENT, never by the hash the document claims (Codex c4 r1 MEDIUM: two documents with the same version and the same
    // upstream_sha256 but different items were deduplicated by input order). Identical content (order-insensitive) counts once; the same version with
    // different content refuses the whole source, whatever the input order.
    const uniq = new Map();
    for (const m of list) { const k = `${m.version}\u0000${contentKey(m.doc)}`; if (!uniq.has(k)) uniq.set(k, m); }
    const versions = new Map(); for (const m of uniq.values()) versions.set(m.version, (versions.get(m.version) ?? 0) + 1);
    const base = (m) => ({ kind: m.kind, source_id: m.source_id, version: m.version, content_sha256: m.content_sha256 });
    if ([...versions.values()].some((n) => n > 1)) {
      for (const [v, n] of versions) { const m = [...uniq.values()].find((x) => x.version === v); inputs.push({ ...base(m), content_sha256: n > 1 ? null : m.content_sha256, role: 'refused', reason: n > 1 ? 'conflicting_snapshots_same_version' : 'source_has_conflicting_snapshots', variants: n }); }
      continue;
    }
    // Latest-snapshot selection must not depend on input order (Codex c4 r2 F2): two different versions with equal ordering keys, or a version order that
    // contradicts the release-time order (KEV: a higher catalogue version released earlier), refuse the whole source.
    const snaps = [...uniq.values()].sort(cmpBy((m) => m.order[0], (m) => m.order[1]));
    const byVersion = [...snaps].sort(cmpBy((m) => m.order[1], (m) => m.order[0]));
    const tie = snaps.some((m, i) => i > 0 && m.order[0] === snaps[i - 1].order[0] && m.order[1] === snaps[i - 1].order[1]);
    if (tie || snaps.some((m, i) => m !== byVersion[i])) {
      for (const m of snaps) inputs.push({ ...base(m), role: 'refused', reason: tie ? 'snapshots_with_equal_order' : 'snapshot_order_inconsistent' });
      continue;
    }
    const evals = snaps.map((m) => ({ m, ...(m.kind === 'kev' ? evalKev(m) : evalIndex(m)) })), latest = evals.at(-1);
    for (const e of evals) inputs.push({ ...base(e.m), role: e === latest ? 'latest' : 'superseded' });
    current.push(...latest.props); rejections.push(...latest.rej);
    // Retraction compares the STRONGEST support (Codex c4 r2 F1): asserted support that the latest snapshot no longer gives at the asserted level is
    // retracted, also when the latest still mentions it as a candidate (that candidate is emitted separately). Candidate-only support that vanished
    // is retracted as a candidate. One entry per (relation, retracted state), from the newest older snapshot that had it.
    const nowAny = new Set(latest.props.map(relKey)), nowAsserted = new Set(latest.props.filter((p) => p.state === 'asserted').map(relKey)), gone = new Map();
    for (const e of evals.slice(0, -1)) for (const p of e.props) {
      const k = relKey(p);
      if (p.state === 'asserted' ? nowAsserted.has(k) : nowAny.has(k)) continue;
      gone.set(`${k}\u0000${p.state}`, { type: RULES[p.rule_id].type, from: p.from, to: p.to, rule_id: p.rule_id, source_id: e.m.source_id, state: p.state, last_seen_version: e.m.version,
        reason: nowAny.has(k) ? 'downgraded_in_latest_snapshot' : 'absent_from_latest_snapshot' });
    }
    retracted.push(...gone.values());
  }
  const relations = aggregate(current);
  // conflicts: different statements about the weaknesses of one vulnerability (kept both, never resolved here)
  const conflicts = [], perVuln = new Map();
  for (const r of relations) if (r.rule_id === 'R-KEV-CWE-1' && r.state === 'asserted') for (const e of r.evidence) {
    if (!perVuln.has(r.from)) perVuln.set(r.from, new Map());
    const m = perVuln.get(r.from), k = `${e.source_id}\u0000${e.original_source_id}`; if (!m.has(k)) m.set(k, { source_id: e.source_id, original_source_id: e.original_source_id, values: new Set() });
    m.get(k).values.add(r.to);
  }
  for (const [vuln, m] of perVuln) {
    const st = [...m.values()].map((x) => ({ ...x, values: [...x.values].sort() })).sort(cmpBy((x) => x.source_id, (x) => x.original_source_id));
    if (st.length > 1 && new Set(st.map((x) => JSON.stringify(x.values))).size > 1) conflicts.push({ kind: 'weakness_statements_differ', subject: vuln, statements: st });
  }
  const rel = (a) => [a.type ?? '', a.from ?? '', a.to ?? '', a.rule_id ?? '', a.source_id ?? '', a.version ?? '', a.input ?? '', a.reason ?? '', a.last_seen_version ?? '', a.detail ?? '', a.state ?? ''];
  const byArr = (x, y) => { const a = rel(x), b = rel(y); for (let i = 0; i < a.length; i++) { const c = cmp(a[i], b[i]); if (c) return c; } return 0; };
  // identical rejections (the same malformed value twice) are reported once
  const dedupe = (list) => [...new Map(list.map((x) => [JSON.stringify(canon(x)), x])).values()];
  return {
    schema: OUTPUT_SCHEMA,
    rules: Object.entries(RULES).map(([id, r]) => ({ id, ...r })),
    inputs: dedupe(inputs).sort(cmpBy((x) => x.kind, (x) => x.source_id, (x) => x.version ?? '', (x) => x.content_sha256 ?? '', (x) => x.role, (x) => x.reason ?? '')),
    relations,
    rejections: dedupe(rejections).sort(byArr),
    retracted: retracted.sort(byArr),
    conflicts: conflicts.sort(cmpBy((x) => x.subject)),
    counts: { relations: relations.length, asserted: relations.filter((r) => r.state === 'asserted').length, candidate: relations.filter((r) => r.state === 'candidate').length,
      rejections: dedupe(rejections).length, retracted: retracted.length, conflicts: conflicts.length },
  };
}

/** Order-insensitive content identity of a source document: keys sorted and every array sorted by its elements' canonical text (the engine reads all
 *  these arrays as sets), so a reordered copy is the same content and any changed value is different content. */
function canonSet(x) {
  if (Array.isArray(x)) return x.map(canonSet).map((y) => [JSON.stringify(y), y]).sort((a, b) => cmp(a[0], b[0])).map((p) => p[1]);
  if (isObj(x)) return Object.fromEntries(Object.keys(x).sort().map((k) => [k, canonSet(x[k])]));
  return x;
}
const contentKey = (doc) => JSON.stringify(canonSet(doc));

/** Canonical value: object keys sorted, recursively. */
export function canon(x) {
  if (Array.isArray(x)) return x.map(canon);
  if (isObj(x)) return Object.fromEntries(Object.keys(x).sort().map((k) => [k, canon(x[k])]));
  return x;
}
/** Byte-deterministic serialisation of an engine result (compact JSON, sorted keys, trailing newline). */
export const serialize = (result) => JSON.stringify(canon(result)) + '\n';

/** How one proposal maps onto the CURRENT schema (0004/0005 + intel_graph.js), one DB relationship per original source (the DB relationship has a single
 *  source_id and no original_source_id column, so independence is represented by the number of DB relationships). Pure: returns descriptions only. */
export function toGraph(rel) {
  const m = STATE_MAP[rel.state];
  const ent = (id) => { const [type, namespace, ...rest] = id.split(':'); return { type, namespace, key: rest.join(':') }; };
  const byOrig = new Map();
  for (const e of rel.evidence) { if (!byOrig.has(e.original_source_id)) byOrig.set(e.original_source_id, []); byOrig.get(e.original_source_id).push(e); }
  return {
    entities: [ent(rel.from), ent(rel.to)],
    relationships: [...byOrig.entries()].sort(cmpBy(([k]) => k)).map(([orig, ev]) => ({
      relate: { type: rel.type, from: rel.from, to: rel.to, source_id: orig, method: m.method, version: `${rel.rule_id}@${rel.rule_version}`, exposure: m.exposure,
        evidence: ev.map((e) => ({ kind: m.evidence_kind, ref: e.locator, sha256: e.content_sha256, source_id: e.source_id, note: `original_source_id=${e.original_source_id}` })) },
      assessment: { confidence: m.confidence, verification: m.verification, reason: `${rel.rule_id} v${rel.rule_version}: ${rel.basis.join(', ')}`, actor: `engine:${rel.rule_id}` },
    })),
  };
}
