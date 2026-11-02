// Correlation engine (src/intel_correlate.js) against the adversarial corpus test/fixtures/correlation/<case>/{case.json, expected.json}.
// Each case is checked three ways: the exact output bytes (expected.json, regenerated only with gen.mjs --write-expected and reviewed), the HAND-WRITTEN
// expectations in case.json (exact asserted and candidate sets, rejection reasons, retractions), and corpus-wide invariants that do not trust the engine:
// every evidence row is traced back to one input statement that names both endpoints, no forbidden relation type, no severity, determinism.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { correlate, serialize, toGraph, projectState, RULES, STATE_MAP, CONTRACT_TYPE_MISMATCHES, HASH_KEYS, CVE_KEYS, MAX_ASSERTED_PER_RULE, YARA_SOURCE_ID } from '../src/intel_correlate.js';

const DIR = new URL('./fixtures/correlation/', import.meta.url);
const CASES = readdirSync(DIR).filter((d) => /^\d\d_/.test(d)).sort().map((name) => ({
  name, c: JSON.parse(readFileSync(new URL(`${name}/case.json`, DIR), 'utf8')), expected: readFileSync(new URL(`${name}/expected.json`, DIR), 'utf8') }));
const REQUIRED = ['verified_relations', 'unrelated_entities', 'ambiguous_aliases', 'malformed_identifiers', 'cve_similar_products', 'generic_rules', 'wrong_references',
  'contradicting_sources', 'retracted_data', 'duplicate_evidence', 'false_transitivity', 'identity_and_provenance', 'snapshot_conflict_order_a', 'snapshot_conflict_order_b',
  'downgrade_and_ties_order_a', 'downgrade_and_ties_order_b', 'malformed_structured_values'];
const triple = (r) => JSON.stringify([r[0] ?? r.type, r[1] ?? r.from, r[2] ?? r.to]);
const set = (list) => new Set(list.map(triple));
function rng(seed) { let s = seed >>> 0; return () => { s = (s + 0x6d2b79f5) >>> 0; let t = s; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
function shuffleDeep(x, r) {
  if (Array.isArray(x)) { const a = x.map((y) => shuffleDeep(y, r)); for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(r() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a; }
  if (x && typeof x === 'object') { const k = Object.keys(x); for (let i = k.length - 1; i > 0; i--) { const j = Math.floor(r() * (i + 1)); [k[i], k[j]] = [k[j], k[i]]; } return Object.fromEntries(k.map((y) => [y, shuffleDeep(x[y], r)])); }
  return x;
}

test('corpus: every required adversarial case is present and has an expected output', () => {
  assert.deepEqual(CASES.map((x) => x.name.slice(3)), REQUIRED);
  for (const { name, c } of CASES) { assert.ok(c.description.length > 40, name); assert.ok(Array.isArray(c.expect.asserted) && Array.isArray(c.expect.candidate), name); }
});

for (const { name, c, expected } of CASES) {
  test(`case ${name}: exact output bytes`, () => { assert.equal(serialize(correlate(c.input)), expected); });

  test(`case ${name}: hand-written expectations (exact asserted/candidate sets, rejections, retractions)`, () => {
    const out = correlate(c.input), e = c.expect;
    assert.deepEqual(set(out.relations.filter((r) => r.state === 'asserted')), set(e.asserted), 'asserted set (zero false relations at the asserted level)');
    assert.deepEqual(set(out.relations.filter((r) => r.state === 'candidate')), set(e.candidate), 'candidate set');
    const reasons = {}; for (const r of out.rejections) reasons[r.reason] = (reasons[r.reason] ?? 0) + 1;
    assert.deepEqual(reasons, e.rejections ?? {}, 'rejection reasons');
    assert.deepEqual(set(out.retracted), set(e.retracted ?? []), 'retracted');
    assert.equal(out.conflicts.length, e.conflicts ?? 0, 'conflicts');
    assert.equal(out.inputs.filter((i) => i.role === 'refused').length, e.refused_inputs ?? 0, 'refused inputs');
    for (const f of e.forbidden ?? []) assert.ok(!out.relations.some((r) => triple(r) === triple(f)), `forbidden ${f}`);
    for (const [k, n] of Object.entries(e.evidence_rows ?? {})) { const [t, f, to] = k.split(' '); assert.equal(out.relations.find((r) => r.type === t && r.from === f && r.to === to).evidence.length, n, k); }
    if (e.independent_sources_all !== undefined) for (const r of out.relations) assert.equal(r.independent_sources, e.independent_sources_all, triple(r));
  });
}

/** Independent tracer: the evidence locator must point at ONE input statement that names both endpoints of the relation. Type-safe (strict equality and
 *  typeof only, never coercion), so it can judge fuzzed inputs too. */
function trace(input, rel, ev) {
  const S = (x) => typeof x === 'string';
  if (rel.type === 'VULN_HAS_WEAKNESS') {
    const m = /#catalogVersion=([^;]+);cveID=([^;]+);cwe=(.+)$/.exec(ev.locator); if (!m) return false;
    return (Array.isArray(input.kev) ? input.kev : []).some((w) => { const d = w?.document, s = d?.source; return S(s?.id) && (w.source_id ?? s.id) === ev.source_id && s.id === ev.original_source_id && s.catalog_version === m[1]
      && s.upstream_sha256 === ev.content_sha256 && Array.isArray(d.items) && d.items.some((it) => it?.cve_id === m[2] && Array.isArray(it.cwes) && it.cwes.includes(m[3]))
      && rel.from === `vulnerability:cve:${m[2]}` && rel.to === `weakness:cwe:${m[3]}`; });
  }
  const m = /^(rules-[0-9]+-[0-9]+)\/(.+):([0-9]+)#meta\.([A-Za-z_][A-Za-z0-9_]*)$/.exec(ev.locator); if (!m) return false;
  return (Array.isArray(input.rule_indexes) ? input.rule_indexes : []).some((w) => { const d = w?.document; return (w.source_id ?? YARA_SOURCE_ID) === ev.source_id && d?.release?.tag === m[1] && Array.isArray(d.assertions) && d.assertions.some((a) =>
    S(a?.subject) && S(a.value) && a.provenance?.path === m[2] && a.provenance.line === +m[3] && a.meta_key === m[4] && a.provenance.file_sha256 === ev.content_sha256 && `rule:${a.subject}` === rel.from
    && rel.to === (rel.type === 'RULE_REFERENCES_SAMPLE' ? `sample:sha256:${a.value}` : `vulnerability:cve:${a.value}`)); });
}

test('invariants over the whole corpus: traceable evidence, allowed types and endpoints, no detection claims, no severity, no transitivity', () => {
  const allowed = { VULN_HAS_WEAKNESS: ['vulnerability:cve:', 'weakness:cwe:'], RULE_REFERENCES_SAMPLE: ['rule:yara:', 'sample:sha256:'], RULE_ASSOCIATED_WITH_CVE: ['rule:yara:', 'vulnerability:cve:'] };
  let rels = 0;
  for (const { name, c } of CASES) {
    const out = correlate(c.input), text = JSON.stringify([out.relations, out.retracted, out.conflicts]);
    assert.ok(!/RULE_DETECTS_CVE|ALIAS_OF|INDICATOR_ASSOCIATED_WITH_CVE|RULE_META_/.test(text), `${name}: forbidden or non-schema type in output`);
    assert.ok(!/cvss|severity|epss/i.test(JSON.stringify(out.relations)), `${name}: severity data in relations`);
    for (const r of out.relations) {
      rels++;
      const [f, t] = allowed[r.type]; assert.ok(r.from.startsWith(f) && r.to.startsWith(t), `${name}: ${r.type} endpoints ${r.from} -> ${r.to}`);
      assert.equal(RULES[r.rule_id].type, r.type); assert.equal(r.rule_version, RULES[r.rule_id].version);
      assert.ok(['asserted', 'candidate'].includes(r.state));
      assert.ok(r.evidence.length >= 1, `${name}: relation without evidence`);
      for (const ev of r.evidence) {
        assert.deepEqual(Object.keys(ev).sort(), ['content_sha256', 'locator', 'original_source_id', 'source_id']);
        assert.ok(trace(c.input, r, ev), `${name}: evidence not traceable to one input statement: ${ev.locator}`);
      }
      assert.equal(r.independent_sources, new Set(r.evidence.map((e) => e.original_source_id)).size);
    }
  }
  assert.ok(rels > 500, 'the corpus exercises the tracer');
});

test('determinism: shuffled inputs (arrays and key order) give the same bytes; the input is never mutated', () => {
  const r = rng(20261102);
  for (const { name, c, expected } of CASES) {
    const before = JSON.stringify(c.input);
    for (let i = 0; i < 5; i++) assert.equal(serialize(correlate(shuffleDeep(c.input, r))), expected, `${name} shuffle ${i}`);
    assert.equal(JSON.stringify(c.input), before, `${name}: input mutated`);
  }
});

test('regression (Codex c4 r1): same version, different content is refused in both input orders; both orders give the same bytes', () => {
  const a = CASES.find((x) => x.name.endsWith('order_a')), b = CASES.find((x) => x.name.endsWith('order_b'));
  assert.equal(a.expected, b.expected);
  const out = correlate(a.c.input);
  assert.deepEqual(out.inputs.filter((i) => i.role === 'refused').map((i) => [i.source_id, i.reason, i.variants]).sort(),
    [['cisa-kev', 'conflicting_snapshots_same_version', 2], ['macguard-yara-release', 'conflicting_snapshots_same_version', 2]]);
  assert.ok(!out.relations.some((r) => r.evidence.some((e) => e.source_id === 'cisa-kev' || e.source_id === 'macguard-yara-release')));
  // the exact repro from the review: two wrappers, both orders
  const orig = CASES.find((x) => x.name.startsWith('01_')).c.input.kev[0], clone = structuredClone(orig); clone.document.items[0].cwes = ['CWE-89'];
  const x = serialize(correlate({ kev: [orig, clone] })), y = serialize(correlate({ kev: [clone, orig] }));
  assert.equal(x, y); assert.equal(JSON.parse(x).relations.length, 0); assert.match(x, /conflicting_snapshots_same_version/);
  assert.equal(correlate({ kev: [orig, structuredClone(orig)] }).relations.length, 5, 'an identical copy is deduplicated');
});

test('regression (Codex c4 r2): a downgraded asserted relation is retracted; non-canonical tags/versions and inconsistent order are refused; both orders same bytes', () => {
  const a = CASES.find((x) => x.name.endsWith('ties_order_a')), b = CASES.find((x) => x.name.endsWith('ties_order_b'));
  assert.equal(a.expected, b.expected);
  const out = correlate(a.c.input);
  const down = out.retracted.find((r) => r.type === 'RULE_REFERENCES_SAMPLE');
  assert.deepEqual([down.state, down.reason, down.last_seen_version], ['asserted', 'downgraded_in_latest_snapshot', 'rules-20260101-1']);
  assert.equal(out.relations.find((r) => triple(r) === triple(down)).state, 'candidate', 'the candidate is emitted separately');
  const kevDrop = out.retracted.find((r) => r.type === 'VULN_HAS_WEAKNESS');
  assert.deepEqual([kevDrop.state, kevDrop.reason, kevDrop.to], ['asserted', 'absent_from_latest_snapshot', 'weakness:cwe:CWE-79']);
  assert.deepEqual(out.inputs.filter((i) => i.role === 'refused').map((i) => i.reason).sort(),
    ['release block incomplete', 'snapshot_order_inconsistent', 'snapshot_order_inconsistent', 'source block incomplete']);
  // the exact F1 repro: sha256 key in the older release, description only in the newer one, both input orders
  const ix = (tag, key, match) => ({ document: { schema: 'macguard.search-index/1', release: { tag, manifest_sha256: (tag.endsWith('1') ? 'a' : 'b').repeat(64) }, entities: [{ id: 'yara:r/a.yar#R', kind: 'rule', path: 'r/a.yar', name: 'R', file_sha256: 'c'.repeat(64), source: null }],
    assertions: [{ type: 'rule_meta_mentions_hash', subject: 'yara:r/a.yar#R', value: 'd'.repeat(64), value_kind: 'sha256', meta_key: key, match, status: 'asserted_by_rule_metadata', provenance: { release_tag: tag, path: 'r/a.yar', file_sha256: 'c'.repeat(64), line: 3 } }] } });
  const o1 = ix('rules-20260101-1', 'sha256', 'whole_value'), o2 = ix('rules-20260102-2', 'description', 'embedded');
  const x = correlate({ rule_indexes: [o1, o2] }), y = correlate({ rule_indexes: [o2, o1] });
  assert.equal(serialize(x), serialize(y));
  assert.deepEqual(x.relations.map((r) => r.state), ['candidate']);
  assert.deepEqual(x.retracted.map((r) => [r.state, r.reason]), [['asserted', 'downgraded_in_latest_snapshot']]);
  // F2 repro: rules-20260101-1 and rules-20260101-01 -> the non-canonical tag is refused at input, whatever the order
  const t1 = ix('rules-20260101-1', 'sha256', 'whole_value'), t2 = ix('rules-20260101-01', 'hash', 'whole_value');
  assert.equal(serialize(correlate({ rule_indexes: [t1, t2] })), serialize(correlate({ rule_indexes: [t2, t1] })));
  assert.ok(correlate({ rule_indexes: [t2] }).inputs.every((i) => i.role === 'refused'));
});

test('property (Codex c4 fix round): 12 seeded permutations of key order and set-array order, and every wrapper supplied twice in two permutations, give the same bytes', () => {
  const r = rng(20261103);
  for (const { name, c, expected } of CASES) {
    for (let i = 0; i < 12; i++) {
      assert.equal(serialize(correlate(shuffleDeep(c.input, r))), expected, `${name} permutation ${i}`);
      const a = shuffleDeep(c.input, r), b = shuffleDeep(c.input, r), twice = {};
      for (const k of ['kev', 'rule_indexes']) if (c.input[k]) twice[k] = [...a[k], ...b[k]].reverse();
      assert.equal(serialize(correlate(twice)), expected, `${name} duplicated wrappers ${i}`);
    }
  }
});

test('regression (Codex c4 fix round): malformed structured values are printed canonically and capped', () => {
  const doc = (cwes) => ({ document: { schema: 'macguard.intel-kev/1', items: [{ cve_id: 'CVE-2099-0900', cwes }], source: { id: 'cisa-kev', url: 'u', catalog_version: '2026.01.01', date_released: '2026-01-01T00:00:00.000Z', upstream_sha256: 'a'.repeat(64) } } });
  const x = doc([{ id: 'CWE-79', name: 'x' }]), y = doc([{ name: 'x', id: 'CWE-79' }]);
  const outs = [[x], [y], [x, y], [y, x]].map((kev) => serialize(correlate({ kev })));
  assert.ok(outs.every((o) => o === outs[0]), 'key order of a malformed value never changes the output');
  assert.match(outs[0], /CVE-2099-0900 \{\\"id\\":\\"CWE-79\\",\\"name\\":\\"x\\"\}/);
  const long = correlate({ kev: [doc(['C'.repeat(5000)])] }).rejections[0].input;
  assert.ok([...long].length < 700 && long.endsWith('(5000 code points)'), long.slice(-40));
});

test('robustness: garbage never throws, produces no relation and is reported', () => {
  const junk = [undefined, null, 1, 'x', [], {}, { kev: 'x' }, { kev: [null, 1, {}, { document: null }, { document: { schema: 'macguard.intel-kev/1' } }] },
    { rule_indexes: [{ document: { schema: 'macguard.search-index/1', release: { tag: 'rules-1-1' } } }] },
    { kev: [{ document: { schema: 'macguard.intel-kev/1', chunk: { index: 0, of: 2 }, items: [], source: { id: 'cisa-kev', url: 'u', catalog_version: '2026.01.01', date_released: '2026-01-01T00:00:00.000Z', upstream_sha256: 'a'.repeat(64) } } }] },
    { kev: [{ source_id: 'Bad Id', document: { schema: 'macguard.intel-kev/1', items: [], source: { id: 'cisa-kev', url: 'u', catalog_version: '2026.01.01', date_released: '2026-01-01T00:00:00.000Z', upstream_sha256: 'a'.repeat(64) } } }] },
    { kev: [{ document: { schema: 'macguard.intel-kev/1', items: [null, 7, { cve_id: 5 }, { cve_id: 'CVE-2099-1234', cwes: 'CWE-79' }, { cve_id: 'CVE-2099-1235', cwes: [null, 79] }],
      source: { id: 'cisa-kev', url: 'u', catalog_version: '2026.01.01', date_released: '2026-01-01T00:00:00.000Z', upstream_sha256: 'a'.repeat(64) } } }] },
    { rule_indexes: [{ document: { schema: 'macguard.search-index/1', release: { tag: 'rules-20260101-1', manifest_sha256: 'b'.repeat(64) }, entities: [null, { kind: 'rule', id: 7 }], assertions: [null, 3, { type: 'rule_meta_mentions_hash' }] } }] }];
  for (const j of junk) {
    const out = correlate(j);
    assert.equal(out.relations.length, 0, JSON.stringify(j));
    assert.equal(serialize(correlate(j)), serialize(out));
  }
  assert.ok(correlate(junk[9]).inputs.some((i) => i.reason?.includes('partial snapshot')), 'a loader chunk is never a snapshot');
  assert.ok(correlate(junk[10]).inputs.some((i) => i.reason === 'bad source_id'));
});

test('rule definitions: allow-lists are exact on the ASCII-lower-cased key; fan-out limits; contract type mismatches are declared', () => {
  for (const k of ['hash', 'hash0', 'hash1', 'hash257', 'sha256', 'sample', 'samples']) assert.ok(HASH_KEYS.test(k), k);
  for (const k of ['sha1', 'md5', 'imphash', 'hashes', 'sample_sha256', 'hash_1', 'hasha', 'original_sample_sha1', 'description', 'reference', 'Hash1']) assert.ok(!HASH_KEYS.test(k), k);
  for (const k of ['cve', 'cves', 'vuln', 'vulnerability', 'reference']) assert.ok(CVE_KEYS.test(k), k);
  for (const k of ['cve_id', 'description', 'reference_3', 'ref', 'url', 'id', 'CVE']) assert.ok(!CVE_KEYS.test(k), k);
  assert.deepEqual(MAX_ASSERTED_PER_RULE, { 'R-YARA-HASH-1': 256, 'R-YARA-CVE-1': 5 });
  assert.deepEqual(Object.values(RULES).map((r) => r.type).sort(), ['RULE_ASSOCIATED_WITH_CVE', 'RULE_REFERENCES_SAMPLE', 'VULN_HAS_WEAKNESS']);
  assert.deepEqual(CONTRACT_TYPE_MISMATCHES.map((m) => [m.contract, m.emitted_as]), [['RULE_META_MENTIONS_SAMPLE', 'RULE_REFERENCES_SAMPLE'], ['RULE_META_REFERENCES_CVE', 'RULE_ASSOCIATED_WITH_CVE']]);
});

test('state mapping: engine states onto the 0004 vocabulary, and the total projection of contract v3 §4', () => {
  assert.deepEqual(STATE_MAP.asserted, { method: 'asserted_by_source', evidence_kind: 'source_statement', confidence: 'REPORTED', verification: 'UNVERIFIED', exposure: 'public' });
  assert.deepEqual(STATE_MAP.candidate, { method: 'derived_from_content', evidence_kind: 'document', confidence: 'INFERRED', verification: 'UNVERIFIED', exposure: 'restricted' });
  const P = (confidence, verification, evidenceKinds = [], sourceApproved = true) => projectState({ confidence, verification, evidenceKinds, sourceApproved });
  for (const c of ['CONFIRMED', 'REPORTED', 'INFERRED', 'DISPUTED', 'UNKNOWN']) assert.equal(P(c, 'FAILED', ['source_statement']), 'rejected', c);
  for (const v of ['VERIFIED', 'UNVERIFIED']) assert.equal(P('DISPUTED', v, ['source_statement']), 'disputed');
  assert.equal(P('CONFIRMED', 'VERIFIED'), 'verified');
  assert.equal(P('REPORTED', 'UNVERIFIED', ['source_statement']), 'asserted');
  assert.equal(P('REPORTED', 'UNVERIFIED', ['document']), 'asserted');
  assert.equal(P('CONFIRMED', 'UNVERIFIED', ['source_statement']), 'asserted');
  assert.equal(P('REPORTED', 'UNVERIFIED', ['source_statement'], false), 'candidate', 'unapproved source is never asserted');
  assert.equal(P('REPORTED', 'UNVERIFIED', ['content_match']), 'candidate');
  assert.equal(P('INFERRED', 'UNVERIFIED', ['document']), 'candidate');
  assert.equal(P('UNKNOWN', 'UNVERIFIED'), 'candidate');
  // the engine's own outputs project back to their state when the source is approved (asserted) / for any source (candidate)
  assert.equal(P(STATE_MAP.asserted.confidence, STATE_MAP.asserted.verification, [STATE_MAP.asserted.evidence_kind]), 'asserted');
  assert.equal(P(STATE_MAP.candidate.confidence, STATE_MAP.candidate.verification, [STATE_MAP.candidate.evidence_kind]), 'candidate');
});

test('toGraph: one DB relationship per original source; evidence and assessment follow STATE_MAP; ids are 0004 entity ids', () => {
  const dup = CASES.find((x) => x.name.endsWith('duplicate_evidence')).c.input;
  const rel = correlate(dup).relations.find((r) => r.type === 'VULN_HAS_WEAKNESS');
  const g = toGraph(rel);
  assert.deepEqual(g.entities, [{ type: 'vulnerability', namespace: 'cve', key: 'CVE-2099-0400' }, { type: 'weakness', namespace: 'cwe', key: 'CWE-79' }]);
  assert.equal(g.relationships.length, 1, 'aggregator copy is the same original source');
  assert.equal(g.relationships[0].relate.source_id, 'cisa-kev'); assert.equal(g.relationships[0].relate.evidence.length, 2);
  assert.ok(g.relationships[0].relate.evidence.every((e) => e.kind === 'source_statement'));
  assert.deepEqual([g.relationships[0].assessment.confidence, g.relationships[0].assessment.verification], ['REPORTED', 'UNVERIFIED']);
});

// ---- Codex extraordinary review on d14cd19 (MEDIUM, intel_correlate.js kevMeta): metadata types are checked before any regex or coercion -------------
const KEV_SRC = { id: 'cisa-kev', url: 'https://www.cisa.gov/kev.json', catalog_version: '2026.01.01', date_released: '2026-01-01T00:00:00.000Z', upstream_sha256: 'a'.repeat(64) };
const kevDoc = (src, source_id) => ({ ...(source_id === undefined ? {} : { source_id }), document: { schema: 'macguard.intel-kev/1', source: src, items: [{ cve_id: 'CVE-2099-0901', cwes: ['CWE-79'] }] } });
// Values a JSON document (or a JS caller) can put where a string is expected. Every one of them must be refused, never coerced.
const label = (v) => (typeof v === 'string' ? `string(${v.length})` : typeof v === 'object' && v !== null ? `${Array.isArray(v) ? 'array' : 'object'} ${Object.keys(v)}` : typeof v);
const CONFUSE = [['cisa-kev'], [['cisa-kev']], { toString: null }, { valueOf: null, toString: null }, { toString: () => 'cisa-kev' }, { valueOf: () => 'cisa-kev', toString: () => 'cisa-kev' },
  { toJSON: null }, 42, 0, -1, 1e308, NaN, true, false, null, '', 'x'.repeat(100000), 'cisa-kev'.repeat(2000), 10n, Symbol('s'), () => 'cisa-kev'];

test('regression (Codex d14cd19 MEDIUM): array source ids are refused, so two copies are never two independent sources; {toString:null} never throws', () => {
  const two = correlate({ kev: [kevDoc({ ...KEV_SRC, id: ['cisa-kev'] }, 'copy-a'), kevDoc({ ...KEV_SRC, id: ['cisa-kev'] }, 'copy-b')] });
  assert.equal(two.relations.length, 0, 'array document.source.id is not a source id');
  assert.deepEqual(two.inputs.map((i) => [i.role, i.reason]), [['refused', 'source block incomplete'], ['refused', 'source block incomplete']]);
  const ok = correlate({ kev: [kevDoc(KEV_SRC, 'copy-a'), kevDoc(KEV_SRC, 'copy-b')] });
  assert.equal(ok.relations.length, 1); assert.equal(ok.relations[0].independent_sources, 1, 'two republishers of one original source are ONE independent source');
  assert.doesNotThrow(() => correlate({ kev: [kevDoc({ ...KEV_SRC, id: { toString: null } })] }));
  assert.equal(correlate({ kev: [kevDoc({ ...KEV_SRC, id: { toString: null } })] }).relations.length, 0);
});

test('type confusion: every metadata field of KEV and rule-index inputs accepts only its primitive type; the engine never throws', () => {
  const ix = () => ({ document: { schema: 'macguard.search-index/1', release: { tag: 'rules-20260101-1', manifest_sha256: 'b'.repeat(64) },
    entities: [{ id: 'yara:r/a.yar#R', kind: 'rule', path: 'r/a.yar', name: 'R', file_sha256: 'c'.repeat(64), source: 'community' }],
    assertions: [{ type: 'rule_meta_mentions_cve', subject: 'yara:r/a.yar#R', value: 'CVE-2099-0902', value_kind: 'cve', meta_key: 'cve', match: 'whole_value', status: 'asserted_by_rule_metadata', provenance: { release_tag: 'rules-20260101-1', path: 'r/a.yar', file_sha256: 'c'.repeat(64), line: 3 } }] } });
  const base = { kev: [kevDoc(KEV_SRC)], rule_indexes: [ix()] };
  assert.equal(correlate(base).counts.asserted, 2, 'control: the untouched input asserts both relations');
  const paths = [['kev', 0, 'source_id'], ['kev', 0, 'document', 'source', 'id'], ['kev', 0, 'document', 'source', 'url'], ['kev', 0, 'document', 'source', 'catalog_version'],
    ['kev', 0, 'document', 'source', 'date_released'], ['kev', 0, 'document', 'source', 'upstream_sha256'], ['kev', 0, 'document', 'items', 0, 'cve_id'], ['kev', 0, 'document', 'items', 0, 'cwes', 0],
    ['rule_indexes', 0, 'source_id'], ['rule_indexes', 0, 'document', 'release', 'tag'], ['rule_indexes', 0, 'document', 'release', 'manifest_sha256'],
    ...['id', 'kind', 'path', 'name', 'file_sha256', 'source'].map((k) => ['rule_indexes', 0, 'document', 'entities', 0, k]),
    ...['type', 'subject', 'value', 'value_kind', 'meta_key', 'match', 'status'].map((k) => ['rule_indexes', 0, 'document', 'assertions', 0, k]),
    ...['release_tag', 'path', 'file_sha256', 'line'].map((k) => ['rule_indexes', 0, 'document', 'assertions', 0, 'provenance', k])];
  for (const path of paths) for (const v of CONFUSE) {
    const input = { kev: [kevDoc(KEV_SRC)], rule_indexes: [ix()] };
    let o = input; for (const k of path.slice(0, -1)) o = o[k]; o[path.at(-1)] = v;
    let out; assert.doesNotThrow(() => { out = correlate(input); }, `${path.join('.')} = ${label(v)}`);
    assert.equal(serialize(correlate(input)), serialize(out), 'deterministic');
    for (const r of out.relations) {
      for (const e of r.evidence) for (const k of ['source_id', 'original_source_id', 'locator', 'content_sha256']) assert.equal(typeof e[k], 'string', `${path.join('.')}: ${k}`);
      assert.equal(r.independent_sources, new Set(r.evidence.map((e) => e.original_source_id)).size);
      assert.ok(r.evidence.every((e) => e.locator.length <= 1024), 'every locator fits intel_relationship_evidence.ref');
    }
    // a coerced value never yields an asserted relation that the untouched value would not give: the asserted set only shrinks
    assert.ok(out.relations.filter((r) => r.state === 'asserted').every((r) => correlate(base).relations.some((b) => triple(b) === triple(r) && b.state === 'asserted')), path.join('.'));
  }
  // deep and cyclic values never overflow the stack
  let deep = 'CWE-79'; for (let i = 0; i < 20000; i++) deep = [deep];
  const cyc = { a: 1 }; cyc.self = cyc;
  for (const v of [deep, cyc]) {
    assert.doesNotThrow(() => correlate({ kev: [{ ...kevDoc(KEV_SRC), source_id: v }] }));
    const d = kevDoc(KEV_SRC); d.document.items[0].cwes = [v]; assert.doesNotThrow(() => correlate({ kev: [d] }));
    assert.equal(correlate({ kev: [d] }).relations.length, 0);
  }
});

/** Seeded random mutations of the corpus: values replaced by type-confusion values, other corpus values or garbage; keys deleted; arrays duplicated. */
function mutate(input, r) {
  const x = structuredClone(input), slots = [];
  (function walk(v) { if (v && typeof v === 'object') for (const k of Object.keys(v)) { slots.push([v, k]); walk(v[k]); } })(x);
  const n = 1 + Math.floor(r() * 4);
  for (let i = 0; i < n && slots.length; i++) {
    const [o, k] = slots[Math.floor(r() * slots.length)], op = r();
    if (op < 0.45) o[k] = CONFUSE[Math.floor(r() * CONFUSE.length)];
    else if (op < 0.65) { const [o2, k2] = slots[Math.floor(r() * slots.length)]; o[k] = o2[k2]; }
    else if (op < 0.8) { if (Array.isArray(o)) o.splice(Number(k), 1); else delete o[k]; }
    else if (op < 0.9 && Array.isArray(o)) o.push(o[k]);
    else if (typeof o[k] === 'string') o[k] = o[k].length > 1 ? o[k].slice(0, -1) + (r() < 0.5 ? '0' : o[k].at(-1).toUpperCase()) : '';
  }
  return x;
}
test('fuzz (seed 20261102, 600 iterations): mutated corpus inputs never throw, are deterministic, emit only allowed types, and every asserted relation traces to one input statement', () => {
  const r = rng(20261102), allowed = new Set(Object.values(RULES).map((x) => x.type));
  let asserted = 0;
  for (let i = 0; i < 600; i++) {
    const { name, c } = CASES[i % CASES.length], input = mutate(c.input, r);
    let out; assert.doesNotThrow(() => { out = correlate(input); }, `${name} mutation ${i}`);
    assert.equal(serialize(correlate(input)), serialize(out), `${name} mutation ${i}: deterministic`);
    assert.doesNotThrow(() => JSON.parse(serialize(out)));
    for (const rel of out.relations) {
      assert.ok(allowed.has(rel.type) && RULES[rel.rule_id].type === rel.type, `${name} mutation ${i}: type ${rel.type}`);
      assert.ok(!/^RULE_DETECTS|^ALIAS_OF|^INDICATOR_/.test(rel.type));
      assert.equal(rel.independent_sources, new Set(rel.evidence.map((e) => e.original_source_id)).size);
      for (const e of rel.evidence) assert.ok(['source_id', 'original_source_id', 'locator', 'content_sha256'].every((k) => typeof e[k] === 'string'), `${name} mutation ${i}: evidence types`);
      if (rel.state !== 'asserted') continue;
      asserted++;
      for (const e of rel.evidence) {
        let ok = false; try { ok = trace(input, rel, e); } catch { ok = false; }
        assert.ok(ok, `${name} mutation ${i}: asserted evidence not traceable: ${e.locator}`);
      }
    }
  }
  assert.ok(asserted > 1000, `the fuzz keeps exercising asserted relations (${asserted})`);
});
