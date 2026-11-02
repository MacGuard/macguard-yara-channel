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
  'contradicting_sources', 'retracted_data', 'duplicate_evidence', 'false_transitivity', 'identity_and_provenance', 'snapshot_conflict_order_a', 'snapshot_conflict_order_b'];
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

/** Independent tracer: the evidence locator must point at ONE input statement that names both endpoints of the relation. */
function trace(input, rel, ev) {
  if (rel.type === 'VULN_HAS_WEAKNESS') {
    const m = /#catalogVersion=([^;]+);cveID=([^;]+);cwe=(.+)$/.exec(ev.locator); if (!m) return false;
    return (input.kev ?? []).some((w) => (w.source_id ?? w.document.source.id) === ev.source_id && w.document.source.id === ev.original_source_id && w.document.source.catalog_version === m[1]
      && w.document.source.upstream_sha256 === ev.content_sha256 && w.document.items.some((it) => it.cve_id === m[2] && it.cwes.includes(m[3]))
      && rel.from === `vulnerability:cve:${m[2]}` && rel.to === `weakness:cwe:${m[3]}`);
  }
  const m = /^(rules-[0-9]+-[0-9]+)\/(.+):([0-9]+)#meta\.([A-Za-z_][A-Za-z0-9_]*)$/.exec(ev.locator); if (!m) return false;
  return (input.rule_indexes ?? []).some((w) => (w.source_id ?? YARA_SOURCE_ID) === ev.source_id && w.document.release.tag === m[1] && w.document.assertions.some((a) =>
    a.provenance.path === m[2] && a.provenance.line === +m[3] && a.meta_key === m[4] && a.provenance.file_sha256 === ev.content_sha256 && `rule:${a.subject}` === rel.from
    && rel.to === (rel.type === 'RULE_REFERENCES_SAMPLE' ? `sample:sha256:${a.value}` : `vulnerability:cve:${a.value}`)));
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

test('robustness: garbage never throws, produces no relation and is reported', () => {
  const junk = [undefined, null, 1, 'x', [], {}, { kev: 'x' }, { kev: [null, 1, {}, { document: null }, { document: { schema: 'macguard.intel-kev/1' } }] },
    { rule_indexes: [{ document: { schema: 'macguard.search-index/1', release: { tag: 'rules-1-1' } } }] },
    { kev: [{ document: { schema: 'macguard.intel-kev/1', chunk: { index: 0, of: 2 }, items: [], source: { id: 'cisa-kev', url: 'u', catalog_version: '1', date_released: '2026-01-01T00:00:00.000Z', upstream_sha256: 'a'.repeat(64) } } }] },
    { kev: [{ source_id: 'Bad Id', document: { schema: 'macguard.intel-kev/1', items: [], source: { id: 'cisa-kev', url: 'u', catalog_version: '1', date_released: '2026-01-01T00:00:00.000Z', upstream_sha256: 'a'.repeat(64) } } }] },
    { kev: [{ document: { schema: 'macguard.intel-kev/1', items: [null, 7, { cve_id: 5 }, { cve_id: 'CVE-2099-1234', cwes: 'CWE-79' }, { cve_id: 'CVE-2099-1235', cwes: [null, 79] }],
      source: { id: 'cisa-kev', url: 'u', catalog_version: '1', date_released: '2026-01-01T00:00:00.000Z', upstream_sha256: 'a'.repeat(64) } } }] },
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
  assert.deepEqual(STATE_MAP.asserted, { method: 'asserted_by_source', evidence_kind: 'source_statement', confidence: 'REPORTED', verification: 'UNVERIFIED', exposure: 'internal' });
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
