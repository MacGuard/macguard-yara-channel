// Engine output loaded into a scratch INTEL database built from migrations 0001-0005 (the same d1shim as intel_graph.test.js), through intel_graph.js only.
// NO schema change. Two groups of tests:
//   * ENFORCED: contract guarantees the CURRENT schema already enforces (they pass and must keep passing).
//   * GAP (needs 0007): guarantees the current schema CANNOT enforce. Each gap has
//       - a `GAP (needs 0007)` test that pins today's permissive behaviour (so it fails, and must be flipped, the day 0007 closes it), and
//       - a `todo` test asserting the contract behaviour, reported by node:test as TODO (an expected failure, never counted as a pass).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { newDb } from './d1shim.js';
import { putEntity, relate, assess, addEvidence, getEntity, normalizeKey, relationshipDetail } from '../src/intel_graph.js';
import { correlate, toGraph, projectState, YARA_SOURCE_ID } from '../src/intel_correlate.js';

const M = ['0001_intel.sql', '0002_decisions.sql', '0003_effective_state.sql', '0004_canonical_graph.sql', '0005_vulnerability_model.sql'].map((f) => `../migrations-intel/${f}`);
const NOW = '2026-11-02T12:00:00Z';
const caseInput = (n) => JSON.parse(readFileSync(new URL(`./fixtures/correlation/${n}/case.json`, import.meta.url), 'utf8')).input;
const REGISTRY = JSON.parse(readFileSync(new URL('../../../config/intel/sources.registry.json', import.meta.url), 'utf8'));
const approved = (id) => REGISTRY.sources.some((s) => s.id === id && s.approval_state === 'APPROVED_PUBLIC');
const raw = (db, sql, ...a) => db.raw.prepare(sql).run(...a);
const one = (db, sql, ...a) => db.raw.prepare(sql).get(...a);

/** Load every proposal of an engine result through intel_graph.js. Returns [{ rel, dbId, source_id }]. */
async function load(db, out) {
  const loaded = [];
  for (const rel of out.relations) {
    const g = toGraph(rel);
    const ids = []; for (const e of g.entities) ids.push(await putEntity(db, e, NOW));
    assert.deepEqual(ids, [rel.from, rel.to], 'engine ids are 0004 entity ids');
    for (const x of g.relationships) {
      const { id } = await relate(db, { ...x.relate, observed_at: NOW }, NOW);
      await assess(db, id, x.assessment, NOW);
      loaded.push({ rel, dbId: id, source_id: x.relate.source_id });
    }
  }
  return loaded;
}
async function scratch(...cases) {
  const db = newDb(M), all = [];
  for (const c of cases) all.push(...await load(db, correlate(caseInput(c))));
  return { db, all };
}

// ---- ENFORCED by the current schema ----------------------------------------------------------------------------------------------------------------------
test('ENFORCED: engine output loads into 0001-0005 unchanged; state = REPORTED (asserted) / INFERRED (candidate); evidence counted', async () => {
  const { db, all } = await scratch('01_verified_relations', '07_wrong_references', '08_contradicting_sources', '10_duplicate_evidence', '11_false_transitivity');
  assert.ok(all.length >= 25);
  for (const { rel, dbId } of all) {
    const d = await relationshipDetail(db, dbId);
    assert.equal(d.type, rel.type);
    assert.equal(d.confidence, rel.state === 'asserted' ? 'REPORTED' : 'INFERRED');
    assert.equal(d.verification, 'UNVERIFIED');
    assert.equal(d.method, rel.state === 'asserted' ? 'asserted_by_source' : 'derived_from_content');
    assert.ok(d.evidence.every((e) => e.kind === (rel.state === 'asserted' ? 'source_statement' : 'document')));
    assert.ok(d.evidence_count >= 1);
  }
  assert.equal(one(db, "SELECT COUNT(*) n FROM intel_relationships WHERE type LIKE 'RULE_DETECTS%' OR type = 'ALIAS_OF'").n, 0);
});

test('ENFORCED: relationships are immutable and never deleted; evidence and assessments are append-only', async () => {
  const { db, all } = await scratch('01_verified_relations');
  const id = all[0].dbId;
  assert.throws(() => raw(db, 'UPDATE intel_relationships SET to_id = to_id WHERE id = ?', id), /immutable/);
  assert.throws(() => raw(db, 'DELETE FROM intel_relationships WHERE id = ?', id), /never deleted/);
  assert.throws(() => raw(db, "UPDATE intel_relationship_evidence SET ref = 'x' WHERE relationship_id = ?", id), /append-only/);
  assert.throws(() => raw(db, 'DELETE FROM intel_relationship_evidence WHERE relationship_id = ?', id), /append-only/);
  assert.throws(() => raw(db, "UPDATE intel_relationship_assessments SET confidence = 'CONFIRMED' WHERE relationship_id = ?", id), /append-only/);
  assert.throws(() => raw(db, "UPDATE intel_relationship_state SET confidence = 'CONFIRMED' WHERE relationship_id = ?", id), /latest assessment/);
});

test('ENFORCED: retraction and contradiction are new assessments; the history stays', async () => {
  const { db, all } = await scratch('08_contradicting_sources');
  const id = all[0].dbId;
  await assess(db, id, { confidence: 'UNKNOWN', reason: 'absent_from_latest_snapshot (engine retracted report)', actor: 'engine:R-KEV-CWE-1' }, NOW);
  const d = await relationshipDetail(db, id);
  assert.deepEqual(d.assessments.map((a) => a.confidence), ['UNKNOWN', 'REPORTED']);
  assert.equal(d.confidence, 'UNKNOWN');
  // both sides of the contradiction are separate relationships with their own source
  assert.deepEqual(all.map((x) => x.source_id).sort(), ['cisa-kev', 'synthetic-list-b']);
});

test('ENFORCED: REPORTED needs a source_statement or document; endpoint types; only existing types; CONFIRMED detection needs a test_run; no CVSS outside vulnerabilities', async () => {
  const { db } = await scratch('01_verified_relations');
  const rule = 'rule:yara:rules/community/synthetic/papercut.yar#SYNTH_PaperCut_Artefact', vuln = 'vulnerability:cve:CVE-2023-27351', cwe = 'weakness:cwe:CWE-287';
  assert.ok(await getEntity(db, rule));
  const bare = await relate(db, { type: 'RULE_ASSOCIATED_WITH_CVE', from: rule, to: vuln, source_id: 'test-no-evidence', method: 'asserted_by_source' }, NOW);
  await assert.rejects(assess(db, bare.id, { confidence: 'REPORTED', reason: 'no evidence at all', actor: 'test' }, NOW), /REPORTED needs/);
  await assert.rejects(relate(db, { type: 'RULE_ASSOCIATED_WITH_CVE', from: rule, to: cwe, source_id: 's', method: 'asserted_by_source' }, NOW), /endpoint types/);
  for (const t of ['RULE_META_REFERENCES_CVE', 'RULE_META_MENTIONS_SAMPLE']) await assert.rejects(relate(db, { type: t, from: rule, to: vuln, source_id: 's', method: 'asserted_by_source' }, NOW), /endpoint types/, `${t} does not exist in 0004/0005`);
  const det = await relate(db, { type: 'RULE_DETECTS_CVE', from: rule, to: vuln, source_id: 's', method: 'asserted_by_source', evidence: [{ kind: 'source_statement', ref: 'x' }, { kind: 'human_review', ref: 'y' }] }, NOW);
  await assert.rejects(assess(db, det.id, { confidence: 'CONFIRMED', verification: 'VERIFIED', reason: 'no test run', actor: 'a' }, NOW), /test run/);
  assert.throws(() => raw(db, "INSERT INTO intel_severity_assessments (vuln_id,source_id,cvss_version,availability,vector,base_score,severity,assessed_at,recorded_at) VALUES (?,?,?,?,?,?,?,?,?)", rule, 's', '3.1', 'AVAILABLE', 'CVSS:3.1/AV:N', 9.8, 'CRITICAL', '2026-11-02T00:00:00.000Z', NOW), /severity belongs to a vulnerability/);
  await assert.rejects(relate(db, { type: 'ALIAS_OF', from: vuln, to: 'vulnerability:cve:CVE-2023-27351', source_id: 's', method: 'correlated' }, NOW), /ALIAS_OF|CHECK/);
});

test('ENFORCED: the 512-character entity key cap is why the engine refuses longer rule identities (never truncated)', async () => {
  const db = newDb(M), dir = 'rules/' + 'd'.repeat(99) + '/' + 'e'.repeat(99) + '/' + 'f'.repeat(99) + '/', n = 'N' + 'x'.repeat(127);
  const fit = dir + 'g'.repeat(512 - 1 - 128 - dir.length - 4) + '.yar', long = dir + 'g'.repeat(400 - dir.length - 4) + '.yar';
  assert.equal(`${fit}#${n}`.length, 512); assert.equal(`${long}#${n}`.length, 529);
  await putEntity(db, { type: 'rule', namespace: 'yara', key: `${fit}#${n}` }, NOW);
  await assert.rejects(putEntity(db, { type: 'rule', namespace: 'yara', key: `${long}#${n}` }, NOW), /too long|CHECK/);
  const out = correlate(caseInput('12_identity_and_provenance'));
  assert.ok(out.rejections.some((r) => r.reason === 'rule_key_exceeds_db_limit'));
  await load(db, out);   // everything the engine emits fits
});

// ---- GAPS: what the current schema cannot enforce (needs 0007) -------------------------------------------------------------------------------------------
/** A critical relation (RULE_DETECTS_CVE) proposed by user:analyst-a (the relationship's source_id: 0004 has no proposer column) with test_run evidence. */
async function criticalWithTest(db) {
  const all = await load(db, correlate(caseInput('01_verified_relations')));
  const rule = all.find((x) => x.rel.type === 'RULE_ASSOCIATED_WITH_CVE' && x.rel.state === 'asserted').rel;
  const det = await relate(db, { type: 'RULE_DETECTS_CVE', from: rule.from, to: rule.to, source_id: 'user:analyst-a', method: 'manual', evidence: [{ kind: 'test_run', ref: 'test-run:synthetic-1' }] }, NOW);
  return det.id;
}

test('GAP (needs 0007) proposer != approver: today the proposer of a critical relation can confirm it alone, and an ai:* actor can confirm', async () => {
  const db = newDb(M), id = await criticalWithTest(db);
  await assess(db, id, { confidence: 'CONFIRMED', verification: 'VERIFIED', reason: 'self-approved by the proposer', actor: 'user:analyst-a' }, NOW);
  await assess(db, id, { confidence: 'CONFIRMED', verification: 'VERIFIED', reason: 'approved by a model', actor: 'ai:some-model' }, NOW);
  assert.equal((await relationshipDetail(db, id)).verification, 'VERIFIED', 'accepted today: no reviews table, no CHECK approver <> proposer');
  assert.equal(one(db, "SELECT COUNT(*) n FROM sqlite_master WHERE name = 'intel_relationship_reviews'").n, 0);
});
test('needs 0007: a critical relation is VERIFIED only through a review by another, non-AI actor', { todo: 'needs 0007: intel_relationship_reviews + CHECK approver <> proposer + ai:* refused' }, async () => {
  const db = newDb(M), id = await criticalWithTest(db);
  await assert.rejects(assess(db, id, { confidence: 'CONFIRMED', verification: 'VERIFIED', reason: 'self-approved by the proposer', actor: 'user:analyst-a' }, NOW));
  await assert.rejects(assess(db, id, { confidence: 'CONFIRMED', verification: 'VERIFIED', reason: 'approved by a model', actor: 'ai:some-model' }, NOW));
});

test('GAP (needs 0007) candidate state: an engine candidate can be promoted to REPORTED by anyone (its document evidence satisfies 0004:107); no origin column', async () => {
  const { db, all } = await scratch('07_wrong_references');
  const cand = all.find((x) => x.rel.state === 'candidate');
  await assess(db, cand.dbId, { confidence: 'REPORTED', reason: 'promoted without any review', actor: 'ai:some-model' }, NOW);
  const d = await relationshipDetail(db, cand.dbId);
  assert.equal(d.confidence, 'REPORTED', 'accepted today');
  assert.equal(projectState({ confidence: d.confidence, verification: d.verification, evidenceKinds: d.evidence.map((e) => e.kind), sourceApproved: true }), 'asserted', 'it would project as asserted for an approved source');
  assert.ok(!db.raw.prepare('PRAGMA table_info(intel_relationships)').all().some((c) => c.name === 'origin'));
});
test('needs 0007: a candidate (origin engine/ai, derived_from_content) never reaches REPORTED without a review', { todo: 'needs 0007: origin column + trigger: candidate -> asserted only through a review' }, async () => {
  const { db, all } = await scratch('07_wrong_references');
  const cand = all.find((x) => x.rel.state === 'candidate');
  await assert.rejects(assess(db, cand.dbId, { confidence: 'REPORTED', reason: 'promoted without any review', actor: 'ai:some-model' }, NOW));
});

test('GAP (needs 0007) original_source_id: evidence has no original_source_id column; republished copies and re-imports inflate evidence_count', async () => {
  const { db, all } = await scratch('10_duplicate_evidence');
  assert.ok(!db.raw.prepare('PRAGMA table_info(intel_relationship_evidence)').all().some((c) => c.name === 'original_source_id'));
  const kev = all.find((x) => x.rel.type === 'VULN_HAS_WEAKNESS');
  assert.equal((await relationshipDetail(db, kev.dbId)).evidence_count, 2, 'CISA + aggregator copy: two rows, one independent source (only in the note text)');
  await load(db, correlate(caseInput('10_duplicate_evidence')));   // the very same output imported again
  assert.equal((await relationshipDetail(db, kev.dbId)).evidence_count, 4, 'accepted today: identical evidence appended twice');
});
test('needs 0007: identical evidence of one original source is recorded once', { todo: 'needs 0007: original_source_id on evidence + uniqueness (relationship, original_source_id, ref, sha256)' }, async () => {
  const { db, all } = await scratch('10_duplicate_evidence');
  const kev = all.find((x) => x.rel.type === 'VULN_HAS_WEAKNESS'), before = (await relationshipDetail(db, kev.dbId)).evidence_count;
  await load(db, correlate(caseInput('10_duplicate_evidence')));
  assert.equal((await relationshipDetail(db, kev.dbId)).evidence_count, before);
});

test('GAP (needs 0007) publication (rule 8): no public view; the YARA release and its upstreams are not registered sources, so r8 would hide every YARA relation', async () => {
  const { db, all } = await scratch('01_verified_relations');
  assert.equal(one(db, "SELECT COUNT(*) n FROM sqlite_master WHERE type = 'view' AND name = 'intel_relationship_public'").n, 0);
  assert.ok(approved('cisa-kev'));
  for (const id of [YARA_SOURCE_ID, 'yara-upstream:nextron', 'yara-upstream:community']) assert.ok(!REGISTRY.sources.some((s) => s.id === id), `${id} is not in config/intel/sources.registry.json`);
  const proj = all.map(({ rel, dbId, source_id }) => ({ rel, source_id, s: one(db, 'SELECT confidence, verification FROM intel_relationship_state WHERE relationship_id = ?', dbId) }))
    .map((x) => ({ ...x, p: projectState({ ...x.s, evidenceKinds: [x.rel.state === 'asserted' ? 'source_statement' : 'document'], sourceApproved: approved(x.source_id) }) }));
  assert.ok(proj.filter((x) => x.rel.type === 'VULN_HAS_WEAKNESS').every((x) => x.p === 'asserted'));
  assert.ok(proj.filter((x) => x.rel.type !== 'VULN_HAS_WEAKNESS').every((x) => x.p === 'candidate'), 'unregistered source: an engine-asserted YARA relation projects to candidate');
});

test('GAP (needs 0007) retraction: the schema has no retracted state; an engine retraction can only be an UNKNOWN assessment, indistinguishable from "never assessed"', async () => {
  const db = newDb(M);
  const out = correlate(caseInput('09_retracted_data'));
  assert.equal(out.retracted.length, 3);
  const v = await putEntity(db, { type: 'vulnerability', namespace: 'cve', key: 'CVE-2099-0301' }, NOW), w = await putEntity(db, { type: 'weakness', namespace: 'cwe', key: 'CWE-20' }, NOW);
  const r = await relate(db, { type: 'VULN_HAS_WEAKNESS', from: v, to: w, source_id: 'cisa-kev', method: 'asserted_by_source', evidence: [{ kind: 'source_statement', ref: 'x' }] }, NOW);
  await assess(db, r.id, { confidence: 'UNKNOWN', reason: 'absent_from_latest_snapshot', actor: 'engine:R-KEV-CWE-1' }, NOW);
  assert.throws(() => raw(db, "INSERT INTO intel_relationship_assessments (relationship_id,confidence,verification,reason,actor,at) VALUES (?, 'RETRACTED', 'UNVERIFIED', 'retracted by creator', 'a', ?)", r.id, NOW), /CHECK/);
});

test('GAP (documented) rule identity: intel_graph.js normalizeKey has no yara case, so the database accepts rule keys intel_ids.py refuses', () => {
  for (const k of ['rules/a/../b.yar#R', 'rules/a.yar#rule', 'rules/a.txt#R', 'not a rule']) assert.equal(normalizeKey('rule', 'yara', k), k, `accepted by the DB normaliser: ${k}`);
});

test('ENFORCED: evidence can still be appended after the fact (append-only, not frozen)', async () => {
  const { db, all } = await scratch('11_false_transitivity');
  await addEvidence(db, all[0].dbId, { kind: 'document', ref: 'later note' }, NOW);
  assert.equal((await relationshipDetail(db, all[0].dbId)).evidence_count, all[0].rel.evidence.length + 1);
});
