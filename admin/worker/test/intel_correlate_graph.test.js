// Engine output loaded into a scratch INTEL database built from migrations 0001-0005 + 0007 (the same d1shim as intel_graph.test.js), through intel_graph.js only.
//   * ENFORCED: contract guarantees enforced by 0004/0005 (they pass and must keep passing).
//   * 0007: the gaps pinned before INTEL 0007 (formerly `GAP (needs 0007)` + three `todo` tests), now closed by the database and asserted as passing tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { newDb } from './d1shim.js';
import { putEntity, relate, assess, addEvidence, getEntity, normalizeKey, relationshipDetail as detail } from '../src/intel_graph.js';
import { correlate, toGraph, projectState, YARA_SOURCE_ID } from '../src/intel_correlate.js';
import { review, setLifecycle, syncSourceApprovals } from '../src/intel_assurance.js';
import { M7 as M, bootstrapReviewers, registryWith, REGISTRY_TEXT } from './intel_m7.js';

const relationshipDetail = (db, id) => detail(db, id, { scope: 'internal' });
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
  await syncSourceApprovals(db, REGISTRY_TEXT, NOW);
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
  const bare = await relate(db, { type: 'RULE_ASSOCIATED_WITH_CVE', from: rule, to: vuln, source_id: 'test-no-evidence', method: 'asserted_by_source', origin: 'source_ingest' }, NOW);
  await assert.rejects(assess(db, bare.id, { confidence: 'REPORTED', reason: 'no evidence at all', actor: 'test' }, NOW), /REPORTED needs/);
  const S = { origin: 'source_ingest' };
  await assert.rejects(relate(db, { type: 'RULE_ASSOCIATED_WITH_CVE', from: rule, to: cwe, source_id: 's', method: 'asserted_by_source', ...S }, NOW), /endpoint types/);
  for (const t of ['RULE_META_REFERENCES_CVE', 'RULE_META_MENTIONS_SAMPLE']) await assert.rejects(relate(db, { type: t, from: rule, to: vuln, source_id: 's', method: 'asserted_by_source', ...S }, NOW), /endpoint types/, `${t} does not exist in 0004/0005`);
  await bootstrapReviewers(db);
  const det = await relate(db, { type: 'RULE_DETECTS_CVE', from: rule, to: vuln, source_id: 's', method: 'asserted_by_source', evidence: [{ kind: 'source_statement', ref: 'x' }, { kind: 'human_review', ref: 'y', source_id: 'user:rev-a' }], ...S }, NOW);
  await review(db, det.id, { approver: 'user:rev-a', decision: 'approve', reason: 'approved without a test run' }, NOW);
  await assert.rejects(assess(db, det.id, { confidence: 'CONFIRMED', verification: 'VERIFIED', reason: 'no test run', actor: 'user:rev-a' }, NOW), /test run/);
  assert.throws(() => raw(db, "INSERT INTO intel_severity_assessments (vuln_id,source_id,cvss_version,availability,vector,base_score,severity,assessed_at,recorded_at) VALUES (?,?,?,?,?,?,?,?,?)", rule, 's', '3.1', 'AVAILABLE', 'CVSS:3.1/AV:N', 9.8, 'CRITICAL', '2026-11-02T00:00:00.000Z', NOW), /severity belongs to a vulnerability/);
  await assert.rejects(relate(db, { type: 'ALIAS_OF', from: vuln, to: 'vulnerability:cve:CVE-2023-27351', source_id: 's', method: 'correlated', origin: 'ai_proposed', proposer: 'ai:m' }, NOW), /ALIAS_OF|CHECK/);
});

test('ENFORCED: the 512-character entity key cap is why the engine refuses longer rule identities (never truncated)', async () => {
  const db = newDb(M), dir = 'rules/' + 'd'.repeat(99) + '/' + 'e'.repeat(99) + '/' + 'f'.repeat(99) + '/', n = 'N' + 'x'.repeat(127);
  const fit = dir + 'g'.repeat(512 - 1 - 128 - dir.length - 4) + '.yar', long = dir + 'g'.repeat(400 - dir.length - 4) + '.yar';
  assert.equal(`${fit}#${n}`.length, 512); assert.equal(`${long}#${n}`.length, 529);
  await putEntity(db, { type: 'rule', namespace: 'yara', key: `${fit}#${n}` }, NOW);
  await assert.rejects(putEntity(db, { type: 'rule', namespace: 'yara', key: `${long}#${n}` }, NOW), /longer than 512|CHECK/);
  assert.throws(() => raw(db, "INSERT INTO intel_entities (id,type,namespace,key,first_seen,updated_at) VALUES (?, 'rule', 'yara', ?, ?, ?)", `rule:yara:${long}#${n}`, `${long}#${n}`, NOW, NOW), /CHECK/, 'the database refuses it too (raw SQL)');
  const out = correlate(caseInput('12_identity_and_provenance'));
  assert.ok(out.rejections.some((r) => r.reason === 'rule_key_exceeds_db_limit'));
  await load(db, out);   // everything the engine emits fits
});

// ---- 0007: the former gaps, closed in the database ---------------------------------------------------------------------------------------------------
/** A critical relation (RULE_DETECTS_CVE) proposed by the analyst user:analyst-a (creation record, origin analyst) with test_run evidence. */
async function criticalWithTest(db) {
  const all = await load(db, correlate(caseInput('01_verified_relations')));
  const rule = all.find((x) => x.rel.type === 'RULE_ASSOCIATED_WITH_CVE' && x.rel.state === 'asserted').rel;
  const det = await relate(db, { type: 'RULE_DETECTS_CVE', from: rule.from, to: rule.to, source_id: 'macguard-lab', method: 'manual', evidence: [{ kind: 'test_run', ref: 'test-run:synthetic-1' }], origin: 'analyst', proposer: 'user:analyst-a' }, NOW);
  return det.id;
}

test('0007 (was todo): a critical relation is VERIFIED only through a review by another, non-AI actor', async () => {
  const db = newDb(M), id = await criticalWithTest(db);
  await assert.rejects(assess(db, id, { confidence: 'CONFIRMED', verification: 'VERIFIED', reason: 'self-approved by the proposer', actor: 'user:analyst-a' }, NOW), /approved review/);
  await assert.rejects(assess(db, id, { confidence: 'CONFIRMED', verification: 'VERIFIED', reason: 'approved by a model', actor: 'ai:some-model' }, NOW), /AI never writes|approved review/);
  await bootstrapReviewers(db, [['user:analyst-a', 2001], ['user:rev-b', 2002]]);
  await assert.rejects(review(db, id, { approver: 'user:analyst-a', decision: 'approve', reason: 'my own proposal' }, NOW), /CHECK/, 'the proposer never approves, even as a reviewer');
  await assert.rejects(review(db, id, { approver: 'ai:some-model', decision: 'approve', reason: 'model approval' }, NOW), /CHECK|allow-list/);
  await review(db, id, { approver: 'user:rev-b', decision: 'approve', reason: 'replayed the test run' }, NOW);
  await assert.rejects(assess(db, id, { confidence: 'CONFIRMED', verification: 'VERIFIED', reason: 'proposer after the review', actor: 'user:analyst-a' }, NOW), /approved review/, 'the approver must be the actor of the VERIFIED assessment');
  await assess(db, id, { confidence: 'CONFIRMED', verification: 'VERIFIED', reason: 'approved review + test run', actor: 'user:rev-b' }, NOW);
  assert.equal((await relationshipDetail(db, id)).state, 'verified');
});

test('0007 (was todo): a candidate (origin engine/ai, derived_from_content) never reaches REPORTED, by any actor, module or raw SQL', async () => {
  const { db, all } = await scratch('07_wrong_references');
  const cand = all.find((x) => x.rel.state === 'candidate');
  await assert.rejects(assess(db, cand.dbId, { confidence: 'REPORTED', reason: 'promoted without any review', actor: 'ai:some-model' }, NOW));
  await assert.rejects(assess(db, cand.dbId, { confidence: 'REPORTED', reason: 'promoted by a human', actor: 'user:analyst-a' }, NOW), /never reaches REPORTED/);
  assert.throws(() => raw(db, "INSERT INTO intel_relationship_assessments (relationship_id,confidence,verification,reason,actor,at) VALUES (?, 'REPORTED', 'UNVERIFIED', 'raw SQL promotion', 'user:x', ?)", cand.dbId, NOW), /never reaches REPORTED/);
  const c = one(db, 'SELECT origin, proposer, rule_id FROM intel_relationship_creation WHERE relationship_id = ?', cand.dbId);
  assert.deepEqual({ ...c }, { origin: 'engine_rule', proposer: `engine:${cand.rel.rule_id}`, rule_id: cand.rel.rule_id }, 'origin recorded at creation');
  assert.equal((await relationshipDetail(db, cand.dbId)).state, 'candidate');
});

test('0007 (was todo): identical evidence of one original source is recorded once; evidence carries original_source_id', async () => {
  const { db, all } = await scratch('10_duplicate_evidence');
  const kev = all.find((x) => x.rel.type === 'VULN_HAS_WEAKNESS'), before = (await relationshipDetail(db, kev.dbId)).evidence_count;
  await load(db, correlate(caseInput('10_duplicate_evidence')));
  assert.equal((await relationshipDetail(db, kev.dbId)).evidence_count, before, 'the very same output imported again adds nothing');
  const ev = (await relationshipDetail(db, kev.dbId)).evidence;
  assert.ok(ev.every((e) => e.original_source_id === 'cisa-kev'), 'a republished copy keeps the ORIGINAL source');
  assert.equal(new Set(ev.map((e) => e.original_source_id)).size, 1, 'one independent source');
  assert.throws(() => raw(db, "INSERT INTO intel_relationship_evidence (relationship_id,kind,ref,source_id,observed_at,recorded_at) VALUES (?, 'document', 'no origin', 'cisa-kev', ?, ?)", kev.dbId, NOW, NOW), /original_source_id/);
});

test('0007 publication (rule 8): the public view holds only asserted relations of APPROVED_PUBLIC sources; YARA relations stay candidate until the owner registers the release', async () => {
  const { db, all } = await scratch('01_verified_relations');
  assert.ok(approved('cisa-kev'));
  for (const id of [YARA_SOURCE_ID, 'yara-upstream:nextron', 'yara-upstream:community']) assert.ok(!REGISTRY.sources.some((s) => s.id === id), `${id} is not in config/intel/sources.registry.json (pending owner decision)`);
  const st = (x) => one(db, 'SELECT state FROM intel_relationship_lifecycle WHERE relationship_id = ?', x.dbId).state;
  for (const x of all) {
    const pub = !!one(db, 'SELECT 1 AS x FROM intel_relationship_public WHERE id = ?', x.dbId);
    const s = st(x), d = one(db, 'SELECT confidence, verification FROM intel_relationship_state WHERE relationship_id = ?', x.dbId);
    assert.equal(s, projectState({ ...d, evidenceKinds: [x.rel.state === 'asserted' ? 'source_statement' : 'document'], sourceApproved: x.rel.type === 'VULN_HAS_WEAKNESS' }), 'the database state equals the engine projection');
    if (x.rel.type === 'VULN_HAS_WEAKNESS') { assert.equal(s, 'asserted'); assert.ok(pub); } else { assert.equal(s, 'candidate'); assert.ok(!pub); }
  }
  // the owner decision simulated on a COPY of the registry (the real one is not edited): the release approved -> its engine-asserted relations become public
  await syncSourceApprovals(db, registryWith([YARA_SOURCE_ID]), NOW);
  for (const x of all) assert.equal(st(x), x.rel.state === 'asserted' ? 'asserted' : 'candidate', `${x.rel.type} ${x.rel.state}`);
  assert.equal(one(db, 'SELECT COUNT(*) n FROM intel_relationship_public').n, all.filter((x) => x.rel.state === 'asserted').length);
});

test('0007 retraction: a retracted marker set only by the original source or the proposer; distinct from "never assessed"', async () => {
  const db = newDb(M);
  await syncSourceApprovals(db, REGISTRY_TEXT, NOW);
  const v = await putEntity(db, { type: 'vulnerability', namespace: 'cve', key: 'CVE-2099-0301' }, NOW), w = await putEntity(db, { type: 'weakness', namespace: 'cwe', key: 'CWE-20' }, NOW);
  const r = await relate(db, { type: 'VULN_HAS_WEAKNESS', from: v, to: w, source_id: 'cisa-kev', method: 'asserted_by_source', exposure: 'public', evidence: [{ kind: 'source_statement', ref: 'x' }], origin: 'engine_rule', rule_id: 'R-KEV-CWE-1' }, NOW);
  await assess(db, r.id, { confidence: 'REPORTED', reason: 'kev cwes field', actor: 'engine:R-KEV-CWE-1' }, NOW);
  assert.equal((await relationshipDetail(db, r.id)).state, 'asserted');
  await assert.rejects(setLifecycle(db, r.id, { marker: 'retracted', actor: 'user:someone-else', reason: 'not my relation' }, NOW), /original source or the proposer/);
  await setLifecycle(db, r.id, { marker: 'retracted', actor: 'engine:R-KEV-CWE-1', reason: 'absent_from_latest_snapshot' }, NOW);
  assert.equal((await relationshipDetail(db, r.id)).state, 'retracted');
  assert.equal(await detail(db, r.id), null, 'retracted: history only, never public');
  await assert.rejects(assess(db, r.id, { confidence: 'REPORTED', reason: 're-assert after retraction', actor: 'engine:R-KEV-CWE-1' }, NOW), /retracted/);
  await setLifecycle(db, r.id, { marker: 'reinstated', actor: 'source:cisa-kev', reason: 'present again in the catalogue' }, NOW);
  assert.equal((await relationshipDetail(db, r.id)).state, 'asserted');
});

test('0007 (C3b): normalizeKey has a yara case aligned with intel_ids; the database refuses non-canonical rule keys', async () => {
  for (const k of ['rules/a/../b.yar#R', 'rules/a.yar#rule', 'rules/a.txt#R', 'not a rule']) assert.throws(() => normalizeKey('rule', 'yara', k), /intel_ids/, k);
  const db = newDb(M);
  for (const k of ['rules/a/../b.yar#R', 'rules/a.yar#rule', 'rules/a.txt#R', 'not a rule']) assert.throws(() => raw(db, "INSERT INTO intel_entities (id,type,namespace,key,first_seen,updated_at) VALUES (?, 'rule', 'yara', ?, ?, ?)", `rule:yara:${k}`, k, NOW, NOW), /yara rule key/, k);
});

test('ENFORCED: evidence can still be appended after the fact (append-only, not frozen)', async () => {
  const { db, all } = await scratch('11_false_transitivity');
  await addEvidence(db, all[0].dbId, { kind: 'document', ref: 'later note' }, NOW);
  assert.equal((await relationshipDetail(db, all[0].dbId)).evidence_count, all[0].rel.evidence.length + 1);
});
