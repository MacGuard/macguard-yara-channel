// R1 vulnerability model (INTEL migration 0005 + src/intel_vuln.js) on the canonical graph of 0004. Synthetic data only; invariants tested through the module AND
// with raw SQL that bypasses it.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { newDb } from './d1shim.js';
import { putEntity, relate, assess, addEvidence, normalizeKey, gcveToCve } from '../src/intel_graph.js';
import { putVulnerability, putWeakness, recordAlias, linkGcve0, aliasesOf, addSeverity, addEpss, recordSnapshot, addExploitation, exploitationStatus, addAffectedRange, putPackage, detectionLevel, vulnerabilityRecord, validCvssVector } from '../src/intel_vuln.js';
import { validate } from '../../../gateway/src/schema.js';

const M4 = ['../migrations-intel/0001_intel.sql', '../migrations-intel/0002_decisions.sql', '../migrations-intel/0003_effective_state.sql', '../migrations-intel/0004_canonical_graph.sql'];
const M5 = readFileSync(new URL('../migrations-intel/0005_vulnerability_model.sql', import.meta.url), 'utf8'), R5 = readFileSync(new URL('../migrations-intel/0005_rollback.sql', import.meta.url), 'utf8');
const VSCHEMA = JSON.parse(readFileSync(new URL('../../../contracts/v1/intel-vulnerability.schema.json', import.meta.url), 'utf8'));
const PSCHEMA = JSON.parse(readFileSync(new URL('../../../contracts/v1/package-manifest.schema.json', import.meta.url), 'utf8'));
const NOW = '2026-11-01T10:00:00Z';
const fresh = () => { const db = newDb(M4); db.raw.exec(M5); return db; };
const raw = (db, sql, ...a) => db.raw.prepare(sql).run(...a);
const count = (db, sql, ...a) => db.raw.prepare(sql).get(...a).n;
const SRC = { kind: 'source_statement', ref: 'https://example.org/feed/item/1' };
const V31 = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', V40 = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';

// ---- migration ----
test('0005 on a 0001-0004 database WITH data: nothing is lost or altered, it is idempotent, 0004 invariants still hold, and the rollback leaves 0001-0004 intact', async () => {
  const db = newDb(M4);
  const rule = await putEntity(db, { type: 'rule', namespace: 'suricata', key: '2000105' }, NOW), cve = await putEntity(db, { type: 'vulnerability', namespace: 'cve', key: 'CVE-2024-1234' }, NOW);
  const { id } = await relate(db, { type: 'RULE_ASSOCIATED_WITH_CVE', from: rule, to: cve, source_id: 'et', method: 'asserted_by_source', evidence: [SRC] }, NOW);
  await assess(db, id, { confidence: 'REPORTED', reason: 'feed metadata', actor: 'ingest' }, NOW);
  const dump = () => JSON.stringify(['intel_entities', 'intel_relationships', 'intel_relationship_evidence', 'intel_relationship_assessments', 'intel_relationship_state', 'intel_relationship_types', 'intel_entity_types'].map((t) => db.raw.prepare(`SELECT * FROM ${t} ORDER BY 1`).all()));
  const objects = () => db.raw.prepare("SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name").all().map((r) => `${r.type}:${r.name}`);
  const before = dump(), objs4 = objects(), types4 = JSON.parse(before)[5];
  db.raw.exec(M5); db.raw.exec(M5);
  const after = JSON.parse(dump());
  assert.deepEqual(after.slice(0, 5), JSON.parse(before).slice(0, 5), 'graph rows unchanged');
  for (const t of types4) assert.ok(after[5].some((x) => JSON.stringify(x) === JSON.stringify(t)), 'existing relationship types unchanged');
  for (const o of objs4) assert.ok(objects().includes(o), `${o} still there`);
  assert.throws(() => raw(db, 'UPDATE intel_relationships SET source_id = ? WHERE id = ?', 'x', id), /immutable/);
  db.raw.exec(R5); assert.deepEqual(objects(), objs4, 'rollback: exactly the 0001-0004 objects'); assert.equal(dump(), before, 'rollback: 0001-0004 rows identical');
  db.raw.exec(M5); assert.equal(count(db, "SELECT COUNT(*) AS n FROM intel_relationship_types WHERE type = 'ALIAS_OF'"), 1, 're-applies after a rollback');
});
test('rollback keeps a 0005 relationship type that is in use (relationships are never deleted) and drops the rest', async () => {
  const db = fresh(); const a = await putVulnerability(db, { namespace: 'euvd', key: 'EUVD-2025-1' }, NOW), b = await putVulnerability(db, { namespace: 'cve', key: 'CVE-2025-0001' }, NOW);
  await recordAlias(db, { from: a, to: b, source_id: 'enisa-euvd', evidence: SRC }, NOW);
  db.raw.exec(R5);
  assert.equal(count(db, "SELECT COUNT(*) AS n FROM intel_relationship_types WHERE type = 'ALIAS_OF'"), 1); assert.equal(count(db, "SELECT COUNT(*) AS n FROM intel_relationship_types WHERE type = 'PACKAGE_IN_RELEASE'"), 0);
  assert.equal(count(db, "SELECT COUNT(*) AS n FROM intel_relationships WHERE type = 'ALIAS_OF'"), 1, 'the alias survives');
});

// ---- identifiers and aliases ----
test('identifiers: GCVE keeps its GNA, CWE normalises, and only GCVE-0 maps to a CVE (never another GNA, never a short number)', () => {
  assert.equal(normalizeKey('vulnerability', 'gcve', 'gcve-1-2025-0001'), 'GCVE-1-2025-0001'); assert.equal(normalizeKey('vulnerability', 'gcve', 'GCVE-007-2025-12'), 'GCVE-7-2025-12');
  assert.equal(normalizeKey('weakness', 'cwe', 'cwe-079'), 'CWE-79'); for (const bad of ['GCVE-2025-1', 'GCVE-x-2025-1']) assert.throws(() => normalizeKey('vulnerability', 'gcve', bad));
  assert.throws(() => normalizeKey('weakness', 'cwe', 'CWE-ABC'));
  assert.equal(gcveToCve('GCVE-0-2024-12345'), 'CVE-2024-12345'); assert.equal(gcveToCve('GCVE-1-2024-12345'), null); assert.equal(gcveToCve('GCVE-0-2024-12'), null);
});
test('aliases: asserted by a source (REPORTED), GCVE-0 by its definition; no CVE is invented for an EUVD or another GNA without a mapping', async () => {
  const db = fresh();
  const g0 = await linkGcve0(db, 'GCVE-0-2024-12345', NOW); assert.ok(g0 && !g0.disputed);
  assert.equal(await linkGcve0(db, 'GCVE-1-2025-0001', NOW), null);
  const euvd = await putVulnerability(db, { namespace: 'euvd', key: 'EUVD-2025-777' }, NOW);
  assert.equal(count(db, "SELECT COUNT(*) AS n FROM intel_entities WHERE namespace = 'cve'"), 1, 'only the GCVE-0 CVE exists: nothing invented for the EUVD or GCVE-1');
  const cve = await putVulnerability(db, { namespace: 'cve', key: 'CVE-2025-1111' }, NOW); await recordAlias(db, { from: euvd, to: cve, source_id: 'enisa-euvd', evidence: SRC }, NOW);
  const al = await aliasesOf(db, cve); assert.deepEqual(al.equivalent.map((x) => [x.id, x.confidence]), [['EUVD-2025-777', 'REPORTED']]); assert.deepEqual(al.disputed, []);
});
test('aliases: conflicting mappings are DISPUTED and kept apart (never merged); text similarity, same-namespace links and unsupported aliases are refused', async () => {
  const db = fresh();
  const e = await putVulnerability(db, { namespace: 'euvd', key: 'EUVD-2025-9' }, NOW), c1 = await putVulnerability(db, { namespace: 'cve', key: 'CVE-2025-0101' }, NOW), c2 = await putVulnerability(db, { namespace: 'cve', key: 'CVE-2025-0202' }, NOW);
  assert.equal((await recordAlias(db, { from: e, to: c1, source_id: 'enisa-euvd', evidence: SRC }, NOW)).disputed, false);
  assert.equal((await recordAlias(db, { from: e, to: c2, source_id: 'other-feed', evidence: SRC }, NOW)).disputed, true);
  const al = await aliasesOf(db, e); assert.deepEqual(al.equivalent, []); assert.deepEqual(al.disputed.map((x) => x.id).sort(), ['CVE-2025-0101', 'CVE-2025-0202']);
  assert.equal(count(db, "SELECT COUNT(*) AS n FROM intel_entities WHERE type = 'vulnerability'"), 3, 'nothing merged');
  await assert.rejects(relate(db, { type: 'ALIAS_OF', from: e, to: c1, source_id: 'similarity', method: 'correlated' }, NOW), /never correlated/, 'text similarity is never an alias (database rule)');
  await assert.rejects(relate(db, { type: 'ALIAS_OF', from: c1, to: c2, source_id: 'x', method: 'manual' }, NOW), /different namespaces/);
  await assert.rejects(recordAlias(db, { from: e, to: c1, source_id: 'x', evidence: { kind: 'content_match', ref: 'titles look alike' } }, NOW), /source statement or document/);
});

// ---- CWE, CVSS ----
test('CVSS: several sources and versions coexist; a newer assessment is appended and becomes current for THAT source only; history is kept; CWE has no CVSS', async () => {
  const db = fresh(), v = await putVulnerability(db, { namespace: 'cve', key: 'CVE-2025-2222' }, NOW), w = await putWeakness(db, { key: 'CWE-79', name: 'XSS', category: 'Base' }, NOW);
  await relate(db, { type: 'VULN_HAS_WEAKNESS', from: v, to: w, source_id: 'nvd', method: 'asserted_by_source', exposure: 'public' }, NOW);
  assert.equal(await addSeverity(db, v, { source_id: 'nvd', cvss_version: '3.1', vector: V31, base_score: 9.8, assessed_at: '2026-10-01T00:00:00Z' }, NOW), 'CRITICAL');
  await addSeverity(db, v, { source_id: 'vendor', cvss_version: '3.1', vector: V31.replace('A:H', 'A:N'), base_score: 9.1, assessed_at: '2026-10-02T00:00:00Z' }, NOW);
  await addSeverity(db, v, { source_id: 'nvd', cvss_version: '4.0', vector: V40, base_score: 9.3, assessed_at: '2026-10-03T00:00:00Z' }, NOW);
  await addSeverity(db, v, { source_id: 'nvd', cvss_version: '3.1', vector: V31.replace('PR:N', 'PR:L'), base_score: 8.8, assessed_at: '2026-10-20T00:00:00Z' }, NOW);
  await addSeverity(db, v, { source_id: 'ghsa', cvss_version: '3.1', availability: 'NOT_PROVIDED', assessed_at: '2026-10-21T00:00:00Z' }, NOW);
  const cur = db.raw.prepare('SELECT source_id, cvss_version, base_score, severity, availability FROM intel_severity_current WHERE vuln_id = ? ORDER BY source_id, cvss_version').all(v).map((r) => ({ ...r }));
  assert.deepEqual(cur, [{ source_id: 'ghsa', cvss_version: '3.1', base_score: null, severity: null, availability: 'NOT_PROVIDED' }, { source_id: 'nvd', cvss_version: '3.1', base_score: 8.8, severity: 'HIGH', availability: 'AVAILABLE' },
    { source_id: 'nvd', cvss_version: '4.0', base_score: 9.3, severity: 'CRITICAL', availability: 'AVAILABLE' }, { source_id: 'vendor', cvss_version: '3.1', base_score: 9.1, severity: 'CRITICAL', availability: 'AVAILABLE' }]);
  assert.equal(count(db, 'SELECT COUNT(*) AS n FROM intel_severity_assessments WHERE vuln_id = ?', v), 5, 'the replaced NVD 3.1 value is still in the history');
  assert.throws(() => raw(db, 'UPDATE intel_severity_assessments SET base_score = 1 WHERE vuln_id = ?', v), /append-only/);
  assert.throws(() => raw(db, "INSERT INTO intel_severity_assessments (vuln_id,source_id,cvss_version,availability,vector,base_score,severity,assessed_at,recorded_at) VALUES (?,?,?,?,?,?,?,?,?)", w, 'x', '3.1', 'AVAILABLE', V31, 5.0, 'MEDIUM', NOW, NOW), /CWE weakness has no CVSS/);
  assert.throws(() => raw(db, "INSERT INTO intel_severity_assessments (vuln_id,source_id,cvss_version,availability,vector,base_score,severity,assessed_at,recorded_at) VALUES (?,?,?,?,?,?,?,?,?)", v, 'x', '3.1', 'AVAILABLE', V31, 9.8, 'LOW', NOW, NOW), /CHECK/, 'severity must match the score');
  assert.throws(() => raw(db, "INSERT INTO intel_severity_assessments (vuln_id,source_id,cvss_version,availability,vector,base_score,severity,assessed_at,recorded_at) VALUES (?,?,?,?,?,?,?,?,?)", v, 'x', '4.0', 'AVAILABLE', V31, 9.8, 'CRITICAL', NOW, NOW), /CHECK/, 'vector prefix must match the version');
});
test('CVSS vectors are validated per version (base metrics complete, known values, no duplicates)', async () => {
  assert.ok(validCvssVector('3.1', V31)); assert.ok(validCvssVector('3.0', V31.replace('3.1', '3.0'))); assert.ok(validCvssVector('4.0', V40)); assert.ok(validCvssVector('2.0', 'AV:N/AC:L/Au:N/C:P/I:P/A:P'));
  assert.ok(validCvssVector('3.1', V31 + '/E:F/RL:O')); assert.ok(validCvssVector('4.0', V40 + '/E:A/U:Red'));
  for (const [ver, vec] of [['3.1', V31.replace('/A:H', '')], ['3.1', V31 + '/A:H'], ['3.1', V31.replace('AV:N', 'AV:Q')], ['3.0', V31], ['4.0', V31], ['4.0', V40.replace('/AT:N', '')], ['2.0', 'CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P'], ['3.1', V31 + '/ZZ:1']]) assert.equal(validCvssVector(ver, vec), false, `${ver} ${vec}`);
  const db = fresh(), v = await putVulnerability(db, { namespace: 'cve', key: 'CVE-2025-3333' }, NOW);
  await assert.rejects(addSeverity(db, v, { source_id: 'nvd', cvss_version: '3.1', vector: V31.replace('/A:H', ''), base_score: 9.8, assessed_at: NOW }, NOW), /invalid CVSS/);
  await assert.rejects(addSeverity(db, v, { source_id: 'nvd', cvss_version: '3.1', availability: 'NOT_PROVIDED', base_score: 0, assessed_at: NOW }, NOW), /no vector or score/);
});

// ---- EPSS ----
test('EPSS: the latest moves only forward in time, history is per date, values stay in [0,1]', async () => {
  const db = fresh(), v = await putVulnerability(db, { namespace: 'cve', key: 'CVE-2025-4444' }, NOW);
  await addEpss(db, v, { score_date: '2026-10-30', probability: 0.12, percentile: 0.93, keepHistory: true }, NOW);
  await addEpss(db, v, { score_date: '2026-10-31', probability: 0.2, percentile: 0.95, keepHistory: true }, NOW);
  assert.deepEqual(await addEpss(db, v, { score_date: '2026-10-29', probability: 0.9, percentile: 0.99, keepHistory: true }, NOW), { latest_updated: false }, 'a late older file does not overwrite');
  const l = db.raw.prepare('SELECT score_date, probability FROM intel_epss_latest WHERE vuln_id = ?').get(v); assert.deepEqual({ ...l }, { score_date: '2026-10-31', probability: 0.2 });
  assert.deepEqual(db.raw.prepare('SELECT score_date FROM intel_epss_history WHERE vuln_id = ? ORDER BY score_date').all(v).map((r) => r.score_date), ['2026-10-29', '2026-10-30', '2026-10-31']);
  assert.throws(() => raw(db, "UPDATE intel_epss_latest SET score_date = '2026-01-01' WHERE vuln_id = ?", v), /only moves forward/);
  for (const bad of [{ probability: 1.2, percentile: 0.5 }, { probability: 0.5, percentile: -0.1 }]) await assert.rejects(addEpss(db, v, { score_date: '2026-11-01', ...bad }, NOW), /\[0,1\]/);
  await assert.rejects(addEpss(db, v, { score_date: '2026-02-30', probability: 0.1, percentile: 0.1 }, NOW), /YYYY-MM-DD/);
});

// ---- KEV and exploitation ----
test('KEV: UNKNOWN without a snapshot, NOT_LISTED only "as of" a snapshot (never "not exploited"), LISTED with its dates and action', async () => {
  const db = fresh(), v = await putVulnerability(db, { namespace: 'cve', key: 'CVE-2025-5555' }, NOW), k = await putVulnerability(db, { namespace: 'cve', key: 'CVE-2025-6666' }, NOW);
  let s = await exploitationStatus(db, v); assert.equal(s.kev.status, 'UNKNOWN'); assert.equal(s.evidence_status, 'NO_EVIDENCE_RECORDED');
  const snap = await recordSnapshot(db, { source_id: 'cisa-kev', snapshot_at: '2026-11-01T06:00:00Z', item_count: 1800, sha256: 'a'.repeat(64) }, NOW);
  s = await exploitationStatus(db, v); assert.equal(s.kev.status, 'NOT_LISTED'); assert.equal(s.kev.as_of, '2026-11-01T06:00:00Z'); assert.match(s.kev.note, /not evidence that it is not exploited/);
  assert.equal(s.evidence_status, 'NO_EVIDENCE_RECORDED'); assert.ok(!JSON.stringify(s).includes('NOT_EXPLOITED'));
  await addExploitation(db, k, { source_id: 'cisa-kev', kind: 'KEV_LISTED', listed_at: '2026-10-15', due_date: '2026-11-05', required_action: 'Apply vendor updates.', evidence_ref: 'kev:CVE-2025-6666', snapshot_id: snap, observed_at: '2026-11-01T06:00:00Z' }, NOW);
  s = await exploitationStatus(db, k); assert.deepEqual([s.kev.status, s.kev.date_added, s.kev.due_date, s.evidence_status], ['LISTED', '2026-10-15', '2026-11-05', 'EVIDENCE_RECORDED']);
  assert.throws(() => raw(db, "INSERT INTO intel_exploitation_evidence (vuln_id,source_id,kind,evidence_ref,observed_at,recorded_at) VALUES (?,?,?,?,?,?)", v, 'x', 'NOT_EXPLOITED', 'r', NOW, NOW), /CHECK/, 'there is no "not exploited" state');
  assert.throws(() => raw(db, "INSERT INTO intel_exploitation_evidence (vuln_id,source_id,kind,evidence_ref,observed_at,recorded_at) VALUES (?,?,?,?,?,?)", v, 'cisa-kev', 'KEV_LISTED', 'r', NOW, NOW), /CHECK/, 'a KEV listing has its date');
  await addExploitation(db, k, { source_id: 'cisa-kev', kind: 'KEV_DELISTED', evidence_ref: 'kev-removed', observed_at: '2026-11-02T06:00:00Z' }, NOW);
  s = await exploitationStatus(db, k); assert.equal(s.kev.status, 'NOT_LISTED'); assert.equal(s.evidence_status, 'EVIDENCE_RECORDED', 'the earlier listing stays as evidence');
});

// ---- products and ranges ----
test('affected products and version ranges: a range is its own identity, fixed and last_affected are exclusive, ecosystem ranges name their ecosystem', async () => {
  const db = fresh(), v = await putVulnerability(db, { namespace: 'cve', key: 'CVE-2025-7777' }, NOW), product = { namespace: 'purl', key: 'pkg:npm/left-pad' };
  const a = await addAffectedRange(db, { vuln_id: v, product, scheme: 'SEMVER', introduced: '1.0.0', fixed: '1.3.1', source_id: 'osv', evidence: SRC }, NOW);
  const b = await addAffectedRange(db, { vuln_id: v, product, scheme: 'SEMVER', introduced: '1.0.0', fixed: '1.3.1', source_id: 'osv', evidence: SRC }, NOW);
  assert.equal(a.rangeId, b.rangeId); assert.equal(count(db, 'SELECT COUNT(*) AS n FROM intel_version_ranges'), 1);
  await addAffectedRange(db, { vuln_id: v, product, scheme: 'ECOSYSTEM', ecosystem: 'npm', introduced: '0', last_affected: '0.9.9', source_id: 'osv' }, NOW);
  await assert.rejects(addAffectedRange(db, { vuln_id: v, product, scheme: 'SEMVER', fixed: '2', last_affected: '1', source_id: 'osv' }, NOW), /exclusive/);
  await assert.rejects(addAffectedRange(db, { vuln_id: v, product, scheme: 'ECOSYSTEM', introduced: '0', source_id: 'osv' }, NOW), /ecosystem/);
  assert.throws(() => raw(db, 'UPDATE intel_version_ranges SET fixed = ? WHERE entity_id = ?', '9', a.rangeId), /immutable/);
  const rec = await vulnerabilityRecord(db, v); assert.equal(rec.affected.length, 2); assert.deepEqual(rec.affected.find((x) => x.scheme === 'SEMVER'), { product: { namespace: 'purl', key: 'pkg:npm/left-pad' }, scheme: 'SEMVER', ecosystem: null, introduced: '1.0.0', fixed: '1.3.1', last_affected: null, source: 'osv', confidence: 'REPORTED' });
});

// ---- rules, IOC, packages, PoC ----
test('rule <-> vulnerability levels: related / compatible / behaviour / claimed; validated-detection ONLY with a test run (a human review or content match is not enough)', async () => {
  const db = fresh(), v = await putVulnerability(db, { namespace: 'cve', key: 'CVE-2025-8888' }, NOW), r = await putEntity(db, { type: 'rule', namespace: 'sigma', key: 'a1b2c3d4-0000-4000-8000-000000000001' }, NOW);
  const { id } = await relate(db, { type: 'RULE_DETECTS_CVE', from: r, to: v, source_id: 'sigmahq', method: 'asserted_by_source', evidence: [{ kind: 'human_review', ref: 'review-1' }, { kind: 'content_match', ref: 'rule mentions CVE' }] }, NOW);
  await assert.rejects(assess(db, id, { confidence: 'CONFIRMED', verification: 'VERIFIED', reason: 'reviewed only', actor: 'analyst' }, NOW), /only by a test run/);
  assert.equal(detectionLevel('RULE_DETECTS_CVE', 'REPORTED', 'UNVERIFIED'), 'claimed-detection');
  await addEvidence(db, id, { kind: 'test_run', ref: 'lab-run-42', sha256: 'b'.repeat(64) }, NOW); await assess(db, id, { confidence: 'CONFIRMED', verification: 'VERIFIED', reason: 'detected the replayed exploit in the lab', actor: 'qa' }, NOW);
  await relate(db, { type: 'RULE_ASSOCIATED_WITH_CVE', from: r, to: v, source_id: 'sigmahq', method: 'asserted_by_source' }, NOW);
  const rec = await vulnerabilityRecord(db, v, { maxExposure: 'internal' });
  assert.deepEqual(rec.detections.map((d) => d.level).sort(), ['related', 'validated-detection']);
  assert.equal(detectionLevel('RULE_APPLIES_TO_PRODUCT', 'UNKNOWN', 'UNVERIFIED'), 'compatible'); assert.equal(detectionLevel('RULE_DETECTS_CVE_BEHAVIOUR', 'CONFIRMED', 'VERIFIED'), 'detects-behaviour');
  assert.deepEqual((await vulnerabilityRecord(db, v)).detections, [], 'internal edges are not in the public view');
});
test('packages: recorded immutable, never empty, with licences; a defensive package can NEVER contain a PoC reference (no type exists, none can be added)', async () => {
  const db = fresh(); const rule = await putEntity(db, { type: 'rule', namespace: 'yara', key: 'MacGuard_Test_Rule' }, NOW);
  const poc = await putEntity(db, { type: 'poc_reference', namespace: 'url', key: 'https://example.org/poc' }, NOW);
  const p = { family: 'yara', tier: 'community', name: 'yara-community', version: '20261101', engine: 'yara', engine_min_version: '4.5.0', format: 'yara-text', items_count: 3, size_bytes: 1024, manifest_sha256: 'c'.repeat(64), artifact_sha256: 'd'.repeat(64), licences: ['DRL-1.1'], validation_state: 'ENGINE_COMPILED' };
  const id = await putPackage(db, p, NOW); assert.equal(id, 'package:yara:yara-community@20261101');
  await relate(db, { type: 'PACKAGE_CONTAINS_RULE', from: id, to: rule, source_id: 'publish', method: 'derived_from_content', exposure: 'public' }, NOW);
  await assert.rejects(relate(db, { type: 'PACKAGE_CONTAINS_RULE', from: id, to: poc, source_id: 'publish', method: 'manual' }, NOW), /does not allow these endpoint types/);
  assert.throws(() => raw(db, "INSERT INTO intel_relationship_types (type, from_type, to_type) VALUES ('PACKAGE_CONTAINS_POC','package','poc_reference')"), /never contain a PoC/);
  assert.equal(count(db, "SELECT COUNT(*) AS n FROM intel_relationship_types WHERE from_type = 'package' AND to_type = 'poc_reference'"), 0);
  await assert.rejects(putPackage(db, { ...p, version: 'empty', items_count: 0 }, NOW), /empty package/);
  await assert.rejects(putPackage(db, { ...p, version: 'nolic', licences: [] }, NOW), /licences/);
  assert.throws(() => raw(db, "UPDATE intel_packages SET tier = 'premium' WHERE entity_id = ?", id), /immutable/); assert.throws(() => raw(db, 'DELETE FROM intel_packages'), /never deleted/);
  assert.throws(() => raw(db, "INSERT INTO intel_packages (entity_id,family,tier,name,version,engine,format,items_count,size_bytes,manifest_sha256,artifact_sha256,licences,validation_state,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", id, 'poc', 'community', 'x', '1', 'e', 'f', 1, 1, 'c'.repeat(64), 'd'.repeat(64), '["x"]', 'ENGINE_TESTED', NOW), /CHECK/, 'there is no PoC family');
});

// ---- export contract ----
test('the export record validates against macguard.intel-vulnerability/1 (missing data stays null/empty) and the package example against macguard.package-manifest/1', async () => {
  const db = fresh(), v = await putVulnerability(db, { namespace: 'cve', key: 'CVE-2025-9999', display: 'Synthetic', attrs: { summary: 'Synthetic record', published: '2026-10-01T00:00:00Z' } }, NOW);
  const empty = await vulnerabilityRecord(db, v); assert.deepEqual(validate(VSCHEMA, empty, 'record'), []); assert.equal(empty.epss, null); assert.deepEqual(empty.severity, []); assert.equal(empty.exploitation.kev.status, 'UNKNOWN');
  await addSeverity(db, v, { source_id: 'nvd', cvss_version: '3.1', vector: V31, base_score: 9.8, assessed_at: NOW }, NOW); await addEpss(db, v, { score_date: '2026-10-31', probability: 0.5, percentile: 0.99 }, NOW);
  const w = await putWeakness(db, { key: 'CWE-787' }, NOW); await relate(db, { type: 'VULN_HAS_WEAKNESS', from: v, to: w, source_id: 'nvd', method: 'asserted_by_source', exposure: 'public' }, NOW);
  const poc = await putEntity(db, { type: 'poc_reference', namespace: 'url', key: 'https://example.org/writeup' }, NOW); await relate(db, { type: 'CVE_HAS_POC_REFERENCE', from: v, to: poc, source_id: 'x', method: 'asserted_by_source', exposure: 'public' }, NOW);
  const full = await vulnerabilityRecord(db, v); assert.deepEqual(validate(VSCHEMA, full, 'record'), []); assert.equal(full.weaknesses[0].cwe, 'CWE-787'); assert.equal(full.poc_references[0].executable_content, false); assert.equal(full.poc_references[0].review, 'NOT_REVIEWED');
  assert.ok(validate(VSCHEMA, { ...full, exploitation: { ...full.exploitation, evidence_status: 'NOT_EXPLOITED' } }, 'r').length > 0, 'the contract has no "not exploited" value');
  const ex = JSON.parse(readFileSync(new URL('../../../contracts/v1/examples/package-manifest-sigma.json', import.meta.url), 'utf8')); assert.deepEqual(validate(PSCHEMA, ex, 'pkg'), []);
  for (const bad of [{ ...ex, package: { ...ex.package, family: 'poc' } }, { ...ex, files: [] }, { ...ex, files: [{ ...ex.files[0], path: '../etc/passwd' }] }, { ...ex, validation: { ...ex.validation, state: 'VALIDATED' } }]) assert.ok(validate(PSCHEMA, bad, 'pkg').length > 0, JSON.stringify(bad).slice(0, 80));
});

// ---- bounded reads ----
test('reads are keyed: the vulnerability-page queries use indexes, never a table scan', () => {
  const db = fresh(); const plan = (sql, ...a) => db.raw.prepare('EXPLAIN QUERY PLAN ' + sql).all(...a).map((r) => r.detail).join(' | ');
  for (const [sql, args] of [['SELECT * FROM intel_severity_current WHERE vuln_id = ?', ['x']], ['SELECT * FROM intel_epss_latest WHERE vuln_id = ? LIMIT 1', ['x']], ['SELECT * FROM intel_exploitation_evidence WHERE vuln_id = ? ORDER BY id DESC LIMIT 200', ['x']],
    ['SELECT id FROM intel_source_snapshots WHERE source_id = ? AND complete = 1 ORDER BY snapshot_at DESC LIMIT 1', ['x']], ['SELECT * FROM intel_version_ranges WHERE entity_id = ?', ['x']], ['SELECT * FROM intel_packages WHERE family = ? AND name = ? ORDER BY created_at DESC LIMIT 20', ['yara', 'x']]]) {
    const p = plan(sql, ...args); assert.doesNotMatch(p, /SCAN (intel_severity_assessments|intel_epss_latest|intel_exploitation_evidence|intel_source_snapshots|intel_version_ranges|intel_packages)\b(?! USING)/, `${sql}: ${p}`);
  }
});

// ---- sizing (the numbers in the 0005 header) ----
test('sizing: bytes per vulnerability with realistic field lengths stay within the 0005 estimate', async () => {
  const db = fresh(), pages = () => db.raw.prepare('PRAGMA page_count').get().page_count * db.raw.prepare('PRAGMA page_size').get().page_size, N = 1500, base = pages();
  for (let i = 0; i < N; i++) {
    const id = `vulnerability:cve:CVE-2025-${String(10000 + i)}`;
    raw(db, 'INSERT INTO intel_entities (id,type,namespace,key,display,attrs,source_id,first_seen,updated_at) VALUES (?,?,?,?,?,?,?,?,?)', id, 'vulnerability', 'cve', `CVE-2025-${10000 + i}`, 'x'.repeat(90), JSON.stringify({ summary: 'y'.repeat(350), published: NOW, modified: NOW }), 'nvd', NOW, NOW);
    raw(db, 'INSERT INTO intel_severity_assessments (vuln_id,source_id,cvss_version,availability,vector,base_score,severity,assessed_at,recorded_at) VALUES (?,?,?,?,?,?,?,?,?)', id, 'nvd', '3.1', 'AVAILABLE', V31, 9.8, 'CRITICAL', NOW, NOW);
    raw(db, 'INSERT INTO intel_epss_latest (vuln_id,source_id,score_date,probability,percentile,model_version,recorded_at) VALUES (?,?,?,?,?,?,?)', id, 'first-epss', '2026-10-31', 0.01, 0.5, 'v2025.03.14', NOW);
  }
  const perVuln = (pages() - base) / N;
  assert.ok(perVuln < 1600, `~${Math.round(perVuln)} B per vulnerability (entity + one CVSS + latest EPSS); 300k -> ~${Math.round(perVuln * 300000 / 1e6)} MB`);
});

// ---- Codex review r1-canonical-20261101 round 1: four HIGH findings ----
test('F1: a public export never shows a restricted or internal alias (nor its source); internal/restricted views do', async () => {
  const db = fresh(), cve = await putVulnerability(db, { namespace: 'cve', key: 'CVE-2025-0001' }, NOW), eu = await putVulnerability(db, { namespace: 'euvd', key: 'EUVD-2025-1' }, NOW);
  const { id } = await relate(db, { type: 'ALIAS_OF', from: eu, to: cve, source_id: 'secret-source', method: 'asserted_by_source', exposure: 'restricted', evidence: [SRC] }, NOW);
  await assess(db, id, { confidence: 'REPORTED', reason: 'restricted feed', actor: 'ingest' }, NOW);
  const pub = await vulnerabilityRecord(db, cve); assert.ok(!JSON.stringify(pub).includes('secret-source') && !JSON.stringify(pub).includes('EUVD-2025-1'), 'not in the public record');
  assert.deepEqual(await aliasesOf(db, cve), { equivalent: [], disputed: [] });
  assert.equal((await aliasesOf(db, cve, { maxExposure: 'restricted' })).equivalent[0].source, 'secret-source');
  await assert.rejects(aliasesOf(db, cve, { maxExposure: 'everything' }));
});
test('F2: re-importing one side of a conflict keeps BOTH sides DISPUTED (a dispute is never cleared by an import)', async () => {
  const db = fresh(), eu = await putVulnerability(db, { namespace: 'euvd', key: 'EUVD-2025-1' }, NOW);
  const c1 = await putVulnerability(db, { namespace: 'cve', key: 'CVE-2025-0001' }, NOW), c2 = await putVulnerability(db, { namespace: 'cve', key: 'CVE-2025-0002' }, NOW);
  await recordAlias(db, { from: eu, to: c1, source_id: 'enisa-euvd', evidence: SRC, observed_at: NOW }, NOW);
  assert.equal((await recordAlias(db, { from: eu, to: c2, source_id: 'enisa-euvd', evidence: SRC, observed_at: NOW }, NOW)).disputed, true);
  const again = await recordAlias(db, { from: eu, to: c1, source_id: 'enisa-euvd', evidence: SRC, observed_at: NOW }, NOW);
  assert.equal(again.disputed, true); const a = await aliasesOf(db, eu); assert.equal(a.equivalent.length, 0); assert.equal(a.disputed.length, 2);
  const third = await putVulnerability(db, { namespace: 'cve', key: 'CVE-2025-0003' }, NOW);   // a NEW conflicting mapping joins the dispute too
  assert.equal((await recordAlias(db, { from: eu, to: third, source_id: 'other', evidence: SRC, observed_at: NOW }, NOW)).disputed, true); assert.equal((await aliasesOf(db, eu)).disputed.length, 3);
});
test('F3: the state table cannot be reset to UNKNOWN to hide an existing assessment (raw SQL); a relationship without assessments still starts UNKNOWN; rollback restores 0004', async () => {
  const db = fresh(), rule = await putEntity(db, { type: 'rule', namespace: 'suricata', key: '2000105' }, NOW), cve = await putVulnerability(db, { namespace: 'cve', key: 'CVE-2024-1234' }, NOW);
  const { id } = await relate(db, { type: 'RULE_ASSOCIATED_WITH_CVE', from: rule, to: cve, source_id: 'et', method: 'asserted_by_source', evidence: [SRC] }, NOW);
  await assess(db, id, { confidence: 'REPORTED', reason: 'feed metadata', actor: 'ingest' }, NOW);
  assert.throws(() => raw(db, "UPDATE intel_relationship_state SET confidence='UNKNOWN', verification='UNVERIFIED', assessment_id=NULL WHERE relationship_id=?", id), /latest assessment/);
  assert.equal(db.raw.prepare('SELECT confidence FROM intel_relationship_state WHERE relationship_id = ?').get(id).confidence, 'REPORTED');
  const g4 = readFileSync(new URL('../migrations-intel/0004_canonical_graph.sql', import.meta.url), 'utf8').split('\n').find((l) => l.includes('intel_rel_state_guard_update'));
  db.raw.exec(R5); assert.equal(db.raw.prepare("SELECT sql FROM sqlite_master WHERE name = 'intel_rel_state_guard_update'").get().sql + ';', g4.replace('CREATE TRIGGER IF NOT EXISTS', 'CREATE TRIGGER'), 'rollback restores the 0004 trigger verbatim');
});
test('F4: KEV status follows OBSERVATION time: a late import of an older LISTED never overrides a newer DELISTED', async () => {
  const db = fresh(), v = await putVulnerability(db, { namespace: 'cve', key: 'CVE-2024-9999' }, NOW);
  await recordSnapshot(db, { source_id: 'cisa-kev', snapshot_at: '2026-11-01T00:00:00Z', item_count: 1800, sha256: 'a'.repeat(64) }, NOW);
  await addExploitation(db, v, { source_id: 'cisa-kev', kind: 'KEV_DELISTED', evidence_ref: 'kev/2026-10-31', observed_at: '2026-10-31T00:00:00Z' }, NOW);
  await addExploitation(db, v, { source_id: 'cisa-kev', kind: 'KEV_LISTED', listed_at: '2026-01-01', evidence_ref: 'kev/2026-01-01', observed_at: '2026-01-01T00:00:00Z' }, NOW);
  const s = await exploitationStatus(db, v); assert.equal(s.kev.status, 'NOT_LISTED', JSON.stringify(s.kev)); assert.match(s.kev.note, /not evidence that it is not exploited/);
});
