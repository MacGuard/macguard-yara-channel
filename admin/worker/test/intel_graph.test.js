// Canonical intelligence graph (INTEL migration 0004 + src/intel_graph.js). Synthetic data only. The invariants are tested at the DATABASE level (raw SQL that
// bypasses the module) and through the module; a seeded generator exercises normalisation and random operation sequences (property-style, reproducible).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { newDb } from './d1shim.js';
import { normalizeKey, entityId, putEntity, relate, assess, addEvidence, neighbours, relationshipDetail, getEntity, MAX_PAGE } from '../src/intel_graph.js';

const M = ['../migrations-intel/0001_intel.sql', '../migrations-intel/0002_decisions.sql', '../migrations-intel/0003_effective_state.sql', '../migrations-intel/0004_canonical_graph.sql'];
const NOW = '2026-10-31T12:00:00Z';
const fresh = () => newDb(M);
const raw = (db, sql, ...a) => db.raw.prepare(sql).run(...a);
function rng(seed) { let s = seed >>> 0; return () => { s = (s + 0x6d2b79f5) >>> 0; let t = s; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }

async function base(db) {
  const rule = await putEntity(db, { type: 'rule', namespace: 'suricata', key: '2000105', display: 'ET TEST trojan' }, NOW);
  const cve = await putEntity(db, { type: 'vulnerability', namespace: 'cve', key: 'cve-2024-1234' }, NOW);
  const ip = await putEntity(db, { type: 'indicator', namespace: 'ipv4', key: '203.0.113.7' }, NOW);
  const hash = await putEntity(db, { type: 'indicator', namespace: 'sha256', key: 'AB'.repeat(32) }, NOW);
  const sample = await putEntity(db, { type: 'sample', namespace: 'sha256', key: 'ab'.repeat(32) }, NOW);
  const poc = await putEntity(db, { type: 'poc_reference', namespace: 'url', key: 'https://example.org/poc#frag' }, NOW);
  return { rule, cve, ip, hash, sample, poc };
}

test('normalisation: canonical forms per namespace', () => {
  const cases = [['indicator', 'sha256', 'AB'.repeat(32), 'ab'.repeat(32)], ['indicator', 'x509-sha256', 'AA:'.repeat(31) + 'AA', 'aa'.repeat(32)], ['indicator', 'ipv4', '203.0.113.7', '203.0.113.7'],
    ['indicator', 'ipv6', '2001:0DB8:0000:0000:0000:0000:0000:0001', '2001:db8::1'], ['indicator', 'ipv6', '2001:db8:0:1:0:0:0:1', '2001:db8:0:1::1'], ['indicator', 'ipv6', '::ffff:192.0.2.1', '::ffff:c000:201'],
    ['indicator', 'ipv6', '2001:db8:1:1:1:1:0:1', '2001:db8:1:1:1:1:0:1'], ['indicator', 'domain', 'Evil.Example.COM.', 'evil.example.com'], ['indicator', 'url', 'https://User@x.example/a', null],
    ['indicator', 'url', 'HTTPS://X.Example:443/a?b=1#f', 'https://x.example/a?b=1'], ['vulnerability', 'cve', 'cve-2024-1234', 'CVE-2024-1234'], ['vulnerability', 'ghsa', 'ghsa-jfh8-c2jp-5v3q', 'GHSA-jfh8-c2jp-5v3q'],
    ['technique', 'mitre-attack', 't1059.001', 'T1059.001'], ['rule', 'suricata', '2000105', '1:2000105'], ['rule', 'snort', '3:1000', '3:1000'], ['rule', 'sigma', 'A1B2C3D4-0000-4000-8000-000000000001', 'a1b2c3d4-0000-4000-8000-000000000001'],
    ['product', 'cpe', 'cpe:2.3:a:Vendor:Prod:1.0:*:*:*:*:*:*:*', 'cpe:2.3:a:vendor:prod:1.0:*:*:*:*:*:*:*'], ['product', 'purl', 'pkg:NPM/left-pad@1.3.0', 'pkg:npm/left-pad@1.3.0']];
  for (const [t, n, k, want] of cases) { if (want === null) assert.throws(() => normalizeKey(t, n, k), /credentials/); else assert.equal(normalizeKey(t, n, k), want, `${n} ${k}`); }
  for (const [n, k] of [['ipv4', '010.1.1.1'], ['ipv4', '256.1.1.1'], ['ipv6', '1::2::3'], ['ipv6', 'fe80::1%eth0'], ['domain', 'localhost'], ['domain', 'bücher.example'], ['domain', 'a.123'], ['url', 'ftp://x.example/'],
    ['cve', 'CVE-24-1'], ['sha256', 'zz'.repeat(32)], ['sigma', 'not-a-uuid'], ['cpe', 'cpe:/a:x'], ['mitre-attack', 'T12']]) assert.throws(() => normalizeKey('indicator', n, k), undefined, `${n} ${k}`);
  assert.throws(() => normalizeKey('rule', 'yara', 'a\u0000b')); assert.throws(() => normalizeKey('rule', 'yara', ' '.repeat(3)));
});

test('property: normalisation is idempotent and IPv6 output re-parses to the same 128-bit value (2000 seeded cases)', () => {
  const r = rng(20261031), h4 = () => Math.floor(r() * 65536).toString(16), val = (s) => { const full = normalizeKey('indicator', 'ipv6', s); return full; };
  for (let i = 0; i < 2000; i++) {
    const g = Array.from({ length: 8 }, () => (r() < 0.4 ? '0' : h4())); const s = g.join(':').toUpperCase();
    const n = val(s); assert.equal(val(n), n, s); assert.ok(!/:::/.test(n) && (n.match(/::/g) || []).length <= 1, n);
    const back = (x) => { const [a, b = ''] = x.split('::'); const A = a ? a.split(':') : [], B = b ? b.split(':') : []; return [...A, ...Array(x.includes('::') ? 8 - A.length - B.length : 0).fill('0'), ...B].map((y) => parseInt(y, 16)); };
    assert.deepEqual(back(n), g.map((y) => parseInt(y, 16)), s);
    const d = Array.from({ length: 2 + Math.floor(r() * 3) }, () => Array.from({ length: 1 + Math.floor(r() * 10) }, () => 'abcxyz019'[Math.floor(r() * 9)]).join('')).join('.') + '.Ex';
    const nd = normalizeKey('indicator', 'domain', d.toUpperCase()); assert.equal(normalizeKey('indicator', 'domain', nd), nd);
  }
});

test('entities: identity is stable and immutable; refresh updates only display/attrs', async () => {
  const db = fresh(); const { cve } = await base(db);
  assert.equal(cve, 'vulnerability:cve:CVE-2024-1234'); assert.equal(entityId('vulnerability', 'cve', 'CVE-2024-1234'), cve);
  await putEntity(db, { type: 'vulnerability', namespace: 'cve', key: 'CVE-2024-1234', display: 'new title', attrs: { cvss: 9.8 } }, '2026-11-01T00:00:00Z');
  const e = await getEntity(db, cve); assert.equal(e.display, 'new title'); assert.equal(e.first_seen, NOW); assert.deepEqual(e.attrs, { cvss: 9.8 });
  assert.throws(() => raw(db, 'UPDATE intel_entities SET key = ? WHERE id = ?', 'CVE-2024-9999', cve), /immutable/);
  assert.throws(() => raw(db, "INSERT INTO intel_entities (id,type,namespace,key,first_seen,updated_at) VALUES ('rule:x:y','rule','x','z',?,?)", NOW, NOW), /CHECK/);
  assert.throws(() => raw(db, "INSERT INTO intel_entities (id,type,namespace,key,first_seen,updated_at) VALUES ('bogus:x:y','bogus','x','y',?,?)", NOW, NOW), /FOREIGN|constraint/i, 'unknown type refused (foreign key) - see note');
});

test('relationships: only allowed endpoint types; immutable; never deleted; deterministic id (idempotent import)', async () => {
  const db = fresh(); const { rule, cve, ip, hash, sample } = await base(db);
  const a = await relate(db, { type: 'RULE_ASSOCIATED_WITH_CVE', from: rule, to: cve, source_id: 'emerging-threats-open', method: 'asserted_by_source', evidence: [{ kind: 'source_statement', ref: 'metadata cve 2024-1234' }] }, NOW);
  const again = await relate(db, { type: 'RULE_ASSOCIATED_WITH_CVE', from: rule, to: cve, source_id: 'emerging-threats-open', method: 'asserted_by_source' }, NOW);
  assert.equal(a.created, true); assert.equal(again.created, false); assert.equal(a.id, again.id);
  await assert.rejects(relate(db, { type: 'RULE_DETECTS_INDICATOR', from: cve, to: ip, source_id: 's', method: 'manual' }, NOW), /endpoint types/);
  await assert.rejects(relate(db, { type: 'HASH_IDENTIFIES_SAMPLE', from: ip, to: sample, source_id: 's', method: 'manual' }, NOW), /endpoint types|file-hash/);
  await assert.rejects(relate(db, { type: 'RULE_DETECTS_INDICATOR', from: rule, to: 'indicator:ipv4:198.51.100.1', source_id: 's', method: 'manual' }, NOW), /endpoint/);
  const h = await relate(db, { type: 'HASH_IDENTIFIES_SAMPLE', from: hash, to: sample, source_id: 'malwarebazaar', method: 'derived_from_content' }, NOW); assert.ok(h.created);
  assert.throws(() => raw(db, "UPDATE intel_relationships SET exposure = 'public' WHERE id = ?", a.id), /immutable/);
  assert.throws(() => raw(db, 'DELETE FROM intel_relationships WHERE id = ?', a.id), /never deleted/);
  assert.throws(() => raw(db, 'DELETE FROM intel_entities WHERE id = ?', rule), /cannot be deleted/);
});

test('confidence: a new relationship is UNKNOWN; REPORTED needs a source statement; CONFIRMED needs strong evidence; a correlation needs a test or a human', async () => {
  const db = fresh(); const { rule, cve, ip } = await base(db);
  const r = await relate(db, { type: 'RULE_ASSOCIATED_WITH_CVE', from: rule, to: cve, source_id: 'et', method: 'asserted_by_source' }, NOW);
  assert.equal((await relationshipDetail(db, r.id)).confidence, 'UNKNOWN');
  await assert.rejects(assess(db, r.id, { confidence: 'REPORTED', reason: 'the source says so', actor: 'pipeline' }, NOW), /REPORTED needs/);
  await addEvidence(db, r.id, { kind: 'source_statement', ref: 'rule metadata: reference cve,2024-1234' }, NOW);
  await assess(db, r.id, { confidence: 'REPORTED', reason: 'the source says so', actor: 'pipeline' }, NOW);
  await assert.rejects(assess(db, r.id, { confidence: 'CONFIRMED', verification: 'VERIFIED', reason: 'looks right to me', actor: 'x' }, NOW), /CONFIRMED needs/);
  await assert.rejects(assess(db, r.id, { confidence: 'REPORTED', verification: 'VERIFIED', reason: 'mismatch test', actor: 'x' }, NOW), /CHECK/);
  const c = await relate(db, { type: 'RULE_DETECTS_INDICATOR', from: rule, to: ip, source_id: 'correlator', method: 'correlated', evidence: [{ kind: 'content_match', ref: 'string match in rule body', sha256: 'cd'.repeat(32) }] }, NOW);
  await assess(db, c.id, { confidence: 'INFERRED', reason: 'automatic correlation', actor: 'correlator' }, NOW);
  await assert.rejects(assess(db, c.id, { confidence: 'CONFIRMED', reason: 'content match only', actor: 'x' }, NOW), /correlation is confirmed only/);
  await addEvidence(db, c.id, { kind: 'test_run', ref: 'pcap replay run 42: alert sid 2000105 on 203.0.113.7' }, NOW);
  await assess(db, c.id, { confidence: 'CONFIRMED', verification: 'VERIFIED', reason: 'positive test on an authorised PCAP', actor: 'qa' }, NOW);
  const d = await relationshipDetail(db, c.id); assert.deepEqual([d.confidence, d.verification, d.evidence_count, d.strong_evidence, d.assessments.length], ['CONFIRMED', 'VERIFIED', 2, true, 2]);
  await assess(db, c.id, { confidence: 'DISPUTED', reason: 'false positive reported by a reviewer', actor: 'reviewer' }, NOW);
  assert.equal((await relationshipDetail(db, c.id)).confidence, 'DISPUTED', 'revocation is a new assessment; history kept'); assert.equal((await relationshipDetail(db, c.id)).assessments.length, 3);
});

test('a PoC reference is never confirmed automatically: only a human review of the document', async () => {
  const db = fresh(); const { cve, poc } = await base(db);
  const r = await relate(db, { type: 'CVE_HAS_POC_REFERENCE', from: cve, to: poc, source_id: 'nvd', method: 'asserted_by_source', evidence: [{ kind: 'source_statement', ref: 'NVD reference tagged Exploit' }, { kind: 'signature', ref: 'sigstore bundle of the page snapshot' }] }, NOW);
  await assert.rejects(assess(db, r.id, { confidence: 'CONFIRMED', reason: 'tagged as exploit by NVD', actor: 'pipeline' }, NOW), /PoC reference is confirmed only by a human review/);
  await addEvidence(db, r.id, { kind: 'human_review', ref: 'reviewer read the advisory; no code executed' }, NOW);
  await assess(db, r.id, { confidence: 'CONFIRMED', reason: 'documentary link reviewed', actor: 'reviewer' }, NOW);
  assert.equal((await getEntity(db, poc)).key, 'https://example.org/poc', 'fragment dropped from the canonical URL');
});

test('the state table cannot be forged and the logs are append-only (raw SQL bypassing the module)', async () => {
  const db = fresh(); const { rule, cve } = await base(db);
  const r = await relate(db, { type: 'RULE_ASSOCIATED_WITH_CVE', from: rule, to: cve, source_id: 'et', method: 'asserted_by_source', evidence: [{ kind: 'source_statement', ref: 'x' }] }, NOW);
  assert.throws(() => raw(db, "UPDATE intel_relationship_state SET confidence = 'CONFIRMED', verification = 'VERIFIED' WHERE relationship_id = ?", r.id), /latest assessment/);
  assert.throws(() => raw(db, 'UPDATE intel_relationship_state SET evidence_count = 99 WHERE relationship_id = ?', r.id), /evidence count/);
  assert.throws(() => raw(db, 'DELETE FROM intel_relationship_state WHERE relationship_id = ?', r.id), /not deleted/);
  assert.throws(() => raw(db, "INSERT INTO intel_relationship_state VALUES ('x','CONFIRMED','VERIFIED',NULL,0)"), /starts UNKNOWN/);
  await assess(db, r.id, { confidence: 'REPORTED', reason: 'source says', actor: 'p' }, NOW);
  assert.throws(() => raw(db, "UPDATE intel_relationship_assessments SET confidence = 'CONFIRMED'"), /append-only/);
  assert.throws(() => raw(db, 'DELETE FROM intel_relationship_assessments'), /append-only/);
  assert.throws(() => raw(db, "UPDATE intel_relationship_evidence SET kind = 'test_run'"), /append-only/);
  assert.throws(() => raw(db, 'DELETE FROM intel_relationship_evidence'), /append-only/);
  assert.throws(() => raw(db, "INSERT INTO intel_relationship_evidence (relationship_id,kind,ref,sha256,observed_at,recorded_at) VALUES (?,?,?,?,?,?)", r.id, 'document', 'x', 'XYZ', NOW, NOW), /CHECK/);
});

test('property: random operation sequences never yield CONFIRMED without strong evidence, and the state always equals the latest assessment (300 seeded runs)', async () => {
  const kinds = ['source_statement', 'content_match', 'test_run', 'human_review', 'signature', 'document'], confs = ['CONFIRMED', 'REPORTED', 'INFERRED', 'DISPUTED', 'UNKNOWN'], methods = ['asserted_by_source', 'correlated', 'manual', 'test'];
  const r = rng(31102026), pick = (a) => a[Math.floor(r() * a.length)];
  for (let run = 0; run < 300; run++) {
    const db = fresh(); const { rule, cve } = await base(db); const method = pick(methods);
    const rel = await relate(db, { type: 'RULE_ASSOCIATED_WITH_CVE', from: rule, to: cve, source_id: 's', method }, NOW);
    for (let step = 0; step < 8; step++) {
      if (r() < 0.4) await addEvidence(db, rel.id, { kind: pick(kinds), ref: `e${step}` }, NOW);
      else { const c = pick(confs); try { await assess(db, rel.id, { confidence: c, verification: c === 'CONFIRMED' && r() < 0.5 ? 'VERIFIED' : 'UNVERIFIED', reason: `step ${step}`, actor: 'fuzz' }, NOW); } catch { /* refused: fine */ } }
      const st = db.raw.prepare('SELECT * FROM intel_relationship_state WHERE relationship_id = ?').get(rel.id), ev = db.raw.prepare('SELECT kind FROM intel_relationship_evidence WHERE relationship_id = ?').all(rel.id).map((x) => x.kind);
      const last = db.raw.prepare('SELECT * FROM intel_relationship_assessments WHERE relationship_id = ? ORDER BY id DESC LIMIT 1').get(rel.id);
      assert.equal(st.evidence_count, ev.length);
      if (last) assert.deepEqual([st.confidence, st.verification], [last.confidence, last.verification]); else assert.equal(st.confidence, 'UNKNOWN');
      if (st.confidence === 'CONFIRMED') { assert.ok(ev.some((k) => ['test_run', 'human_review', 'signature', 'content_match'].includes(k)), `run ${run}`); if (method === 'correlated') assert.ok(ev.some((k) => ['test_run', 'human_review'].includes(k))); }
      if (st.confidence === 'REPORTED') assert.ok(ev.some((k) => ['source_statement', 'document'].includes(k)));
    }
  }
});

test('reads are bounded and filtered: page size capped, keyset pagination complete, confidence and exposure filters, indexed plans', async () => {
  const db = fresh(); const { rule } = await base(db);
  for (let i = 0; i < 260; i++) {
    const ip = await putEntity(db, { type: 'indicator', namespace: 'ipv4', key: `198.51.${i >> 8}.${i & 255}` }, NOW);
    const rel = await relate(db, { type: 'RULE_DETECTS_INDICATOR', from: rule, to: ip, source_id: 's', method: 'asserted_by_source', exposure: i % 3 === 0 ? 'restricted' : 'public', evidence: [{ kind: 'source_statement', ref: 'x' }] }, NOW);
    if (i % 2 === 0) await assess(db, rel.id, { confidence: 'REPORTED', reason: 'source says', actor: 'p' }, NOW);
  }
  const big = await neighbours(db, rule, { limit: 10000, maxExposure: 'restricted' }); assert.equal(big.edges.length, MAX_PAGE); assert.ok(big.next);
  let seen = [], next = null; do { const p = await neighbours(db, rule, { limit: 37, after: next, maxExposure: 'restricted' }); seen.push(...p.edges.map((e) => e.id)); next = p.next; } while (next);
  assert.equal(seen.length, 260); assert.equal(new Set(seen).size, 260);
  const pub = []; next = null; do { const p = await neighbours(db, rule, { limit: 100, after: next }); pub.push(...p.edges); next = p.next; } while (next);
  assert.equal(pub.length, 173); assert.ok(pub.every((e) => e.exposure === 'public'), 'default exposure is public only');
  const rep = []; next = null; do { const p = await neighbours(db, rule, { limit: 100, after: next, minConfidence: 'REPORTED', maxExposure: 'restricted' }); rep.push(...p.edges); next = p.next; } while (next);
  assert.equal(rep.length, 130); assert.ok(rep.every((e) => e.confidence === 'REPORTED'));
  const inbound = await neighbours(db, 'indicator:ipv4:198.51.0.1', { direction: 'in', maxExposure: 'restricted' }); assert.equal(inbound.edges.length, 1); assert.equal(inbound.edges[0].other_id, rule);
  const plan = db.raw.prepare("EXPLAIN QUERY PLAN SELECT r.id FROM intel_relationships r JOIN intel_relationship_state s ON s.relationship_id = r.id WHERE r.from_id = ? ORDER BY r.type, r.id LIMIT 10").all(rule).map((x) => x.detail).join(' | ');
  assert.match(plan, /intel_rel_from/, plan); assert.doesNotMatch(plan, /SCAN r\b|SCAN intel_relationships\b/, plan);
  await assert.rejects(neighbours(db, rule, { types: Array(21).fill('RULE_DETECTS_INDICATOR') }), /at most 20/);
});

test('migration 0004 is idempotent and its rollback leaves 0001-0003 intact', () => {
  const db = fresh(); const m4 = readFileSync(new URL('../migrations-intel/0004_canonical_graph.sql', import.meta.url), 'utf8'), r4 = readFileSync(new URL('../migrations-intel/0004_rollback.sql', import.meta.url), 'utf8');
  db.raw.exec(m4); db.raw.exec(r4);
  const names = db.raw.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'intel_%' ORDER BY name").all().map((x) => x.name);
  assert.deepEqual(names, ['intel_decided', 'intel_decisions', 'intel_events', 'intel_records', 'intel_runs', 'intel_snapshot', 'intel_sources']);
});
