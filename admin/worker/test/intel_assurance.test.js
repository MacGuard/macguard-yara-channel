// INTEL 0007 (correlation assurance), adversarial: for every rule of contract v3 §4.1 and every item C3 (a)-(l), the FORBIDDEN write is attempted with raw SQL
// (bypassing src/) on a scratch database built from migrations 0001-0005 + 0007, and must be refused; the ALLOWED path is shown to work. Plus: the total state
// mapping of §3, the hash-chain verifier (tamper-evidence), the QA probe replay, normaliser/trigger parity, and the 0007 up/down migration.
// Synthetic data only; node:sqlite in memory; nothing is applied to any remote database.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { newDb } from './d1shim.js';
import { putEntity, relate, assess, addEvidence, relationshipId, relationshipDetail, neighbours } from '../src/intel_graph.js';
import { isCanonical } from '../src/intel_ids.js';
import { changeReviewer, review, setLifecycle, syncSourceApprovals, planSourceApprovals, applySourceApprovals, verifyAssurance, verifySourceApprovals, reviewerBootstrapSql, REVIEWER_GUARD_SQL, LOGS } from '../src/intel_assurance.js';
import { chainHash, GENESIS } from '../src/core.js';
import { putVulnerability, recordAlias, linkGcve0, addAffectedRange } from '../src/intel_vuln.js';
import { M5, M7, REGISTRY_TEXT, assuranceDb, bootstrapReviewers, registryWith } from './intel_m7.js';

const NOW = '2026-11-02T12:00:00Z';
const MIG = readFileSync(new URL('../migrations-intel/0007_correlation_assurance.sql', import.meta.url), 'utf8'), RB = readFileSync(new URL('../migrations-intel/0007_rollback.sql', import.meta.url), 'utf8');
const raw = (db, sql, ...a) => db.raw.prepare(sql).run(...a);
const one = (db, sql, ...a) => db.raw.prepare(sql).get(...a);
const n = (db, sql, ...a) => db.raw.prepare(sql).get(...a).n;
const state = (db, id) => one(db, 'SELECT state FROM intel_relationship_lifecycle WHERE relationship_id = ?', id).state;
const isPublic = (db, id) => !!one(db, 'SELECT 1 AS x FROM intel_relationship_public WHERE id = ?', id);
const ING = { origin: 'source_ingest' }, ANALYST = { origin: 'analyst', proposer: 'user:analyst-a' }, AI = { origin: 'ai_proposed', proposer: 'ai:model' };

async function world(opts) {
  const db = await assuranceDb(opts);
  const e = {
    rule: await putEntity(db, { type: 'rule', namespace: 'yara', key: 'rules/a/b.yar#R1' }, NOW),
    rule2: await putEntity(db, { type: 'rule', namespace: 'yara', key: 'rules/a/c.yar#R2' }, NOW),
    cve: await putEntity(db, { type: 'vulnerability', namespace: 'cve', key: 'CVE-2024-0001' }, NOW),
    cve2: await putEntity(db, { type: 'vulnerability', namespace: 'cve', key: 'CVE-2024-0002' }, NOW),
    euvd: await putEntity(db, { type: 'vulnerability', namespace: 'euvd', key: 'EUVD-2025-1' }, NOW),
    cwe: await putEntity(db, { type: 'weakness', namespace: 'cwe', key: 'CWE-79' }, NOW),
    sample: await putEntity(db, { type: 'sample', namespace: 'sha256', key: 'ab'.repeat(32) }, NOW),
    md5: await putEntity(db, { type: 'indicator', namespace: 'md5', key: 'b'.repeat(32) }, NOW),
    ip: await putEntity(db, { type: 'indicator', namespace: 'ipv4', key: '203.0.113.7' }, NOW),
    poc: await putEntity(db, { type: 'poc_reference', namespace: 'url', key: 'https://example.org/poc' }, NOW),
  };
  return { db, e };
}
/** Raw relationship WITHOUT a creation record (a writer that bypasses relate()). */
async function rawRel(db, { type, from, to, source_id = 's', method = 'asserted_by_source', exposure = 'public' }) {
  const id = await relationshipId({ type, from, to, source_id, method });
  raw(db, 'INSERT INTO intel_relationships (id,type,from_id,to_id,source_id,method,exposure,observed_at,created_at) VALUES (?,?,?,?,?,?,?,?,?)', id, type, from, to, source_id, method, exposure, NOW, NOW);
  return id;
}
const rawEv = (db, rel, kind, ref, source = 's', orig = source, sha = null) => raw(db, 'INSERT INTO intel_relationship_evidence (relationship_id,kind,ref,sha256,source_id,original_source_id,observed_at,recorded_at) VALUES (?,?,?,?,?,?,?,?)', rel, kind, ref, sha, source, orig, NOW, NOW);
const rawAs = (db, rel, confidence, verification, actor, reason = 'raw SQL assessment') => raw(db, 'INSERT INTO intel_relationship_assessments (relationship_id,confidence,verification,reason,actor,at) VALUES (?,?,?,?,?,?)', rel, confidence, verification, reason, actor, NOW);
/** A correctly CHAINED raw insert into a 0007 log (what a raw-SQL writer who computes hashes can do): returns the hash. */
async function rawChained(db, table, row, rel = null) {
  const prev = one(db, `SELECT hash FROM ${table} ORDER BY id DESC LIMIT 1`)?.hash ?? GENESIS;
  const e = { log: LOGS[table].tag }; for (const c of LOGS[table].cols) e[c] = row[c] ?? null;
  if (rel) Object.assign(e, { type: rel.type, from_id: rel.from_id, to_id: rel.to_id, source_id: rel.source_id, method: rel.method });
  const hash = await chainHash(prev, e), cols = [...Object.keys(row), 'prev_hash', 'hash'];
  raw(db, `INSERT INTO ${table} (${cols.join(',')}) VALUES (${cols.map(() => '?').join(',')})`, ...Object.values(row), prev, hash);
  return hash;
}
/** Source-asserted relationship through the module, with source_statement evidence and a REPORTED assessment. */
async function asserted(db, { type, from, to, source_id = 'cisa-kev', exposure = 'public', ref = 'stmt' }) {
  const { id } = await relate(db, { type, from, to, source_id, method: 'asserted_by_source', exposure, evidence: [{ kind: 'source_statement', ref }], ...ING }, NOW);
  await assess(db, id, { confidence: 'REPORTED', reason: 'the source states it', actor: `source:${source_id}` }, NOW);
  return id;
}

// ---- (a) frozen type catalogues -------------------------------------------------------------------------------------------------------------------------
test('(a) type catalogues are frozen: no UPDATE, DELETE or new row at runtime; re-applying 0004/0005 after 0007 is harmless', async () => {
  const { db } = await world();
  assert.throws(() => raw(db, "UPDATE intel_relationship_types SET from_type = 'sample' WHERE type = 'RULE_DETECTS_CVE'"), /frozen/);
  assert.throws(() => raw(db, "DELETE FROM intel_relationship_types WHERE type = 'RULE_DETECTS_CVE'"), /frozen/);
  assert.throws(() => raw(db, "INSERT INTO intel_relationship_types VALUES ('RULE_EXPLOITS_CVE','rule','vulnerability',NULL)"), /frozen/);
  assert.throws(() => raw(db, "UPDATE intel_entity_types SET grp = 'x' WHERE type = 'rule'"), /frozen/);
  assert.throws(() => raw(db, "DELETE FROM intel_entity_types WHERE type = 'poc_reference'"), /frozen/);
  assert.throws(() => raw(db, "INSERT INTO intel_entity_types VALUES ('exploit','vulnerabilities')"), /frozen/);
  const schema = () => JSON.stringify(db.raw.prepare('SELECT type, name, sql FROM sqlite_master ORDER BY type, name').all());
  const before = schema(), rows = n(db, 'SELECT COUNT(*) n FROM intel_relationship_types');
  for (const f of M5.slice(3)) db.raw.exec(readFileSync(new URL(f, import.meta.url), 'utf8'));
  assert.equal(schema(), before); assert.equal(n(db, 'SELECT COUNT(*) n FROM intel_relationship_types'), rows);
});

// ---- (b) key grammar ------------------------------------------------------------------------------------------------------------------------------------
const insEnt = (db, type, ns, key) => raw(db, 'INSERT INTO intel_entities (id,type,namespace,key,first_seen,updated_at) VALUES (?,?,?,?,?,?)', `${type}:${ns}:${key}`, type, ns, key, NOW, NOW);
test('(b) per-namespace key grammar in the database (raw SQL): only canonical cve, cwe, hashes and yara rule keys; >512 refused, never truncated', async () => {
  const { db } = await world();
  const bad = [['vulnerability', 'cve', ['cve-2024-1234', 'CVE-2024-01234', 'CVE-2024-12345678', 'CVE_2021_44228', 'CVE-24-1234', 'CVE-2024-123', 'CVE-２０２１-44228', 'CVE-2024-1234 ']],
    ['weakness', 'cwe', ['CWE-0', 'CWE-079', 'CWE-100000', 'cwe-79', 'CWE-', 'CWE-7a']],
    ['sample', 'sha256', ['AB'.repeat(32), 'a'.repeat(63), 'g'.repeat(64), 'aa']], ['indicator', 'sha1', ['a'.repeat(39), 'A'.repeat(40)]], ['indicator', 'md5', ['a'.repeat(33), 'Z'.repeat(32)]],
    ['rule', 'yara', ['BAD key with ../ and :colon', 'rules/a/../b.yar#R', 'rules/a.yar#rule', 'rules/a.txt#R', '/rules/a.yar#R', 'rules//a.yar#R', 'rules/a.yar#1R', 'rules/a.yar#R#S', '.yar#R', 'rules/ä.yar#R', `rules/${'p'.repeat(396)}.yar#R`]]];
  for (const [t, ns, keys] of bad) for (const k of keys) assert.throws(() => insEnt(db, t, ns, k), /key must|CHECK/, `${ns} ${k}`);
  const good = [['vulnerability', 'cve', 'CVE-2024-12345'], ['vulnerability', 'cve', 'CVE-2024-1234567'], ['weakness', 'cwe', 'CWE-99999'], ['sample', 'sha256', 'c'.repeat(64)], ['indicator', 'sha1', 'd'.repeat(40)],
    ['indicator', 'md5', 'e'.repeat(32)], ['rule', 'yara', 'rules/x y+(z)[1]@2.YARA#_r9'], ['rule', 'yara', 'b.yar#R']];
  for (const [t, ns, k] of good) insEnt(db, t, ns, k);
  const long = `rules/${'p'.repeat(380)}.yar#${'N'.repeat(128)}`; assert.ok(long.length > 512);
  assert.throws(() => insEnt(db, 'rule', 'yara', long), /CHECK/, 'over 512: refused');
  assert.equal(n(db, "SELECT COUNT(*) n FROM intel_entities WHERE length(key) > 512"), 0, 'nothing truncated');
  insEnt(db, 'package', 'yara', 'yara-community@20261101');   // a package of family yara is not a rule identity
});
test('(b) parity: the database key triggers accept EXACTLY the identifiers intel_ids calls canonical (3000 seeded keys per kind)', async () => {
  const db = newDb(M7);
  let s = 20261104 >>> 0; const r = () => { s = (s + 0x6d2b79f5) >>> 0; let t = s; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  const pick = (a) => a[Math.floor(r() * a.length)], str = (alpha, lo, hi) => Array.from({ length: lo + Math.floor(r() * (hi - lo + 1)) }, () => pick(alpha)).join('');
  const hexish = (len) => { let h = str('0123456789abcdef', len, len); const m = r(); if (m < 0.2) h = h.slice(1); else if (m < 0.35) h += 'a'; else if (m < 0.5) { const i = Math.floor(r() * len); h = h.slice(0, i) + pick(['A', 'F', 'g', ' ', ':']) + h.slice(i + 1); } return h; };
  const gen = {
    cve: () => `${pick(['CVE', 'cve', 'CVE'])}${pick(['-', '-', '_'])}${str('0123456789', 3, 5)}-${str('00123456789', 2, 9)}`,
    cwe: () => `${pick(['CWE', 'cwe'])}-${str('0123456789', 0, 7)}`,
    sha256: () => hexish(64), sha1: () => hexish(40), md5: () => hexish(32),
    yara_rule: () => `${pick(['', 'rules/', '/', 'r/../', 'a//', './'])}${str('abAB09._-/ +@()[]#:ä', 0, 12)}${pick(['.yar', '.yara', '.YAR', '.txt', ''])}#${pick(['', '_', '1', 'R', 'rule', 'all'])}${str('abZ_09#', 0, 6)}`,
  };
  const NS = { cve: ['vulnerability', 'cve'], cwe: ['weakness', 'cwe'], sha256: ['sample', 'sha256'], sha1: ['indicator', 'sha1'], md5: ['indicator', 'md5'], yara_rule: ['rule', 'yara'] };
  const tally = {};
  for (const kind of Object.keys(gen)) {
    tally[kind] = [0, 0];
    for (let i = 0; i < 3000; i++) {
      const key = gen[kind](), [t, ns] = NS[kind];
      const canon = kind === 'yara_rule' ? isCanonical('yara_rule', `yara:${key}`) && key.length <= 512 : isCanonical(kind, key);
      let ok = true; try { db.raw.exec('SAVEPOINT p'); insEnt(db, t, ns, key); } catch { ok = false; } finally { db.raw.exec('ROLLBACK TO p'); db.raw.exec('RELEASE p'); }
      assert.equal(ok, canon, `${kind} ${JSON.stringify(key)}: trigger ${ok}, intel_ids ${canon}`);
      tally[kind][canon ? 0 : 1]++;
    }
    assert.ok(tally[kind][0] > 20 && tally[kind][1] > 20, `${kind}: both outcomes exercised ${tally[kind]}`);
  }
});

// ---- (c) creation record --------------------------------------------------------------------------------------------------------------------------------
test('(c) creation record: written by relate() in the same batch; without it nothing goes beyond candidate; late, forged, mismatched or edited records refused', async () => {
  const { db, e } = await world();
  const bare = await rawRel(db, { type: 'VULN_HAS_WEAKNESS', from: e.cve, to: e.cwe, source_id: 'cisa-kev' });
  rawEv(db, bare, 'source_statement', 'kev says', 'cisa-kev');
  for (const [c, v] of [['REPORTED', 'UNVERIFIED'], ['CONFIRMED', 'UNVERIFIED'], ['DISPUTED', 'UNVERIFIED'], ['UNKNOWN', 'FAILED']]) assert.throws(() => rawAs(db, bare, c, v, 'source:cisa-kev'), /creation record/, `${c}/${v}`);
  rawAs(db, bare, 'INFERRED', 'UNVERIFIED', 'x'); assert.equal(state(db, bare), 'candidate'); assert.ok(!isPublic(db, bare), 'approved source, statement evidence, public exposure: still not public without a creation record');
  const rel = one(db, 'SELECT * FROM intel_relationships WHERE id = ?', bare);
  await assert.rejects(rawChained(db, 'intel_relationship_creation', { relationship_id: bare, exposure: 'public', proposer: 'source:cisa-kev', origin: 'source_ingest', rule_id: null, created_at: NOW }, rel), /same batch/, 'no creation record after evidence/assessments');
  const late = await rawRel(db, { type: 'VULN_HAS_WEAKNESS', from: e.cve2, to: e.cwe, source_id: 'cisa-kev' });
  const r2 = one(db, 'SELECT * FROM intel_relationships WHERE id = ?', late);
  await assert.rejects(rawChained(db, 'intel_relationship_creation', { relationship_id: late, exposure: 'public', proposer: 'source:cisa-kev', origin: 'source_ingest', rule_id: null, created_at: '2026-11-03T00:00:00Z' }, r2), /same batch/, 'another created_at');
  await assert.rejects(rawChained(db, 'intel_relationship_creation', { relationship_id: late, exposure: 'internal', proposer: 'source:cisa-kev', origin: 'source_ingest', rule_id: null, created_at: NOW }, r2), /same batch/, 'another exposure');
  await assert.rejects(rawChained(db, 'intel_relationship_creation', { relationship_id: late, exposure: 'public', proposer: 'source:other', origin: 'source_ingest', rule_id: null, created_at: NOW }, r2), /origin and method disagree/, 'source_ingest proposer = source:<source_id>');
  await assert.rejects(rawChained(db, 'intel_relationship_creation', { relationship_id: late, exposure: 'public', proposer: 'ai:model', origin: 'ai_proposed', rule_id: null, created_at: NOW }, r2), /origin and method disagree/, 'an AI never proposes an asserted_by_source relation');
  await assert.rejects(rawChained(db, 'intel_relationship_creation', { relationship_id: late, exposure: 'public', proposer: 'ai:model', origin: 'analyst', rule_id: null, created_at: NOW }, r2), /CHECK/, 'an ai: proposer is always origin ai_proposed');
  await assert.rejects(rawChained(db, 'intel_relationship_creation', { relationship_id: late, exposure: 'public', proposer: 'user:x', origin: 'engine_rule', rule_id: 'R-KEV-CWE-1', created_at: NOW }, r2), /CHECK/, 'engine_rule proposer = engine:<rule_id>');
  assert.throws(() => raw(db, 'INSERT INTO intel_relationship_creation (relationship_id,exposure,proposer,origin,rule_id,created_at,prev_hash,hash) VALUES (?,?,?,?,?,?,?,?)', late, 'public', 'source:cisa-kev', 'source_ingest', null, NOW, 'a'.repeat(64), 'b'.repeat(64)), /hash chain/, 'a link that does not continue the head');
  await rawChained(db, 'intel_relationship_creation', { relationship_id: late, exposure: 'public', proposer: 'source:cisa-kev', origin: 'source_ingest', rule_id: null, created_at: NOW }, r2);   // allowed: same batch semantics
  assert.throws(() => raw(db, "UPDATE intel_relationship_creation SET proposer = 'source:x'"), /append-only/);
  assert.throws(() => raw(db, 'DELETE FROM intel_relationship_creation'), /append-only/);
  const { id } = await relate(db, { type: 'RULE_ASSOCIATED_WITH_CVE', from: e.rule, to: e.cve, source_id: 'r', method: 'manual', ...ANALYST }, NOW);
  assert.deepEqual({ ...one(db, 'SELECT proposer, origin, rule_id FROM intel_relationship_creation WHERE relationship_id = ?', id) }, { proposer: 'user:analyst-a', origin: 'analyst', rule_id: null });
  await relate(db, { type: 'RULE_ASSOCIATED_WITH_CVE', from: e.rule, to: e.cve, source_id: 'r', method: 'manual', origin: 'analyst', proposer: 'user:analyst-b' }, '2026-11-05T00:00:00Z');
  assert.equal(one(db, 'SELECT proposer FROM intel_relationship_creation WHERE relationship_id = ?', id).proposer, 'user:analyst-a', 'a re-import keeps the first proposer');
  await assert.rejects(relate(db, { type: 'RULE_ASSOCIATED_WITH_CVE', from: e.rule, to: e.cve, source_id: 'r', method: 'manual' }, NOW), /origin must be/);
  assert.equal((await verifyAssurance(db)).ok, true);
});

// ---- (d) reviewer allow-list -----------------------------------------------------------------------------------------------------------------------------
test('(d) reviewer allow-list: no self-registration, no AI, two distinct active reviewers per change, bootstrap only by migration', async () => {
  const empty = await assuranceDb({ reviewers: false });
  await assert.rejects(changeReviewer(empty, { event: 'add', actor_id: 'user:eve', github_user_id: 66, by: ['user:eve2', 'user:eve3'], reason: 'want to review', request_id: 'req-boot-0001' }, NOW), /two distinct ACTIVE reviewers/, 'an empty allow-list has no runtime path');
  await assert.rejects(rawChained(empty, 'intel_reviewer_events', { event: 'add', actor_id: 'user:eve', github_user_id: 66, role: 'ADMIN', by_1: 'migration:0008_x', by_2: 'owner-approval:fake', reason: 'self bootstrap', request_id: 'req-boot-0002', at: NOW }), /two distinct ACTIVE/, 'pretending to be a migration does not work at runtime');
  const { db } = await world();
  const add = (actor_id, github_user_id, by, request_id) => changeReviewer(db, { event: 'add', actor_id, github_user_id, by, reason: 'new reviewer', request_id }, NOW);
  await assert.rejects(rawChained(db, 'intel_reviewer_events', { event: 'add', actor_id: 'user:eve', github_user_id: 66, role: 'REVIEWER', by_1: 'user:eve', by_2: 'user:rev-a', reason: 'self registration', request_id: 'req-self-0001', at: NOW }), /CHECK|two distinct ACTIVE/, 'self-registration');
  await assert.rejects(add('user:eve', 66, ['user:rev-a', 'user:nobody'], 'req-add-0001'), /two distinct ACTIVE/, 'one signer is not a reviewer');
  await assert.rejects(add('user:eve', 66, ['user:rev-a', 'user:rev-a'], 'req-add-0002'), /CHECK|refused/, 'the same reviewer twice');
  await assert.rejects(rawChained(db, 'intel_reviewer_events', { event: 'add', actor_id: 'ai:model', github_user_id: 67, role: 'REVIEWER', by_1: 'user:rev-a', by_2: 'user:rev-b', reason: 'an AI reviewer', request_id: 'req-ai-00001', at: NOW }), /CHECK|refused/, 'an AI identity cannot be written');
  await assert.rejects(add('ai:model', 67, ['user:rev-a', 'user:rev-b'], 'req-ai-00002'), /human account/);
  await assert.rejects(add('user:Eve_X', 68, ['user:rev-a', 'user:rev-b'], 'req-add-0003'), /human account/);
  await assert.rejects(add('user:rev-c', 1003, ['user:rev-a', 'user:rev-b'], 'req-add-0004'), /two distinct ACTIVE|add only a non-reviewer/, 'already active');
  await assert.rejects(add('user:rev-c-alt', 1003, ['user:rev-a', 'user:rev-b'], 'req-add-0005'), /one GitHub account, one reviewer/, 'one human, one reviewer id');
  await add('user:eve', 66, ['user:rev-a', 'user:rev-b'], 'req-add-0006');
  assert.ok(one(db, "SELECT 1 AS x FROM intel_reviewers_active WHERE actor_id = 'user:eve'"));
  const rv = (actor_id, by, request_id, gid) => changeReviewer(db, { event: 'revoke', actor_id, github_user_id: gid, by, reason: 'leaves the team', request_id }, NOW);
  await assert.rejects(rv('user:rev-c', ['user:rev-c', 'user:rev-a'], 'req-rev-0001', 1003), /CHECK|refused/, 'nobody signs their own change');
  await rv('user:rev-c', ['user:rev-a', 'user:eve'], 'req-rev-0002', 1003);
  await assert.rejects(add('user:frank', 69, ['user:rev-c', 'user:rev-a'], 'req-add-0007'), /two distinct ACTIVE/, 'a revoked reviewer no longer signs');
  await assert.rejects(rv('user:rev-c', ['user:rev-a', 'user:eve'], 'req-rev-0003', 1003), /revoke only an active/);
  assert.equal(one(db, "SELECT revoked_at FROM intel_reviewers WHERE actor_id = 'user:rev-c'").revoked_at, NOW);
  assert.throws(() => raw(db, "UPDATE intel_reviewer_events SET event = 'add' WHERE actor_id = 'user:rev-c'"), /append-only/);
  assert.throws(() => raw(db, "DELETE FROM intel_reviewer_events WHERE event = 'revoke'"), /append-only/);
  assert.ok(MIG.includes(REVIEWER_GUARD_SQL), 'the bootstrap generator recreates the guard VERBATIM');
  const sql = await reviewerBootstrapSql([{ actor_id: 'user:x', github_user_id: 1 }, { actor_id: 'user:y', github_user_id: 2 }], { migration: 'migration:0008_reviewers', approval_record: 'owner-approval:issue-1', at: NOW });
  assert.ok(sql.endsWith(REVIEWER_GUARD_SQL + '\n') && sql.includes('DROP TRIGGER IF EXISTS intel_reviewer_events_guard;'));
  await assert.rejects(reviewerBootstrapSql([{ actor_id: 'user:x', github_user_id: 1 }], { migration: 'migration:0008_x', approval_record: 'owner-approval:issue-2', at: NOW }), /at least two/);
  assert.equal((await verifyAssurance(db)).ok, true);
});

// ---- (e) reviews and rule 10 ------------------------------------------------------------------------------------------------------------------------------
test('(e) + rule 10: a review has approver <> proposer, an active non-AI approver, and the proposer of the creation record', async () => {
  const { db, e } = await world();
  const { id } = await relate(db, { type: 'RULE_DETECTS_CVE', from: e.rule, to: e.cve, source_id: 'lab', method: 'manual', evidence: [{ kind: 'test_run', ref: 'run-1' }], origin: 'analyst', proposer: 'user:rev-a' }, NOW);
  const ins = (row) => rawChained(db, 'intel_relationship_reviews', { relationship_id: id, proposer: 'user:rev-a', approver: 'user:rev-b', decision: 'approve', reason: 'checked the test run', at: NOW, ...row });
  await assert.rejects(ins({ approver: 'user:rev-a' }), /CHECK/, 'approver = proposer (an active reviewer, so only the CHECK refuses it)');
  await assert.rejects(ins({ approver: 'ai:model' }), /CHECK|allow-list/, 'AI approver');
  await assert.rejects(ins({ approver: 'user:nobody' }), /allow-list/, 'not a reviewer');
  await assert.rejects(ins({ proposer: 'user:someone-else' }), /creation record/, 'a faked proposer (to dodge approver <> proposer)');
  await assert.rejects(review(db, id, { approver: 'user:rev-a', decision: 'approve', reason: 'mine' }, NOW), /CHECK/);
  await review(db, id, { approver: 'user:rev-b', decision: 'approve', reason: 'checked the test run' }, NOW);
  assert.throws(() => raw(db, "UPDATE intel_relationship_reviews SET decision = 'reject'"), /append-only/);
  assert.throws(() => raw(db, 'DELETE FROM intel_relationship_reviews'), /append-only/);
  const bare = await rawRel(db, { type: 'RULE_DETECTS_CVE', from: e.rule2, to: e.cve, method: 'manual' });
  await assert.rejects(rawChained(db, 'intel_relationship_reviews', { relationship_id: bare, proposer: 'user:x', approver: 'user:rev-b', decision: 'approve', reason: 'no creation record', at: NOW }), /creation record/);
});

// ---- (f) + rule 1 -----------------------------------------------------------------------------------------------------------------------------------------
test('(f) + rule 1: correlated/derived never REPORTED or CONFIRMED; an AI never asserts, confirms, disputes, verifies, approves or supplies strong evidence', async () => {
  const { db, e } = await world();
  for (const method of ['correlated', 'derived_from_content']) {
    const { id } = await relate(db, { type: 'RULE_ASSOCIATED_WITH_CVE', from: e.rule, to: e.cve, source_id: `ai-${method}`, method, evidence: [{ kind: 'document', ref: 'similar names' }, { kind: 'content_match', ref: 'string match' }], ...AI }, NOW);
    for (const c of ['REPORTED', 'CONFIRMED']) assert.throws(() => rawAs(db, id, c, 'UNVERIFIED', 'user:rev-a'), /never reaches REPORTED or CONFIRMED/, `${method} ${c}`);
    rawAs(db, id, 'INFERRED', 'UNVERIFIED', 'ai:model'); assert.equal(state(db, id), 'candidate');
  }
  const { id } = await relate(db, { type: 'RULE_ASSOCIATED_WITH_CVE', from: e.rule, to: e.cve, source_id: 'cisa-kev', method: 'asserted_by_source', evidence: [{ kind: 'source_statement', ref: 's' }], ...ING }, NOW);
  for (const [c, v] of [['REPORTED', 'UNVERIFIED'], ['CONFIRMED', 'UNVERIFIED'], ['DISPUTED', 'UNVERIFIED'], ['UNKNOWN', 'FAILED']]) assert.throws(() => rawAs(db, id, c, v, 'ai:llm'), /AI never writes/, `${c}/${v}`);
  for (const kind of ['test_run', 'signature']) assert.throws(() => rawEv(db, id, kind, `ai-${kind}`, 'ai:llm'), /AI never supplies/, kind);
  assert.throws(() => rawEv(db, id, 'test_run', 'laundered', 'lab', 'ai:llm'), /AI never supplies/, 'nor through a republisher');
  assert.throws(() => rawEv(db, id, 'human_review', 'self', 'ai:llm'), /active reviewer|AI never/);
  await assert.rejects(relate(db, { type: 'RULE_ASSOCIATED_WITH_CVE', from: e.rule, to: e.cve2, source_id: 'x', method: 'asserted_by_source', ...AI }, NOW), /origin and method disagree/, 'an AI never claims a source assertion');
  // QA probe repro: ai:llm, method correlated, CONFIRMED/VERIFIED with self-made evidence
  const probe = await rawRel(db, { type: 'RULE_ASSOCIATED_WITH_CVE', from: e.rule2, to: e.cve, source_id: 'ai:llm', method: 'correlated' });
  rawEv(db, probe, 'content_match', 'name similarity', 'ai:llm');
  assert.throws(() => rawAs(db, probe, 'CONFIRMED', 'VERIFIED', 'ai:llm', 'names look similar'));
  assert.equal(n(db, "SELECT COUNT(*) n FROM intel_relationship_assessments WHERE actor GLOB 'ai:*' AND confidence NOT IN ('UNKNOWN','INFERRED')"), 0);
});

// ---- (g) critical types + rule 7 + rule 5 ---------------------------------------------------------------------------------------------------------------
test('(g) + rules 5, 7, 10: critical types are CONFIRMED/VERIFIED only through an approved review by the asserting actor; detection links need a test run', async () => {
  const { db, e } = await world();
  const cases = [['RULE_DETECTS_CVE', e.rule, e.cve, 'test_run'], ['RULE_DETECTS_CVE_BEHAVIOUR', e.rule, e.cve, 'test_run'], ['INDICATOR_ASSOCIATED_WITH_CVE', e.ip, e.cve, 'test_run'], ['ALIAS_OF', e.euvd, e.cve, 'document']];
  for (const [type, from, to, strong] of cases) {
    const { id } = await relate(db, { type, from, to, source_id: 'lab', method: 'manual', exposure: 'public', evidence: [{ kind: 'source_statement', ref: `${type} stmt` }, { kind: 'human_review', ref: 'read', source_id: 'user:rev-c' }], origin: 'analyst', proposer: 'user:analyst-a' }, NOW);
    for (const v of ['UNVERIFIED', 'VERIFIED']) assert.throws(() => rawAs(db, id, 'CONFIRMED', v, 'user:analyst-a', 'proposer alone'), /approved review|test run/, `${type} ${v} by the proposer`);
    await review(db, id, { approver: 'user:rev-b', decision: 'approve', reason: 'two-person check' }, NOW);
    if (strong === 'test_run') { assert.throws(() => rawAs(db, id, 'CONFIRMED', 'VERIFIED', 'user:rev-b'), /test run/, `${type}: test run required`); rawEv(db, id, 'test_run', `${type} run`, 'lab'); }
    assert.throws(() => rawAs(db, id, 'CONFIRMED', 'VERIFIED', 'user:rev-a'), /approved review/, `${type}: another reviewer than the approver`);
    assert.throws(() => rawAs(db, id, 'CONFIRMED', 'VERIFIED', 'user:analyst-a'), /approved review/, `${type}: the proposer after the review`);
    rawAs(db, id, 'CONFIRMED', 'VERIFIED', 'user:rev-b');
    assert.equal(state(db, id), 'verified', type);
    await review(db, id, { approver: 'user:rev-c', decision: 'reject', reason: 'second look: wrong' }, NOW);
    assert.throws(() => rawAs(db, id, 'CONFIRMED', 'VERIFIED', 'user:rev-c'), /approved review/, `${type}: the LATEST review decides`);
  }
  // non-critical VERIFIED also needs the review (rule 1: VERIFIED only by an allow-listed approver)
  const nc = await asserted(db, { type: 'VULN_HAS_WEAKNESS', from: e.cve, to: e.cwe });
  rawEv(db, nc, 'human_review', 'checked', 'user:rev-a');
  assert.throws(() => rawAs(db, nc, 'CONFIRMED', 'VERIFIED', 'source:cisa-kev'), /approved review/);
  rawAs(db, nc, 'CONFIRMED', 'UNVERIFIED', 'source:cisa-kev'); assert.equal(state(db, nc), 'asserted', 'CONFIRMED/UNVERIFIED of a non-critical type stays asserted (§3 row 4)');
  // rule 5: identity links need the asserting statement; HASH_IDENTIFIES_SAMPLE never correlated
  const al = await rawRel(db, { type: 'ALIAS_OF', from: e.euvd, to: e.cve2, source_id: 'feed', method: 'asserted_by_source' });
  await assert.rejects(relate(db, { type: 'HASH_IDENTIFIES_SAMPLE', from: e.md5, to: e.sample, source_id: 'c', method: 'correlated', ...AI }, NOW), /never correlated or derived/);
  assert.throws(() => raw(db, 'INSERT INTO intel_relationships (id,type,from_id,to_id,source_id,method,exposure,observed_at,created_at) VALUES (?,?,?,?,?,?,?,?,?)', 'd'.repeat(64), 'HASH_IDENTIFIES_SAMPLE', e.md5, e.sample, 'src', 'correlated', 'public', NOW, NOW), /never correlated or derived/);
  const { id: hs } = await relate(db, { type: 'HASH_IDENTIFIES_SAMPLE', from: e.md5, to: e.sample, source_id: 'mb', method: 'asserted_by_source', ...ING }, NOW);
  rawEv(db, hs, 'signature', 'sig', 'mb');
  assert.throws(() => rawAs(db, hs, 'CONFIRMED', 'UNVERIFIED', 'source:mb'), /identity link/, 'HASH_IDENTIFIES_SAMPLE without the asserting statement');
  assert.throws(() => rawAs(db, al, 'REPORTED', 'UNVERIFIED', 'source:feed'), /creation record|REPORTED needs|identity link/, 'ALIAS_OF with no evidence');
});

// ---- (h) evidence provenance and de-duplication ----------------------------------------------------------------------------------------------------------
test('(h) evidence: source_id and original_source_id required on new rows; identical evidence stored once; a human review only from the allow-list', async () => {
  const { db, e } = await world();
  const id = await asserted(db, { type: 'VULN_HAS_WEAKNESS', from: e.cve, to: e.cwe });
  assert.throws(() => raw(db, "INSERT INTO intel_relationship_evidence (relationship_id,kind,ref,source_id,observed_at,recorded_at) VALUES (?, 'document', 'x', 'cisa-kev', ?, ?)", id, NOW, NOW), /original_source_id/);
  assert.throws(() => raw(db, "INSERT INTO intel_relationship_evidence (relationship_id,kind,ref,original_source_id,observed_at,recorded_at) VALUES (?, 'document', 'x', 'cisa-kev', ?, ?)", id, NOW, NOW), /source_id/);
  assert.throws(() => raw(db, "INSERT INTO intel_relationship_evidence (relationship_id,kind,ref,source_id,original_source_id,observed_at,recorded_at) VALUES (?, 'document', 'x', X'636973612d6b6576', 'cisa-kev', ?, ?)", id, NOW, NOW), /text/, 'a blob is not a source id');
  rawEv(db, id, 'document', 'kev entry', 'aggregator', 'cisa-kev', 'c'.repeat(64));
  assert.throws(() => rawEv(db, id, 'document', 'kev entry', 'other-aggregator', 'cisa-kev', 'c'.repeat(64)), /UNIQUE|never overwritten/, 'the same statement through another republisher is the same evidence');
  rawEv(db, id, 'document', 'kev entry', 'aggregator', 'cisa-kev', 'd'.repeat(64));   // other content: other evidence
  const before = n(db, 'SELECT evidence_count n FROM intel_relationship_state WHERE relationship_id = ?', id);
  assert.equal(await addEvidence(db, id, { kind: 'source_statement', ref: 'stmt' }, NOW), false, 'the module re-import is a no-op');
  assert.equal(n(db, 'SELECT evidence_count n FROM intel_relationship_state WHERE relationship_id = ?', id), before);
  assert.throws(() => rawEv(db, id, 'human_review', 'I looked', 'user:not-a-reviewer'), /active reviewer/);
  rawEv(db, id, 'human_review', 'I looked', 'user:rev-a');
  assert.throws(() => raw(db, "UPDATE intel_relationship_evidence SET original_source_id = 'x' WHERE relationship_id = ?", id), /append-only/);
});

// ---- (i) source approval ----------------------------------------------------------------------------------------------------------------------------------
test('(i) source approval in the database: deterministic, idempotent loader from the registry; append-only; forged approvals detected', async () => {
  const db = newDb(M7);
  const a = await syncSourceApprovals(db, REGISTRY_TEXT, NOW);
  const reg = JSON.parse(REGISTRY_TEXT);
  assert.equal(a.changed.length, reg.sources.length); assert.deepEqual(a.changed.map((x) => x.source_id), [...reg.sources.map((s) => s.id)].sort());
  assert.deepEqual((await syncSourceApprovals(db, REGISTRY_TEXT, NOW)).changed, [], 'idempotent');
  assert.deepEqual(db.raw.prepare("SELECT source_id FROM intel_source_approvals WHERE approval_state = 'APPROVED_PUBLIC'").all().map((r) => r.source_id), ['cisa-kev']);
  const db2 = newDb(M7); await syncSourceApprovals(db2, REGISTRY_TEXT, NOW);
  assert.deepEqual(db2.raw.prepare('SELECT source_id, approval_state, hash FROM intel_source_approval_events ORDER BY id').all(), db.raw.prepare('SELECT source_id, approval_state, hash FROM intel_source_approval_events ORDER BY id').all(), 'same registry, same time: same chain');
  const changed = await syncSourceApprovals(db, registryWith(['nvd']), NOW); assert.deepEqual(changed.changed, [{ source_id: 'nvd', approval_state: 'APPROVED_PUBLIC' }]);
  const dropped = JSON.parse(REGISTRY_TEXT); dropped.as_of = '2030-01-01'; dropped.sources = dropped.sources.filter((s) => s.id !== 'cisa-kev');
  assert.deepEqual((await syncSourceApprovals(db, JSON.stringify(dropped), NOW)).changed.map((x) => [x.source_id, x.approval_state]), [['cisa-kev', 'ABSENT'], ['nvd', 'RETAINED']]);
  assert.throws(() => raw(db, "UPDATE intel_source_approval_events SET approval_state = 'APPROVED_PUBLIC'"), /append-only/);
  assert.throws(() => raw(db, 'DELETE FROM intel_source_approval_events'), /append-only/);
  assert.throws(() => raw(db, "INSERT INTO intel_source_approval_events (source_id,approval_state,registry_sha256,registry_as_of,at,prev_hash,hash) VALUES ('evil','APPROVED_PUBLIC',?,?,?,?,?)", 'a'.repeat(64), '2099-12-31', NOW, GENESIS, 'b'.repeat(64)), /hash chain|UNIQUE/);
  await assert.rejects(syncSourceApprovals(db, '{"schema":"macguard.intel-sources/1","as_of":"2026-11-01","sources":[{"id":"x","approval_state":"YES"}]}', NOW), /unknown approval_state/);
  // a raw-SQL writer who computes the chain correctly can forge an approval: the chain verifies, the registry cross-check does not
  await rawChained(db, 'intel_source_approval_events', { source_id: 'evil-feed', approval_state: 'APPROVED_PUBLIC', registry_sha256: 'a'.repeat(64), registry_as_of: '2099-12-31', at: NOW });
  assert.equal((await verifyAssurance(db)).ok, true, 'a correctly chained forgery is not detectable by the chain alone');
  const x = await verifySourceApprovals(db, JSON.stringify(dropped)); assert.equal(x.ok, false); assert.deepEqual(x.mismatches, [{ source_id: 'evil-feed', recorded: 'APPROVED_PUBLIC', registry: 'ABSENT' }]);
  assert.equal((await verifySourceApprovals(db2, REGISTRY_TEXT)).ok, true);
});

// ---- (j) lifecycle and the total state mapping of §3 ------------------------------------------------------------------------------------------------------
test('(j) + §3: retraction only by the original source or the proposer; the lifecycle view is total and ordered (retracted > rejected > disputed > verified > asserted > candidate)', async () => {
  const { db, e } = await world();
  const id = await asserted(db, { type: 'VULN_HAS_WEAKNESS', from: e.cve, to: e.cwe });
  assert.equal(state(db, id), 'asserted');
  const lc = (marker, actor) => rawChained(db, 'intel_relationship_lifecycle_events', { relationship_id: id, marker, actor, reason: 'raw lifecycle', at: NOW });
  for (const actor of ['user:rev-a', 'ai:model', 'source:other', 'engine:R-KEV-CWE-1']) await assert.rejects(lc('retracted', actor), /original source or the proposer/, actor);
  await assert.rejects(lc('reinstated', 'source:cisa-kev'), /other state/, 'nothing to reinstate');
  await lc('retracted', 'source:cisa-kev'); assert.equal(state(db, id), 'retracted');
  await assert.rejects(lc('retracted', 'source:cisa-kev'), /other state/);
  rawAs(db, id, 'UNKNOWN', 'FAILED', 'source:cisa-kev');   // a rejection after a retraction is allowed, and the retraction still wins
  assert.throws(() => rawAs(db, id, 'REPORTED', 'UNVERIFIED', 'source:cisa-kev'), /retracted/, 'no re-assertion while retracted');
  assert.equal(state(db, id), 'retracted', 'retracted wins over rejected');
  assert.throws(() => raw(db, "UPDATE intel_relationship_lifecycle_events SET marker = 'reinstated'"), /append-only/);
  assert.throws(() => raw(db, 'DELETE FROM intel_relationship_lifecycle_events'), /append-only/);
  // the ladder, one relationship per state
  const ladder = {};
  ladder.candidate = (await relate(db, { type: 'RULE_ASSOCIATED_WITH_CVE', from: e.rule, to: e.cve, source_id: 'x', method: 'derived_from_content', origin: 'engine_rule', rule_id: 'R-YARA-CVE-1' }, NOW)).id;
  ladder.unapproved = await asserted(db, { type: 'RULE_ASSOCIATED_WITH_CVE', from: e.rule, to: e.cve, source_id: 'nvd' });
  ladder.asserted = await asserted(db, { type: 'VULN_HAS_WEAKNESS', from: e.cve2, to: e.cwe });
  ladder.rejected = await asserted(db, { type: 'RULE_REFERENCES_SAMPLE', from: e.rule, to: e.sample });
  await assess(db, ladder.rejected, { confidence: 'REPORTED', verification: 'FAILED', reason: 'the test failed', actor: 'user:rev-a' }, NOW);
  ladder.disputed = await asserted(db, { type: 'RULE_REFERENCES_SAMPLE', from: e.rule2, to: e.sample });
  await assess(db, ladder.disputed, { confidence: 'DISPUTED', reason: 'contradicted', actor: 'source:cisa-kev' }, NOW);
  const { id: ver } = await relate(db, { type: 'RULE_ASSOCIATED_WITH_CVE', from: e.rule2, to: e.cve2, source_id: 'cisa-kev', method: 'manual', exposure: 'public', evidence: [{ kind: 'source_statement', ref: 's' }, { kind: 'human_review', ref: 'r', source_id: 'user:rev-a' }], ...ANALYST }, NOW);
  await review(db, ver, { approver: 'user:rev-a', decision: 'approve', reason: 'checked' }, NOW); await assess(db, ver, { confidence: 'CONFIRMED', verification: 'VERIFIED', reason: 'reviewed', actor: 'user:rev-a' }, NOW); ladder.verified = ver;
  assert.deepEqual(Object.fromEntries(Object.entries(ladder).map(([k, v]) => [k, state(db, v)])), { candidate: 'candidate', unapproved: 'candidate', asserted: 'asserted', rejected: 'rejected', disputed: 'disputed', verified: 'verified' });
  const states = new Set(db.raw.prepare('SELECT state FROM intel_relationship_lifecycle').all().map((r) => r.state));
  assert.ok([...states].every((s) => ['retracted', 'rejected', 'disputed', 'verified', 'asserted', 'candidate'].includes(s)));
  assert.equal(n(db, 'SELECT COUNT(*) n FROM intel_relationship_lifecycle'), n(db, 'SELECT COUNT(*) n FROM intel_relationships'), 'total: one state per relationship');
  assert.equal((await verifyAssurance(db)).ok, true);
});

// ---- (k) EPSS and version ranges + rule 6 --------------------------------------------------------------------------------------------------------------
test('(k) + rule 6: EPSS history only on vulnerabilities; EPSS history/latest and version ranges are never deleted; no CVSS outside vulnerabilities', async () => {
  const { db, e } = await world();
  assert.throws(() => raw(db, "INSERT INTO intel_epss_history VALUES (?, 'first', '2026-01-01', 0.1, 0.2, NULL, ?)", e.rule, NOW), /EPSS belongs to a vulnerability/);
  assert.throws(() => raw(db, "INSERT INTO intel_epss_history VALUES (?, 'first', '2026-01-01', 0.1, 0.2, NULL, ?)", e.cwe, NOW), /EPSS belongs to a vulnerability/);
  raw(db, "INSERT INTO intel_epss_history VALUES (?, 'first', '2026-01-01', 0.1, 0.2, NULL, ?)", e.cve, NOW);
  raw(db, "INSERT INTO intel_epss_latest VALUES (?, 'first', '2026-01-01', 0.1, 0.2, NULL, ?)", e.cve, NOW);
  assert.throws(() => raw(db, 'DELETE FROM intel_epss_history'), /append-only/);
  assert.throws(() => raw(db, 'DELETE FROM intel_epss_latest'), /never deleted/);
  const pr = await putEntity(db, { type: 'product', namespace: 'purl', key: 'pkg:npm/x' }, NOW), vr = await putEntity(db, { type: 'version_range', namespace: 'range', key: 'r1' }, NOW);
  raw(db, "INSERT INTO intel_version_ranges (entity_id,product_id,scheme,introduced) VALUES (?, ?, 'SEMVER', '1.0')", vr, pr);
  assert.throws(() => raw(db, 'DELETE FROM intel_version_ranges'), /never deleted/);
  for (const target of [e.rule, e.sample, e.cwe]) assert.throws(() => raw(db, "INSERT INTO intel_severity_assessments (vuln_id,source_id,cvss_version,availability,vector,base_score,severity,assessed_at,recorded_at) VALUES (?,'nvd','3.1','AVAILABLE','CVSS:3.1/AV:N',9.8,'CRITICAL','2026-01-01T00:00:00.000Z',?)", target, NOW), /severity belongs to a vulnerability/);
});

// ---- (l) public and conflict views + rules 2, 8, 9 ------------------------------------------------------------------------------------------------------
test('(l) + rules 2, 8, 9: the public view holds only asserted/verified, public, approved-source, non-PoC relations; siblings that disagree are disputed and listed', async () => {
  const { db, e } = await world();
  const ok = await asserted(db, { type: 'VULN_HAS_WEAKNESS', from: e.cve, to: e.cwe });
  assert.ok(isPublic(db, ok));
  const restricted = await asserted(db, { type: 'VULN_HAS_WEAKNESS', from: e.cve2, to: e.cwe, exposure: 'restricted' });
  assert.equal(state(db, restricted), 'asserted'); assert.ok(!isPublic(db, restricted), 'exposure is a ceiling');
  const unapproved = await asserted(db, { type: 'RULE_ASSOCIATED_WITH_CVE', from: e.rule, to: e.cve, source_id: 'nvd' }); assert.ok(!isPublic(db, unapproved));
  // rule 8: a REPORTED relation of an approved source whose only statement comes through an UNAPPROVED republisher is not public
  const { id: rep } = await relate(db, { type: 'RULE_ASSOCIATED_WITH_CVE', from: e.rule2, to: e.cve, source_id: 'cisa-kev', method: 'asserted_by_source', exposure: 'public', evidence: [{ kind: 'source_statement', ref: 'copy', source_id: 'aggregator', original_source_id: 'cisa-kev' }], ...ING }, NOW);
  await assess(db, rep, { confidence: 'REPORTED', reason: 'copied', actor: 'source:aggregator' }, NOW); assert.equal(state(db, rep), 'candidate'); assert.ok(!isPublic(db, rep));
  // rule 2: content similarity alone never publishes (a CONFIRMED manual relation with only a content match has no approved statement)
  const { id: sim } = await relate(db, { type: 'RULE_REFERENCES_SAMPLE', from: e.rule, to: e.sample, source_id: 'cisa-kev', method: 'manual', exposure: 'public', evidence: [{ kind: 'content_match', ref: 'strings overlap' }], ...ANALYST }, NOW);
  await assess(db, sim, { confidence: 'CONFIRMED', reason: 'looks the same', actor: 'user:analyst-a' }, NOW); assert.equal(state(db, sim), 'candidate'); assert.ok(!isPublic(db, sim));
  // PoC never public
  const poc = await asserted(db, { type: 'CVE_HAS_POC_REFERENCE', from: e.cve, to: e.poc }); assert.equal(state(db, poc), 'asserted'); assert.ok(!isPublic(db, poc));
  // rule 9 / §4.2: a sibling (same type, from, to; another source) disputes the public one -> both kept, the positive one becomes disputed, not public
  await syncSourceApprovals(db, registryWith(['nvd']), NOW);
  assert.ok(isPublic(db, unapproved), 'nvd approved: its asserted relation is public');
  const { id: neg } = await relate(db, { type: 'VULN_HAS_WEAKNESS', from: e.cve, to: e.cwe, source_id: 'nvd', method: 'asserted_by_source', exposure: 'public', evidence: [{ kind: 'source_statement', ref: 'not CWE-79' }], ...ING }, NOW);
  await assess(db, neg, { confidence: 'DISPUTED', reason: 'NVD says another CWE', actor: 'source:nvd' }, NOW);
  assert.equal(state(db, ok), 'disputed'); assert.ok(!isPublic(db, ok));
  assert.deepEqual(db.raw.prepare('SELECT relationship_id, sibling_id, source_id, sibling_source_id FROM intel_relationship_conflicts').all().map((r) => ({ ...r })), [{ relationship_id: ok, sibling_id: neg, source_id: 'cisa-kev', sibling_source_id: 'nvd' }]);
  await setLifecycle(db, neg, { marker: 'retracted', actor: 'source:nvd', reason: 'withdrawn' }, NOW);
  assert.equal(state(db, ok), 'asserted', 'a retracted sibling no longer disputes'); assert.ok(isPublic(db, ok));
  // every public row is asserted/verified with approved evidence; no candidate, disputed, rejected, retracted or PoC ever
  for (const r of db.raw.prepare('SELECT * FROM intel_relationship_public').all()) { assert.ok(['asserted', 'verified'].includes(r.state)); assert.ok(r.approved_evidence_count >= 1); assert.notEqual(r.type, 'CVE_HAS_POC_REFERENCE'); }
  // readers: default scope is the public view
  assert.deepEqual((await neighbours(db, e.cve)).edges.map((x) => x.id), [ok], 'out of the CVE: only the public weakness (no PoC, no retracted sibling)');
  assert.deepEqual((await neighbours(db, e.cve, { direction: 'in' })).edges.map((x) => x.id), [unapproved], 'into the CVE: only the approved asserted rule link');
  assert.equal(await relationshipDetail(db, poc), null); assert.equal((await relationshipDetail(db, poc, { scope: 'internal' })).state, 'asserted');
});

// ---- rules 3, 4: nothing derives relations ----------------------------------------------------------------------------------------------------------------
test('rules 3, 4: no trigger or view writes relationships (no transitivity, search results never become relations)', async () => {
  const { db, e } = await world();
  assert.equal(n(db, "SELECT COUNT(*) n FROM sqlite_master WHERE type = 'trigger' AND (sql LIKE '%INSERT INTO intel_relationships %' OR sql LIKE '%INSERT INTO intel_relationships(%')"), 0);
  const a = await asserted(db, { type: 'HASH_IDENTIFIES_SAMPLE', from: e.md5, to: e.sample }), b = await asserted(db, { type: 'RULE_REFERENCES_SAMPLE', from: e.rule, to: e.sample });
  assert.ok(a && b); assert.equal(n(db, 'SELECT COUNT(*) n FROM intel_relationships'), 2, 'A-B and C-B never yield A-C');
});

// ---- tamper-evidence ----------------------------------------------------------------------------------------------------------------------------------------
test('tamper-evidence: with the triggers dropped (D1 has no roles), rewritten, removed, reordered or truncated log entries and rewritten relationships are detected', async () => {
  const build = async () => {
    const { db, e } = await world();
    const id = await asserted(db, { type: 'VULN_HAS_WEAKNESS', from: e.cve, to: e.cwe });
    const { id: d } = await relate(db, { type: 'RULE_DETECTS_CVE', from: e.rule, to: e.cve, source_id: 'lab', method: 'manual', evidence: [{ kind: 'test_run', ref: 'r' }], ...ANALYST }, NOW);
    await review(db, d, { approver: 'user:rev-a', decision: 'reject', reason: 'first look' }, NOW); await review(db, d, { approver: 'user:rev-b', decision: 'approve', reason: 'second look' }, NOW);
    await setLifecycle(db, id, { marker: 'retracted', actor: 'source:cisa-kev', reason: 'gone away' }, NOW);
    return { db, id, d };
  };
  const drop = (db) => { for (const t of db.raw.prepare("SELECT name FROM sqlite_master WHERE type = 'trigger' AND (name LIKE '%no_update' OR name LIKE '%no_delete' OR name LIKE '%immutable' OR name LIKE '%_chain' OR name LIKE '%guard%')").all()) db.raw.exec(`DROP TRIGGER ${t.name}`); };
  const ok = await build(); const v0 = await verifyAssurance(ok.db); assert.equal(v0.ok, true, JSON.stringify(v0));
  const heads = Object.fromEntries(Object.entries(v0.logs).map(([k, v]) => [k, v.head]));
  const attacks = {
    'review decision rewritten': (x) => raw(x.db, "UPDATE intel_relationship_reviews SET decision = 'approve' WHERE reason = 'first look'"),
    'review removed from the middle': (x) => raw(x.db, "DELETE FROM intel_relationship_reviews WHERE reason = 'first look'"),
    'reviews reordered': (x) => { raw(x.db, 'UPDATE intel_relationship_reviews SET id = id + 100'); raw(x.db, "UPDATE intel_relationship_reviews SET id = 1 WHERE reason = 'second look'"); },
    'proposer rewritten': (x) => raw(x.db, "UPDATE intel_relationship_creation SET proposer = 'user:rev-b' WHERE relationship_id = ?", x.d),
    'relationship type rewritten': (x) => raw(x.db, "UPDATE intel_relationships SET type = 'RULE_ASSOCIATED_WITH_CVE' WHERE id = ?", x.d),
    'relationship exposure rewritten': (x) => raw(x.db, "UPDATE intel_relationships SET exposure = 'restricted' WHERE id = ?", x.id),
    'retraction removed (last entry)': (x) => raw(x.db, 'DELETE FROM intel_relationship_lifecycle_events'),
    'reviewer forged': (x) => raw(x.db, "UPDATE intel_reviewer_events SET actor_id = 'user:mallory' WHERE actor_id = 'user:rev-c'"),
    'approval flipped': (x) => raw(x.db, "UPDATE intel_source_approval_events SET approval_state = 'APPROVED_PUBLIC' WHERE source_id = 'nvd'"),
  };
  for (const [name, attack] of Object.entries(attacks)) {
    const x = await build(); drop(x.db); attack(x);
    const v = await verifyAssurance(x.db, { heads });
    assert.equal(v.ok, false, `${name} went undetected: ${JSON.stringify(v.logs)}`);
  }
  // removing the LAST entry is caught by sqlite_sequence; if the attacker also rewinds sqlite_sequence, only an externally kept head detects it (documented limit)
  const t = await build(); drop(t.db); raw(t.db, 'DELETE FROM intel_relationship_lifecycle_events');
  assert.match((await verifyAssurance(t.db)).logs.intel_relationship_lifecycle_events.error, /sqlite_sequence/);
  raw(t.db, "UPDATE sqlite_sequence SET seq = 0 WHERE name = 'intel_relationship_lifecycle_events'");
  assert.equal((await verifyAssurance(t.db)).ok, true, 'a consistent tail rewrite (sequence included) is invisible from inside the database');
  assert.equal((await verifyAssurance(t.db, { heads })).ok, false, '... and detected against the external head');
  // cross-checks against independent projections: a VERIFIED assessment whose review vanished
  const c = await build(); rawEv(c.db, c.d, 'test_run', 'r2', 'lab'); rawAs(c.db, c.d, 'CONFIRMED', 'VERIFIED', 'user:rev-b');   // legitimately verified ...
  drop(c.db); raw(c.db, "DELETE FROM intel_relationship_reviews WHERE reason = 'second look'"); raw(c.db, "UPDATE sqlite_sequence SET seq = seq - 1 WHERE name = 'intel_relationship_reviews'");   // ... then its review erased consistently
  const vc = await verifyAssurance(c.db); assert.equal(vc.logs.intel_relationship_reviews.ok, true, 'the review log alone looks intact'); assert.equal(vc.cross.ok, false, 'the assessment projection exposes it');
});

test('concurrency: two writers on one chained log both succeed (the loser of the head race retries); the chain stays linear', async () => {
  const { db, e } = await world();
  const ids = [];
  for (const [from, to] of [[e.rule, e.cve], [e.rule2, e.cve], [e.rule, e.cve2], [e.rule2, e.cve2]]) ids.push((await relate(db, { type: 'RULE_DETECTS_CVE', from, to, source_id: 'lab', method: 'manual', ...ANALYST }, NOW)).id);
  const r = await Promise.allSettled(ids.map((id, i) => review(db, id, { approver: i % 2 ? 'user:rev-a' : 'user:rev-b', decision: 'approve', reason: `parallel ${i}` }, NOW)));
  assert.deepEqual(r.map((x) => x.status), ['fulfilled', 'fulfilled', 'fulfilled', 'fulfilled'], JSON.stringify(r.map((x) => x.reason?.message)));
  const rel = await Promise.allSettled([[e.cve, e.cwe], [e.cve2, e.cwe]].map(([from, to]) => relate(db, { type: 'VULN_HAS_WEAKNESS', from, to, source_id: 'cisa-kev', method: 'asserted_by_source', ...ING }, NOW)));
  assert.deepEqual(rel.map((x) => x.status), ['fulfilled', 'fulfilled']);
  assert.equal(n(db, 'SELECT COUNT(*) n FROM intel_relationship_reviews'), 4); assert.equal((await verifyAssurance(db)).ok, true);
});

// ---- QA probe replay -------------------------------------------------------------------------------------------------------------------------------------
test('QA probe replay (corr-contract-review/probe.sql): every forbidden write that succeeded on 0001-0005 is refused on 0001-0007', async () => {
  const db = await assuranceDb({ reviewers: false });
  const T = 't';
  const forbidden = [
    ["INSERT INTO intel_entities (id,type,namespace,key,first_seen,updated_at) VALUES ('sample:sha256:aa','sample','sha256','aa',?,?)", T, T],
    ["INSERT INTO intel_entities (id,type,namespace,key,first_seen,updated_at) VALUES ('rule:yara:BAD key with ../ and :colon','rule','yara','BAD key with ../ and :colon',?,?)", T, T],
    ["INSERT INTO intel_entities (id,type,namespace,key,first_seen,updated_at) VALUES ('vulnerability:cve:cve-2024-0001','vulnerability','cve','cve-2024-0001',?,?)", T, T],
    ["UPDATE intel_relationship_types SET from_type = 'sample' WHERE type = 'RULE_DETECTS_CVE'"],
    ["INSERT INTO intel_relationship_types VALUES ('RULE_EXPLOITS_CVE','rule','vulnerability',NULL)"],
  ];
  for (const [sql, ...a] of forbidden) assert.throws(() => raw(db, sql, ...a), undefined, sql);
  const rule = 'rule:yara:a/b.yar#R1', cve = 'vulnerability:cve:CVE-2024-0001';
  insEnt(db, 'rule', 'yara', 'a/b.yar#R1'); insEnt(db, 'vulnerability', 'cve', 'CVE-2024-0001'); insEnt(db, 'weakness', 'cwe', 'CWE-79');
  // the probe's 'legit' public UNKNOWN relation with zero evidence and the ai:llm RULE_DETECTS_CVE are accepted as ROWS (relationships are proposals) ...
  raw(db, "INSERT INTO intel_relationships VALUES (?, 'RULE_ASSOCIATED_WITH_CVE', ?, ?, 'ai:llm', 'correlated', NULL, 'public', ?, ?)", 'a'.repeat(64), rule, cve, T, T);
  raw(db, "INSERT INTO intel_relationships VALUES (?, 'RULE_DETECTS_CVE', ?, ?, 'ai:llm', 'correlated', NULL, 'public', ?, ?)", 'b'.repeat(64), rule, cve, T, T);
  // ... but none of them ever leaves candidate, and none is public
  assert.equal(n(db, 'SELECT COUNT(*) n FROM intel_relationship_public'), 0);
  for (const sql of ["INSERT INTO intel_relationship_evidence (relationship_id,kind,ref,source_id,observed_at,recorded_at) VALUES ('" + 'b'.repeat(64) + "','human_review','self','ai:llm','t','t')",
    "INSERT INTO intel_relationship_evidence (relationship_id,kind,ref,source_id,original_source_id,observed_at,recorded_at) VALUES ('" + 'b'.repeat(64) + "','human_review','self','ai:llm','ai:llm','t','t')",
    "INSERT INTO intel_relationship_evidence (relationship_id,kind,ref,source_id,original_source_id,observed_at,recorded_at) VALUES ('" + 'b'.repeat(64) + "','test_run','fake','ai:llm','ai:llm','t','t')",
    "INSERT INTO intel_relationship_assessments (relationship_id,confidence,verification,reason,actor,at) VALUES ('" + 'b'.repeat(64) + "','CONFIRMED','VERIFIED','ai says so','ai:llm','t')",
    "INSERT INTO intel_relationship_assessments (relationship_id,confidence,verification,reason,actor,at) VALUES ('" + 'a'.repeat(64) + "','CONFIRMED','VERIFIED','names look similar','ai:llm','t')",
    "INSERT INTO intel_epss_history VALUES ('" + rule + "','first','2026-01-01',0.1,0.2,NULL,'t')"]) assert.throws(() => raw(db, sql), undefined, sql);
  rawEv(db, 'b'.repeat(64), 'source_statement', 'dup', 'kev'); assert.throws(() => rawEv(db, 'b'.repeat(64), 'source_statement', 'dup', 'kev'), /UNIQUE|never overwritten/, 'duplicate evidence');
  raw(db, "INSERT INTO intel_epss_history VALUES (?, 'first', '2026-01-01', 0.1, 0.2, NULL, 't')", cve); assert.throws(() => raw(db, 'DELETE FROM intel_epss_history'), /append-only/);
  insEnt(db, 'vulnerability', 'cve', 'CVE-2024-0002'); insEnt(db, 'indicator', 'md5', 'b'.repeat(32)); insEnt(db, 'sample', 'sha256', 'c'.repeat(64));
  assert.throws(() => raw(db, "INSERT INTO intel_relationships VALUES (?, 'HASH_IDENTIFIES_SAMPLE', ?, ?, 'src', 'correlated', NULL, 'public', 't', 't')", 'd'.repeat(64), `indicator:md5:${'b'.repeat(32)}`, `sample:sha256:${'c'.repeat(64)}`), /never correlated/);
  assert.equal(n(db, "SELECT COUNT(*) n FROM intel_relationship_lifecycle WHERE state <> 'candidate'"), 0);
});

// ---- migration up/down ------------------------------------------------------------------------------------------------------------------------------------
test('migration 0007 on a 0005 database WITH data, then rollback: pre-0007 rows untouched and candidate-only; rollback leaves the 0005 schema byte-identical and keeps the data', async () => {
  const db = newDb(M5);
  const schema = () => JSON.stringify(db.raw.prepare("SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name <> 'sqlite_sequence' ORDER BY type, name").all());
  const dump = (cols = '*') => JSON.stringify(['intel_entities', 'intel_relationships', 'intel_relationship_assessments', 'intel_relationship_state', 'intel_relationship_types', 'intel_entity_types', 'intel_epss_history', 'intel_version_ranges'].map((t) => db.raw.prepare(`SELECT ${cols} FROM ${t} ORDER BY 1`).all())
    .concat([db.raw.prepare('SELECT id, relationship_id, kind, ref, sha256, source_id, observed_at, recorded_at, note FROM intel_relationship_evidence ORDER BY id').all()]));
  insEnt(db, 'vulnerability', 'cve', 'CVE-2024-0001'); insEnt(db, 'weakness', 'cwe', 'CWE-79'); insEnt(db, 'rule', 'yara', 'legacy key without grammar');
  const old = await relationshipId({ type: 'VULN_HAS_WEAKNESS', from: 'vulnerability:cve:CVE-2024-0001', to: 'weakness:cwe:CWE-79', source_id: 'cisa-kev', method: 'asserted_by_source' });   // content-derived, as every pre-0007 producer wrote it
  raw(db, "INSERT INTO intel_relationships VALUES (?, 'VULN_HAS_WEAKNESS', 'vulnerability:cve:CVE-2024-0001', 'weakness:cwe:CWE-79', 'cisa-kev', 'asserted_by_source', NULL, 'public', ?, ?)", old, NOW, NOW);
  raw(db, "INSERT INTO intel_relationship_evidence (relationship_id,kind,ref,source_id,observed_at,recorded_at) VALUES (?, 'source_statement', 'kev', 'cisa-kev', ?, ?)", old, NOW, NOW);
  raw(db, "INSERT INTO intel_relationship_evidence (relationship_id,kind,ref,source_id,observed_at,recorded_at) VALUES (?, 'source_statement', 'kev', 'cisa-kev', ?, ?)", old, NOW, NOW);   // a pre-0007 duplicate
  raw(db, "INSERT INTO intel_relationship_assessments (relationship_id,confidence,verification,reason,actor,at) VALUES (?, 'REPORTED', 'UNVERIFIED', 'legacy import', 'ingest', ?)", old, NOW);
  raw(db, "INSERT INTO intel_epss_history VALUES ('vulnerability:cve:CVE-2024-0001', 'first', '2026-01-01', 0.1, 0.2, NULL, ?)", NOW);
  const s5 = schema(), d5 = dump();
  db.raw.exec(MIG);
  assert.equal(dump(), d5, '0007 alters no 0001-0005 row (legacy duplicates and non-grammar keys stay)');
  await syncSourceApprovals(db, REGISTRY_TEXT, NOW);
  assert.equal(one(db, 'SELECT origin FROM intel_relationship_creation WHERE relationship_id = ?', old).origin, 'legacy_import', 'backfilled by 0007'); assert.equal(state(db, old), 'asserted', 'a legacy source assertion keeps its REPORTED state (approved source, statement evidence)');
  raw(db, "INSERT INTO intel_relationship_assessments (relationship_id,confidence,verification,reason,actor,at) VALUES (?, 'REPORTED', 'UNVERIFIED', 'again', 'ingest', ?)", old, NOW);   // re-asserted by its producer: allowed
  // 0007-era data
  await bootstrapReviewers(db);
  const v2 = await putEntity(db, { type: 'vulnerability', namespace: 'cve', key: 'CVE-2024-0002' }, NOW);
  const { id: neu } = await relate(db, { type: 'VULN_HAS_WEAKNESS', from: v2, to: 'weakness:cwe:CWE-79', source_id: 'cisa-kev', method: 'asserted_by_source', exposure: 'public', evidence: [{ kind: 'source_statement', ref: 'kev2' }], ...ING }, NOW);
  await assess(db, neu, { confidence: 'REPORTED', reason: 'kev listing', actor: 'source:cisa-kev' }, NOW); assert.ok(isPublic(db, neu));
  const d7 = dump();
  db.raw.exec(RB);
  assert.equal(schema(), s5, 'rollback: the 0005 schema, byte for byte');
  assert.equal(dump(), d7, 'rollback: every 0001-0005 row kept (including relationships created under 0007)');
  assert.equal(n(db, "SELECT COUNT(*) n FROM sqlite_master WHERE name LIKE 'intel_relationship_creation%' OR name LIKE 'intel_reviewer%' OR name LIKE 'intel_source_approval%'"), 0);
  db.raw.exec(MIG); assert.equal(one(db, 'SELECT origin FROM intel_relationship_creation WHERE relationship_id = ?', neu).origin, 'legacy_import', 'forward again: every relationship is backfilled as legacy_import');
  await syncSourceApprovals(db, REGISTRY_TEXT, NOW); assert.equal(state(db, neu), 'asserted'); { const vv = await verifyAssurance(db); assert.equal(vv.ok, true, JSON.stringify(vv)); }
});

test('hash-chain linkage on every 0007 log: a row whose prev_hash is not the head is refused even when it is unique (no fork, no gap)', async () => {
  const { db, e } = await world();
  const id = await asserted(db, { type: 'VULN_HAS_WEAKNESS', from: e.cve, to: e.cwe });
  const P = 'a'.repeat(64), H = 'b'.repeat(64);
  const rows = {
    intel_reviewer_events: ["INSERT INTO intel_reviewer_events (event,actor_id,github_user_id,role,by_1,by_2,reason,request_id,at,prev_hash,hash) VALUES ('add','user:eve',66,'REVIEWER','user:rev-a','user:rev-b','new reviewer','req-chain-0001',?,?,?)", NOW],
    intel_relationship_reviews: ['INSERT INTO intel_relationship_reviews (relationship_id,proposer,approver,decision,reason,at,prev_hash,hash) VALUES (?,?,?,?,?,?,?,?)', id, 'source:cisa-kev', 'user:rev-a', 'approve', 'checked it', NOW],
    intel_relationship_lifecycle_events: ['INSERT INTO intel_relationship_lifecycle_events (relationship_id,marker,actor,reason,at,prev_hash,hash) VALUES (?,?,?,?,?,?,?)', id, 'retracted', 'source:cisa-kev', 'withdrawn', NOW],
    intel_source_approval_events: ["INSERT INTO intel_source_approval_events (source_id,approval_state,registry_sha256,registry_as_of,at,prev_hash,hash) VALUES ('evil','APPROVED_PUBLIC',?,'2099-12-31',?,?,?)", 'c'.repeat(64), NOW],
  };
  for (const [table, [sql, ...a]] of Object.entries(rows)) assert.throws(() => raw(db, sql, ...a, P, H), /hash chain/, table);
  assert.equal((await verifyAssurance(db)).ok, true);
});

// ---- Codex intel-0007 round 1, F1 BLOCKER: INSERT OR REPLACE / REPLACE / upsert must never overwrite an append-only or immutable row ----------------------
test('F1 repro: a BLOCKED source re-chained as APPROVED_PUBLIC and written with INSERT OR REPLACE (same id) is refused; with schema rights it is caught by the registry cross-check', async () => {
  for (const recursive of [false, true]) {
    const db = newDb(M7); db.raw.exec(`PRAGMA recursive_triggers = ${recursive ? 'ON' : 'OFF'}`);
    const reg = JSON.stringify({ schema: 'macguard.intel-sources/1', as_of: '2026-11-01', sources: [{ id: 'shady-feed', approval_state: 'BLOCKED' }] });
    await syncSourceApprovals(db, reg, NOW);
    const row = one(db, 'SELECT * FROM intel_source_approval_events'), forged = { ...row, approval_state: 'APPROVED_PUBLIC' };
    forged.hash = await chainHash(row.prev_hash, { log: LOGS.intel_source_approval_events.tag, ...Object.fromEntries(LOGS.intel_source_approval_events.cols.map((c) => [c, forged[c]])) });
    const cols = Object.keys(forged), ins = (verb) => raw(db, `${verb} intel_source_approval_events (${cols}) VALUES (${cols.map(() => '?')})`, ...cols.map((c) => forged[c]));
    for (const verb of ['INSERT OR REPLACE INTO', 'REPLACE INTO', 'INSERT OR IGNORE INTO', 'INSERT OR ROLLBACK INTO', 'INSERT OR FAIL INTO']) assert.throws(() => ins(verb), /never overwritten|hash chain/, `${verb} (recursive_triggers ${recursive})`);
    assert.throws(() => raw(db, `INSERT INTO intel_source_approval_events (${cols}) VALUES (${cols.map(() => '?')}) ON CONFLICT(id) DO UPDATE SET approval_state = excluded.approval_state, hash = excluded.hash`, ...cols.map((c) => forged[c])), /never overwritten|hash chain/);
    assert.equal(one(db, 'SELECT approval_state FROM intel_source_approval_events').approval_state, 'BLOCKED');
    // with schema rights (triggers dropped) the replace succeeds, the chain still verifies, and the registry cross-check catches it
    for (const t of db.raw.prepare("SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'intel_source_approval_events'").all()) db.raw.exec(`DROP TRIGGER ${t.name}`);
    ins('INSERT OR REPLACE INTO');
    assert.equal((await verifyAssurance(db)).ok, true, 'a single consistently re-chained row is invisible to the chain');
    assert.equal((await verifySourceApprovals(db, reg)).ok, false, 'the registry cross-check detects it');
  }
});

/** One populated scratch database with a row in EVERY append-only or immutable table of 0004/0005/0007. */
async function everyTable() {
  const { db, e } = await world();
  const id = await asserted(db, { type: 'VULN_HAS_WEAKNESS', from: e.cve, to: e.cwe });
  rawEv(db, id, 'document', 'second', 'cisa-kev');
  await review(db, id, { approver: 'user:rev-a', decision: 'reject', reason: 'second look' }, NOW);
  const gone = await asserted(db, { type: 'VULN_HAS_WEAKNESS', from: e.cve2, to: e.cwe });   // retract ANOTHER relationship: the last assessment must stay re-insertable by every other trigger
  await setLifecycle(db, gone, { marker: 'retracted', actor: 'source:cisa-kev', reason: 'withdrawn' }, NOW);
  await assess(db, id, { confidence: 'REPORTED', reason: 'restated by the source', actor: 'source:cisa-kev' }, NOW);
  raw(db, "INSERT INTO intel_source_snapshots (source_id,snapshot_at,item_count,sha256,complete,recorded_at) VALUES ('cisa-kev','2026-11-01T00:00:00.000Z',5,?,1,?)", 'a'.repeat(64), NOW);
  raw(db, "INSERT INTO intel_severity_assessments (vuln_id,source_id,cvss_version,availability,vector,base_score,severity,assessed_at,recorded_at) VALUES (?,'nvd','3.1','AVAILABLE','CVSS:3.1/AV:N',9.8,'CRITICAL','2026-01-01T00:00:00.000Z',?)", e.cve, NOW);
  raw(db, "INSERT INTO intel_epss_latest VALUES (?, 'first', '2026-01-02', 0.1, 0.2, NULL, ?)", e.cve, NOW);
  raw(db, "INSERT INTO intel_epss_history VALUES (?, 'first', '2026-01-02', 0.1, 0.2, NULL, ?)", e.cve, NOW);
  raw(db, "INSERT INTO intel_exploitation_evidence (vuln_id,source_id,kind,listed_at,evidence_ref,observed_at,recorded_at) VALUES (?, 'cisa-kev', 'KEV_LISTED', '2026-01-01', 'kev/1', '2026-01-01T00:00:00.000Z', ?)", e.cve, NOW);
  const pr = await putEntity(db, { type: 'product', namespace: 'purl', key: 'pkg:npm/x' }, NOW), vr = await putEntity(db, { type: 'version_range', namespace: 'range', key: 'r1' }, NOW);
  raw(db, "INSERT INTO intel_version_ranges (entity_id,product_id,scheme,introduced) VALUES (?, ?, 'SEMVER', '1.0')", vr, pr);
  const pk = await putEntity(db, { type: 'package', namespace: 'yara', key: 'p@1' }, NOW), pk2 = await putEntity(db, { type: 'package', namespace: 'yara', key: 'p@2' }, NOW);
  raw(db, "INSERT INTO intel_packages (entity_id,family,tier,name,version,engine,format,items_count,size_bytes,manifest_sha256,artifact_sha256,licences,validation_state,created_at) VALUES (?, 'yara', 'community', 'p', '1', 'yara', 'yara-text', 1, 1, ?, ?, '[\"DRL-1.1\"]', 'ENGINE_COMPILED', ?)", pk, 'c'.repeat(64), 'd'.repeat(64), NOW);
  return { db, e, id, pk2 };
}
// [table, primary key columns, content change that passes the column CHECKs, secondary UNIQUE keys (a row with ANOTHER primary key but the same unique key)]
const GUARDED = [
  ['intel_entity_types', ['type'], { grp: 'forged' }, []],
  ['intel_relationship_types', ['type'], { note: 'forged' }, []],
  ['intel_entities', ['id'], { first_seen: '1999-01-01T00:00:00Z' }, []],
  ['intel_relationships', ['id'], { exposure: 'restricted' }, [{ id: '9'.repeat(64) }]],
  ['intel_relationship_evidence', ['id'], { ref: 'forged' }, [{ id: 999 }]],
  ['intel_relationship_assessments', ['id'], { reason: 'forged reason' }, []],
  ['intel_relationship_state', ['relationship_id'], { confidence: 'UNKNOWN', verification: 'UNVERIFIED', assessment_id: null, evidence_count: 0 }, []],
  ['intel_source_snapshots', ['id'], { item_count: 999 }, [{ id: 999 }]],
  ['intel_severity_assessments', ['id'], { recorded_at: 'forged' }, [{ id: 999 }]],
  ['intel_epss_latest', ['vuln_id', 'source_id'], { score_date: '2000-01-01' }, []],
  ['intel_epss_history', ['vuln_id', 'source_id', 'score_date'], { probability: 0.99 }, []],
  ['intel_exploitation_evidence', ['id'], { evidence_ref: 'forged' }, [{ id: 999 }]],
  ['intel_version_ranges', ['entity_id'], { introduced: '0.0.1' }, []],
  ['intel_packages', ['entity_id'], { tier: 'premium' }, [{ entity_id: 'PK2' }]],
  ['intel_relationship_creation', ['id'], { proposer: 'source:other' }, [{ id: 999 }]],
  ['intel_reviewer_events', ['id'], { role: 'ADMIN' }, [{ id: 999, prev_hash: '1'.repeat(64), hash: '2'.repeat(64) }]],
  ['intel_relationship_reviews', ['id'], { decision: 'approve' }, [{ id: 999, hash: '3'.repeat(64) }]],
  ['intel_relationship_lifecycle_events', ['id'], { reason: 'forged reason' }, [{ id: 999, hash: '4'.repeat(64) }]],
  ['intel_source_approval_events', ['id'], { approval_state: 'APPROVED_PUBLIC' }, [{ id: 999, hash: '5'.repeat(64) }]],
];
test('no overwrite (F1 class): every append-only or immutable table refuses INSERT OR REPLACE, REPLACE INTO, ON CONFLICT DO UPDATE/NOTHING and OR IGNORE on an existing key, and on any secondary UNIQUE key, with recursive_triggers OFF and ON', async () => {
  let attempts = 0;
  for (const recursive of ['OFF', 'ON']) {
    const { db, pk2 } = await everyTable(); db.raw.exec(`PRAGMA recursive_triggers = ${recursive}`);
    for (const [table, pk, change, uniques] of GUARDED) {
      const dump = () => JSON.stringify(db.raw.prepare(`SELECT * FROM ${table} ORDER BY ${pk.join(',')}`).all());
      const last = one(db, `SELECT * FROM ${table} ORDER BY ${pk.map((c) => `${c} DESC`).join(',')} LIMIT 1`); assert.ok(last, `${table} has a row`);
      const before = dump(), rows = [{ ...last, ...change }, last, ...uniques.map((u) => ({ ...last, ...Object.fromEntries(Object.entries(u).map(([k, v]) => [k, v === 'PK2' ? pk2 : v])) }))];
      for (const row of rows) {
        const cols = Object.keys(row), vals = cols.map((c) => row[c]), list = `(${cols.join(',')}) VALUES (${cols.map(() => '?').join(',')})`;
        const set = cols.filter((c) => !pk.includes(c)).map((c) => `${c} = excluded.${c}`).join(', ');
        for (const sql of [`INSERT OR REPLACE INTO ${table} ${list}`, `REPLACE INTO ${table} ${list}`, `INSERT INTO ${table} ${list} ON CONFLICT(${pk.join(',')}) DO UPDATE SET ${set}`,
          `INSERT INTO ${table} ${list} ON CONFLICT DO NOTHING`, `INSERT OR IGNORE INTO ${table} ${list}`]) {
          attempts++;
          let threw = false; try { raw(db, sql, ...vals); } catch { threw = true; }
          const identicalTypeRow = ['intel_entity_types', 'intel_relationship_types'].includes(table) && row === last;
          if (!identicalTypeRow) assert.ok(threw, `${table}: ${sql.split(' (')[0]} (recursive_triggers ${recursive}) was accepted`);
          assert.equal(dump(), before, `${table}: content changed by ${sql.split(' (')[0]} (recursive_triggers ${recursive})`);
        }
      }
    }
    assert.equal((await verifyAssurance(db)).ok, true);
  }
  assert.ok(attempts > 400, String(attempts));
});
test('no overwrite: the module writers still re-import idempotently (insert-if-absent, then UPDATE of the mutable columns)', async () => {
  const { db, e } = await world();
  const before = one(db, 'SELECT first_seen FROM intel_entities WHERE id = ?', e.cve).first_seen;
  await putEntity(db, { type: 'vulnerability', namespace: 'cve', key: 'CVE-2024-0001', display: 'new title' }, '2027-01-01T00:00:00Z');
  assert.deepEqual({ ...one(db, 'SELECT display, first_seen FROM intel_entities WHERE id = ?', e.cve) }, { display: 'new title', first_seen: before });
  const id = await asserted(db, { type: 'VULN_HAS_WEAKNESS', from: e.cve, to: e.cwe });
  assert.equal((await relate(db, { type: 'VULN_HAS_WEAKNESS', from: e.cve, to: e.cwe, source_id: 'cisa-kev', method: 'asserted_by_source', exposure: 'public', evidence: [{ kind: 'source_statement', ref: 'stmt' }], ...ING }, NOW)).created, false);
  assert.equal(n(db, 'SELECT evidence_count n FROM intel_relationship_state WHERE relationship_id = ?', id), 1);
});
test('no overwrite: log rows that EVERY other trigger would accept again (re-chained, guard conditions met) are still refused, recursive_triggers OFF and ON', async () => {
  for (const recursive of ['OFF', 'ON']) {
    const { db, e } = await world(); db.raw.exec(`PRAGMA recursive_triggers = ${recursive}`);
    const { id: fresh } = await relate(db, { type: 'RULE_ASSOCIATED_WITH_CVE', from: e.rule, to: e.cve, source_id: 'r', method: 'manual', ...ANALYST }, NOW);   // no evidence, no assessment yet
    await changeReviewer(db, { event: 'add', actor_id: 'user:eve', github_user_id: 66, by: ['user:rev-a', 'user:rev-b'], reason: 'new reviewer', request_id: 'req-eve-0001' }, NOW);
    await changeReviewer(db, { event: 'revoke', actor_id: 'user:eve', github_user_id: 66, by: ['user:rev-a', 'user:rev-b'], reason: 'left the team', request_id: 'req-eve-0002' }, NOW);
    const rel = await asserted(db, { type: 'VULN_HAS_WEAKNESS', from: e.cve, to: e.cwe });
    await setLifecycle(db, rel, { marker: 'retracted', actor: 'source:cisa-kev', reason: 'withdrawn' }, NOW); await setLifecycle(db, rel, { marker: 'reinstated', actor: 'source:cisa-kev', reason: 'back again' }, NOW);
    const targets = [
      ['intel_relationship_creation', one(db, 'SELECT * FROM intel_relationship_creation WHERE relationship_id = ?', fresh), { proposer: 'user:analyst-b' }, one(db, 'SELECT * FROM intel_relationships WHERE id = ?', fresh)],
      ['intel_reviewer_events', one(db, "SELECT * FROM intel_reviewer_events WHERE request_id = 'req-eve-0001'"), { role: 'ADMIN' }, null],
      ['intel_relationship_lifecycle_events', one(db, "SELECT * FROM intel_relationship_lifecycle_events WHERE marker = 'retracted'"), { reason: 'rewritten history' }, null],
    ];
    for (const [table, row, change, relRow] of targets) {
      const forged = { ...row, ...change }, en = { log: LOGS[table].tag }; for (const c of LOGS[table].cols) en[c] = forged[c] ?? null;
      if (relRow) Object.assign(en, { type: relRow.type, from_id: relRow.from_id, to_id: relRow.to_id, source_id: relRow.source_id, method: relRow.method });
      forged.hash = await chainHash(row.prev_hash, en);
      const cols = Object.keys(forged), before = JSON.stringify(db.raw.prepare(`SELECT * FROM ${table} ORDER BY id`).all());
      for (const verb of ['INSERT OR REPLACE INTO', 'REPLACE INTO']) assert.throws(() => raw(db, `${verb} ${table} (${cols}) VALUES (${cols.map(() => '?')})`, ...cols.map((c) => forged[c])), /never overwritten|hash chain/, `${table} ${verb} (${recursive})`);
      assert.equal(JSON.stringify(db.raw.prepare(`SELECT * FROM ${table} ORDER BY id`).all()), before, table);
    }
  }
});

test('caller time is informational (Codex fix round MEDIUM): out-of-order timestamps verify ok with a warning on every 0007 log; a reordered or replaced row is still detected', async () => {
  const { db, e } = await world();
  const reg2 = registryWith(['nvd']);
  await syncSourceApprovals(db, reg2, '2026-11-02T00:00:02Z'); await syncSourceApprovals(db, registryWith([]), '2026-11-02T00:00:01Z');   // the later request finishes first
  const { id } = await relate(db, { type: 'RULE_DETECTS_CVE', from: e.rule, to: e.cve, source_id: 'lab', method: 'manual', ...ANALYST }, '2026-11-03T00:00:00Z');
  await relate(db, { type: 'RULE_DETECTS_CVE', from: e.rule2, to: e.cve, source_id: 'lab', method: 'manual', ...ANALYST }, '2026-11-01T00:00:00Z');
  await review(db, id, { approver: 'user:rev-a', decision: 'reject', reason: 'later decision' }, '2026-11-03T00:00:00Z'); await review(db, id, { approver: 'user:rev-b', decision: 'approve', reason: 'earlier clock' }, '2026-11-01T00:00:00Z');
  await changeReviewer(db, { event: 'add', actor_id: 'user:eve', github_user_id: 66, by: ['user:rev-a', 'user:rev-b'], reason: 'clock behind', request_id: 'req-skew-0001' }, '2000-01-01T00:00:00Z');
  const rel = await asserted(db, { type: 'VULN_HAS_WEAKNESS', from: e.cve, to: e.cwe });
  await setLifecycle(db, rel, { marker: 'retracted', actor: 'source:cisa-kev', reason: 'withdrawn' }, '2026-11-05T00:00:00Z'); await setLifecycle(db, rel, { marker: 'reinstated', actor: 'source:cisa-kev', reason: 'back again' }, '2026-11-04T00:00:00Z');
  const v = await verifyAssurance(db);
  assert.equal(v.ok, true, JSON.stringify(v.logs));
  for (const t of Object.keys(LOGS)) assert.ok(v.logs[t].warnings.length >= 1, `${t}: skew reported as a warning`);
  // genuine tampering is still detected, through ids/chain/sequence, not time
  for (const t of db.raw.prepare("SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'intel_relationship_reviews'").all()) db.raw.exec(`DROP TRIGGER ${t.name}`);
  raw(db, 'UPDATE intel_relationship_reviews SET id = id + 100'); raw(db, "UPDATE intel_relationship_reviews SET id = 1 WHERE reason = 'earlier clock'"); raw(db, "UPDATE intel_relationship_reviews SET id = 2 WHERE reason = 'later decision'");
  assert.match((await verifyAssurance(db)).logs.intel_relationship_reviews.error, /chain link broken/, 'reordered rows (dense ids kept)');
  raw(db, "UPDATE intel_relationship_reviews SET id = 3 WHERE reason = 'later decision'"); raw(db, "UPDATE intel_relationship_reviews SET id = 2 WHERE reason = 'earlier clock'"); raw(db, "UPDATE intel_relationship_reviews SET id = 1 WHERE reason = 'later decision'");
  assert.equal((await verifyAssurance(db)).logs.intel_relationship_reviews.ok, true, 'order restored');
  raw(db, "UPDATE intel_relationship_reviews SET decision = 'approve', approver = 'user:rev-a' WHERE id = 1");
  assert.match((await verifyAssurance(db)).logs.intel_relationship_reviews.error, /content was altered/, 'replaced row content');
});

// ---- Codex intel-0007 final round, F1 HIGH: relationships that predate 0007 are backfilled (legacy_import) and every producer can re-import them --------
/** Pre-0007 data exactly as the 0004/0005 producers wrote it (content-derived ids; evidence without original_source_id), on a 0001-0005 database. */
async function legacyWorld() {
  const db = newDb(M5), T = '2026-10-01T00:00:00Z';
  const ent = (type, ns, key) => { insEnt(db, type, ns, key); return `${type}:${ns}:${key}`; };
  const cve = ent('vulnerability', 'cve', 'CVE-2025-0101'), cve2 = ent('vulnerability', 'cve', 'CVE-2025-0202'), euvd = ent('vulnerability', 'euvd', 'EUVD-2025-9');
  const g0 = ent('vulnerability', 'gcve', 'GCVE-0-2024-12345'), cg = ent('vulnerability', 'cve', 'CVE-2024-12345'), cwe = ent('weakness', 'cwe', 'CWE-79');
  const rule = ent('rule', 'yara', 'rules/a/b.yar#R1'), prod = ent('product', 'purl', 'pkg:npm/left-pad');
  const rels = {};
  const rel = async (name, type, from, to, source_id, method, exposure, ev = [], as = []) => {
    const id = await relationshipId({ type, from, to, source_id, method });
    raw(db, 'INSERT INTO intel_relationships (id,type,from_id,to_id,source_id,method,version,exposure,observed_at,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)', id, type, from, to, source_id, method, 'macguard.norm/1', exposure, T, T);
    for (const [kind, ref, src] of ev) raw(db, 'INSERT INTO intel_relationship_evidence (relationship_id,kind,ref,source_id,observed_at,recorded_at) VALUES (?,?,?,?,?,?)', id, kind, ref, src ?? source_id, T, T);
    for (const [c, v, actor] of as) raw(db, 'INSERT INTO intel_relationship_assessments (relationship_id,confidence,verification,reason,actor,at) VALUES (?,?,?,?,?,?)', id, c, v, 'legacy assessment', actor, T);
    rels[name] = id; return id;
  };
  const SRC = 'https://example.org/feed/item/1';
  await rel('alias', 'ALIAS_OF', euvd, cve, 'enisa-euvd', 'asserted_by_source', 'public', [['source_statement', SRC]], [['REPORTED', 'UNVERIFIED', 'ingest']]);
  await rel('aliasDisputed', 'ALIAS_OF', euvd, cve2, 'other-feed', 'asserted_by_source', 'public', [['source_statement', SRC]], [['REPORTED', 'UNVERIFIED', 'ingest'], ['DISPUTED', 'UNVERIFIED', 'system']]);
  await rel('gcve', 'ALIAS_OF', g0, cg, 'gcve-spec', 'asserted_by_source', 'public', [['document', 'GCVE BCP-03: GCVE-0 is the CVE namespace']], [['REPORTED', 'UNVERIFIED', 'ingest']]);
  await rel('kevCwe', 'VULN_HAS_WEAKNESS', cve, cwe, 'cisa-kev', 'asserted_by_source', 'public', [['source_statement', 'kev cwes']], [['REPORTED', 'UNVERIFIED', 'engine:R-KEV-CWE-1']]);
  await rel('ruleLink', 'RULE_ASSOCIATED_WITH_CVE', rule, cve, 'yara-upstream:community', 'asserted_by_source', 'internal', [['source_statement', 'meta cve']], [['REPORTED', 'UNVERIFIED', 'engine:R-YARA-CVE-1']]);
  await rel('detects', 'RULE_DETECTS_CVE', rule, cve2, 'lab', 'asserted_by_source', 'public', [['source_statement', 'claim'], ['test_run', 'run-1']], [['CONFIRMED', 'VERIFIED', 'qa']]);
  await rel('correlated', 'RULE_ASSOCIATED_WITH_CVE', rule, cve2, 'ai:llm', 'correlated', 'public', [['content_match', 'names']], [['INFERRED', 'UNVERIFIED', 'ai:llm']]);
  return { db, rels, e: { cve, cve2, euvd, g0, cg, cwe, rule, prod }, SRC };
}
test('F1 (final round): 0007 backfills every pre-0007 relationship as legacy_import; every producer re-imports it; legacy may keep REPORTED but never becomes VERIFIED without a review; rollback stays byte-identical', async () => {
  const { db, rels, e, SRC } = await legacyWorld();
  const schema = () => JSON.stringify(db.raw.prepare("SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name <> 'sqlite_sequence' ORDER BY type, name").all());
  const s5 = schema(), evBefore = db.raw.prepare('SELECT relationship_id, COUNT(*) n FROM intel_relationship_evidence GROUP BY 1 ORDER BY 1').all().map((r) => ({ ...r }));
  db.raw.exec(MIG);
  const cr = db.raw.prepare('SELECT * FROM intel_relationship_creation ORDER BY id').all();
  assert.deepEqual(cr.map((r) => r.relationship_id), Object.values(rels).sort(), 'one record per relationship, in relationship-id order');
  assert.ok(cr.every((r, i) => r.origin === 'legacy_import' && r.proposer === 'migration:0007' && r.prev_hash === String(i).padStart(64, '0') && r.hash === String(i + 1).padStart(64, '0')));
  await syncSourceApprovals(db, registryWith(['enisa-euvd', 'other-feed', 'gcve-spec', 'osv']), NOW); await bootstrapReviewers(db);
  { const v0 = await verifyAssurance(db); assert.equal(v0.ok, true, JSON.stringify(v0.logs.intel_relationship_creation) + JSON.stringify(v0.cross));assert.equal(v0.cross.warnings.length, 1, 'the legacy VERIFIED without a review is a warning'); }
  assert.deepEqual(Object.fromEntries(Object.entries(rels).map(([k, v]) => [k, state(db, v)])), { alias: 'asserted', aliasDisputed: 'disputed', gcve: 'asserted', kevCwe: 'asserted', ruleLink: 'candidate', detects: 'candidate', correlated: 'candidate' },
    'legacy keeps its assessed state; a legacy VERIFIED without a review and a correlation stay candidate');
  // every producer re-imports, nothing duplicates
  await recordAlias(db, { from: e.euvd, to: e.cve, source_id: 'enisa-euvd', evidence: { kind: 'source_statement', ref: SRC }, observed_at: NOW }, NOW);
  await recordAlias(db, { from: e.euvd, to: e.cve2, source_id: 'other-feed', evidence: { kind: 'source_statement', ref: SRC }, observed_at: NOW }, NOW);
  assert.ok((await linkGcve0(db, 'GCVE-0-2024-12345', NOW)) && true);
  await relate(db, { type: 'VULN_HAS_WEAKNESS', from: e.cve, to: e.cwe, source_id: 'cisa-kev', method: 'asserted_by_source', exposure: 'public', evidence: [{ kind: 'source_statement', ref: 'kev cwes' }], origin: 'engine_rule', rule_id: 'R-KEV-CWE-1' }, NOW);
  await assess(db, rels.kevCwe, { confidence: 'REPORTED', reason: 'kev cwes field', actor: 'engine:R-KEV-CWE-1' }, NOW);
  await relate(db, { type: 'RULE_ASSOCIATED_WITH_CVE', from: e.rule, to: e.cve, source_id: 'yara-upstream:community', method: 'asserted_by_source', exposure: 'internal', evidence: [{ kind: 'source_statement', ref: 'meta cve', source_id: 'yara-upstream:community' }], origin: 'engine_rule', rule_id: 'R-YARA-CVE-1' }, NOW);
  await assess(db, rels.ruleLink, { confidence: 'REPORTED', reason: 'meta cve', actor: 'engine:R-YARA-CVE-1' }, NOW);
  await addAffectedRange(db, { vuln_id: e.cve, product: { namespace: 'purl', key: 'pkg:npm/left-pad' }, scheme: 'SEMVER', introduced: '1.0.0', fixed: '1.3.1', source_id: 'osv', evidence: { kind: 'source_statement', ref: SRC } }, NOW);
  assert.deepEqual(db.raw.prepare('SELECT relationship_id, COUNT(*) n FROM intel_relationship_evidence WHERE relationship_id IN (' + Object.values(rels).map(() => '?').join(',') + ') GROUP BY 1 ORDER BY 1').all(...Object.values(rels)).map((r) => ({ ...r })), evBefore, 're-imports never duplicate pre-0007 evidence');
  assert.equal(n(db, "SELECT COUNT(*) n FROM intel_relationship_creation WHERE origin = 'legacy_import'"), Object.keys(rels).length, 'a re-import keeps the legacy creation record');
  // what legacy_import may NOT do
  for (const actor of ['migration:0007', 'qa', 'user:rev-a']) assert.throws(() => rawAs(db, rels.detects, 'CONFIRMED', 'VERIFIED', actor), /approved review/, actor);
  assert.throws(() => rawAs(db, rels.correlated, 'REPORTED', 'UNVERIFIED', 'user:rev-a'), /never reaches REPORTED/);
  await assert.rejects(setLifecycle(db, rels.kevCwe, { marker: 'retracted', actor: 'migration:0007', reason: 'not the source' }, NOW), /original source or the proposer/);
  await assert.rejects(rawChained(db, 'intel_relationship_creation', { relationship_id: rels.kevCwe, exposure: 'public', proposer: 'migration:0007', origin: 'legacy_import', rule_id: null, created_at: '2026-10-01T00:00:00Z' }), /legacy_import|never overwritten/, 'no legacy record at runtime');
  const fresh = await rawRel(db, { type: 'RULE_DETECTS_CVE', from: e.rule, to: e.cg, source_id: 'lab', method: 'manual' });   // created after 0007 WITHOUT a creation record
  const freshRow = one(db, 'SELECT * FROM intel_relationships WHERE id = ?', fresh);
  await assert.rejects(rawChained(db, 'intel_relationship_creation', { relationship_id: fresh, exposure: 'public', proposer: 'migration:0007', origin: 'legacy_import', rule_id: null, created_at: NOW }, freshRow), /legacy_import|origin and method disagree/, 'a post-0007 relationship cannot pose as legacy');
  // ... and what it MAY do with a review: the reviewed legacy detection becomes verified
  await review(db, rels.detects, { approver: 'user:rev-a', decision: 'approve', reason: 'replayed run-1' }, NOW);
  rawAs(db, rels.detects, 'CONFIRMED', 'VERIFIED', 'user:rev-a'); assert.equal(state(db, rels.detects), 'verified');
  await setLifecycle(db, rels.kevCwe, { marker: 'retracted', actor: 'source:cisa-kev', reason: 'source withdrew it' }, NOW); assert.equal(state(db, rels.kevCwe), 'retracted');
  const v = await verifyAssurance(db); assert.equal(v.ok, true, JSON.stringify(v.logs.intel_relationship_creation));
  // the verifier: a legacy record forged after the prefix, or an altered one, is detected
  const t = await legacyWorld(); t.db.raw.exec(MIG); t.db.raw.exec('DROP TRIGGER intel_rel_creation_no_overwrite'); t.db.raw.exec('DROP TRIGGER intel_rel_creation_no_update');
  raw(t.db, "UPDATE intel_relationship_creation SET exposure = 'restricted' WHERE id = 1"); assert.equal((await verifyAssurance(t.db)).ok, false, 'altered legacy record');
  db.raw.exec(RB); assert.equal(schema(), s5, 'rollback after a backfill: the 0005 schema, byte for byte');
});

// ---- Codex intel-0007 final round, F2 HIGH: a stale registry sync never restores a revoked approval ------------------------------------------------------
const reg = (as_of, state) => JSON.stringify({ schema: 'macguard.intel-sources/1', as_of, sources: [{ id: 's', approval_state: state }, { id: 'cisa-kev', approval_state: 'APPROVED_PUBLIC' }] });
const approval = (db) => ({ ...one(db, "SELECT approval_state, registry_as_of FROM intel_source_approvals WHERE source_id = 's'") });
test('F2 (final round): the exact interleaving: a stale sync paused before its write cannot restore a revoked public approval (DB-enforced), in either completion order', async () => {
  const A = reg('2026-11-01', 'APPROVED_PUBLIC'), B = reg('2026-11-02', 'BLOCKED');
  // A plans (reads head + projection), B completes, A resumes
  const db = newDb(M7), planA = await planSourceApprovals(db, A, NOW);
  await syncSourceApprovals(db, B, NOW);
  await assert.rejects(applySourceApprovals(db, planA), /hash chain|stale or conflicting/, 'compare-and-swap on the head');
  await assert.rejects(syncSourceApprovals(db, A, NOW), /stale or conflicting/, 're-planned on the new head: refused as stale');
  assert.deepEqual(approval(db), { approval_state: 'BLOCKED', registry_as_of: '2026-11-02' });
  // B plans, A completes first, B resumes: the newer revocation still wins
  const db2 = newDb(M7), planB = await planSourceApprovals(db2, B, NOW);
  await syncSourceApprovals(db2, A, NOW); assert.equal(approval(db2).approval_state, 'APPROVED_PUBLIC');
  await assert.rejects(applySourceApprovals(db2, planB), /hash chain/, 'the stale plan of the NEWER registry is refused as a unit ...');
  await syncSourceApprovals(db2, B, NOW); assert.deepEqual(approval(db2), { approval_state: 'BLOCKED', registry_as_of: '2026-11-02' }, '... and re-planned it wins');
  // a raw-SQL writer who chains correctly is still refused by the database
  const head = one(db, 'SELECT hash FROM intel_source_approval_events ORDER BY id DESC LIMIT 1').hash, row = { source_id: 's', approval_state: 'APPROVED_PUBLIC', registry_sha256: 'a'.repeat(64), registry_as_of: '2026-11-01', at: NOW };
  const hash = await chainHash(head, { log: LOGS.intel_source_approval_events.tag, ...row });
  assert.throws(() => raw(db, 'INSERT INTO intel_source_approval_events (source_id,approval_state,registry_sha256,registry_as_of,at,prev_hash,hash) VALUES (?,?,?,?,?,?,?)', ...Object.values(row), head, hash), /stale or conflicting/);
  // atomic: a sync is all or nothing (one batch)
  const db3 = newDb(M7); await syncSourceApprovals(db3, B, NOW);
  const multi = JSON.stringify({ schema: 'macguard.intel-sources/1', as_of: '2026-11-03', sources: [{ id: 'a-first', approval_state: 'APPROVED_PUBLIC' }, { id: 's', approval_state: 'APPROVED_PUBLIC' }] });
  const plan = await planSourceApprovals(db3, multi, NOW); plan.rows[1].hash = 'f'.repeat(64);   // the second row breaks: nothing of the sync may land
  await assert.rejects(applySourceApprovals(db3, plan));
  assert.equal(n(db3, "SELECT COUNT(*) n FROM intel_source_approval_events WHERE registry_as_of = '2026-11-03'"), 0, 'no partial sync');
  assert.equal((await verifyAssurance(db3)).ok, true);
});
test('F2 (final round): equal as_of with different content is a conflict; equal as_of with the same bytes is idempotent; an older identical registry is a no-op', async () => {
  const db = newDb(M7), B = reg('2026-11-02', 'BLOCKED');
  await syncSourceApprovals(db, B, NOW);
  assert.deepEqual((await syncSourceApprovals(db, B, '2026-11-03T00:00:00Z')).changed, [], 'same bytes again: nothing appended');
  await assert.rejects(syncSourceApprovals(db, reg('2026-11-02', 'APPROVED_PUBLIC'), NOW), /stale or conflicting/, 'same as_of, other content');
  assert.deepEqual((await syncSourceApprovals(db, reg('2026-11-01', 'BLOCKED'), NOW)).changed, [], 'an older registry that changes nothing writes nothing');
  await syncSourceApprovals(db, reg('2026-11-04', 'APPROVED_PUBLIC'), NOW); assert.deepEqual(approval(db), { approval_state: 'APPROVED_PUBLIC', registry_as_of: '2026-11-04' }, 'a newer registry may re-approve');
  assert.equal((await verifyAssurance(db)).ok, true);
});
