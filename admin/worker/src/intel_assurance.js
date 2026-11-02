// Correlation assurance (INTEL migration 0007, contract docs/design/CORRELATION-ENGINE.md v3 §3/§4.1/§4.2/§9 C3): the writers and the verifier of the five
// hash-chained, append-only logs (relationship creation, reviewer allow-list events, reviews, lifecycle markers, source approvals).
// The DATABASE enforces who may write what (triggers, see the migration header for what it can and cannot guarantee); this module computes the chain hashes
// (SQLite cannot compute SHA-256), retries when a concurrent writer moved the head, and verifies every log end to end (tamper-evidence).
// Hash = SHA-256(prev_hash || canonical(entry)): the panel audit-chain function of core.js, reused unchanged.
import { chainHash, GENESIS, sha256hex } from './core.js';

class AssuranceError extends Error { constructor(msg, code = 'invalid') { super(msg); this.code = code; } }
export { AssuranceError };

export const ORIGINS = ['source_ingest', 'engine_rule', 'analyst', 'ai_proposed'];
export const CRITICAL_TYPES = ['RULE_DETECTS_CVE', 'RULE_DETECTS_CVE_BEHAVIOUR', 'INDICATOR_ASSOCIATED_WITH_CVE', 'ALIAS_OF'];
export const APPROVAL_STATES = ['RETAINED', 'APPROVED_INTERNAL', 'APPROVED_PUBLIC', 'APPROVED_PREMIUM', 'BLOCKED'];
const REVIEWER_ID = /^user:[a-z0-9][a-z0-9-]{0,38}$/;
const SOURCE_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const need = (c, m) => { if (!c) throw new AssuranceError(m); };

/** The log tables, their chained columns (in hash order) and the entry tag. The tag separates the logs: an entry of one log never verifies in another. */
export const LOGS = Object.freeze({
  intel_relationship_creation: { tag: 'macguard.intel.creation/1', cols: ['relationship_id', 'exposure', 'proposer', 'origin', 'rule_id', 'created_at'] },
  intel_reviewer_events: { tag: 'macguard.intel.reviewer/1', cols: ['event', 'actor_id', 'github_user_id', 'role', 'by_1', 'by_2', 'reason', 'request_id', 'at'] },
  intel_relationship_reviews: { tag: 'macguard.intel.review/1', cols: ['relationship_id', 'proposer', 'approver', 'decision', 'reason', 'at'] },
  intel_relationship_lifecycle_events: { tag: 'macguard.intel.lifecycle/1', cols: ['relationship_id', 'marker', 'actor', 'reason', 'at'] },
  intel_source_approval_events: { tag: 'macguard.intel.source-approval/1', cols: ['source_id', 'approval_state', 'registry_sha256', 'registry_as_of', 'at'] },
});
/** Canonical entry of one row. A creation entry also covers the immutable identity of its relationship (type, endpoints, source, method), so a relationship
 *  row rewritten after dropping the 0004 immutability trigger no longer verifies. */
export function entryOf(table, row, rel = null) {
  const L = LOGS[table], e = { log: L.tag };
  for (const c of L.cols) e[c] = row[c] ?? null;
  if (table === 'intel_relationship_creation') { e.type = rel?.type ?? null; e.from_id = rel?.from_id ?? null; e.to_id = rel?.to_id ?? null; e.source_id = rel?.source_id ?? null; e.method = rel?.method ?? null; }
  return e;
}
const isChainConflict = (e) => /hash chain|UNIQUE constraint failed: \w+\.(prev_hash|hash)/.test(String(e?.message ?? e));

/** Append to a chained log: read the head, hash, write (via `write(prev, hash)`, usually one batch), retry when another writer moved the head meanwhile. */
export async function chained(db, table, entry, write, { attempts = 8 } = {}) {
  need(LOGS[table], `not a chained log: ${table}`);
  for (let i = 0; ; i++) {
    const head = await db.prepare(`SELECT hash FROM ${table} ORDER BY id DESC LIMIT 1`).first();
    const prev = head?.hash ?? GENESIS, hash = await chainHash(prev, entry);
    try { return await write(prev, hash); } catch (e) { if (i + 1 < attempts && isChainConflict(e)) continue; throw e; }
  }
}

// ---- (d) reviewer allow-list -----------------------------------------------------------------------------------------------------------------------
/** Add or revoke a reviewer. The database requires two DISTINCT ACTIVE reviewers other than the person (`by`), refuses self-registration and any non-human id.
 *  The Worker must pass the authenticated session's own reviewer ids in `by`, never ids supplied by the client. */
export async function changeReviewer(db, { event, actor_id, github_user_id, role = 'REVIEWER', by = [], reason, request_id }, now) {
  need(['add', 'revoke'].includes(event), 'event is add or revoke'); need(REVIEWER_ID.test(actor_id ?? ''), 'a reviewer is user:<github login> (a human account)');
  need(Number.isSafeInteger(github_user_id) && github_user_id > 0, 'github_user_id: the immutable GitHub account id'); need(Array.isArray(by) && by.length === 2, 'two signing reviewers');
  const row = { event, actor_id, github_user_id, role, by_1: by[0], by_2: by[1], reason, request_id, at: now };
  return chained(db, 'intel_reviewer_events', entryOf('intel_reviewer_events', row), (prev, hash) => db.prepare('INSERT INTO intel_reviewer_events (event,actor_id,github_user_id,role,by_1,by_2,reason,request_id,at,prev_hash,hash) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
    .bind(event, actor_id, github_user_id, role, by[0], by[1], reason, request_id, now, prev, hash).run());
}
/** The guard trigger exactly as 0007 creates it (a test keeps them identical). A bootstrap migration drops it, inserts, and recreates it with this text. */
export const REVIEWER_GUARD_SQL = "CREATE TRIGGER IF NOT EXISTS intel_reviewer_events_guard BEFORE INSERT ON intel_reviewer_events WHEN COALESCE((SELECT x.event FROM intel_reviewer_events x WHERE x.actor_id = NEW.by_1 ORDER BY x.id DESC LIMIT 1), '') <> 'add' OR COALESCE((SELECT x.event FROM intel_reviewer_events x WHERE x.actor_id = NEW.by_2 ORDER BY x.id DESC LIMIT 1), '') <> 'add' OR (NEW.event = 'add' AND (COALESCE((SELECT x.event FROM intel_reviewer_events x WHERE x.actor_id = NEW.actor_id ORDER BY x.id DESC LIMIT 1), '') = 'add' OR EXISTS (SELECT 1 FROM intel_reviewer_events g WHERE g.github_user_id = NEW.github_user_id AND g.event = 'add' AND g.id = (SELECT MAX(z.id) FROM intel_reviewer_events z WHERE z.actor_id = g.actor_id)))) OR (NEW.event = 'revoke' AND NOT EXISTS (SELECT 1 FROM intel_reviewer_events a WHERE a.actor_id = NEW.actor_id AND a.event = 'add' AND a.github_user_id = NEW.github_user_id AND a.id = (SELECT MAX(z.id) FROM intel_reviewer_events z WHERE z.actor_id = NEW.actor_id))) BEGIN SELECT RAISE(ABORT, 'reviewer change refused: two distinct ACTIVE reviewers other than the person must sign it; add only a non-reviewer (one GitHub account, one reviewer); revoke only an active reviewer'); END;";
const q = (s) => `'${String(s).replace(/'/g, "''")}'`;
/** Text of a bootstrap MIGRATION adding the first reviewers (owner decision: who they are). Each row is signed by the migration and the owner's approval record,
 *  chained from `prevHash` (GENESIS on an empty log). The only way to add a reviewer without two existing ones; there is no runtime equivalent. */
export async function reviewerBootstrapSql(reviewers, { migration, approval_record, at, prevHash = GENESIS }) {
  need(/^migration:[0-9]{4}[a-z0-9_]*$/.test(migration ?? ''), 'migration:<NNNN_name>'); need(/^owner-approval:[A-Za-z0-9._#/-]{3,100}$/.test(approval_record ?? ''), 'owner-approval:<record>');
  need(Array.isArray(reviewers) && reviewers.length >= 2, 'at least two reviewers, so that later changes can be signed by two');
  const out = ['-- Reviewer bootstrap (generated by reviewerBootstrapSql). Apply ONCE, as a migration; the guard is recreated verbatim at the end.', 'DROP TRIGGER IF EXISTS intel_reviewer_events_guard;'];
  let prev = prevHash, n = 0;
  for (const r of reviewers) {
    need(REVIEWER_ID.test(r.actor_id ?? '') && Number.isSafeInteger(r.github_user_id) && r.github_user_id > 0, 'reviewer: user:<login> + github_user_id');
    const row = { event: 'add', actor_id: r.actor_id, github_user_id: r.github_user_id, role: r.role ?? 'REVIEWER', by_1: migration, by_2: approval_record, reason: r.reason ?? 'initial reviewer (owner decision)', request_id: `${migration}:${++n}`, at };
    const hash = await chainHash(prev, entryOf('intel_reviewer_events', row));
    out.push(`INSERT INTO intel_reviewer_events (event,actor_id,github_user_id,role,by_1,by_2,reason,request_id,at,prev_hash,hash) VALUES (${['add', row.actor_id].map(q).join(',')},${row.github_user_id},${[row.role, row.by_1, row.by_2, row.reason, row.request_id, row.at, prev, hash].map(q).join(',')});`);
    prev = hash;
  }
  out.push(REVIEWER_GUARD_SQL);
  return out.join('\n') + '\n';
}

// ---- (e) reviews, (j) lifecycle ----------------------------------------------------------------------------------------------------------------------
/** Record a review of a relationship. The proposer is read from its creation record (never supplied by the caller). */
export async function review(db, relId, { approver, decision, reason }, now) {
  need(['approve', 'reject'].includes(decision), 'decision is approve or reject');
  const c = await db.prepare('SELECT proposer FROM intel_relationship_creation WHERE relationship_id = ?').bind(relId).first();
  need(c, 'no creation record: the relationship cannot be reviewed');
  const row = { relationship_id: relId, proposer: c.proposer, approver, decision, reason, at: now };
  return chained(db, 'intel_relationship_reviews', entryOf('intel_relationship_reviews', row), (prev, hash) => db.prepare('INSERT INTO intel_relationship_reviews (relationship_id,proposer,approver,decision,reason,at,prev_hash,hash) VALUES (?,?,?,?,?,?,?,?)')
    .bind(relId, c.proposer, approver, decision, reason, now, prev, hash).run());
}
/** Retract (or reinstate) a relationship. Only its original source ('source:<source_id>') or its proposer may (database rule). */
export async function setLifecycle(db, relId, { marker, actor, reason }, now) {
  need(['retracted', 'reinstated'].includes(marker), 'marker is retracted or reinstated');
  const row = { relationship_id: relId, marker, actor, reason, at: now };
  return chained(db, 'intel_relationship_lifecycle_events', entryOf('intel_relationship_lifecycle_events', row), (prev, hash) => db.prepare('INSERT INTO intel_relationship_lifecycle_events (relationship_id,marker,actor,reason,at,prev_hash,hash) VALUES (?,?,?,?,?,?,?)')
    .bind(relId, marker, actor, reason, now, prev, hash).run());
}

// ---- (i) source approval -------------------------------------------------------------------------------------------------------------------------------
/** Deterministic loader: config/intel/sources.registry.json (its exact bytes) -> intel_source_approval_events. Appends one event per source whose state changed
 *  (sorted by id), and 'ABSENT' for a recorded source that left the registry. Idempotent: the same registry twice appends nothing. It never edits the registry.
 *  ATOMIC and MONOTONIC (Codex intel-0007 final round, F2): planSourceApprovals() reads the chain head FIRST, then the projection; applySourceApprovals()
 *  writes the whole plan in ONE batch chained from that head, so a sync that another sync overtook fails as a unit (chain trigger = compare-and-swap) and
 *  is re-planned from the new state; the database refuses any event from a registry older than (or conflicting with, at equal as_of) one already applied. */
export async function planSourceApprovals(db, registryText, now) {
  need(typeof registryText === 'string', 'registry text');
  let reg; try { reg = JSON.parse(registryText); } catch { throw new AssuranceError('registry is not JSON'); }
  need(reg?.schema === 'macguard.intel-sources/1' && Array.isArray(reg.sources) && /^\d{4}-\d{2}-\d{2}$/.test(reg.as_of ?? ''), 'not a macguard.intel-sources/1 registry');
  const sha = await sha256hex(registryText), want = new Map();
  for (const s of reg.sources) {
    need(typeof s?.id === 'string' && SOURCE_ID.test(s.id) && !want.has(s.id), `bad or duplicate source id ${JSON.stringify(s?.id)}`);
    need(typeof s.approval_state === 'string' && APPROVAL_STATES.includes(s.approval_state), `${s.id}: unknown approval_state`);
    want.set(s.id, s.approval_state);
  }
  const head = (await db.prepare('SELECT hash FROM intel_source_approval_events ORDER BY id DESC LIMIT 1').first())?.hash ?? GENESIS;
  const cur = new Map((await db.prepare('SELECT source_id, approval_state FROM intel_source_approvals ORDER BY source_id LIMIT 10000').all()).results.map((r) => [r.source_id, r.approval_state]));
  for (const id of cur.keys()) if (!want.has(id) && cur.get(id) !== 'ABSENT') want.set(id, 'ABSENT');
  const changes = [...want.entries()].filter(([id, st]) => cur.get(id) !== st).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  const rows = []; let prev = head;
  for (const [source_id, approval_state] of changes) {
    const row = { source_id, approval_state, registry_sha256: sha, registry_as_of: reg.as_of, at: now }, hash = await chainHash(prev, entryOf('intel_source_approval_events', row));
    rows.push({ ...row, prev_hash: prev, hash }); prev = hash;
  }
  return { registry_sha256: sha, registry_as_of: reg.as_of, head, rows };
}
export async function applySourceApprovals(db, plan) {
  if (plan.rows.length) await db.batch(plan.rows.map((r) => db.prepare('INSERT INTO intel_source_approval_events (source_id,approval_state,registry_sha256,registry_as_of,at,prev_hash,hash) VALUES (?,?,?,?,?,?,?)')
    .bind(r.source_id, r.approval_state, r.registry_sha256, r.registry_as_of, r.at, r.prev_hash, r.hash)));
  return { registry_sha256: plan.registry_sha256, changed: plan.rows.map((r) => ({ source_id: r.source_id, approval_state: r.approval_state })) };
}
export async function syncSourceApprovals(db, registryText, now, { attempts = 8 } = {}) {
  for (let i = 0; ; i++) {
    const plan = await planSourceApprovals(db, registryText, now);
    try { return await applySourceApprovals(db, plan); } catch (e) { if (i + 1 < attempts && isChainConflict(e)) continue; throw e; }
  }
}

// ---- verifier (tamper-evidence) -------------------------------------------------------------------------------------------------------------------------
const relIdOf = async (r) => sha256hex(JSON.stringify(['macguard.rel/1', r.type, r.from_id, r.to_id, r.source_id, r.method]));
/** Recompute every chained log from GENESIS (paged, keyed by id). Per log it also checks: ids dense from 1 (AUTOINCREMENT ids are never reused and a failed
 *  write rolls its id back, so a gap is a deleted or replaced row), the time column never decreases, and sqlite_sequence equals the last id (a deleted
 *  LAST row leaves the sequence ahead). The caller-supplied time column (at / created_at) is INFORMATIONAL: writers finish out of order and clocks skew, so
 *  a time that goes backwards is reported in `warnings`, never as a failure; integrity rests on the dense ids, the hash chain, sqlite_sequence and the
 *  external head (Codex intel-0007 fix round, MEDIUM). For creation records it checks the relationship (exists, id = content hash of its identity, same created_at and
 *  exposure). Cross-checks against independent projections: every VERIFIED or critical CONFIRMED assessment has an approved review by its actor (not the
 *  proposer); every assessment beyond candidate has a creation record; every review names the creation proposer.
 *  `heads` (kept OUTSIDE the database, e.g. in the panel audit chain or a signed anchor) is what detects a log rewritten from some row to its end with
 *  recomputed hashes AND a matching sqlite_sequence: without it, an attacker with schema rights who rewrites the tail consistently is not detected.
 *  Returns { ok, logs: { table: { ok, entries, head, error?, at?, warnings } }, cross: { ok, errors } }. */
export async function verifyAssurance(db, { pageSize = 500, heads = {}, crossLimit = 10000 } = {}) {
  const logs = {};
  for (const table of Object.keys(LOGS)) {
    const timeCol = table === 'intel_relationship_creation' ? 'created_at' : 'at';
    let prev = GENESIS, after = 0, n = 0, res = null, lastTime = '';
    const warnings = []; let legacy = 0;
    for (;;) {
      const rows = (await db.prepare(`SELECT * FROM ${table} WHERE id > ? ORDER BY id LIMIT ?`).bind(after, pageSize).all()).results;
      for (const r of rows) {
        let rel = null;
        if (r.id !== n + 1) { res = { ok: false, at: r.id, error: 'id sequence has a gap (a row was deleted or replaced)' }; break; }
        if (String(r[timeCol]) < lastTime && warnings.length < 100) warnings.push({ at: r.id, warning: `${timeCol} earlier than the previous entry (caller time, informational)` });
        if (table === 'intel_relationship_creation') {
          rel = await db.prepare('SELECT id, type, from_id, to_id, source_id, method, exposure, created_at FROM intel_relationships WHERE id = ?').bind(r.relationship_id).first();
          if (!rel) { res = { ok: false, at: r.id, error: 'relationship of a creation record is missing' }; break; }
          if (await relIdOf(rel) !== rel.id || rel.created_at !== r.created_at || rel.exposure !== r.exposure) { res = { ok: false, at: r.id, error: 'relationship row was altered (identity, created_at or exposure)' }; break; }
        }
        if (r.prev_hash !== prev) { res = { ok: false, at: r.id, error: 'chain link broken (entry removed or reordered)' }; break; }
        if (table === 'intel_relationship_creation' && r.origin === 'legacy_import') {
          // 0007 backfill: a surrogate link (SQLite has no SHA-256), valid only as a PREFIX of the log, with content fixed by the relationship (checked above)
          if (r.id !== legacy + 1 || r.hash !== String(r.id).padStart(64, '0') || r.proposer !== 'migration:0007' || r.rule_id !== null) { res = { ok: false, at: r.id, error: 'legacy_import record outside the 0007 backfill prefix or altered' }; break; }
          legacy++; prev = r.hash; n++; after = r.id; lastTime = String(r[timeCol]); continue;
        }
        if (await chainHash(prev, entryOf(table, r, rel)) !== r.hash) { res = { ok: false, at: r.id, error: 'entry content was altered' }; break; }
        prev = r.hash; n++; after = r.id; lastTime = String(r[timeCol]);
      }
      if (res || rows.length < pageSize) break;
    }
    if (!res) {
      let seq = null; try { seq = (await db.prepare('SELECT seq FROM sqlite_sequence WHERE name = ?').bind(table).first())?.seq ?? 0; } catch { seq = null; }
      if (seq !== null && seq !== n) res = { ok: false, error: `sqlite_sequence is ${seq} but the log ends at ${n} (rows removed at the end)` };
    }
    if (!res && heads[table] && heads[table] !== prev) res = { ok: false, error: 'head differs from the externally kept head (truncated or forked)' };
    logs[table] = res ? { ...res, entries: n, head: prev, warnings } : { ok: true, entries: n, head: prev, warnings };
  }
  const errors = [], warnings = [], q = async (sql, why) => { for (const r of (await db.prepare(sql).bind(crossLimit).all()).results) (r.legacy ? warnings : errors).push({ [r.legacy ? 'warning' : 'error']: why, relationship_id: r.relationship_id, assessment_id: r.id ?? null }); };
  // A pre-0007 (legacy_import) relationship may carry a VERIFIED assessment written before reviews existed: reported as a WARNING. It still projects to
  // candidate (the lifecycle view re-checks the review), so it is never 'verified' nor public; only a review by another human makes it verified.
  await q(`SELECT a.id, a.relationship_id, EXISTS (SELECT 1 FROM intel_relationship_creation lc WHERE lc.relationship_id = a.relationship_id AND lc.origin = 'legacy_import') AS legacy FROM intel_relationship_assessments a JOIN intel_relationships r ON r.id = a.relationship_id WHERE (a.verification = 'VERIFIED' OR (a.confidence = 'CONFIRMED' AND r.type IN (${CRITICAL_TYPES.map((t) => `'${t}'`).join(',')}))) AND NOT EXISTS (SELECT 1 FROM intel_relationship_reviews v JOIN intel_relationship_creation c ON c.relationship_id = v.relationship_id WHERE v.relationship_id = a.relationship_id AND v.decision = 'approve' AND v.approver = a.actor AND v.approver <> c.proposer) LIMIT ?`, 'VERIFIED/critical CONFIRMED assessment without an approved review by its actor');
  await q("SELECT a.id, a.relationship_id FROM intel_relationship_assessments a WHERE (a.confidence NOT IN ('UNKNOWN','INFERRED') OR a.verification <> 'UNVERIFIED') AND NOT EXISTS (SELECT 1 FROM intel_relationship_creation c WHERE c.relationship_id = a.relationship_id) LIMIT ?", 'assessment beyond candidate without a creation record');
  await q('SELECT v.id, v.relationship_id FROM intel_relationship_reviews v WHERE NOT EXISTS (SELECT 1 FROM intel_relationship_creation c WHERE c.relationship_id = v.relationship_id AND c.proposer = v.proposer) LIMIT ?', 'review whose proposer is not the creation proposer');
  const cross = { ok: errors.length === 0, errors, warnings };
  return { ok: Object.values(logs).every((l) => l.ok) && cross.ok, logs, cross };
}

/** Cross-check the recorded source approvals against the registry file (its exact bytes, e.g. from git): every recorded state must equal the registry's, and
 *  every registry source must be recorded. Detects an approval forged with raw SQL even when its chain hash was computed correctly. */
export async function verifySourceApprovals(db, registryText) {
  const reg = JSON.parse(registryText), want = new Map(reg.sources.map((s) => [s.id, s.approval_state]));
  const rows = (await db.prepare('SELECT source_id, approval_state FROM intel_source_approvals ORDER BY source_id LIMIT 10000').all()).results;
  const bad = [];
  for (const r of rows) if ((want.get(r.source_id) ?? 'ABSENT') !== r.approval_state) bad.push({ source_id: r.source_id, recorded: r.approval_state, registry: want.get(r.source_id) ?? 'ABSENT' });
  for (const id of want.keys()) if (!rows.some((r) => r.source_id === id)) bad.push({ source_id: id, recorded: null, registry: want.get(id) });
  return { ok: bad.length === 0, mismatches: bad };
}
