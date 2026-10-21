// Audit anchors (archive phase 1). An anchor says: "the audit chain up to `seq` ended with `hash`, and that segment is sealed and archived".
// It lets the chain continue (appendAudit) and be verified (/api/audit/verify) from a point other than GENESIS once older rows leave D1.
// Nothing here deletes audit rows. Anchors are written ONLY through writeAnchor(), which refuses unless the sealed segment is proven
// archived in all three providers and a restore of it was rehearsed (receipt produced by scripts/archive/).
import { GENESIS, canonical, sha256hex, verifyChain } from './core.js';

export const SEAL_SCHEMA = 'macguard-audit-seal/1';
export const RECEIPT_SCHEMA = 'macguard-archive-receipt/1';
export const PROVIDERS = ['b2', 'r2', 'scaleway'];
const HEX64 = /^[0-9a-f]{64}$/;

export class AnchorError extends Error { constructor(message, code) { super(message); this.code = code; } }

/** The hash the next audit entry must link to: the last audit row; if the table is empty, the newest anchor; GENESIS only for a database that never had either. */
export async function chainHead(db) {
  const last = await db.prepare('SELECT hash FROM audit ORDER BY seq DESC LIMIT 1').first();
  if (last) return last.hash;
  let a = null;
  try { a = await db.prepare('SELECT hash FROM audit_anchor ORDER BY seq DESC LIMIT 1').first(); } catch (e) { if (!/no such table/i.test(String(e))) throw e; }   // 0004 not applied yet: nothing can have been pruned
  return a ? a.hash : GENESIS;
}
export async function listAnchors(db) {
  try { return (await db.prepare('SELECT seq, hash, rows, seal_sha256, created_at, author FROM audit_anchor ORDER BY seq ASC').all()).results; }
  catch (e) { if (/no such table/i.test(String((e && e.message) || e))) return []; throw e; }   // 0004 not applied yet: there are no anchors, and /api/audit/verify must keep working
}

/** Bytes of a seal file are canonical(seal) + "\n"; the seal digest is the SHA-256 of exactly those bytes (same rule as scripts/archive/canon.py). */
export async function sealSha256(seal) { return sha256hex(canonical(seal) + '\n'); }

function checkSealShape(seal) {
  const bad = (m) => { throw new AnchorError(`seal rejected: ${m}`, 'bad_seal'); };
  if (!seal || typeof seal !== 'object' || seal.schema !== SEAL_SCHEMA) bad('schema');
  for (const k of ['first_prev_hash', 'head_hash', 'segment_sha256']) if (!HEX64.test(seal[k] || '')) bad(k);
  if (seal.prev_seal_sha256 !== null && !HEX64.test(seal.prev_seal_sha256 || '')) bad('prev_seal_sha256');
  for (const k of ['first_seq', 'last_seq', 'count']) if (!Number.isSafeInteger(seal[k]) || seal[k] < 1) bad(k);
  if (seal.last_seq < seal.first_seq || seal.count > seal.last_seq - seal.first_seq + 1) bad('seq range does not fit the count');
  if (typeof seal.period !== 'string' || !/^\d{4}-\d{2}$/.test(seal.period)) bad('period');
}

function checkReceipt(receipt, seal, sealSha) {
  const bad = (m) => { throw new AnchorError(`archive not proven: ${m}`, 'not_archived'); };
  if (!receipt || receipt.schema !== RECEIPT_SCHEMA) bad('receipt schema');
  if (receipt.seal_sha256 !== sealSha) bad('receipt names another seal');
  if (receipt.segment_sha256 !== seal.segment_sha256) bad('receipt names another segment');
  const copies = Array.isArray(receipt.copies) ? receipt.copies : [];
  const names = copies.map((c) => c && c.provider).sort();
  if (JSON.stringify(names) !== JSON.stringify(PROVIDERS)) bad(`need exactly one verified copy in each of ${PROVIDERS.join(', ')}`);
  const ct = copies[0].ciphertext_sha256;
  for (const c of copies) {
    if (c.readback_verified !== true) bad(`${c.provider} copy was not verified by reading it back`);
    if (!HEX64.test(c.ciphertext_sha256 || '') || c.ciphertext_sha256 !== ct) bad('the three copies are not byte-identical');
    if (c.seal_sha256 !== sealSha) bad(`${c.provider} holds another seal`);
  }
  const r = receipt.restore;
  if (!r || r.ok !== true || r.seal_sha256 !== sealSha || r.segment_sha256 !== seal.segment_sha256 || !PROVIDERS.includes(r.provider)) bad('no passing restore rehearsal for this segment');
}

/** Write the anchor for a sealed, proven-archived segment. Atomic and single-writer-safe: the INSERT itself carries the continuity condition, so two concurrent
 *  writers cannot both succeed. Re-writing the identical anchor is an idempotent no-op; any different anchor for a taken position is refused. */
export async function writeAnchor(db, { seal, receipt, author }, now) {
  checkSealShape(seal);
  if (typeof author !== 'string' || !author.trim()) throw new AnchorError('author is required', 'bad_author');
  const sealSha = await sealSha256(seal);
  checkReceipt(receipt, seal, sealSha);
  const row = await db.prepare('SELECT hash FROM audit WHERE seq = ?').bind(seal.last_seq).first();
  if (row && row.hash !== seal.head_hash) throw new AnchorError('seal head does not match the audit row it claims to close', 'anchor_mismatch');
  const prev = await db.prepare('SELECT seq, hash, seal_sha256 FROM audit_anchor ORDER BY seq DESC LIMIT 1').first();
  if (prev && prev.seq === seal.last_seq) {
    if (prev.hash === seal.head_hash && prev.seal_sha256 === sealSha) return { status: 'exists', seq: prev.seq };
    throw new AnchorError('a different anchor already holds this position', 'conflict');
  }
  if (prev && seal.last_seq < prev.seq) throw new AnchorError('anchors only move forward', 'conflict');
  if (seal.first_prev_hash !== (prev ? prev.hash : GENESIS)) throw new AnchorError('seal does not continue from the previous anchor', 'not_continuous');
  if (prev && seal.prev_seal_sha256 !== prev.seal_sha256) throw new AnchorError('seal does not chain to the previous anchor seal', 'not_continuous');
  if (!prev && seal.prev_seal_sha256 !== null) throw new AnchorError('first anchor cannot name a previous seal', 'not_continuous');
  const r = await db.prepare(
    `INSERT INTO audit_anchor (seq, hash, rows, seal_sha256, created_at, author)
     SELECT ?, ?, ?, ?, ?, ? WHERE COALESCE((SELECT hash FROM audit_anchor ORDER BY seq DESC LIMIT 1), '${GENESIS}') = ?
       AND NOT EXISTS (SELECT 1 FROM audit_anchor WHERE seq >= ?)`)
    .bind(seal.last_seq, seal.head_hash, seal.count, sealSha, now, author.trim(), seal.first_prev_hash, seal.last_seq).run();
  if (!r.meta || r.meta.changes !== 1) throw new AnchorError('another writer moved the anchors first; nothing was written', 'conflict');
  return { status: 'created', seq: seal.last_seq };
}

/** Verify the audit chain page by page (bounded memory, no row ceiling). It starts at GENESIS when the oldest row links to GENESIS, otherwise at the anchor
 *  whose head hash that row names. A pass is limited to `maxPages`; when it stops early it says so (`complete: false`) with a resume point, and never reports
 *  the chain as verified beyond what it read. */
export async function verifyAuditChain(db, { pageSize = 1000, maxPages = 100, after = 0, head = null } = {}) {
  const anchors = await listAnchors(db);
  const bySeq = new Map(anchors.map((a) => [a.seq, a]));
  let prev, startedAt = null, entries = 0, lastSeq = after, pages = 0;
  if (after > 0) {
    const r = await db.prepare('SELECT hash FROM audit WHERE seq = ?').bind(after).first();
    if (!r || r.hash !== head) return { ok: false, error: 'resume point does not match the audit chain', at: after };
    prev = head;
  } else {
    const first = await db.prepare('SELECT seq, prev_hash FROM audit ORDER BY seq ASC LIMIT 1').first();
    if (!first) {
      const last = anchors[anchors.length - 1];
      return { ok: true, entries: 0, head: last ? last.hash : GENESIS, anchor: last ? { seq: last.seq, hash: last.hash } : null, complete: true };
    }
    if (first.prev_hash === GENESIS) prev = GENESIS;
    else {
      const a = anchors.filter((x) => x.hash === first.prev_hash && x.seq < first.seq).pop();
      if (!a) return { ok: false, at: first.seq, error: 'the oldest retained entry links to a hash that is neither GENESIS nor an anchor (anchor missing or not matching)' };
      prev = a.hash; startedAt = { seq: a.seq, hash: a.hash };
    }
  }
  for (;;) {
    const page = (await db.prepare('SELECT * FROM audit WHERE seq > ? ORDER BY seq ASC LIMIT ?').bind(lastSeq, pageSize).all()).results;
    if (!page.length) break;
    const v = await verifyChain(page, prev);
    if (!v.ok) return { ok: false, at: v.at, error: v.error, ...(startedAt ? { anchor: startedAt } : {}) };
    for (const r of page) { const a = bySeq.get(r.seq); if (a) { if (a.hash !== r.hash) return { ok: false, at: r.seq, error: 'anchor does not match the audit row at its position' } } }
    entries += page.length; prev = v.head; lastSeq = page[page.length - 1].seq;
    if (++pages >= maxPages && page.length === pageSize) {
      const more = await db.prepare('SELECT 1 AS x FROM audit WHERE seq > ? LIMIT 1').bind(lastSeq).first();
      if (more) return { ok: true, complete: false, entries, verified_through_seq: lastSeq, head: prev, resume: { after: lastSeq, head: prev }, ...(startedAt ? { anchor: startedAt } : {}) };
    }
  }
  const newest = anchors[anchors.length - 1];
  if (newest && newest.seq > lastSeq) return { ok: false, at: lastSeq, error: 'an anchor lies beyond the end of the audit chain (rows missing)' };
  return { ok: true, entries, head: prev, complete: true, ...(startedAt ? { anchor: startedAt } : {}) };
}
