import { canonical, iso, redact, sha256Hex } from './util.js';
export const GENESIS = '0'.repeat(64);
// Append-only, hash-chained. Details are redacted by KEY NAME and must never contain a key, token or customer secret.
export async function audit(db, clock, tenantId, action, detail = {}) {
  const prev = (await db.prepare('SELECT hash FROM audit ORDER BY seq DESC LIMIT 1').first())?.hash ?? GENESIS;
  const at = iso(clock()), d = canonical(redact(detail));
  const hash = await sha256Hex(prev + canonical({ at, tenant_id: tenantId ?? null, action, detail: d }));
  await db.prepare('INSERT INTO audit(at, tenant_id, action, detail, prev_hash, hash) VALUES (?,?,?,?,?,?)').bind(at, tenantId ?? null, action, d, prev, hash).run();
}
export async function verifyAudit(db) {
  let prev = GENESIS;
  for (const r of (await db.prepare('SELECT * FROM audit ORDER BY seq').all()).results) {
    if (r.prev_hash !== prev || (await sha256Hex(prev + canonical({ at: r.at, tenant_id: r.tenant_id, action: r.action, detail: r.detail }))) !== r.hash) return { ok: false, at: r.seq };
    prev = r.hash;
  }
  return { ok: true };
}
