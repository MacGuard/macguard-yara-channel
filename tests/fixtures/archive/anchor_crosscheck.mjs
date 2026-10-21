// Used by tests/test_archive_store.py: feeds a Python-built seal + receipt to the Worker's REAL writeAnchor() on the node:sqlite shim, then prunes (test only)
// and verifies the chain from the anchor. Usage: node anchor_crosscheck.mjs <input.json>   input = {rows, seal, receipt}
import { readFileSync } from 'node:fs';
import { newDb } from '../../../admin/worker/test/d1shim.js';
import { writeAnchor, verifyAuditChain, chainHead } from '../../../admin/worker/src/anchor.js';
const j = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const db = newDb();
const ins = db.raw.prepare('INSERT INTO audit (seq, at, actor, role, action, target, detail, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?)');
for (const r of j.rows) ins.run(r.seq, r.at, r.actor, r.role, r.action, r.target, r.detail, r.prev_hash, r.hash);
const out = { before: await verifyAuditChain(db) };
try { out.anchor = await writeAnchor(db, { seal: j.seal, receipt: j.receipt, author: 'owner' }, '2026-10-21T00:00:00.000Z'); } catch (e) { out.anchor_error = { code: e.code, message: e.message }; }
if (out.anchor) {
  db.raw.exec('DROP TRIGGER audit_no_delete'); db.raw.exec(`DELETE FROM audit WHERE seq <= ${j.seal.last_seq}`);   // what a prune would do after owner authorization
  out.after = await verifyAuditChain(db); out.head = await chainHead(db);
}
console.log(JSON.stringify(out));
