// Reconciles two copies of the evidence log (for the transition main <-> evidence branch). It only ever ADDS what the destination lacks, in the source's order, and REPORTS what disagrees: it never deletes,
// rewrites or reorders a record, so running it twice does the same as running it once and a failed half-way run loses nothing.
//   node evidence_reconcile.mjs --from SRC.jsonl --to DST.jsonl [--apply]     without --apply it only reports (exit 0 when nothing is missing and nothing disagrees, 1 otherwise)
// Identity of a record: a backup is (resource, run_id); a restore is the restoration (sameRestore in backup_record.mjs); anything else is its exact JSON.
import { appendFileSync, existsSync, readFileSync, realpathSync } from 'node:fs';
import { sameRestore } from './backup_record.mjs';
import { fileURLToPath } from 'node:url';
const isMain = () => { try { return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url)); } catch { return false; } };   // argv[1] may go through a symlink (/var -> /private/var): comparing raw strings would silently do nothing

const parse = (text) => String(text || '').split('\n').filter(Boolean).map((l) => { try { return { line: l, rec: JSON.parse(l) }; } catch { return { line: l, rec: null }; } });
const same = (a, b) => (a.kind === 'backup' && b.kind === 'backup' ? a.run_id === b.run_id && (a.resource ?? 'gateway') === (b.resource ?? 'gateway') : a.kind === 'restore' && b.kind === 'restore' ? sameRestore(a, b) : JSON.stringify(a) === JSON.stringify(b));

/** { missing: lines to append to dst, conflicts: records both have under one identity but with different content, unreadable: lines of src that are not JSON } */
export function reconcile(srcText, dstText) {
  const src = parse(srcText), dst = parse(dstText).filter((x) => x.rec), missing = [], conflicts = [], unreadable = [];
  for (const s of src) {
    if (!s.rec || typeof s.rec !== 'object') { unreadable.push(s.line.slice(0, 80)); continue; }
    const twin = dst.find((d) => same(d.rec, s.rec));
    if (!twin) { missing.push(s.line); dst.push({ line: s.line, rec: s.rec }); }   // pushed so that a duplicate inside the source is not added twice
    else if (s.rec.kind === 'backup' && twin.line !== s.line) conflicts.push({ kind: 'backup', run_id: s.rec.run_id, resource: s.rec.resource ?? 'gateway' });
  }
  return { missing, conflicts, unreadable };
}

if (isMain()) {
  const arg = (n, d = null) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : d; }, from = arg('--from'), to = arg('--to'), apply = process.argv.includes('--apply');
  if (!from || !to || !existsSync(from)) { console.error('usage: evidence_reconcile.mjs --from SRC --to DST [--apply]'); process.exit(2); }
  const r = reconcile(readFileSync(from, 'utf8'), existsSync(to) ? readFileSync(to, 'utf8') : '');
  console.log(JSON.stringify({ missing: r.missing.length, conflicts: r.conflicts, unreadable: r.unreadable.length, applied: apply && r.missing.length > 0 }));
  if (apply && r.missing.length) { const dstText = existsSync(to) ? readFileSync(to, 'utf8') : ''; appendFileSync(to, (dstText && !dstText.endsWith('\n') ? '\n' : '') + r.missing.join('\n') + '\n'); }
  process.exit(!apply && (r.missing.length || r.conflicts.length) || r.conflicts.length ? 1 : 0);
}
