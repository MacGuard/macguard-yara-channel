// Retention for LOCAL backups: keeps the newest N daily, M weekly and K monthly. DRY RUN unless --apply. Only directories named like a backup stamp are ever considered; the newest, the one status.json
// points at, and anything listed in <root>/protected.json are never removed. Usage: node tools/backup_prune.mjs [--root DIR] [--daily 7] [--weekly 4] [--monthly 12] [--apply]
import { prune, ROOT_DEFAULT } from './backup_flow.mjs';
const arg = (n, d) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : d; };
const r = prune({ root: arg('--root', ROOT_DEFAULT), daily: Number(arg('--daily', 7)), weekly: Number(arg('--weekly', 4)), monthly: Number(arg('--monthly', 12)), apply: process.argv.includes('--apply') });
console.log(JSON.stringify(r, null, 1)); console.error(r.applied ? `removed ${r.remove.length}` : `dry run: would remove ${r.remove.length}, keep ${r.keep.length} (add --apply to remove)`);
