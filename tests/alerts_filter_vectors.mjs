// Runs tests/fixtures/alerts/filter-vectors.json through web/intelligence/alerts/filter.js with node. Exit code 0 = every vector agrees with the expected answer.
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const F = require(join(here, '..', 'web', 'intelligence', 'alerts', 'filter.js'));
const doc = JSON.parse(readFileSync(join(here, 'fixtures', 'alerts', 'filter-vectors.json'), 'utf8'));
const now = Date.parse(doc.now.replace('Z', '.000Z'));
let bad = 0; const dump = process.argv.includes('--dump'); const outAll = [];
for (const v of doc.vectors) {
  const alert = Object.assign({}, doc.base, v.alert_overrides);
  const out = F.evaluate({ schema: 'macguard.subscription-filter/1', version: 1, expr: v.expr }, alert, { now, changes: v.changes, stale: v.stale });
  if (out.matched !== v.expect) { bad++; console.log('MISMATCH', v.name, 'got', out.matched, 'expected', v.expect); }
  outAll.push({ name: v.name, matched: out.matched, reasons: out.reasons });
  if (!out.reasons.length) { bad++; console.log('NO REASON', v.name); }
}
if (dump) { console.log(JSON.stringify(outAll)); process.exit(0); }
console.log(`${doc.vectors.length} vectors, ${bad} mismatches`);
process.exit(bad ? 1 : 0);
