// Prints every SQL statement one steady-state request issues (telemetry off by default), to see where D1 reads and writes come from. Usage: node tools/d1_trace.mjs [path] [--telemetry]
import { apiWorld } from '../test/apiworld.js';

const path = process.argv.slice(2).find((a) => !a.startsWith('--')) ?? '/v1/intelligence/hash/' + 'a'.repeat(64);
const w = await apiWorld({ envExtra: { KEY_PEPPER: 'k'.repeat(40), ANALYTICS_PEPPER: 'a'.repeat(40), ANALYTICS_ENABLED: process.argv.includes('--telemetry') ? '1' : '0' } });
await w.tenant('t1'); const key = (await w.key('t1')).key; await w.call(path, { key });
const real = w.env.DB, log = [];
w.env.DB = { raw: real.raw, prepare: (sql) => { const s = real.prepare(sql); const o = { _real: s, _sql: sql, _args: s._args, bind(...a) { s.bind(...a); return o; },
  first: () => { log.push('R1 ' + sql); return s.first(); }, all: () => { log.push('R* ' + sql); return s.all(); }, run: () => { log.push('W  ' + sql); return s.run(); } }; return o; },
  batch: (l) => { log.push('BATCH[' + l.length + ']'); l.forEach((x) => log.push('  b ' + x._sql)); return real.batch(l.map((x) => x._real)); } };
await w.call(path, { key });
for (const l of log) console.log(l.replace(/\s+/g, ' ').slice(0, 190));
