// Measures D1 cost per request on the REAL SQL (node:sqlite behind the D1 shim): round trips, read statements, write statements and rows actually written, with telemetry on and off.
// Statement/round-trip counts are exact for this code; they say nothing about latency or billing (D1 bills rows read/written, and a no-op INSERT OR IGNORE writes no row).
// Usage: node tools/d1_cost.mjs [--runs=20] [--json]
import { apiWorld } from '../test/apiworld.js';

const runs = Number((process.argv.find((a) => a.startsWith('--runs=')) ?? '--runs=20').slice(7));
function spy(db) {
  const m = { round_trips: 0, reads: 0, writes: 0, rows_written: 0 }, isRead = (sql) => /^\s*select/i.test(sql);
  const wrap = (real) => { const w = { _real: real, _sql: real._sql, _args: real._args, bind(...a) { real.bind(...a); return w; },
    async first() { m.round_trips++; const r = await real.first(); if (isRead(real._sql)) m.reads++; else { m.writes++; m.rows_written += r ? 1 : 0; } return r; },
    async all() { m.round_trips++; const r = await real.all(); if (isRead(real._sql)) m.reads++; else { m.writes++; m.rows_written += r.results.length; } return r; },
    async run() { m.round_trips++; const r = await real.run(); if (isRead(real._sql)) m.reads++; else { m.writes++; m.rows_written += r.meta.changes; } return r; } }; return w; };
  return { m, db: { prepare: (sql) => wrap(db.prepare(sql)), raw: db.raw, async batch(list) { m.round_trips++; const res = await db.batch(list.map((s) => s._real)); list.forEach((s, i) => { if (isRead(s._sql)) m.reads++; else { m.writes++; m.rows_written += res[i].meta.changes; } }); return res; } } };
}
const SC = {
  'community redirect (anonymous)': (w) => w.call('/v1/community/releases/rules-20261021-1/download'),
  'REST included op (intel.hash)': (w, k) => w.call('/v1/intelligence/hash/' + 'a'.repeat(64), { key: k }),
  'REST metered op (intel.ioc.search)': (w, k, i) => w.call('/v1/intelligence/ioc/search', { method: 'POST', key: k, json: { value: 'evil' + i + '.test' }, headers: { 'idempotency-key': 'bench-' + String(i).padStart(6, '0') } }),
  'MCP tools/call (lookup_hash)': (w, k, i) => w.call('/mcp', { method: 'POST', key: k, headers: { 'mcp-protocol-version': '2026-07-28', 'mcp-method': 'tools/call', 'mcp-name': 'macguard_lookup_hash', accept: 'application/json, text/event-stream' },
    json: { jsonrpc: '2.0', id: i + 1, method: 'tools/call', params: { name: 'macguard_lookup_hash', arguments: { hash: 'a'.repeat(64) }, _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {}, 'io.modelcontextprotocol/clientInfo': { name: 'b', version: '1' } } } } }),
};
const rows = [];
for (const [name, fn] of Object.entries(SC)) for (const telemetry of [false, true]) {
  const w = await apiWorld({ envExtra: { KEY_PEPPER: 'k'.repeat(40), ANALYTICS_PEPPER: 'a'.repeat(40), COMMUNITY_DOWNLOAD_BASE: 'https://dl.example.test/base', COMMUNITY_DEFAULT_ASSET: 'bundle.tar.gz', ANALYTICS_ENABLED: telemetry ? '1' : '0' } }); await w.tenant('t1'); const key = (await w.key('t1')).key;
  await fn(w, key, 0);                                                                 // warm-up (policy cache, first-of-day rows) is not what a steady request costs
  const { m, db } = spy(w.env.DB); w.env.DB = db; let ok = 0;
  for (let i = 1; i <= runs; i++) { const r = await fn(w, key, i); if (r.status < 400 || r.status === 302) ok++; }
  rows.push({ scenario: name, telemetry: telemetry ? 'on' : 'off', ok_of: `${ok}/${runs}`, round_trips: m.round_trips / runs, read_stmts: m.reads / runs, write_stmts: m.writes / runs, rows_written: m.rows_written / runs });
}
if (process.argv.includes('--json')) console.log(JSON.stringify(rows, null, 1));
else { console.log('scenario'.padEnd(38), 'telem', 'ok', '  trips  reads writes rows_written (per request, steady state)'); for (const r of rows) console.log(r.scenario.padEnd(38), r.telemetry.padEnd(5), r.ok_of.padEnd(6), String(r.round_trips).padEnd(6), String(r.read_stmts).padEnd(6), String(r.write_stmts).padEnd(6), r.rows_written); }
