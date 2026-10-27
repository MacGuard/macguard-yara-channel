#!/usr/bin/env node
// Row budget for anything that touches the productive Cloudflare account's D1. On 2026-10-26 a test import of 75,148 records plus unbounded screen scans used the free daily quota
// (5,000,000 rows read, 100,000 rows written): every D1 database of the account failed until 00:00 UTC. Rules enforced here, before a command runs:
//   * a single operation may use at most 10% of the day's read quota and 25% of the write quota;
//   * after it, the day may not be above 60% of either quota (the rest is reserved for normal production traffic);
//   * usage is measured from Cloudflare's analytics (no D1 query), estimated before, measured after, and both are logged.
// Usage:  node tools/d1_budget.mjs usage                      today's rows by database (needs CLOUDFLARE_API_TOKEN with Analytics read, or `wrangler auth token`)
//         node tools/d1_budget.mjs estimate-file FILE.sql     rows an import of this file would write (statements x (1 + indexes))
//         node tools/d1_budget.mjs preflight --reads N --writes M --label TEXT     exits 3 (refuses) when the operation does not fit; logs the estimate
//         node tools/d1_budget.mjs record --label TEXT --before FILE   logs measured use since the preflight
import { readFileSync, appendFileSync, writeFileSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';

export const FREE = { rowsRead: 5_000_000, rowsWritten: 100_000 };
export const POLICY = { opReadShare: 0.10, opWriteShare: 0.25, dayShare: 0.60 };
export const INDEXES_PER_TABLE = { intel_records: 4, intel_events: 2, intel_runs: 1, audit: 1, candidates: 2 };   // secondary indexes written with each row (estimate)

/** Rows an import writes: every INSERT row plus one write per secondary index of its table. Counts VALUES tuples only roughly (one per statement, which is how D1 exports and our scripts emit them). */
export function estimateImport(sql) {
  let rows = 0, writes = 0; const per = {};
  for (const m of sql.matchAll(/^INSERT (?:OR \w+ )?INTO\s+"?([A-Za-z_][A-Za-z0-9_]*)"?/gim)) { const t = m[1]; per[t] = (per[t] || 0) + 1; rows += 1; writes += 1 + (INDEXES_PER_TABLE[t] ?? 1); }
  return { rows, writes, per };
}
/** Decision: does an operation with these estimates fit today? `used` = rows already used today (all databases). */
export function decide({ reads = 0, writes = 0 }, used = { rowsRead: 0, rowsWritten: 0 }, free = FREE, policy = POLICY) {
  const why = [];
  if (reads > free.rowsRead * policy.opReadShare) why.push(`one operation may read at most ${free.rowsRead * policy.opReadShare} rows; this one needs ~${reads}`);
  if (writes > free.rowsWritten * policy.opWriteShare) why.push(`one operation may write at most ${free.rowsWritten * policy.opWriteShare} rows; this one needs ~${writes}`);
  if (used.rowsRead + reads > free.rowsRead * policy.dayShare) why.push(`reads would reach ${used.rowsRead + reads} of ${free.rowsRead} today (limit for a planned operation: ${free.rowsRead * policy.dayShare})`);
  if (used.rowsWritten + writes > free.rowsWritten * policy.dayShare) why.push(`writes would reach ${used.rowsWritten + writes} of ${free.rowsWritten} today (limit for a planned operation: ${free.rowsWritten * policy.dayShare})`);
  return { ok: why.length === 0, why };
}
/** Alert level of the day so far: ok < 50% <= warn < 80% <= critical, for the worse of reads and writes. */
export function level(used, free = FREE) { const r = Math.max(used.rowsRead / free.rowsRead, used.rowsWritten / free.rowsWritten); return r >= 0.8 ? 'critical' : r >= 0.5 ? 'warn' : 'ok'; }

export async function usageToday(token, accountId, fetchImpl = fetch, day = new Date().toISOString().slice(0, 10)) {
  const query = `query($acc: String!, $d: Date!) { viewer { accounts(filter: {accountTag: $acc}) { d1AnalyticsAdaptiveGroups(limit: 200, filter: {date_geq: $d, date_leq: $d}) { dimensions { databaseId } sum { readQueries writeQueries rowsRead rowsWritten } } } } }`;
  const r = await fetchImpl('https://api.cloudflare.com/client/v4/graphql', { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ query, variables: { acc: accountId, d: day } }) });
  if (!r.ok) throw new Error(`analytics HTTP ${r.status}`); const j = await r.json(); if (j.errors && j.errors.length) throw new Error(`analytics: ${j.errors[0].message}`);
  const groups = j.data.viewer.accounts[0].d1AnalyticsAdaptiveGroups, byDb = {}, total = { rowsRead: 0, rowsWritten: 0, readQueries: 0, writeQueries: 0 };
  for (const g of groups) { const id = g.dimensions.databaseId, x = byDb[id] || { rowsRead: 0, rowsWritten: 0, readQueries: 0, writeQueries: 0 }; for (const k of Object.keys(total)) { x[k] += g.sum[k]; total[k] += g.sum[k]; } byDb[id] = x; }
  return { day, total, byDb };
}
const LOG = process.env.D1_USAGE_LOG || join(homedir(), 'macguard-d1-usage.jsonl');
const log = (o) => { try { appendFileSync(LOG, JSON.stringify({ at: new Date().toISOString(), ...o }) + '\n', { mode: 0o600 }); } catch { /* the log is a convenience; the decision does not depend on it */ } };
const arg = (name, argv) => { const i = argv.indexOf(`--${name}`); return i >= 0 ? argv[i + 1] : undefined; };
const tokenFromEnv = () => {   // a read-only analytics token from the environment, else the operator's own wrangler login (its banner is skipped: only a token-shaped line is used)
  if (process.env.CLOUDFLARE_API_TOKEN) return process.env.CLOUDFLARE_API_TOKEN;
  const out = execFileSync('npx', ['--yes', 'wrangler@4.149.0', 'auth', 'token'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).split('\n').map((l) => l.trim()).filter((l) => /^[A-Za-z0-9._~+/=-]{20,}$/.test(l));
  if (!out.length) throw new Error('no token available'); return out[out.length - 1];
};

async function main(argv) {
  const cmd = argv[0], account = process.env.CLOUDFLARE_ACCOUNT_ID || '9e96e19f6dc0ccdd53e02f7c3b5cacab';
  if (cmd === 'estimate-file') { const e = estimateImport(readFileSync(argv[1], 'utf8')); console.log(JSON.stringify(e)); return 0; }
  if (cmd === 'usage') { const u = await usageToday(tokenFromEnv(), account); console.log(JSON.stringify({ ...u, level: level(u.total) })); return 0; }
  if (cmd === 'preflight') {
    const est = { reads: Number(arg('reads', argv) || 0), writes: Number(arg('writes', argv) || 0) }, label = arg('label', argv) || 'unlabelled'; let used;
    try { used = (await usageToday(tokenFromEnv(), account)).total; } catch (e) { console.error(`BLOCKED: today's usage cannot be read (${String(e.message).slice(0, 120)}); an operation without a known budget is not run`); log({ label, est, blocked: 'usage-unreadable' }); return 3; }
    const d = decide(est, used); log({ label, est, used_before: used, ok: d.ok, why: d.why });
    if (!d.ok) { console.error(`BLOCKED (${label}): ${d.why.join('; ')}`); return 3; }
    const f = arg('before', argv); if (f) writeFileSync(f, JSON.stringify(used), { mode: 0o600 }); console.log(`budget ok (${label}): ~${est.reads} reads, ~${est.writes} writes; used so far today: ${used.rowsRead} / ${used.rowsWritten}`); return 0;
  }
  if (cmd === 'record') {
    const before = JSON.parse(readFileSync(arg('before', argv), 'utf8')), now = (await usageToday(tokenFromEnv(), account)).total, label = arg('label', argv) || 'unlabelled';
    const actual = { rowsRead: now.rowsRead - before.rowsRead, rowsWritten: now.rowsWritten - before.rowsWritten }; log({ label, actual }); console.log(JSON.stringify({ label, actual, level: level(now) })); return 0;
  }
  console.error('usage: d1_budget.mjs usage | estimate-file FILE | preflight --reads N --writes M --label T [--before F] | record --label T --before F'); return 2;
}
if (import.meta.url === `file://${process.argv[1]}`) main(process.argv.slice(2)).then((c) => process.exit(c), (e) => { console.error(String(e.message || e)); process.exit(1); });
export { existsSync };
