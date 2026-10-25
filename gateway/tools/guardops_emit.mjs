// Sends the FIRING alerts printed by backup_check.mjs (macguard.alert/1 on stdin) to GuardOps as macguard.event/1, using the same allow-listed endpoint and limited credential as the Worker. If the receiver is
// unreachable the events are appended to a local spool (<root>/guardops-spool.jsonl) and retried on the next run. Nothing is sent unless GUARDOPS_INGEST_URL and GUARDOPS_INGEST_TOKEN are set.
// Usage: node tools/backup_check.mjs | node tools/guardops_emit.mjs [--spool FILE]
import { appendFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { endpoint, envelopeFromAlert } from '../src/guardops.js';
import { ROOT_DEFAULT } from './backup_flow.mjs';

export async function emitAlerts(alerts, env = process.env, { spool = join(ROOT_DEFAULT, 'guardops-spool.jsonl'), fetchImpl = fetch } = {}) {
  const url = endpoint(env), firing = alerts.filter((a) => a.state === 'FIRING'), out = { sent: 0, spooled: 0, skipped: !url || !env.GUARDOPS_INGEST_TOKEN };
  if (out.skipped) return out;
  const pending = existsSync(spool) ? readFileSync(spool, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)) : [];
  const events = [...pending, ...(await Promise.all(firing.map((a) => envelopeFromAlert(a, env))))], seen = new Set(), batch = events.filter((e) => !seen.has(e.event_id) && seen.add(e.event_id));
  if (!batch.length) return out;
  let ok = false; try { const r = await fetchImpl(url.toString(), { method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(8000), headers: { 'content-type': 'application/json', authorization: `Bearer ${env.GUARDOPS_INGEST_TOKEN}`, 'user-agent': 'macguard-backup' }, body: JSON.stringify({ schema: 'macguard.event-batch/1', events: batch }) }); ok = r.status >= 200 && r.status < 300; } catch { ok = false; }
  if (ok) { out.sent = batch.length; if (existsSync(spool)) writeFileSync(spool, ''); } else { writeFileSync(spool, batch.map((e) => JSON.stringify(e)).join('\n') + '\n', { mode: 0o600 }); out.spooled = batch.length; }
  return out;
}
if (process.argv[1]?.endsWith('guardops_emit.mjs')) { let t = ''; for await (const c of process.stdin) t += c; const i = process.argv.indexOf('--spool'); const r = await emitAlerts(JSON.parse(t || '[]'), process.env, i > 0 ? { spool: process.argv[i + 1] } : {}); console.log(JSON.stringify(r)); }
