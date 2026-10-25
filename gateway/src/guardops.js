// Adapter that sends AUTHORISED operational events to GuardOps' ingestion endpoint (https://ingest.mac-guard.com). MacGuard does not implement incidents, on-call or escalation: it only reports facts, with a
// versioned envelope (contracts/v1/event.schema.json, macguard.event/1) and a limited credential. Delivery is durable and never touches a request: events go to a D1 outbox (idempotent by event_id) and
// are flushed after the response or by the hourly cron, with exponential backoff and a dead-letter state. Nothing is sent unless GUARDOPS_INGEST_URL is set AND its host is allow-listed.
// Payloads carry ids and counters only: no keys, tokens, addresses, payloads or file contents (events.js already redacts secrets by key name).
import { HttpError, iso, sha256Hex } from './util.js';

// Which internal events are forwarded, and as what. Business events (download.authorized, usage.near_limit, tenant.suspended, release.premium_published) are NOT operational and stay out.
const FORWARD = {
  'gateway.incident': (d) => (/collector|cron|retention|stripe-report/.test(d.component) ? ['cron.run.failed', 'high'] : d.component === 'origin' ? ['download.failed', 'high'] : ['gateway.error', 'high']),
  'stripe.failure': () => ['gateway.error', 'high'], 'billing.error': () => ['gateway.error', 'high'], 'api.saturated': () => ['saturation.detected', 'medium'],
  'abuse.detected': () => ['security.incident', 'high'], 'signature.invalid': () => ['integrity.error', 'critical'], 'replication.failed': () => ['backup.failed', 'high'],
};
export const FORWARDED_TYPES = Object.freeze(Object.keys(FORWARD));
const ALLOWED_DEFAULT = 'ingest.mac-guard.com', MAX_BATCH = 50, MAX_ATTEMPTS = 20, BACKOFF_CAP_S = 6 * 3600;

export function endpoint(env) {
  const raw = env.GUARDOPS_INGEST_URL; if (!raw) return null;
  let u; try { u = new URL(raw); } catch { return null; }
  const allowed = String(env.GUARDOPS_ALLOWED_HOSTS || ALLOWED_DEFAULT).split(',').map((h) => h.trim().toLowerCase()), local = env.GUARDOPS_ALLOW_INSECURE_LOCAL === '1' && u.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(u.hostname);
  if (!(local || (u.protocol === 'https:' && allowed.includes(u.hostname.toLowerCase())))) return null;     // the credential is only ever sent to an allow-listed https host
  return u;
}
// Deterministic id: the same fact reported twice (retry, double emission) is one event for the receiver.
async function idFor(type, data, at) { return 'mg-' + (await sha256Hex(JSON.stringify([type, data, at.slice(0, 16)]))).slice(0, 40); }
export async function toEnvelope(ev, env, clock) {
  const map = FORWARD[ev.type]; if (!map) return null; const [type, severity] = map(ev.data ?? {}), at = ev.at ?? iso(clock());
  const data = { severity, internal_type: ev.type, ...Object.fromEntries(Object.entries(ev.data ?? {}).filter(([k]) => !/^(tenant_id|api_key_id)$/.test(k))) };
  return { schema: 'macguard.event/1', event_id: await idFor(type, data, at), type, occurred_at: at, tenant_id: env.GUARDOPS_TENANT || 'macguard', ...(env.GUARDOPS_PROJECT_ID ? { project_id: env.GUARDOPS_PROJECT_ID } : {}),
    source: { kind: 'gateway', id: 'macguard-gateway' }, source_channel: 'gateway', status: 'error', data };
}
// A backup / operations alert (macguard.alert/1) becomes the same envelope, so local tools can report through the same contract.
export async function envelopeFromAlert(a, env = {}, clock = () => new Date()) {
  const type = /^backup\./.test(a.rule_id) ? 'backup.failed' : /integrity|signature/.test(a.rule_id) ? 'integrity.error' : /^telemetry|collector/.test(a.rule_id) ? 'cron.run.failed' : 'gateway.error', at = a.evaluated_at ?? iso(clock());
  const data = { severity: a.severity, rule_id: a.rule_id, state: a.state, message: String(a.message).slice(0, 300), ...(a.value != null ? { value: a.value } : {}) };
  return { schema: 'macguard.event/1', event_id: await idFor(type, data, at), type, occurred_at: at, tenant_id: env.GUARDOPS_TENANT || 'macguard', source: { kind: a.source?.kind ?? 'agent', id: a.source?.id ?? 'alert' }, status: 'error', data };
}
export async function enqueue(db, clock, envelope) {
  const now = iso(clock()); await db.prepare("INSERT OR IGNORE INTO guardops_outbox(event_id,created_at,envelope,state,attempts,next_attempt_at) VALUES (?,?,?,'pending',0,?)").bind(envelope.event_id, now, JSON.stringify(envelope), now).run();
}
// Forward one internal event if (and only if) GuardOps is configured. Never throws.
export async function forward(env, db, clock, ev) {
  try { if (!endpoint(env) || !db) return false; const e = await toEnvelope(ev, env, clock); if (!e) return false; await enqueue(db, clock, e); env.__guardopsDirty = true; return true; } catch { return false; }
}
// Sends due events in one batch. Returns counts; never throws. 2xx -> sent (unless the receiver lists rejected ids -> dead), 429/5xx/network -> retry with backoff, other 4xx -> dead.
export async function flush(env, db, clock, fetchImpl = (env.guardopsFetch ?? fetch)) {
  const url = endpoint(env), out = { skipped: !url, sent: 0, retry: 0, dead: 0 }; if (!url || !env.GUARDOPS_INGEST_TOKEN || !db) return { ...out, skipped: true };
  try {
    const now = clock(), due = (await db.prepare("SELECT event_id, envelope, attempts FROM guardops_outbox WHERE state = 'pending' AND next_attempt_at <= ? ORDER BY created_at LIMIT ?").bind(iso(now), MAX_BATCH).all()).results; if (!due.length) return out;
    const body = JSON.stringify({ schema: 'macguard.event-batch/1', events: due.map((r) => JSON.parse(r.envelope)) });
    const mark = async (state, r, err, delayS = 0) => db.prepare('UPDATE guardops_outbox SET state = ?, attempts = attempts + 1, last_error = ?, next_attempt_at = ?, sent_at = ? WHERE event_id = ?').bind(state, err, iso(new Date(now.getTime() + delayS * 1000)), state === 'sent' ? iso(now) : null, r.event_id).run();
    let res; try { res = await fetchImpl(url.toString(), { method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(5000), headers: { 'content-type': 'application/json', authorization: `Bearer ${env.GUARDOPS_INGEST_TOKEN}`, 'idempotency-key': 'mgb-' + (await sha256Hex(due.map((r) => r.event_id).join(','))).slice(0, 32), 'user-agent': 'macguard-gateway' }, body }); } catch { res = null; }
    const retryAfter = res ? Number(res.headers.get('retry-after')) || 0 : 0;
    for (const r of due) {
      const backoff = Math.min(BACKOFF_CAP_S, Math.max(retryAfter, 60 * 2 ** r.attempts));
      if (res && res.status >= 200 && res.status < 300) { await mark('sent', r, null); out.sent++; }
      else if (res && res.status >= 400 && res.status < 500 && res.status !== 429 && res.status !== 408) { await mark('dead', r, `receiver answered ${res.status}`); out.dead++; }
      else if (r.attempts + 1 >= MAX_ATTEMPTS) { await mark('dead', r, `gave up after ${MAX_ATTEMPTS} attempts`); out.dead++; }
      else { await mark('pending', r, res ? `receiver answered ${res.status}` : 'network error', backoff); out.retry++; }
    }
  } catch { /* delivery problems are recorded per event; this function never throws */ }
  return out;
}
// Daily operational snapshot: counters only, from data the gateway already holds.
export async function metricsSnapshot(db, clock) {
  const day = iso(clock()).slice(0, 10), y = iso(new Date(clock().getTime() - 86400000)).slice(0, 10);
  const rows = (await db.prepare("SELECT status_class sc, SUM(requests) r FROM analytics_daily WHERE day = ? AND tenant_id <> '-' GROUP BY status_class").bind(y).all()).results, total = rows.reduce((a, r) => a + r.r, 0), bad = rows.filter((r) => r.sc === '5xx' || r.sc === 'tool_error').reduce((a, r) => a + r.r, 0);
  const runs = (await db.prepare('SELECT status FROM gh_sync_log WHERE observed_at > ?').bind(iso(new Date(clock().getTime() - 86400000))).all()).results;
  return { schema: 'macguard.event/1', event_id: 'mg-metrics-' + day, type: 'metrics.snapshot', occurred_at: iso(clock()), tenant_id: 'PLACEHOLDER', source: { kind: 'gateway', id: 'macguard-gateway' }, status: 'ok',
    data: { day: y, requests: total, server_errors: bad, error_rate: total ? +(bad / total).toFixed(4) : null, collector_runs_24h: runs.length, collector_ok_24h: runs.filter((r) => r.status === 'ok').length } };
}
export async function enqueueMetrics(env, db, clock) { try { if (!endpoint(env)) return false; const e = await metricsSnapshot(db, clock); e.tenant_id = env.GUARDOPS_TENANT || 'macguard'; await enqueue(db, clock, e); return true; } catch { return false; } }
