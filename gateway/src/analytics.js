// Request telemetry. It records COUNTS, never contents: no payload, no URL query, no IP address, no header, no raw identifier. An actor is a keyed hash of the API key id.
// Cost discipline: ONE aggregate upsert per request (plus INSERT OR IGNOREs that write nothing after the first request of a day). The billing ledger (usage_events) stays the
// source for money; these aggregates are the source for traffic, adoption and retention and are NOT used to charge.
// track() never throws and the router runs it after the response is decided: a telemetry failure can never fail, slow or alter a request (and Community does not use it at all).
import { hmacHex } from './util.js';

export const BUCKET_LIMITS_MS = [5, 10, 25, 50, 100, 250, 500, 1000, 2500];          // b0..b8 are "<= limit"; b9 is "> 2500"
const COLS = ['b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9'];
export const bucketIndex = (ms) => { const i = BUCKET_LIMITS_MS.findIndex((l) => ms <= l); return i < 0 ? 9 : i; };
export const statusClass = (http, toolError = false) => (toolError ? 'tool_error' : http >= 500 ? '5xx' : http >= 400 ? '4xx' : http >= 300 ? '3xx' : '2xx');
export const day = (d) => d.toISOString().slice(0, 10);

// Percentiles from the histogram are UPPER-BOUND ESTIMATES (the upper edge of the bucket holding the quantile); they are labelled ESTIMATED wherever they are shown.
export function quantile(buckets, q) {
  const total = buckets.reduce((a, b) => a + b, 0); if (!total) return null;
  const target = Math.ceil(total * q); let acc = 0;
  for (let i = 0; i < buckets.length; i++) { acc += buckets[i]; if (acc >= target) return i < BUCKET_LIMITS_MS.length ? BUCKET_LIMITS_MS[i] : Infinity; }
  return null;
}
export async function actorHash(env, keyId) {
  const pepper = env.ANALYTICS_PEPPER || env.KEY_PEPPER; if (!pepper) return null;
  return (await hmacHex(pepper, 'actor|' + keyId)).slice(0, 32);
}

// Actor/tenant first-seen rows only need writing once per day. This per-database (isolate-local) set skips the redundant INSERT OR IGNOREs and no-op UPDATEs after the first request of the day.
// A key is remembered ONLY after its batch committed, so a failed write is retried by the next request. It is a pure optimisation: the statements stay idempotent, so a cold isolate or an
// eviction just repeats them once. Bounded so it cannot grow without limit.
const seenBy = new WeakMap();
const seenOf = (db) => { let s = seenBy.get(db); if (!s) seenBy.set(db, (s = new Set())); return s; };

// rec: { tenantId, keyId?, actorKind?, channel, product, operation, httpStatus, toolError?, units?, bytes?, durationMs, commercialMode, billable?, theoretical?, replayed? }
export async function track(env, db, clock, rec) {
  try {
    if (env.ANALYTICS_ENABLED === '0') return false;                                     // kill switch: telemetry off, requests unaffected
    const d = day(clock()), sc = statusClass(rec.httpStatus, rec.toolError), col = COLS[bucketIndex(rec.durationMs ?? 0)];
    const units = rec.replayed ? 0 : (rec.units ?? 0), billable = rec.replayed ? 0 : (rec.billable ?? 0), theo = rec.replayed ? 0 : (rec.theoretical ?? 0);
    const premium = rec.product === 'premium' || rec.product === 'api';
    const stmts = [db.prepare(`INSERT INTO analytics_daily(day,tenant_id,channel,product,operation,status_class,commercial_mode,requests,units,bytes,duration_ms_sum,${col},billable_micros,theoretical_micros)
      VALUES (?,?,?,?,?,?,?,1,?,?,?,1,?,?) ON CONFLICT(day,tenant_id,channel,product,operation,status_class,commercial_mode) DO UPDATE SET requests=requests+1, units=units+excluded.units, bytes=bytes+excluded.bytes,
      duration_ms_sum=duration_ms_sum+excluded.duration_ms_sum, ${col}=${col}+1, billable_micros=billable_micros+excluded.billable_micros, theoretical_micros=theoretical_micros+excluded.theoretical_micros`)
      .bind(d, rec.tenantId, rec.channel, rec.product, rec.operation, sc, rec.commercialMode ?? 'FREE_LAUNCH', units, rec.bytes ?? 0, Math.round(rec.durationMs ?? 0), billable, theo)];
    const fresh = [];
    if (rec.keyId) {                                                                      // activity = an AUTHENTICATED actor reached the service (a refused request from a valid key still counts; an unauthenticated one never has a keyId)
      const h = await actorHash(env, rec.keyId), kind = rec.actorKind ?? 'api_key_client';
      const seen = seenOf(db), ka = `a|${d}|${rec.tenantId}|${kind}|${h}`, kp = `p|${d}|${rec.tenantId}|${kind}|${h}`;
      if (h && !seen.has(ka)) { fresh.push(ka); stmts.push(
        db.prepare('INSERT OR IGNORE INTO activity_daily(day,tenant_id,actor_kind,actor_hash,premium) VALUES (?,?,?,?,0)').bind(d, rec.tenantId, kind, h),
        db.prepare('INSERT OR IGNORE INTO actor_first_seen(tenant_id,actor_kind,actor_hash,first_day) VALUES (?,?,?,?)').bind(rec.tenantId, kind, h, d),
        db.prepare('INSERT OR IGNORE INTO tenant_first_seen(tenant_id,first_day) VALUES (?,?)').bind(rec.tenantId, d)); }
      if (h && premium && rec.httpStatus < 400 && !rec.toolError && !seen.has(kp)) { fresh.push(kp); stmts.push(
        db.prepare('UPDATE activity_daily SET premium = 1 WHERE day = ? AND tenant_id = ? AND actor_kind = ? AND actor_hash = ? AND premium = 0').bind(d, rec.tenantId, kind, h),
        db.prepare('UPDATE tenant_first_seen SET first_premium_day = ? WHERE tenant_id = ? AND first_premium_day IS NULL').bind(d, rec.tenantId)); }
    }
    await db.batch(stmts);
    const seen = seenOf(db); if (seen.size >= 5000) seen.clear(); for (const k of fresh) seen.add(k);                  // remembered only after the batch committed
    return true;
  } catch { return false; }
}

// Community redirect telemetry: one tiny upsert; `redirected` counts redirects ISSUED, which is not a completed download.
export async function trackCommunity(db, clock, { tag, asset, actorKind }, env = {}) {
  try {
    if (env.ANALYTICS_ENABLED === '0') return false; await db.prepare('INSERT INTO community_requests_daily(day,release_tag,asset_name,actor_kind,redirected) VALUES (?,?,?,?,1) ON CONFLICT(day,release_tag,asset_name,actor_kind) DO UPDATE SET redirected = redirected + 1').bind(day(clock()), tag, asset, actorKind).run(); return true; }
  catch { return false; }
}
