// Event contracts for a FUTURE GuardOps integration. GuardOps is not deployed or inspected here: these are schemas and an in-process sink, nothing is sent anywhere.
// Events never carry keys, tokens, Stripe ids, IPs or customer contents: only ids that are already internal (tenant, key id, release id) and counters.
import { iso, redact } from './util.js';
import { forward } from './guardops.js';
export const EVENT_TYPES = Object.freeze({
  'download.authorized': ['tenant_id', 'api_key_id', 'release_id'], 'download.rejected': ['tenant_id', 'reason'], 'usage.near_limit': ['tenant_id', 'kind', 'used', 'limit'],
  'tenant.suspended': ['tenant_id', 'reason'], 'billing.error': ['tenant_id', 'stage', 'code'], 'stripe.failure': ['stage', 'status'], 'api.saturated': ['tenant_id', 'scope'],
  'abuse.detected': ['tenant_id', 'signal'], 'release.premium_published': ['release_id', 'rules_root'], 'signature.invalid': ['release_id', 'stage'], 'replication.failed': ['release_id', 'provider'],
  'gateway.incident': ['component', 'code'],
});
export function makeEvent(type, data, clock) {
  const need = EVENT_TYPES[type]; if (!need) throw new Error(`unknown event type ${type}`);
  const missing = need.filter((k) => !(k in data)); if (missing.length) throw new Error(`event ${type} lacks ${missing.join(',')}`);
  return { schema: 'macguard.gateway-event/1', type, at: iso(clock()), data: redact(data) };
}
export const memorySink = () => { const events = []; return { events, emit: (e) => { events.push(e); } }; };
export async function emit(env, clock, type, data) {
  try { const e = makeEvent(type, data, clock); await env.EVENTS?.emit(e); await forward(env, env.DB, clock, e); } catch { /* an observer must never break a request */ }
}
