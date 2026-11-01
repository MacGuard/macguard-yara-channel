// Provider-agnostic subscription state (interface for any payment provider; the Stripe adapter in stripe.js keeps its own, equivalent, rule: dedupe by event id and converge on the
// provider's CURRENT state). Pure: no network, no prices. A provider failure never changes state, so it can never grant access.
//
// event: { id, provider, subscription_id, tenant_id, plan, status, version }   version = the provider's monotonic ordering for that subscription (e.g. its event timestamp)
// state: { seen: Set<provider:id>, subs: { [provider:subscription_id]: { tenant_id, plan, status, version } } }
export const STATUSES = Object.freeze(['active', 'past_due', 'canceled', 'expired', 'refunded', 'revoked']);
const GRANTING = new Set(['active', 'past_due']);                 // past_due keeps access only for the grace period, which the existing cron (sweepPastDue) closes

export const emptyState = () => ({ seen: new Set(), subs: {} });

export function applyEvent(state, ev) {
  const errs = [];
  if (!ev || typeof ev.id !== 'string' || !ev.id) errs.push('id');
  if (typeof ev?.provider !== 'string' || !ev.provider) errs.push('provider');
  if (typeof ev?.subscription_id !== 'string' || !ev.subscription_id) errs.push('subscription_id');
  if (!STATUSES.includes(ev?.status)) errs.push('status');
  if (!Number.isInteger(ev?.version) || ev.version < 0) errs.push('version');
  if (errs.length) return { state, outcome: 'rejected', errors: errs };
  const eid = `${ev.provider}:${ev.id}`, sid = `${ev.provider}:${ev.subscription_id}`;
  if (state.seen.has(eid)) return { state, outcome: 'duplicate' };                                       // a repeated webhook changes nothing
  const seen = new Set(state.seen); seen.add(eid);
  const cur = state.subs[sid];
  if (cur && ev.version <= cur.version) return { state: { ...state, seen }, outcome: 'stale' };          // an older event arriving late never overwrites a newer state
  if (cur && cur.tenant_id !== ev.tenant_id) return { state: { ...state, seen }, outcome: 'tenant_conflict' };
  return { state: { seen, subs: { ...state.subs, [sid]: { tenant_id: ev.tenant_id, plan: ev.plan ?? null, status: ev.status, version: ev.version } } }, outcome: 'applied' };
}
// The plan a tenant gets from its subscriptions: the best granting one, otherwise community. An unknown plan grants nothing.
export function planOf(state, tenantId, knownPlans = ['intelligence', 'business']) {
  const rank = { community: 0, intelligence: 1, business: 2 };
  let best = 'community';
  for (const s of Object.values(state.subs)) if (s.tenant_id === tenantId && GRANTING.has(s.status) && knownPlans.includes(s.plan) && rank[s.plan] > rank[best]) best = s.plan;
  return best;
}
