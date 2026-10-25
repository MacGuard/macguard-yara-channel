import { authenticate } from './auth.js';
import { acceptanceOf, loadActive } from './policy.js';

// Everything a request is allowed to know about itself, derived from VERIFIED credentials and ONE pinned policy version. No client-supplied header contributes to it.
export async function buildContext(request, env, db, clock) {
  const auth = await authenticate(request, env, db, clock);
  const policy = await loadActive(db);                                       // pinned for the whole request: a concurrent policy change cannot split it
  const acceptance = await acceptanceOf(db, auth.tenant.id, policy.doc.billing.pricing.version);
  return { ...auth, policy, acceptance };
}
