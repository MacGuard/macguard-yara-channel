// x402 adapter: EXPERIMENTAL, separate from the main pipeline and OFF unless X402_ENABLED=true. It speaks only what the public x402 documentation states (HTTP 402; Base64 JSON
// in the PAYMENT-REQUIRED, PAYMENT-SIGNATURE and PAYMENT-RESPONSE headers; a facilitator with /verify and /settle). The inner schema of the payment requirements and payloads is
// NOT defined here: the requirements object comes from configuration and goes through unchanged, and verification and settlement are delegated to an injected facilitator.
// No payment data (addresses, signatures) is stored; only the settlement transaction reference goes to the audit log. It is not wired to quotas or to Stripe.
import { audit } from './audit.js';
import * as intel from './intel.js';
import { HttpError, jsonResponse } from './util.js';

const b64 = (o) => btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(o))));
const unb64 = (s) => JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(s), (c) => c.charCodeAt(0))));
export const paymentRequired = (requirements, reason) => new Response(JSON.stringify({ error: { code: 'payment_required', message: reason ?? 'Payment required.' } }), { status: 402, headers: { 'content-type': 'application/json', 'payment-required': b64(requirements), 'cache-control': 'no-store' } });
export function readPayment(request) {
  const h = request.headers.get('payment-signature'); if (!h) return null;
  if (h.length > 16384) throw new HttpError(400, 'invalid_payment', 'The payment header is too large.');
  try { return unb64(h); } catch { throw new HttpError(400, 'invalid_payment', 'The payment header is not Base64 JSON.'); }
}
export async function handleX402(request, env, db, clock, facilitator) {
  if (env.X402_ENABLED !== 'true') return jsonResponse(404, { error: { code: 'not_found', message: 'Not found.' } });
  const m = /^\/x402\/v1\/intelligence\/hash\/([0-9a-fA-F]{32,64})$/.exec(new URL(request.url).pathname); if (!m || request.method !== 'GET') return jsonResponse(404, { error: { code: 'not_found', message: 'Not found.' } });
  let requirements; try { requirements = JSON.parse(env.X402_REQUIREMENTS || 'null'); } catch { requirements = null; }
  if (!requirements) return jsonResponse(503, { error: { code: 'x402_unconfigured', message: 'Pay-per-request is not configured.' } });
  const payment = readPayment(request); if (!payment) return paymentRequired(requirements);
  const v = await facilitator.verify(payment, requirements); if (!v?.isValid && v?.valid !== true) return paymentRequired(requirements, 'The payment could not be verified.');
  const result = await intel.hash(db, clock, m[1]);                                    // computed first, delivered only after settlement succeeds
  const s = await facilitator.settle(payment, requirements);
  if (!s || s.success === false || s.error) return paymentRequired(requirements, s?.error === 'settlement_pending' ? 'Settlement is pending; do not retry blindly.' : 'The payment could not be settled.');
  await audit(db, clock, null, 'x402.settled', { transaction: String(s.transaction ?? '').slice(0, 128), network: String(s.network ?? '').slice(0, 64) });
  return new Response(JSON.stringify(result), { status: 200, headers: { 'content-type': 'application/json', 'payment-response': b64({ transaction: s.transaction, network: s.network, success: true }), 'cache-control': 'no-store' } });
}
