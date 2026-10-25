// Small, dependency-free helpers (WebCrypto only: runs in workerd and in Node 22).
const enc = new TextEncoder();
export const bytes = (s) => (typeof s === 'string' ? enc.encode(s) : s);
export const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
export const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export async function sha256Hex(data) { return hex(await crypto.subtle.digest('SHA-256', bytes(data))); }
export async function hmac(keyBytes, msg) {
  const key = await crypto.subtle.importKey('raw', bytes(keyBytes), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, bytes(msg)));
}
export const hmacHex = async (k, m) => hex(await hmac(k, m));
// Constant-time comparison of two strings of any length (the length itself is not a secret here: all compared values have a fixed length).
export function safeEqual(a, b) {
  const x = bytes(String(a)), y = bytes(String(b)); let d = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) d |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return d === 0;
}
export const randomToken = (n = 32) => b64u(crypto.getRandomValues(new Uint8Array(n)));
export const randomHex = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));
export function canonical(o) {
  if (o === null || typeof o !== 'object') { if (typeof o === 'number' && !Number.isInteger(o)) throw new Error('floats are not allowed in canonical documents'); return JSON.stringify(o); }
  if (Array.isArray(o)) return '[' + o.map(canonical).join(',') + ']';
  return '{' + Object.keys(o).sort().map((k) => JSON.stringify(k) + ':' + canonical(o[k])).join(',') + '}';
}
export const iso = (d) => d.toISOString().replace(/\.\d{3}Z$/, 'Z');
export const windows = (d) => { const s = iso(d); return { minute: s.slice(0, 16), day: s.slice(0, 10), month: s.slice(0, 7) }; };

// Reads a request body but never more than `max` bytes: a declared Content-Length over the limit is refused before reading, and an undeclared or lying length is cut off while streaming.
export async function readBounded(request, max) {
  const declared = Number(request.headers.get('content-length') || 0); if (declared > max) throw new HttpError(413, 'too_large', 'The request body is too large.');
  if (!request.body) return '';
  const reader = request.body.getReader(), parts = []; let size = 0;
  for (;;) { const { done, value } = await reader.read(); if (done) break; size += value.byteLength; if (size > max) { await reader.cancel().catch(() => {}); throw new HttpError(413, 'too_large', 'The request body is too large.'); } parts.push(value); }
  const all = new Uint8Array(size); let o = 0; for (const p of parts) { all.set(p, o); o += p.byteLength; } return new TextDecoder().decode(all);
}

export class HttpError extends Error {
  constructor(status, code, message, extra = {}) { super(message); this.status = status; this.code = code; this.extra = extra; }
}
export const SECRET_KEYS = /secret|token|authorization|password|api[_-]?key|signature|cookie|pepper/i;
export function redact(o, depth = 0) {
  if (depth > 6 || o === null || typeof o !== 'object') return o;
  if (Array.isArray(o)) return o.map((x) => redact(x, depth + 1));
  return Object.fromEntries(Object.entries(o).map(([k, v]) => [k, SECRET_KEYS.test(k) ? '[redacted]' : redact(v, depth + 1)]));
}
export function jsonResponse(status, body, headers = {}) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...headers } });
}
// What a client may learn from a failure: a stable code, a short message and the request id. Never a stack, a SQL string, a key id or a path.
export function errorResponse(err, requestId) {
  if (err instanceof HttpError) return jsonResponse(err.status, { error: { code: err.code, message: err.message, request_id: requestId, ...err.extra } }, { ...(err.extra?.retry_after_seconds ? { 'retry-after': String(err.extra.retry_after_seconds) } : {}), ...(err.headers || {}) });
  return jsonResponse(500, { error: { code: 'internal_error', message: 'The request could not be completed.', request_id: requestId } });
}
