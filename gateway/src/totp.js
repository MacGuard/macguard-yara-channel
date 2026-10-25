// RFC 6238 TOTP (HMAC-SHA1, 30 s, 6 digits) with WebCrypto, plus sealing of the seed with AES-GCM (platform primitive; the key is derived from an environment secret).
import { b64u, bytes } from './util.js';
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export const toBase32 = (u8) => { let bits = '', out = ''; for (const b of u8) bits += b.toString(2).padStart(8, '0'); for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)]; return out; };
export const fromBase32 = (s) => { let bits = ''; for (const c of s.replace(/=+$/, '').toUpperCase()) bits += B32.indexOf(c).toString(2).padStart(5, '0'); const out = []; for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2)); return new Uint8Array(out); };
export async function totp(secretBytes, step, digits = 6) {
  const msg = new Uint8Array(8); new DataView(msg.buffer).setBigUint64(0, BigInt(step));
  const key = await crypto.subtle.importKey('raw', secretBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg)), o = h[h.length - 1] & 15;
  const n = ((h[o] & 0x7f) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % 10 ** digits;
  return String(n).padStart(digits, '0');
}
export const stepOf = (nowMs) => Math.floor(nowMs / 30000);
// Returns the matching step (so the caller can refuse replays) or null. Window: one step either side for clock skew.
export async function matchStep(secretBytes, code, nowMs) {
  if (!/^\d{6}$/.test(code || '')) return null;
  const s = stepOf(nowMs); let found = null;
  for (const d of [-1, 0, 1]) if ((await totp(secretBytes, s + d)) === code && found === null) found = s + d;     // no early exit: constant work
  return found;
}
const sealKey = async (secret) => crypto.subtle.importKey('raw', await crypto.subtle.digest('SHA-256', bytes('totp-seal|' + secret)), 'AES-GCM', false, ['encrypt', 'decrypt']);
export async function seal(secret, plain) { const iv = crypto.getRandomValues(new Uint8Array(12)); const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await sealKey(secret), plain)); return b64u(iv) + '.' + b64u(ct); }
const fromB64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
export async function unseal(secret, sealed) { const [iv, ct] = sealed.split('.'); return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64u(iv) }, await sealKey(secret), fromB64u(ct))); }
