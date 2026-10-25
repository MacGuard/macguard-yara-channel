// Turns the reason a backup phase failed into a small, secret-free classification that travels as a GitHub job annotation (`macguard-backup: phase=… kind=… …`), so the panel can say WHY a run failed
// without reading logs. Only fixed vocabulary and numeric codes leave this file: never a token, a path to a credential, a SQL line or a free-text message.
const KINDS = ['cloudflare_auth', 'cloudflare_permission', 'cloudflare_not_found', 'rate_limited', 'timeout', 'network', 'verify_failed', 'encrypt_failed', 'unknown'];
export const ANNOTATION_PREFIX = 'macguard-backup:';

/** `text` is what the failing tool printed (already without the token). */
export function classifyFailure(phase, text) {
  const s = String(text || ''), code = (s.match(/\[code:\s*(\d{3,6})\]/i) || [])[1] || null, http = (s.match(/\b(?:HTTP|status)\s*(?:code\s*)?[:=]?\s*(4\d\d|5\d\d)\b/i) || [])[1] || null;
  let kind = 'unknown';
  if (/authentication error/i.test(s) || code === '10000') kind = 'cloudflare_auth';
  else if (/not authorized|permission|forbidden|\b403\b|code:\s*9109/i.test(s)) kind = 'cloudflare_permission';
  else if (/ENOTFOUND|ECONNRESET|ECONNREFUSED|fetch failed|network/i.test(s)) kind = 'network';
  else if (/\bnot found\b|could not find|no such database|code:\s*7404/i.test(s)) kind = 'cloudflare_not_found';
  else if (/rate.?limit|too many requests|\b429\b|code:\s*971\d/i.test(s)) kind = 'rate_limited';
  else if (/timed? ?out|ETIMEDOUT|SIGTERM/i.test(s)) kind = 'timeout';
  else if (phase === 'verify') kind = 'verify_failed'; else if (phase === 'encrypt') kind = 'encrypt_failed';
  return { phase: ['export', 'verify', 'encrypt', 'sign', 'write', 'read'].includes(phase) ? phase : 'export', kind, code: code && /^\d{3,6}$/.test(code) ? code : null, http: http && /^\d{3}$/.test(http) ? http : null };
}

/** The annotation line (a GitHub workflow command): fixed keys, fixed vocabulary. */
export function annotation(resource, c) {
  const kv = [`resource=${resource === 'panel' ? 'panel' : 'gateway'}`, `phase=${c.phase}`, `kind=${KINDS.includes(c.kind) ? c.kind : 'unknown'}`, ...(c.code ? [`code=${c.code}`] : []), ...(c.http ? [`http=${c.http}`] : [])];
  return `::error title=macguard-backup::${ANNOTATION_PREFIX} ${kv.join(' ')}`;
}

/** The reverse, for the panel: null unless the message is exactly this shape. */
export function parseAnnotation(message) {
  const m = String(message || '').match(/^macguard-backup: ((?:[a-z_]+=[A-Za-z0-9_]+ ?)+)$/); if (!m) return null;
  const out = Object.fromEntries(m[1].trim().split(' ').map((p) => p.split('='))); if (!KINDS.includes(out.kind) || !['export', 'verify', 'encrypt', 'sign', 'write', 'read'].includes(out.phase)) return null;
  return { resource: out.resource === 'panel' ? 'panel' : 'gateway', phase: out.phase, kind: out.kind, code: /^\d{3,6}$/.test(out.code || '') ? out.code : null, http: /^\d{3}$/.test(out.http || '') ? out.http : null };
}
