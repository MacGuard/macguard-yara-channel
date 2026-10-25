// Run records (macguard.source-run/1) for the Node tools (backups, publication), with the same rules as intel/telemetry.py: the record is written to a local outbox BEFORE any send; a failed send leaves
// the file and an .error note; flush() retries; nothing is sent twice; telemetry NEVER throws into the operation it describes. The panel stores each run_id once, so a re-send is harmless.
//   node tools/telemetry.mjs flush --outbox DIR --url https://<panel>/api/telemetry/ingest      token: MG_TELEMETRY_TOKEN in the environment (never an argument, never printed)
import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export const SCHEMA = 'macguard.source-run/1';
const SECRETISH = /(bearer\s+[A-Za-z0-9._~+/=-]{8,}|(?:token|key|secret|password|auth)[=:]\s*\S{6,}|[A-Za-z0-9+/_-]{40,})/gi;
export const scrub = (s, n = 300) => String(s ?? '').replace(SECRETISH, '[redacted]').slice(0, n);
const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
/** One class per failure, from facts (an HTTP status first, then the words of the error). */
export function classify(err, httpStatus = null) {
  const m = String(err?.message ?? err ?? '').toLowerCase(), code = httpStatus ?? (m.match(/\b(?:get|put|head|http|status)\s+(\d{3})\b/)?.[1] | 0 || null);
  if (code === 401 || code === 403 || code === 407) return { error_class: 'AUTH', http_status: code };
  if (code === 429) return { error_class: 'RATE_LIMIT', http_status: code };
  if (code >= 400) return { error_class: 'HTTP', http_status: code };
  if (/differs from what was sent|do not match|mismatch|different bytes|checksum|conflict/.test(m)) return { error_class: 'INTEGRITY', http_status: null };
  if (/abort|timeout|timed out/.test(m)) return { error_class: 'TIMEOUT', http_status: null };
  if (/certificate|tls|ssl/.test(m)) return { error_class: 'TLS', http_status: null };
  if (/enotfound|getaddrinfo|dns/.test(m)) return { error_class: 'DNS', http_status: null };
  if (/exist|storage|quota|full|bucket/.test(m)) return { error_class: 'STORAGE', http_status: null };
  return { error_class: 'OTHER', http_status: null };
}
export function makeRecord({ source_id, operation = 'download', started, finished = Date.now(), status = 'ok', error = null, error_class = null, http_status = null, counters = {}, stages = {}, bundle = null, bundle_version = null, run_id = randomUUID().replaceAll('-', '') }) {
  const c = (k) => Math.max(0, Math.trunc(counters[k] ?? 0));
  return { schema: SCHEMA, run_id, source_id, operation, started_at: iso(started), finished_at: iso(Math.max(started, finished)), duration_ms: Math.max(0, Math.round(finished - started)), status, http_status, error_class: status === 'ok' || status === 'not_modified' ? null : (error_class ?? 'OTHER'),
    error: error ? scrub(error) : null, files_attempted: c('files_attempted'), files_downloaded: c('files_downloaded'), bytes_downloaded: c('bytes_downloaded'), answers: c('answers'), pages: c('pages'), records_parsed: c('records_parsed'), records_valid: c('records_valid'), records_duplicate: c('records_duplicate'),
    records_rejected: c('records_rejected'), records_quarantined: c('records_quarantined'), records_approved: c('records_approved'), records_published: c('records_published'), bundle, bundle_version,
    validation_state: stages.validation_state ?? 'not_run', signature_state: stages.signature_state ?? 'n/a', manifest_state: stages.manifest_state ?? 'not_run', tests_state: stages.tests_state ?? 'n/a', publication_state: stages.publication_state ?? 'not_run' };
}

export class Outbox {
  constructor(dir, send = null) { this.dir = dir; this.send = send; try { mkdirSync(join(dir, 'sent'), { recursive: true }); } catch { /* reported by emit */ } }
  async emit(rec) {
    try { const p = join(this.dir, `${rec.run_id}.json`), tmp = join(this.dir, `.tmp-${rec.run_id}`); writeFileSync(tmp, JSON.stringify(rec)); renameSync(tmp, p); }
    catch { process.stderr.write(`telemetry: could not write the run record ${rec.run_id}\n`); return false; }
    return this.deliver(rec.run_id);
  }
  async deliver(id) {
    if (!this.send) return false; const p = join(this.dir, `${id}.json`);
    try { await this.send(JSON.parse(readFileSync(p, 'utf8'))); renameSync(p, join(this.dir, 'sent', `${id}.json`)); rmSync(join(this.dir, `${id}.error`), { force: true }); return true; }
    catch (e) { try { writeFileSync(join(this.dir, `${id}.error`), scrub(`${e?.name}: ${e?.message}`)); } catch { /* nothing more can be done */ } return false; }
  }
  pending() { try { return readdirSync(this.dir).filter((n) => n.endsWith('.json') && !n.startsWith('.')).sort(); } catch { return []; } }
  async flush() { let sent = 0, failed = 0; for (const n of this.pending()) { if (await this.deliver(n.slice(0, -5))) sent++; else failed++; } return { sent, failed }; }
}
/** POST one record to the panel's ingest endpoint. HTTPS only (plain http only for 127.0.0.1 in tests); the token is read at send time and never logged. */
export function httpSender(url, { tokenEnv = 'MG_TELEMETRY_TOKEN', fetchImpl = fetch, timeoutMs = 15000, env = process.env } = {}) {
  const u = new URL(url); if (u.protocol !== 'https:' && !(u.protocol === 'http:' && (u.hostname === '127.0.0.1' || u.hostname === 'localhost'))) throw new Error('telemetry is sent over HTTPS only');
  return async (rec) => {
    const tok = env[tokenEnv]; if (!tok) throw new Error(`${tokenEnv} is not set`);
    const r = await fetchImpl(url, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tok}` }, body: JSON.stringify(rec), signal: AbortSignal.timeout(timeoutMs) });
    if (r.status !== 200 && r.status !== 201) throw new Error(`ingest answered ${r.status}`);
  };
}
/** Outbox from the environment: MG_TELEMETRY_DIR (local evidence) and optionally MG_TELEMETRY_URL. Unset: no telemetry (a library call never writes files on its own). */
export function outboxFromEnv(env = process.env) { if (!env.MG_TELEMETRY_DIR) return null; return new Outbox(env.MG_TELEMETRY_DIR, env.MG_TELEMETRY_URL ? httpSender(env.MG_TELEMETRY_URL, { env }) : null); }
/** Never throws: telemetry is a witness, not a participant. */
export async function safeEmit(outbox, rec) { try { if (outbox) await outbox.emit(rec); } catch { /* ignored on purpose */ } }

if (import.meta.url === `file://${process.argv[1]}`) {
  const arg = (n) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : null; };
  if (process.argv[2] !== 'flush' || !arg('--outbox') || !arg('--url')) { console.error('usage: telemetry.mjs flush --outbox DIR --url URL'); process.exit(2); }
  const ob = new Outbox(arg('--outbox'), httpSender(arg('--url'))); const r = await ob.flush(); console.log(JSON.stringify(r)); process.exit(ob.pending().length ? 1 : 0);
}
