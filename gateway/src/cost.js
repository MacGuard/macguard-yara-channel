// Cost intelligence. Nothing is invented: `confirmed` comes from an invoice (CSV import today; provider APIs need credentials that are not configured), `estimated` comes ONLY from
// an owner-supplied rate (cost_rates, no seed) multiplied by a quantity this system measured. A cost without a tenant is UNALLOCATED. Currencies are never summed together.
import { HttpError, iso, sha256Hex } from './util.js';

export const PROVIDERS = ['cloudflare', 'backblaze', 'scaleway', 'flyio', 'github', 'gitlab', 'stripe', 'intel_feed', 'other'];
// Quantities the gateway really measures, per (service, unit): the only ones an estimate may be built from.
export const MEASURED = { 'cloudflare/workers/request': 'SELECT COALESCE(SUM(requests),0) q FROM analytics_daily WHERE substr(day,1,7) = ?', 'cloudflare/r2/transfer_byte': "SELECT COALESCE(SUM(bytes),0) q FROM analytics_daily WHERE channel = 'download' AND substr(day,1,7) = ?" };

// "12.345678" -> 12345678 micro-units, exactly (no floats). More than 6 decimals, signs other than a leading minus, or thousands separators are rejected.
export function toMicros(text) {
  const m = /^(-?)(\d{1,9})(?:\.(\d{1,6}))?$/.exec(String(text).trim()); if (!m) throw new HttpError(400, 'invalid_amount', `Not a plain decimal amount: ${String(text).slice(0, 24)}`);
  return (m[1] ? -1 : 1) * (Number(m[2]) * 1e6 + Number((m[3] ?? '').padEnd(6, '0')));
}
export function parseCsv(text) {                                                           // RFC 4180 subset: quoted fields, doubled quotes, CRLF
  const rows = []; let row = [], f = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { f += '"'; i++; } else q = false; } else f += c; }
    else if (c === '"') q = true; else if (c === ',') { row.push(f); f = ''; } else if (c === '\n' || c === '\r') { if (c === '\r' && text[i + 1] === '\n') i++; row.push(f); f = ''; if (row.some((x) => x !== '')) rows.push(row); row = []; } else f += c;
  }
  row.push(f); if (row.some((x) => x !== '')) rows.push(row); return rows;
}
const COLS = ['period', 'service', 'amount', 'currency'], OPT = ['tenant_id', 'product', 'usage_unit', 'usage_quantity', 'invoice_ref'];

// Idempotent: the same file imported twice writes nothing the second time (entry_id = content hash + the n-th identical line).
export async function importCsv(db, clock, text, { provider, kind = 'confirmed', batch = null }) {
  if (!PROVIDERS.includes(provider)) throw new HttpError(400, 'invalid_provider', 'Unknown provider.'); if (!['confirmed', 'estimated'].includes(kind)) throw new HttpError(400, 'invalid_kind', 'kind must be confirmed or estimated.');
  const rows = parseCsv(text); if (rows.length < 2) throw new HttpError(400, 'empty_csv', 'The CSV has no data rows.');
  const head = rows[0].map((h) => h.trim().toLowerCase()); for (const c of COLS) if (!head.includes(c)) throw new HttpError(400, 'invalid_csv', `Missing column: ${c}`);
  const unknown = head.filter((h) => ![...COLS, ...OPT].includes(h)); if (unknown.length) throw new HttpError(400, 'invalid_csv', `Unknown column: ${unknown[0].slice(0, 30)}`);
  const at = iso(clock()), seen = new Map(), stmts = [], errors = [];
  rows.slice(1).forEach((r, i) => {
    try {
      const o = Object.fromEntries(head.map((h, j) => [h, (r[j] ?? '').trim()]));
      if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(o.period)) throw new HttpError(400, 'invalid_period', 'period must be YYYY-MM.'); if (!/^[A-Za-z]{3}$/.test(o.currency)) throw new HttpError(400, 'invalid_currency', 'currency must be 3 letters.');
      if (!o.service || o.service.length > 80) throw new HttpError(400, 'invalid_service', 'service is required.');
      const micros = toMicros(o.amount), qty = o.usage_quantity === '' || o.usage_quantity === undefined ? null : Number(o.usage_quantity); if (qty !== null && (!Number.isSafeInteger(qty) || qty < 0)) throw new HttpError(400, 'invalid_quantity', 'usage_quantity must be a non-negative integer.');
      stmts.push({ o, micros, qty, key: [provider, o.service, o.period, kind, o.invoice_ref ?? '', o.tenant_id ?? '', o.product ?? '', micros, o.currency.toUpperCase()].join('|') });
    } catch (e) { errors.push({ line: i + 2, code: e.code ?? 'invalid_row' }); }
  });
  if (errors.length) return { imported: 0, ignored: 0, rejected: errors.length, errors: errors.slice(0, 20), note: 'Nothing was imported: fix the rows and import again.' };       // all-or-nothing
  const ops = []; for (const s of stmts) { const n = (seen.get(s.key) ?? 0) + 1; seen.set(s.key, n); ops.push(db.prepare(`INSERT OR IGNORE INTO cost_entries(entry_id,provider,service,billing_period,kind,amount_micros,currency,tenant_id,product,usage_unit,usage_quantity,source,invoice_ref,import_batch,imported_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,'csv',?,?,?)`).bind('ce_' + (await sha256Hex(s.key + '#' + n)).slice(0, 24), provider, s.o.service, s.o.period, kind, s.micros, s.o.currency.toUpperCase(), s.o.tenant_id || null, s.o.product || null, s.o.usage_unit || null, s.qty, s.o.invoice_ref || null, batch, at)); }
  const res = await db.batch(ops); const imported = res.reduce((a, r) => a + (r.meta?.changes ?? 0), 0);
  return { imported, ignored: ops.length - imported, rejected: 0 };
}

export async function setRate(db, clock, { provider, service, usage_unit, micros_per_unit, currency, source_url, as_of }) {
  if (!PROVIDERS.includes(provider) || !MEASURED[`${provider}/${service}/${usage_unit}`]) throw new HttpError(400, 'unmeasured', `No measured quantity for ${provider}/${service}/${usage_unit}; known: ${Object.keys(MEASURED).join(', ')}`);
  if (!Number.isSafeInteger(micros_per_unit) || micros_per_unit < 0) throw new HttpError(400, 'invalid_rate', 'micros_per_unit must be a non-negative integer.'); if (!/^https:\/\//.test(source_url ?? '')) throw new HttpError(400, 'invalid_source', 'A rate needs the https URL of the published price it comes from.');
  await db.prepare('INSERT INTO cost_rates(provider,service,usage_unit,micros_per_unit,currency,source_url,as_of) VALUES (?,?,?,?,?,?,?) ON CONFLICT(provider,service,usage_unit,as_of) DO UPDATE SET micros_per_unit=excluded.micros_per_unit, currency=excluded.currency, source_url=excluded.source_url')
    .bind(provider, service, usage_unit, micros_per_unit, String(currency).toUpperCase(), source_url, as_of ?? iso(clock()).slice(0, 10)).run();
}
// Recompute the ESTIMATED rows of one month (deterministic ids: re-running replaces, never duplicates). A (service, unit) without a rate produces nothing and is reported.
export async function estimate(db, clock, period) {
  const rates = (await db.prepare('SELECT * FROM cost_rates r WHERE as_of = (SELECT MAX(as_of) FROM cost_rates x WHERE x.provider = r.provider AND x.service = r.service AND x.usage_unit = r.usage_unit AND x.as_of <= ?)').bind(period + '-31').all()).results;
  const done = [], missing = Object.keys(MEASURED).filter((k) => !rates.some((r) => `${r.provider}/${r.service}/${r.usage_unit}` === k));
  for (const r of rates) {
    const sql = MEASURED[`${r.provider}/${r.service}/${r.usage_unit}`]; if (!sql) continue; const q = (await db.prepare(sql).bind(period).first()).q;
    await db.prepare(`INSERT INTO cost_entries(entry_id,provider,service,billing_period,kind,amount_micros,currency,usage_unit,usage_quantity,source,imported_at) VALUES (?,?,?,?,'estimated',?,?,?,?,'rates',?)
      ON CONFLICT(entry_id) DO UPDATE SET amount_micros=excluded.amount_micros, usage_quantity=excluded.usage_quantity, imported_at=excluded.imported_at`)
      .bind(`est_${period}_${r.provider}_${r.service}_${r.usage_unit}`, r.provider, r.service, period, q * r.micros_per_unit, r.currency, r.usage_unit, q, iso(clock())).run(); done.push({ provider: r.provider, service: r.service, quantity: q });
  }
  return { period, estimated: done, missing_rates: missing };
}

// Per (provider, service, currency): estimated vs confirmed, allocated vs unallocated, and reconciliation where both exist. `tolerance` is a parameter, not a finding.
export async function costSummary(db, { period, tenantId = null, tolerance = 0.1 }) {
  const rows = (await db.prepare(`SELECT provider, service, currency, kind, SUM(amount_micros) amt, SUM(CASE WHEN tenant_id IS NULL THEN amount_micros ELSE 0 END) unalloc, COUNT(*) n FROM cost_entries WHERE billing_period = ?${tenantId ? ' AND tenant_id = ?' : ''}
    GROUP BY provider, service, currency, kind ORDER BY provider, service`).bind(period, ...(tenantId ? [tenantId] : [])).all()).results;
  const map = new Map(); for (const r of rows) { const k = `${r.provider}/${r.service}/${r.currency}`; const e = map.get(k) ?? { provider: r.provider, service: r.service, currency: r.currency, estimated_micros: null, confirmed_micros: null, unallocated_micros: 0, allocated_micros: 0 };
    e[r.kind + '_micros'] = r.amt; if (r.kind === 'confirmed') { e.unallocated_micros += r.unalloc; e.allocated_micros += r.amt - r.unalloc; } map.set(k, e); }
  const lines = [...map.values()].map((e) => { const both = e.estimated_micros !== null && e.confirmed_micros !== null;
    return { ...e, reconciliation: !both ? { status: 'UNKNOWN', reason: e.confirmed_micros === null ? 'no invoice imported' : 'no estimate (no rate)' } : { status: Math.abs(e.confirmed_micros - e.estimated_micros) <= Math.abs(e.confirmed_micros) * tolerance ? 'RECONCILED' : 'MISMATCH', delta_micros: e.confirmed_micros - e.estimated_micros, tolerance } }; });
  const totals = {}; for (const l of lines) { const t = (totals[l.currency] ??= { confirmed_micros: 0, estimated_only_micros: 0, unallocated_micros: 0 }); if (l.confirmed_micros !== null) { t.confirmed_micros += l.confirmed_micros; t.unallocated_micros += l.unallocated_micros; } else t.estimated_only_micros += l.estimated_micros ?? 0; }
  return { period, lines, totals_by_currency: totals, note: 'confirmed = invoices; estimated_only = months/services with no invoice yet; currencies are never summed together', state: lines.length ? 'REAL_VERIFIED' : 'NO_DATA' };
}
// Unit costs exist only when BOTH the cost and its denominator were measured; otherwise null with the reason (never a made-up ratio).
export async function unitCosts(db, period) {
  const reqs = (await db.prepare('SELECT COALESCE(SUM(requests),0) q FROM analytics_daily WHERE substr(day,1,7) = ?').bind(period).first()).q;
  const costs = (await db.prepare("SELECT currency, kind, SUM(amount_micros) a FROM cost_entries WHERE billing_period = ? AND provider = 'cloudflare' AND service = 'workers' GROUP BY currency, kind").bind(period).all()).results;
  const pick = (cur) => costs.find((c) => c.currency === cur && c.kind === 'confirmed') ?? costs.find((c) => c.currency === cur);
  const out = costs.map((c) => c.currency).filter((x, i, a) => a.indexOf(x) === i).map((cur) => { const c = pick(cur); return { metric: 'cost_per_1000_requests_micros', provider: 'cloudflare/workers', currency: cur, accuracy: c.kind === 'confirmed' ? 'EXACT' : 'ESTIMATED', value: reqs ? Math.round((c.a * 1000) / reqs) : null, requests: reqs, reason: reqs ? undefined : 'no requests measured' }; });
  return { period, unit_costs: out.length ? out : [{ metric: 'cost_per_1000_requests_micros', value: null, reason: 'no cost entry for cloudflare/workers' }] };
}
