// Intelligence queries. Only records of sources that are approved for the API product (licence matrix mirrored in intel_sources) are ever returned; there is no switch that
// bypasses it, including during the free launch. Scores are explainable sums of named factors, nothing hidden.
import { HttpError, iso } from './util.js';

const RE = { sha256: /^[0-9a-fA-F]{64}$/, sha1: /^[0-9a-fA-F]{40}$/, md5: /^[0-9a-fA-F]{32}$/, cve: /^CVE-\d{4}-\d{4,7}$/i, ipv4: /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/,
  domain: /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i, url: /^https?:\/\/[^\s\x00-\x1f]{1,2000}$/i };
export const typeOf = (v) => { if (typeof v !== 'string' || v.length > 2048 || /[\x00-\x1f]/.test(v)) return null; for (const t of ['cve', 'sha256', 'sha1', 'md5', 'ipv4', 'url', 'domain']) if (RE[t].test(v)) return t; return null; };
export const normalise = (type, v) => (type === 'cve' ? v.toUpperCase() : ['sha256', 'sha1', 'md5', 'domain'].includes(type) ? v.toLowerCase() : v);
const kindOf = (type) => (type === 'cve' ? 'cve' : ['sha256', 'sha1', 'md5'].includes(type) ? 'hash' : 'ioc');

async function fetchRecords(db, kind, key, nowIso) {
  const rows = (await db.prepare(`SELECT r.source_id, r.doc, r.expires_at, s.attribution FROM intel_records r JOIN intel_sources s ON s.source_id = r.source_id
    WHERE r.kind = ? AND r.key = ? AND s.status = 'PREMIUM_APPROVED' AND s.owner_confirmed = 1 AND s.approved_products LIKE '%"api"%' ORDER BY r.source_id`).bind(kind, key).all()).results;
  return rows.filter((r) => !r.expires_at || r.expires_at > nowIso).map((r) => ({ source_id: r.source_id, attribution: r.attribution, expires_at: r.expires_at, data: JSON.parse(r.doc) }));
}
export async function lookup(db, clock, type, value) {
  const v = normalise(type, value), records = await fetchRecords(db, kindOf(type), v, iso(clock()));
  return { type, value: v, found: records.length > 0, records };
}
// Score = sum of the factors below (cap 100). Example weights, NOT validated against outcomes: the point is that every point is accounted for.
export function priority(records) {
  const f = [], miss = [], by = Object.fromEntries(records.map((r) => [r.source_id, r.data]));
  const kev = records.find((r) => r.data.kev_listed === true || r.source_id === 'cisa-kev'); if (kev) f.push({ factor: 'listed_as_exploited', source: kev.source_id, points: 50 }); else miss.push('exploitation (no approved KEV record)');
  const e = records.find((r) => r.data.epss !== undefined); if (e) { const x = Math.round(parseFloat(e.data.epss) * 1000); const pts = x >= 500 ? 30 : x >= 100 ? 15 : 0; f.push({ factor: 'epss', source: e.source_id, value: String(e.data.epss), points: pts }); } else miss.push('epss');
  const c = records.find((r) => r.data.cvss !== undefined); if (c) { const x = Math.round(parseFloat(c.data.cvss) * 10); f.push({ factor: 'cvss', source: c.source_id, value: String(c.data.cvss), points: x >= 90 ? 15 : x >= 70 ? 8 : 0 }); } else miss.push('cvss');
  const eu = records.find((r) => r.data.euvd_exploited === true); if (eu) f.push({ factor: 'euvd_exploited', source: eu.source_id, points: 5 });
  return { score: Math.min(100, f.reduce((a, x) => a + x.points, 0)), factors: f, missing_inputs: miss, note: 'example weighting, not validated; only approved sources contribute', sources: Object.keys(by) };
}
export async function cve(db, clock, id) {
  const t = typeOf(id); if (t !== 'cve') throw new HttpError(400, 'invalid_input', 'Not a CVE identifier.');
  const r = await lookup(db, clock, 'cve', id); return { ...r, priority: r.found ? priority(r.records) : null };
}
export async function hash(db, clock, v) {
  const t = typeOf(v); if (!['sha256', 'sha1', 'md5'].includes(t)) throw new HttpError(400, 'invalid_input', 'Not a SHA-256, SHA-1 or MD5 hash.');
  return lookup(db, clock, t, v);
}
export async function iocSearch(db, clock, body) {
  const values = Array.isArray(body?.values) ? body.values : (typeof body?.value === 'string' ? [body.value] : null);
  if (!values || values.length < 1 || values.length > 50) throw new HttpError(400, 'invalid_input', 'Send "value" or 1 to 50 "values".');
  const out = [];
  for (const v of values) { const t = typeOf(v); if (!t) throw new HttpError(400, 'invalid_input', 'One of the values is not a recognised indicator.'); if (body.type && body.type !== t) continue; out.push(await lookup(db, clock, t, v)); }
  return { results: out };
}
// Relations come ONLY from fields the stored records carry (malware, cve, attack); nothing is inferred.
export async function enrich(db, clock, body) {
  const list = body?.indicators; if (!Array.isArray(list) || list.length < 1 || list.length > 50) throw new HttpError(400, 'invalid_input', 'Send 1 to 50 "indicators".');
  const out = [];
  for (const v of list) {
    const t = typeOf(v); if (!t) throw new HttpError(400, 'invalid_input', 'One of the indicators is not recognised.');
    const r = await lookup(db, clock, t, v), rel = { malware: new Set(), cves: new Set(), attack: new Set() };
    for (const rec of r.records) { for (const m of rec.data.malware ?? []) rel.malware.add(m); for (const c of rec.data.cve ?? []) rel.cves.add(c); for (const a of rec.data.attack ?? []) rel.attack.add(a); }
    out.push({ ...r, relations: { malware: [...rel.malware].sort(), cves: [...rel.cves].sort(), attack: [...rel.attack].sort() }, priority: t === 'cve' && r.found ? priority(r.records) : null });
  }
  return { results: out };
}
