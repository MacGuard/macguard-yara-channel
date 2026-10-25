// The intelligence families the channel works with (detections, indicators, vulnerabilities, context), each with its REAL state: the declared catalogue config/intel-families.json (versioned, with
// its evidence reference) read from the repository, plus the one family the Worker can measure live (the published YARA release). Nothing is invented: a family without data is NO_DATA, one
// held by policy is RETENIDA with its concrete causes, one without a connector is BLOCKED. Strictly validated: an entry outside the vocabulary is dropped and said so.
export const GROUPS = ['detections', 'indicators', 'vulnerabilities', 'context'];
export const INTEGRATION = ['INTEGRATED_LOCAL', 'NOT_INTEGRATED'];
export const PUBLICATION = ['PUBLISHED', 'RETENIDA', 'NO_DATA', 'NOT_RUN', 'BLOCKED', 'NOT_APPLICABLE'];
const ID = /^[a-z][a-z0-9_]{1,40}$/, CAUSE = /^[a-z][a-z_]{2,40}$/, HEAD = /^[0-9a-f]{64}$/, TEXT = /^[A-Za-z0-9 .,()&+_:\/-]{1,120}$/;   // no markup characters, quotes or equals signs: these strings only ever reach the page as text, and still cannot carry markup

export function validateCatalogue(c) {
  if (!c || c.schema !== 'macguard.intel-families/1' || !Array.isArray(c.families)) return { ok: false, error: 'not a macguard.intel-families/1 catalogue' };
  const dropped = [], families = [], seen = new Set();
  for (const f of c.families.slice(0, 60)) {
    const bad = !f || !ID.test(f.id || '') || seen.has(f.id) || !GROUPS.includes(f.group) || !INTEGRATION.includes(f.integration) || !PUBLICATION.includes(f.publication) || !TEXT.test(f.name || '') || (f.source !== null && !TEXT.test(f.source || ''))
      || !Array.isArray(f.causes) || f.causes.length > 8 || !f.causes.every((x) => CAUSE.test(x)) || !f.counts || typeof f.counts !== 'object' || Object.entries(f.counts).some(([k, v]) => !ID.test(k) || !Number.isInteger(v) || v < 0 || v > 1e12) || (f.evidence_head !== null && !HEAD.test(f.evidence_head || ''));
    if (bad) { dropped.push(String((f && f.id) || '?').slice(0, 40)); continue; }
    seen.add(f.id); families.push({ id: f.id, group: f.group, name: f.name, source: f.source, integration: f.integration, publication: f.publication, counts: f.counts, causes: f.causes, evidence_head: f.evidence_head, live: false });
  }
  const ev = c.evidence || {};
  return { ok: true, families, dropped, as_of: /^\d{4}-\d{2}-\d{2}$/.test(c.as_of || '') ? c.as_of : null, evidence: { doc: TEXT.test(ev.doc || '') ? ev.doc : null, commit: /^[0-9a-f]{7,40}$/.test(ev.commit || '') ? ev.commit : null, branch: TEXT.test(ev.branch || '') ? ev.branch : null, in_main: ev.in_main === true } };
}

/** The YARA family from the signed release the Worker verified: this one is a live reading, not a declaration. */
export function yaraFamily(inv) {
  const sources = {}; for (const [, m] of inv.files) { const s = m.source || 'unknown'; sources[s] = (sources[s] || 0) + 1; }
  const stats = (inv.meta && inv.meta.stats) || {}, counts = { files: inv.files.length, ...(Number.isInteger(stats.yara_rules) ? { rules: stats.yara_rules } : {}), ...Object.fromEntries(Object.entries(sources).map(([k, v]) => [`files_${k.replace(/[^a-z0-9]/gi, '_').toLowerCase()}`, v])) };
  return { id: 'yara', group: 'detections', name: 'YARA (Community channel)', source: 'signed release', integration: 'INTEGRATED_LOCAL', publication: 'PUBLISHED', counts, causes: [], evidence_head: null, live: true, live_release: { tag: inv.tag, published_at: inv.published_at, manifest_sha256: inv.manifest_sha256 } };
}

export async function loadFamilies(env, deps, inv) {
  const raw = env.GITHUB_RAW || 'https://raw.githubusercontent.com', url = `${raw}/${env.REPO}/main/config/intel-families.json`;
  let catalogue = null, error = null;
  try { const r = await deps.fetch(url, { headers: { Accept: 'application/json', 'User-Agent': 'macguard-admin' } }); if (!r.ok) error = `http_${r.status}`; else { const t = await r.text(); if (t.length > 200000) error = 'too_large'; else { const v = validateCatalogue(JSON.parse(t)); if (v.ok) catalogue = v; else error = 'malformed'; } } } catch { error = 'unreachable'; }
  const live = inv ? [yaraFamily(inv)] : [];
  return { families: [...live, ...(catalogue ? catalogue.families : [])], declared: catalogue ? { as_of: catalogue.as_of, evidence: catalogue.evidence, dropped: catalogue.dropped } : null, catalogue_error: error, live_error: inv ? null : 'release_unreadable' };
}
