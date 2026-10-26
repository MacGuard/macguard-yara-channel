// Read API over the INTEL database (promoted intelligence): sources with their latest real run, runs, paginated records with detail, statistics and structured events.
// Every parameter is validated against a closed vocabulary or a strict pattern; pagination is keyset-based and bounded; nothing here writes. When the database is not bound the answer says so (503).
export const FAMILIES = ['yara', 'suricata', 'sigma', 'ioc', 'hash', 'cve', 'epss', 'kev', 'attack', 'advisory'];
export const LEVELS = ['DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL'];
const ID = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,199}$/, SRC = /^[a-z0-9][a-z0-9_-]{1,40}$/, RUN = /^[A-Za-z0-9:._-]{3,120}$/, COMP = /^[a-z0-9][a-z0-9_.-]{1,40}$/, STATE = /^[A-Za-z_]{2,40}$/;
const SORTS = { id: ['id', 'ASC'], score_desc: ['score', 'DESC'], updated_desc: ['updated_at', 'DESC'] };

export const unavailable = () => ({ status: 503, body: { error: 'the intelligence database is not bound to this Worker', code: 'intel_store_unavailable' } });
const bad = (error) => ({ status: 400, body: { error } });
const lim = (v, d = 50, max = 200) => { const n = v === null || v === '' ? d : Number(v); return Number.isInteger(n) && n >= 1 ? Math.min(n, max) : null; };
const likeEsc = (s) => s.replace(/[\\%_]/g, (c) => `\\${c}`);
const b64 = (o) => btoa(JSON.stringify(o)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64 = (s) => { try { return JSON.parse(atob(s.replace(/-/g, '+').replace(/_/g, '/'))); } catch { return null; } };
/** Secrets never leave this API even if one reached the table: token-shaped text is masked on the way out. */
export const redact = (m) => String(m).replace(/(bearer\s+[a-z0-9._-]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AGE-SECRET-KEY-[A-Z0-9]+|[?&](sig|token|jwt|signature)=[^&\s]+)/gi, '[redacted]');
const J = (s, d) => { try { return JSON.parse(s); } catch { return d; } };
/** Every read sees the EFFECTIVE state: the latest human decision if there is one, else the state the promotion imported. Three tiers, from the cheapest, so a Worker deployed before a migration keeps working:
 *  A (0003) the state lives in intel_records.decided_state and is read with no join; B (0002) a join with intel_current; C (nothing applied) the imported state only. */
const TIER_A = { name: 'A', from: 'intel_records', eff: 'COALESCE(decided_state, state)', state: (x) => ({ sql: '((decided_state IS NULL AND state = ?) OR decided_state = ?)', args: [x, x] }),
  scope: (sc) => (sc === 'published' ? "(decided_state IN ('APPROVED','PUBLISHED') OR (decided_state IS NULL AND state IN ('APPROVED','PUBLISHED')))" : "(COALESCE(decided_state, state) IS NULL OR COALESCE(decided_state, state) NOT IN ('APPROVED','PUBLISHED'))") };
const EFF = '(SELECT r.*, COALESCE(c.state, r.state) AS eff_state FROM intel_records r LEFT JOIN intel_current c ON c.record_id = r.id) intel_records';
const EFF_PLAIN = '(SELECT r.*, r.state AS eff_state FROM intel_records r) intel_records';
const viaView = (name, from) => ({ name, from, eff: 'eff_state', state: (x) => ({ sql: 'eff_state = ?', args: [x] }), scope: (sc) => (sc === 'published' ? "eff_state IN ('APPROVED','PUBLISHED')" : "(eff_state IS NULL OR eff_state NOT IN ('APPROVED','PUBLISHED'))") });
const TIER_B = viaView('B', EFF), TIER_C = viaView('C', EFF_PLAIN);
const noColumn = (e) => /no such column: ([\w]+\.)*decided_state/.test(String((e && e.message) || e));
const noOverlay = (e) => /no such (table|view): (main\.)?intel_(current|decisions)/.test(String((e && e.message) || e));
async function withOverlay(fn) {
  try { return await fn(TIER_A); } catch (e) { if (!noColumn(e) && !noOverlay(e)) throw e; }
  try { return await fn(TIER_B); } catch (e) { if (!noOverlay(e)) throw e; }
  return fn(TIER_C);
}
export const overlayMissing = noOverlay;

// ---- the snapshot: ONE pass over the records, kept until a promotion changes the data -------------------------------------------------------------------------------------------------------
// Every screen used to scan the 75k records several times (counts, groups, verdicts). D1 bills the rows scanned, so a handful of page loads used the whole free daily quota. The counts now come from one
// pass, stored in intel_snapshot (migration 0003) and kept in memory; decisions are applied on top as small deltas. The marker changes only when a run is promoted or events are added.
const memo = new WeakMap();   // db -> { at, marker, data }
export const MEMO_MS = 60_000;
const markerOf = async (db) => { const r = await db.prepare('SELECT COUNT(*) AS n, COALESCE(MAX(promoted_at), \'\') AS p FROM intel_runs').first(), e = await db.prepare('SELECT COALESCE(MAX(id), 0) AS n FROM intel_events').first(); return `${r.n}:${r.p}:${e.n}`; };
const SNAP_SQL = 'SELECT family, source_id, state, held_back, validated, functional, performance, COUNT(*) AS n, MAX(updated_at) AS newest, MIN(id) AS min_id, MAX(id) AS max_id FROM intel_records GROUP BY family, source_id, state, held_back, validated, functional, performance';
async function loadSnapshot(db, nowMs = Date.now()) {
  const m = memo.get(db); if (m && nowMs - m.at < MEMO_MS) return m.data;
  const marker = await markerOf(db); if (m && m.marker === marker) { m.at = nowMs; return m.data; }
  let data = null; try { const row = await db.prepare('SELECT marker, json FROM intel_snapshot WHERE id = 1').first(); if (row && row.marker === marker) data = JSON.parse(row.json); } catch (e) { if (!/no such table/i.test(String(e))) throw e; }
  if (!data) {
    const rows = (await db.prepare(SNAP_SQL).all()).results; data = { schema: 1, marker, cells: rows.map((r) => ({ family: r.family, source_id: r.source_id, state: r.state, held_back: r.held_back === null ? null : r.held_back ? 1 : 0, validated: r.validated, functional: r.functional, performance: r.performance, n: r.n, newest: r.newest, min_id: r.min_id, max_id: r.max_id })) };
    try { await db.prepare('INSERT OR REPLACE INTO intel_snapshot (id, marker, json, generated_at, rows_read) VALUES (1, ?, ?, ?, ?)').bind(marker, JSON.stringify(data), new Date(nowMs).toISOString(), rows.reduce((a, r) => a + r.n, 0)).run(); } catch (e) { if (!/no such table/i.test(String(e))) throw e; }   // 0003 not applied: kept in memory only
  }
  memo.set(db, { at: nowMs, marker, data }); return data;
}
export const resetSnapshotMemo = (db) => memo.delete(db);
/** Decisions on top of the snapshot: for every decided record, one cell loses it (imported state) and another gains it (decided state). Cheap: one row per decided record. */
async function deltas(db) {
  const attempts = ['SELECT family, source_id, state AS imported, decided_state AS effective FROM intel_records WHERE decided_state IS NOT NULL', 'SELECT r.family, r.source_id, r.state AS imported, c.state AS effective FROM intel_current c JOIN intel_records r ON r.id = c.record_id'];
  for (const sql of attempts) { try { return (await db.prepare(sql).all()).results; } catch (e) { if (!noColumn(e) && !noOverlay(e)) throw e; } }
  return [];
}
/** The effective (family, source, state) cells: snapshot minus/plus the decisions. */
async function effectiveCells(db) {
  const snap = await loadSnapshot(db), cube = new Map(), key = (f, s, st) => `${f}\u0000${s}\u0000${st ?? ''}`;
  for (const c of snap.cells) { const k = key(c.family, c.source_id, c.state); cube.set(k, (cube.get(k) || 0) + c.n); }
  for (const d of await deltas(db)) { const a = key(d.family, d.source_id, d.imported), b = key(d.family, d.source_id, d.effective); cube.set(a, (cube.get(a) || 0) - 1); cube.set(b, (cube.get(b) || 0) + 1); }
  return [...cube.entries()].filter(([, n]) => n !== 0).map(([k, n]) => { const [family, source_id, state] = k.split('\u0000'); return { family, source_id, state: state === '' ? null : state, n }; });
}
const PUBLISHED_STATES = ['APPROVED', 'PUBLISHED'];
export const SEARCH_SCAN_MAX = 25_000;
/** Id ranges that contain every record of the chosen families/source: one per (family, source). Records are read by primary-key range in id order, so nothing is ever sorted: a list reads about as many rows as it returns. */
async function idRanges(db, fams, source) {
  const snap = await loadSnapshot(db), r = new Map();
  for (const c of snap.cells) { if (!c.min_id || (fams && !fams.includes(c.family)) || (source && c.source_id !== source)) continue; const k = `${c.family}\u0000${c.source_id}`, x = r.get(k); if (!x) r.set(k, { family: c.family, source_id: c.source_id, lo: c.min_id, hi: c.max_id }); else { if (c.min_id < x.lo) x.lo = c.min_id; if (c.max_id > x.hi) x.hi = c.max_id; } }
  return [...r.values()].sort((a, b) => (a.lo < b.lo ? -1 : a.lo > b.lo ? 1 : 0));
}
const globEsc = (x) => x.replace(/[\[\]*?]/g, (c) => `[${c}]`);
/** Exact total for filters the snapshot can answer (families, source, state, scope); null when it cannot (text search, held_back): the caller then says "50 or more" instead of scanning. */
async function exactTotal(db, { fams, source, state, scope, q, held }) {
  if (q || held !== null) return null;
  const cells = await effectiveCells(db); let n = 0;
  for (const c of cells) { if (fams && !fams.includes(c.family)) continue; if (source && c.source_id !== source) continue; if (state && c.state !== state) continue;
    const pub = PUBLISHED_STATES.includes(c.state); if (scope === 'published' && !pub) continue; if (scope === 'quarantine' && pub) continue; n += c.n; }
  return n;
}

/** Sources with their latest run and the number of records each holds. */
export async function listSources(db) {
  const src = (await db.prepare('SELECT * FROM intel_sources ORDER BY grp, id').all()).results;
  const counts = {}; for (const c of await effectiveCells(db)) counts[c.source_id] = (counts[c.source_id] || 0) + c.n;
  const runs = (await db.prepare('SELECT r.* FROM intel_runs r JOIN (SELECT source_id, MAX(retrieved_at) AS m FROM intel_runs GROUP BY source_id) x ON x.source_id = r.source_id AND (x.m = r.retrieved_at OR (x.m IS NULL AND r.retrieved_at IS NULL)) ORDER BY r.source_id').all()).results;
  const latest = {}; for (const r of runs) latest[r.source_id] = runView(r);
  return { schema: 1, sources: src.map((s) => ({ ...s, configured: !!s.configured, records: counts[s.id] || 0, latest_run: latest[s.id] || null })) };
}
const runView = (r) => ({ ...r, publishable: !!r.publishable, blocking: J(r.blocking, []), evidence: J(r.evidence, {}) });

export async function listRuns(db, p) {
  const source = p.get('source'), limit = lim(p.get('limit'), 50, 200), before = p.get('before');
  if (source !== null && !SRC.test(source)) return bad('invalid source'); if (limit === null) return bad('invalid limit');
  if (before !== null && !RUN.test(before)) return bad('invalid cursor');
  const where = [], args = []; if (source) { where.push('source_id = ?'); args.push(source); } if (before) { where.push("COALESCE(retrieved_at, '') < COALESCE((SELECT retrieved_at FROM intel_runs WHERE id = ?), '')"); args.push(before); }
  const rows = (await db.prepare(`SELECT * FROM intel_runs ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY retrieved_at DESC, id DESC LIMIT ?`).bind(...args, limit + 1).all()).results;
  return { status: 200, body: { schema: 1, items: rows.slice(0, limit).map(runView), next: rows.length > limit ? rows[limit - 1].id : null } };
}

/** Keyset-paginated records. The list never carries the document or the body: only the columns the table shows. */
export const listRecords = (db, p) => withOverlay(async (tier) => { const r = await listRecordsOn(db, p, tier, false); return r.status === 200 && r.body.items.length === 0 && r.body.idSearch && !p.get('cursor') ? listRecordsOn(db, p, tier, true) : r; });   // an identifier-looking text that matches no key is then tried as a title search (still capped)
async function listRecordsOn(db, p, tier, titleOnly) {
  const family = p.get('family'), source = p.get('source'), state = p.get('state'), q = (p.get('q') || '').trim(), sort = p.get('sort') || 'id', cursor = p.get('cursor'), limit = lim(p.get('limit'));
  const fams = family === null ? null : family.split(',');
  if (fams && (fams.length > FAMILIES.length || new Set(fams).size !== fams.length || !fams.every((x) => FAMILIES.includes(x)))) return bad('invalid family'); if (source !== null && !SRC.test(source)) return bad('invalid source'); if (state !== null && !STATE.test(state)) return bad('invalid state');
  if (!SORTS[sort]) return bad('invalid sort'); if (limit === null) return bad('invalid limit'); if (q.length > 80 || /[\x00-\x1f]/.test(q)) return bad('invalid search');
  const held = p.get('held_back'); if (held !== null && !['0', '1'].includes(held)) return bad('invalid held_back');
  const scope = p.get('scope'); if (scope !== null && !['quarantine', 'published'].includes(scope)) return bad('invalid scope');
  const [col, dir] = SORTS[sort], where = [], args = [];
  if (fams) { where.push(fams.length === 1 ? 'family = ?' : `family IN (${fams.map(() => '?').join(',')})`); args.push(...fams); } if (source) { where.push('source_id = ?'); args.push(source); }
  if (state) { const c = tier.state(state); where.push(c.sql); args.push(...c.args); } if (scope) where.push(tier.scope(scope)); if (held !== null) { where.push('held_back = ?'); args.push(+held); }
  // Text search is the one read that cannot be answered from an index. An identifier-looking text is looked up as a prefix of the key (GLOB uses the key index: a few rows read). Anything else scans titles,
  // and a scan of tens of thousands of rows per keystroke is exactly what exhausted the free quota: it is allowed only when the filters already narrow the candidates to SEARCH_SCAN_MAX rows.
  let idSearch = false;
  if (q) {
    idSearch = !titleOnly && /^[A-Za-z0-9][A-Za-z0-9:._-]{1,79}$/.test(q) && !/\s/.test(q);
    if (!idSearch) { const cand = await exactTotal(db, { fams, source, state, scope, q: null, held: null }); if (cand !== null && cand > SEARCH_SCAN_MAX) return { status: 400, body: { error: `searching titles over ${cand} records would read too many rows: pick a family or a source first, or search by identifier`, code: 'search_too_broad', candidates: cand, max: SEARCH_SCAN_MAX } }; }
    if (idSearch) { where.push("key GLOB ?"); args.push(`${globEsc(q)}*`); } else { where.push("(key LIKE ? ESCAPE '\\' OR title LIKE ? ESCAPE '\\')"); args.push(`${likeEsc(q)}%`, `%${likeEsc(q)}%`); }
  }
  // The total comes from the snapshot (no scan). When it is zero nothing can match, so the table is not even touched; when it cannot be known (text search) it is null and the page says so.
  const total = await exactTotal(db, { fams, source, state, scope, q, held: held === null ? null : +held });
  if (total === 0) return { status: 200, body: { schema: 1, total: 0, items: [], next_cursor: null } };
  if (cursor !== null) { const c = unb64(cursor); if (!c || typeof c.id !== 'string' || !ID.test(c.id)) return bad('invalid cursor'); }
  const order = col === 'id' ? 'id ASC' : `COALESCE(${col}, '') ${dir}, id ASC`, cols = `id, family, source_id, run_id, key, title, severity, score, ${tier.eff} AS state, state AS imported_state, validated, functional, performance, held_back, first_seen, last_seen, updated_at`;
  let rows = [];
  if (col === 'id') {   // the normal case: PK ranges, one per (family, source), concatenated in id order
    const ranges = await idRanges(db, fams, source), skip = (fams ? fams.length : 0) + (source ? 1 : 0);
    const base = where.filter((w) => !/^(family|source_id)\b/.test(w)), keep = args.slice(skip);   // the family/source predicates are replaced by one id range per (family, source)
    const cursorId = cursor !== null ? (unb64(cursor) || {}).id : null;
    for (const rg of ranges.length ? ranges : [null]) {
      if (rows.length > limit) break; const w = [...base], a = [...keep];
      if (rg) { if (cursorId && rg.hi <= cursorId) continue; w.push('id >= ?', 'id <= ?', 'family = ?', 'source_id = ?'); a.push(rg.lo, rg.hi, rg.family, rg.source_id); }
      else { if (fams) { w.push(fams.length === 1 ? 'family = ?' : `family IN (${fams.map(() => '?').join(',')})`); a.push(...fams); } if (source) { w.push('source_id = ?'); a.push(source); } }
      if (cursorId) { w.push('id > ?'); a.push(cursorId); }
      rows.push(...(await db.prepare(`SELECT ${cols} FROM ${tier.from} ${w.length ? 'WHERE ' + w.join(' AND ') : ''} ORDER BY id ASC LIMIT ?`).bind(...a, limit + 1 - rows.length).all()).results);
    }
  } else {
    const cand = await exactTotal(db, { fams, source, state, scope, q: null, held: null }); if (cand !== null && cand > SEARCH_SCAN_MAX) return { status: 400, body: { error: `sorting ${cand} records would read too many rows: pick a family or a source first`, code: 'sort_too_broad', candidates: cand, max: SEARCH_SCAN_MAX } };
    if (cursor !== null) { const c = unb64(cursor); if (!c || typeof c.id !== 'string' || !ID.test(c.id)) return bad('invalid cursor'); if (!(c.v === null || typeof c.v === 'number' || typeof c.v === 'string')) return bad('invalid cursor'); where.push(`(COALESCE(${col}, '') ${dir === 'DESC' ? '<' : '>'} COALESCE(?, '') OR (COALESCE(${col}, '') = COALESCE(?, '') AND id > ?))`); args.push(c.v, c.v, c.id); }
    rows = (await db.prepare(`SELECT ${cols} FROM ${tier.from} ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY ${order} LIMIT ?`).bind(...args, limit + 1).all()).results;
  }
  const page = rows.slice(0, limit), last = page[page.length - 1];
  const body = { schema: 1, total, items: page.map((r) => ({ ...r, held_back: r.held_back === null ? null : !!r.held_back })), next_cursor: rows.length > limit && last ? b64({ id: last.id, v: col === 'id' ? undefined : last[col] ?? null }) : null }; if (idSearch) Object.defineProperty(body, 'idSearch', { value: true, enumerable: false }); return { status: 200, body };
}

/** Why a record cannot be approved for publication, in the words of the evidence: gates of the rule matrix that did not pass, a run that is not publishable, a state that does not allow it. */
export function approvability(rec, run, source) {
  const reasons = [];
  if (rec.held_back) reasons.push({ code: 'held_back', detail: (J(rec.doc, {}).matrix_row || {}).reason || null });
  if (!run) reasons.push({ code: 'no_run' }); else if (!run.publishable) for (const b of J(run.blocking, [])) reasons.push({ code: 'run_blocking', detail: String(b).slice(0, 300) });
  if (source && source.redistribution && /^(no|forbidden|prohibited)/i.test(source.redistribution)) reasons.push({ code: 'licence', detail: source.redistribution });
  return { ok: reasons.length === 0, reasons };
}
export const getRecord = (db, id) => withOverlay((tier) => getRecordOn(db, id, tier));
async function getRecordOn(db, id, tier) {
  if (!ID.test(id)) return bad('invalid id');
  const r = await db.prepare(`SELECT r.*, ${tier.name === 'A' ? 'COALESCE(r.decided_state, r.state)' : tier.name === 'B' ? 'COALESCE(c.state, r.state)' : 'r.state'} AS eff_state FROM intel_records r ${tier.name === 'B' ? 'LEFT JOIN intel_current c ON c.record_id = r.id' : ''} WHERE r.id = ?`).bind(id).first(); if (!r) return { status: 404, body: { error: 'not found' } };
  const run = await db.prepare('SELECT * FROM intel_runs WHERE id = ?').bind(r.run_id).first(), source = await db.prepare('SELECT * FROM intel_sources WHERE id = ?').bind(r.source_id).first();
  const history = tier.name !== 'C' ? (await db.prepare('SELECT id, action, from_state, to_state, reason, actor, at, audited FROM intel_decisions WHERE record_id = ? ORDER BY id DESC LIMIT 50').bind(id).all()).results.map((x) => ({ ...x, audited: !!x.audited })) : [];
  const { doc, body, eff_state, decided_state, ...rest } = r, runV = run ? runView(run) : null;
  return { status: 200, body: { schema: 1, record: { ...rest, state: eff_state, imported_state: r.state, held_back: r.held_back === null ? null : !!r.held_back, body, doc: J(doc, null) }, run: runV, source: source ? { ...source, configured: !!source.configured } : null, history, approvable: approvability({ held_back: r.held_back, doc }, run, source) } };
}

export async function stats(db) {
  const cells = await effectiveCells(db), snap = await loadSnapshot(db);
  const byFamilyM = new Map(), byStateM = new Map(), bySourceM = new Map(), verdictM = new Map();
  for (const c of snap.cells) {   // imported facts: records, held back, newest update, verdicts
    const f = byFamilyM.get(c.family) || { family: c.family, records: 0, held_back: 0 }; f.records += c.n; if (c.held_back === 1) f.held_back += c.n; byFamilyM.set(c.family, f);
    const so = bySourceM.get(c.source_id) || { source_id: c.source_id, records: 0, newest_update: null }; so.records += c.n; if (c.newest && (!so.newest_update || c.newest > so.newest_update)) so.newest_update = c.newest; bySourceM.set(c.source_id, so);
    if (c.validated !== null && c.validated !== undefined) { const k = `${c.family}|${c.validated}|${c.functional}|${c.performance}`; const v = verdictM.get(k) || { family: c.family, validated: c.validated, functional: c.functional, performance: c.performance, n: 0 }; v.n += c.n; verdictM.set(k, v); }
  }
  for (const c of cells) { const k = `${c.family}|${c.state ?? 'NONE'}`; byStateM.set(k, { family: c.family, state: c.state ?? 'NONE', n: (byStateM.get(k)?.n || 0) + c.n }); }   // effective states
  const byFamily = [...byFamilyM.values()].sort((a, b) => a.family.localeCompare(b.family)), bySource = [...bySourceM.values()].sort((a, b) => a.source_id.localeCompare(b.source_id));
  const byState = [...byStateM.values()].sort((a, b) => a.family.localeCompare(b.family) || a.state.localeCompare(b.state)), verdicts = [...verdictM.values()].sort((a, b) => a.family.localeCompare(b.family));
  const runs = (await db.prepare('SELECT state, COUNT(*) AS n FROM intel_runs GROUP BY state').all()).results;
  const range = await db.prepare('SELECT MIN(retrieved_at) AS first_run, MAX(retrieved_at) AS last_run, COUNT(*) AS n FROM intel_runs').first();
  const evLevel = (await db.prepare('SELECT level, COUNT(*) AS n FROM intel_events GROUP BY level').all()).results, evComp = (await db.prepare('SELECT component, COUNT(*) AS n FROM intel_events GROUP BY component ORDER BY component').all()).results;
  const perRun = (await db.prepare('SELECT r.id, r.source_id, s.family, r.retrieved_at, r.state, r.accepted, r.rejected, r.retained, r.approved, r.published, r.bytes FROM intel_runs r LEFT JOIN intel_sources s ON s.id = r.source_id ORDER BY r.retrieved_at, r.id').all()).results;
  let decisions = null; try { const d = await db.prepare('SELECT COUNT(*) AS total, COALESCE(SUM(CASE WHEN audited = 0 THEN 1 ELSE 0 END), 0) AS unaudited FROM intel_decisions').first(); decisions = { total: d.total, unaudited: d.unaudited }; } catch (e) { if (!noOverlay(e)) throw e; }   // null: the migration is not applied
  return { schema: 1, decisions, generated_at: new Date().toISOString(), snapshot_marker: snap.marker, by_family: byFamily, by_state: byState, by_source: bySource, runs: { by_state: runs, ...range, items: perRun }, events: { by_level: evLevel, by_component: evComp }, verdicts };
}

export async function listEvents(db, p) {
  const level = p.get('level'), comp = p.get('component'), family = p.get('family'), run = p.get('run_id'), before = p.get('before'), after = p.get('after'), limit = lim(p.get('limit'), 100, 500);
  if (level !== null && !LEVELS.includes(level)) return bad('invalid level'); if (comp !== null && !COMP.test(comp)) return bad('invalid component'); if (family !== null && !FAMILIES.includes(family)) return bad('invalid family');
  if (run !== null && !RUN.test(run)) return bad('invalid run_id'); if (limit === null) return bad('invalid limit'); if (before !== null && !/^\d{1,12}$/.test(before)) return bad('invalid cursor'); if (after !== null && !/^\d{1,12}$/.test(after)) return bad('invalid cursor'); if (before !== null && after !== null) return bad('use before or after, not both');
  const src = p.get('source_id'), text = p.get('q'); if (src !== null && !/^[A-Za-z0-9_.:-]{1,80}$/.test(src)) return bad('invalid source_id'); if (text !== null && (text.length < 2 || text.length > 64)) return bad('q must be 2 to 64 characters');
  const where = [], args = []; if (src) { where.push('source_id = ?'); args.push(src); } if (text) { where.push("(message LIKE ? ESCAPE '\\' OR module LIKE ? ESCAPE '\\' OR component LIKE ? ESCAPE '\\')"); const like = `%${text.replace(/[\\%_]/g, '\\$&')}%`; args.push(like, like, like); } if (level) { where.push('level = ?'); args.push(level); } if (comp) { where.push('component = ?'); args.push(comp); } if (family) { where.push('family = ?'); args.push(family); } if (run) { where.push('run_id = ?'); args.push(run); } if (before) { where.push('id < ?'); args.push(+before); } if (after) { where.push('id > ?'); args.push(+after); }
  const rows = (await db.prepare(`SELECT * FROM intel_events ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY id DESC LIMIT ?`).bind(...args, limit + 1).all()).results;
  const head = await db.prepare('SELECT COALESCE(MAX(id), 0) AS n FROM intel_events').first();
  return { status: 200, body: { schema: 1, items: rows.slice(0, limit).map((e) => ({ ...e, message: redact(e.message) })), next_before: rows.length > limit ? rows[limit - 1].id : null, head: head.n, truncated: after !== null && rows.length > limit } };
}
