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
/** Every read sees the EFFECTIVE state: the latest human decision if there is one, else the state the promotion imported. Decisions are a separate append-only table (migration 0002). */
const EFF = '(SELECT r.*, COALESCE(c.state, r.state) AS eff_state, c.state AS decided_state FROM intel_records r LEFT JOIN intel_current c ON c.record_id = r.id) intel_records';

/** Sources with their latest run and the number of records each holds. */
export async function listSources(db) {
  const src = (await db.prepare('SELECT * FROM intel_sources ORDER BY grp, id').all()).results;
  const counts = Object.fromEntries((await db.prepare('SELECT source_id, COUNT(*) AS n FROM intel_records GROUP BY source_id').all()).results.map((r) => [r.source_id, r.n]));
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
export async function listRecords(db, p) {
  const family = p.get('family'), source = p.get('source'), state = p.get('state'), q = (p.get('q') || '').trim(), sort = p.get('sort') || 'id', cursor = p.get('cursor'), limit = lim(p.get('limit'));
  const fams = family === null ? null : family.split(',');
  if (fams && (fams.length > FAMILIES.length || new Set(fams).size !== fams.length || !fams.every((x) => FAMILIES.includes(x)))) return bad('invalid family'); if (source !== null && !SRC.test(source)) return bad('invalid source'); if (state !== null && !STATE.test(state)) return bad('invalid state');
  if (!SORTS[sort]) return bad('invalid sort'); if (limit === null) return bad('invalid limit'); if (q.length > 80 || /[\x00-\x1f]/.test(q)) return bad('invalid search');
  const held = p.get('held_back'); if (held !== null && !['0', '1'].includes(held)) return bad('invalid held_back');
  const scope = p.get('scope'); if (scope !== null && !['quarantine', 'published'].includes(scope)) return bad('invalid scope');
  const [col, dir] = SORTS[sort], where = [], args = [];
  if (fams) { where.push(fams.length === 1 ? 'family = ?' : `family IN (${fams.map(() => '?').join(',')})`); args.push(...fams); } if (source) { where.push('source_id = ?'); args.push(source); } if (state) { where.push('eff_state = ?'); args.push(state); } if (scope) where.push(scope === 'published' ? "eff_state IN ('APPROVED','PUBLISHED')" : "(eff_state IS NULL OR eff_state NOT IN ('APPROVED','PUBLISHED'))"); if (held !== null) { where.push('held_back = ?'); args.push(+held); }
  if (q) { where.push("(key LIKE ? ESCAPE '\\' OR title LIKE ? ESCAPE '\\')"); args.push(`${likeEsc(q)}%`, `%${likeEsc(q)}%`); }
  const totalWhere = where.length ? 'WHERE ' + where.join(' AND ') : '', total = (await db.prepare(`SELECT COUNT(*) AS n FROM ${EFF} ${totalWhere}`).bind(...args).first()).n;
  if (cursor !== null) {
    const c = unb64(cursor); if (!c || typeof c.id !== 'string' || !ID.test(c.id)) return bad('invalid cursor');
    if (col === 'id') { where.push('id > ?'); args.push(c.id); }
    else { if (!(c.v === null || typeof c.v === 'number' || typeof c.v === 'string')) return bad('invalid cursor'); where.push(`(COALESCE(${col}, '') ${dir === 'DESC' ? '<' : '>'} COALESCE(?, '') OR (COALESCE(${col}, '') = COALESCE(?, '') AND id > ?))`); args.push(c.v, c.v, c.id); }
  }
  const order = col === 'id' ? 'id ASC' : `COALESCE(${col}, '') ${dir}, id ASC`;
  const rows = (await db.prepare(`SELECT id, family, source_id, run_id, key, title, severity, score, eff_state AS state, state AS imported_state, validated, functional, performance, held_back, first_seen, last_seen, updated_at FROM ${EFF} ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY ${order} LIMIT ?`).bind(...args, limit + 1).all()).results;
  const page = rows.slice(0, limit), last = page[page.length - 1];
  return { status: 200, body: { schema: 1, total, items: page.map((r) => ({ ...r, held_back: r.held_back === null ? null : !!r.held_back })), next_cursor: rows.length > limit && last ? b64({ id: last.id, v: col === 'id' ? undefined : last[col] ?? null }) : null } };
}

/** Why a record cannot be approved for publication, in the words of the evidence: gates of the rule matrix that did not pass, a run that is not publishable, a state that does not allow it. */
export function approvability(rec, run, source) {
  const reasons = [];
  if (rec.held_back) reasons.push({ code: 'held_back', detail: (J(rec.doc, {}).matrix_row || {}).reason || null });
  if (!run) reasons.push({ code: 'no_run' }); else if (!run.publishable) for (const b of J(run.blocking, [])) reasons.push({ code: 'run_blocking', detail: String(b).slice(0, 300) });
  if (source && source.redistribution && /^(no|forbidden|prohibited)/i.test(source.redistribution)) reasons.push({ code: 'licence', detail: source.redistribution });
  return { ok: reasons.length === 0, reasons };
}
export async function getRecord(db, id) {
  if (!ID.test(id)) return bad('invalid id');
  const r = await db.prepare('SELECT r.*, COALESCE(c.state, r.state) AS eff_state FROM intel_records r LEFT JOIN intel_current c ON c.record_id = r.id WHERE r.id = ?').bind(id).first(); if (!r) return { status: 404, body: { error: 'not found' } };
  const run = await db.prepare('SELECT * FROM intel_runs WHERE id = ?').bind(r.run_id).first(), source = await db.prepare('SELECT * FROM intel_sources WHERE id = ?').bind(r.source_id).first();
  const history = (await db.prepare('SELECT id, action, from_state, to_state, reason, actor, at, audited FROM intel_decisions WHERE record_id = ? ORDER BY id DESC LIMIT 50').bind(id).all()).results.map((x) => ({ ...x, audited: !!x.audited }));
  const { doc, body, eff_state, ...rest } = r, runV = run ? runView(run) : null;
  return { status: 200, body: { schema: 1, record: { ...rest, state: eff_state, imported_state: r.state, held_back: r.held_back === null ? null : !!r.held_back, body, doc: J(doc, null) }, run: runV, source: source ? { ...source, configured: !!source.configured } : null, history, approvable: approvability({ held_back: r.held_back, doc }, run, source) } };
}

export async function stats(db) {
  const byFamily = (await db.prepare('SELECT family, COUNT(*) AS records, SUM(CASE WHEN held_back = 1 THEN 1 ELSE 0 END) AS held_back FROM intel_records GROUP BY family ORDER BY family').all()).results;
  const byState = (await db.prepare(`SELECT family, COALESCE(eff_state, 'NONE') AS state, COUNT(*) AS n FROM ${EFF} GROUP BY family, eff_state ORDER BY family, eff_state`).all()).results;
  const bySource = (await db.prepare('SELECT source_id, COUNT(*) AS records, MAX(updated_at) AS newest_update FROM intel_records GROUP BY source_id ORDER BY source_id').all()).results;
  const runs = (await db.prepare('SELECT state, COUNT(*) AS n FROM intel_runs GROUP BY state').all()).results;
  const range = await db.prepare('SELECT MIN(retrieved_at) AS first_run, MAX(retrieved_at) AS last_run, COUNT(*) AS n FROM intel_runs').first();
  const verdicts = (await db.prepare('SELECT family, validated, functional, performance, COUNT(*) AS n FROM intel_records WHERE validated IS NOT NULL GROUP BY family, validated, functional, performance ORDER BY family').all()).results;
  const evLevel = (await db.prepare('SELECT level, COUNT(*) AS n FROM intel_events GROUP BY level').all()).results, evComp = (await db.prepare('SELECT component, COUNT(*) AS n FROM intel_events GROUP BY component ORDER BY component').all()).results;
  const perRun = (await db.prepare('SELECT r.id, r.source_id, s.family, r.retrieved_at, r.state, r.accepted, r.rejected, r.retained, r.approved, r.published, r.bytes FROM intel_runs r LEFT JOIN intel_sources s ON s.id = r.source_id ORDER BY r.retrieved_at, r.id').all()).results;
  return { schema: 1, generated_at: new Date().toISOString(), by_family: byFamily, by_state: byState, by_source: bySource, runs: { by_state: runs, ...range, items: perRun }, events: { by_level: evLevel, by_component: evComp }, verdicts };
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
