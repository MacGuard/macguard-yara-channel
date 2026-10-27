// Multi-family aggregation for the panel: one day state that accounts for every family that was observed that day, and a family x day matrix of what was retained or rejected.
// Pure functions (no DOM), so the same rules are tested in Node and used by the dashboard. Nothing is invented: a family with no run that day is "not observed", never zero and never green.
const RANK = { FAIL: 4, WARNING: 3, RUNNING: 2, OK: 1 };   // the worst observed state wins; anything else is "not observed"
const RUN_STATE = { COMPLETE: 'OK', PARTIAL: 'WARNING', FAILED: 'FAIL' };
export const YARA = 'yara';

/** opsDays: /api/ops/overview days (YARA pipeline). runs: /api/intel/stats runs.items (family, retrieved_at, state, accepted, rejected, retained, approved, published).
 *  Returns, for the last `n` days, each day's per-family cell and the combined state. `intelKnown` is false when the caller cannot read intelligence data (a viewer): the combined state then says YARA only. */
export function mergeDays(opsDays, runs, n = 14, intelKnown = true) {
  const byDay = new Map();
  for (const r of runs || []) {
    const d = (r.retrieved_at || '').slice(0, 10); if (!d || !r.family) continue;
    const day = byDay.get(d) || new Map(), c = day.get(r.family) || { family: r.family, state: null, runs: 0, accepted: 0, rejected: 0, retained: 0, approved: 0, published: 0 };
    const st = RUN_STATE[r.state] || null; if (st && (!c.state || RANK[st] > RANK[c.state])) c.state = st;
    c.runs += 1; for (const k of ['accepted', 'rejected', 'retained', 'approved', 'published']) c[k] += Number(r[k]) || 0;
    day.set(r.family, c); byDay.set(d, day);
  }
  return (opsDays || []).slice(-n).map((od) => {
    const cells = [];
    const y = od.stats ? { family: YARA, state: RANK[od.state] ? od.state : null, runs: od.runs || 0, accepted: od.stats.accepted ?? 0, rejected: od.stats.rejected ?? 0, retained: od.stats.quarantined ?? null, approved: 0, published: 0 } : { family: YARA, state: RANK[od.state] ? od.state : null, runs: od.runs || 0, accepted: null, rejected: null, retained: null, approved: 0, published: 0 };
    cells.push(y);
    for (const c of (byDay.get(od.date) || new Map()).values()) cells.push(c);
    const seen = cells.filter((c) => c.state), worst = seen.reduce((a, c) => (!a || RANK[c.state] > RANK[a] ? c.state : a), null);
    const state = worst || od.state;   // nothing observed anywhere: keep the pipeline's own word (NO_RUN, PENDING, BEFORE, CANCELLED...)
    const bad = seen.filter((c) => c.state === 'FAIL' || c.state === 'WARNING').map((c) => ({ family: c.family, state: c.state }));
    return { date: od.date, state, ops_state: od.state, cells, attention: bad, families_observed: seen.length, intel_known: intelKnown };
  });
}

/** Family x day matrix for a measure ('retained' | 'rejected' | 'accepted'): rows are families seen in the window, cells are numbers or null (not observed). Totals ignore nulls. */
export function matrix(days, measure) {
  const fams = []; for (const d of days) for (const c of d.cells) if (!fams.includes(c.family)) fams.push(c.family);
  fams.sort((a, b) => (a === YARA ? -1 : b === YARA ? 1 : a.localeCompare(b)));
  const rows = fams.map((f) => ({ family: f, values: days.map((d) => { const c = d.cells.find((x) => x.family === f); return c && (c.runs > 0 || f === YARA) ? (c[measure] ?? null) : null; }) }));
  const totals = days.map((_, i) => { const v = rows.map((r) => r.values[i]).filter((x) => x !== null); return v.length ? v.reduce((a, b) => a + b, 0) : null; });
  return { rows, totals };
}
