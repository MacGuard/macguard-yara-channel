// Fixture for the F6 binding (review of #53): a fake GitHub "get a workflow run" API and OIDC tokens of runs the panel dispatched. Synthetic ids only.
// A run is "bound" when GitHub shows: workflow_dispatch of publish-expedited.yml on main, triggered by the panel's dispatcher identity, attempt 1, created after the
// dispatch, and the run-name `publish-expedited <request id> <dispatch id>` of the request's CURRENT dispatch. Tests override one field at a time.
export const DISPATCHER = '41898282';
export function bindRuns(w) {
  if (w.ghRuns) return w;
  w.ghRuns = new Map(); w.runLookups = 0; w.runsDown = false; w.env.EXPEDITE_DISPATCHER_ID = DISPATCHER; w.env.GITHUB_DISPATCH_TOKEN = w.env.GITHUB_DISPATCH_TOKEN || 'dispatch-token-for-tests';
  w.route(/\/actions\/runs\/(\d+)$/, (url) => { w.runLookups++; if (w.runsDown) return new Response('down', { status: 502 }); const r = w.ghRuns.get(url.match(/\/actions\/runs\/(\d+)$/)[1]); return r ? new Response(JSON.stringify(r)) : new Response('{}', { status: 404 }); });
  return w;
}
export const currentDispatchOf = (w, requestId) => { try { return w.db.raw.prepare('SELECT dispatch_id, at FROM publication_request_dispatches WHERE request_id = ? ORDER BY at DESC, rowid DESC LIMIT 1').get(requestId); } catch { return undefined; } };   // undefined on a schema before 0010
/** What GitHub shows for run `runId` dispatched by the panel for request `requestId` (its current dispatch), with `over` replacing fields. */
export function ghRun(w, runId, requestId, over = {}) {
  bindRuns(w); const d = currentDispatchOf(w, requestId);
  const r = { id: Number(runId), event: 'workflow_dispatch', path: '.github/workflows/publish-expedited.yml', head_branch: 'main', run_attempt: 1, triggering_actor: { id: Number(DISPATCHER), login: 'macguard-panel[bot]' }, actor: { id: Number(DISPATCHER), login: 'macguard-panel[bot]' },
    display_title: d ? `publish-expedited ${requestId} ${d.dispatch_id}` : 'publish-expedited', created_at: d ? d.at : '2026-11-01T00:00:00.000Z', ...over };
  w.ghRuns.set(String(runId), r); return r;
}
/** The OIDC token of attempt `attempt` of run `runId` of publish-expedited.yml, dispatched by the panel unless `over` says otherwise. */
export const runToken = (w, runId, attempt = 1, over = {}) => w.pipelineToken('publish-expedited.yml', { run_id: String(runId), run_attempt: String(attempt), event_name: 'workflow_dispatch', actor_id: DISPATCHER, ...over });
