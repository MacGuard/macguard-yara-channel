// Structured operational events of the intelligence pipeline (timestamp, level, component, module, message, correlation ids). Real rows from /api/intel/events; live updates add new rows
// without rebuilding the page, so the filters keep their focus. This is the OPERATIONAL log: the audit trail of people and decisions is a different record (Auditoría).
import { t } from '../i18n.js';
import { h, icon, put, pillGroup } from '../ui.js';
import { api, failure } from '../api.js';

const LEVELS = ['DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL'], POLL_MS = 15000;
const FIELDS = ['id', 'ts', 'level', 'component', 'module', 'message', 'run_id', 'trace_id', 'family', 'source_id', 'artifact_id', 'outcome', 'duration_ms', 'actor_id', 'evidence_ref'];

export async function renderLogs(ctx) {
  const { root, query } = ctx, f = { level: LEVELS.includes(query.get('level')) ? query.get('level') : '', component: query.get('component') || '', family: query.get('family') || '', run_id: query.get('run_id') || '' };
  const head = h('div', { class: 'page-head' }, h('div', {}, h('h1', { id: 'page-title', tabindex: '-1', text: t('lg_title') }), h('p', { text: t('lg_lead') })));
  put(root, head, h('div', { class: 'skeleton sk-block' }));
  const st = await api('GET', '/api/intel/stats');
  if (st.status !== 200) { put(root, head, h('p', { class: st.status === 503 ? 'alert alert-warn' : 'alert alert-bad', role: st.status === 503 ? 'status' : 'alert' }, icon('alert'), st.status === 503 ? t('ix_unbound') : failure(st, t('err_generic')))); return; }
  const comps = st.data.events.by_component, levelCount = Object.fromEntries(st.data.events.by_level.map((x) => [x.level, x.n]));
  const lvl = pillGroup(t('lg_level'), [['', t('all')], ...LEVELS.map((l) => [l, l, levelCount[l] || 0])], f.level, (v) => { f.level = v; reload(); });
  const comp = pillGroup(t('lg_component'), [['', t('all')], ...comps.map((c) => [c.component, c.component, c.n])], f.component, (v) => { f.component = v; reload(); });
  const status = h('p', { class: 'note', 'aria-live': 'off', id: 'lg-status' }), tbody = h('tbody', {}), more = h('div', { class: 'pager' }), sheet = h('aside', { class: 'sheet-side', hidden: true, 'aria-label': t('lg_detail') });
  const live = h('input', { type: 'checkbox', id: 'lg-live', checked: true }), liveLabel = h('label', { class: 'flex-8 center', for: 'lg-live' }, live, h('span', { text: t('lg_live') }));
  const table = h('div', { class: 'dt-wrap', role: 'region', 'aria-label': t('lg_title'), tabindex: '0' }, h('table', { class: 'dt dt-sel log' }, h('caption', { class: 'sr', text: t('lg_title') }),
    h('thead', {}, h('tr', {}, ...['lg_h_ts', 'lg_h_level', 'lg_h_component', 'lg_h_module', 'lg_h_message', 'lg_h_run'].map((k) => h('th', { scope: 'col', text: t(k) })))), tbody));
  const fr = (lab, node) => h('div', { class: 'filter-row' }, h('span', { class: 'fl', text: lab }), node);
  put(root, head, fr(t('lg_level'), lvl), fr(t('lg_component'), comp), h('div', { class: 'toolbar' }, status, liveLabel), h('div', { class: 'master-detail' }, h('div', {}, table, more), sheet),
    h('p', { class: 'note', text: t('lg_scope') }));

  let seq = 0, before = null, head_id = 0, selected = null, timer = null;
  const url = () => { const p = new URLSearchParams(); for (const [k, v] of Object.entries(f)) if (v) p.set(k, v); return `#/logs${p.toString() ? `?${p}` : ''}`; };
  const params = (extra) => { const p = new URLSearchParams({ limit: '100', ...extra }); for (const [k, v] of Object.entries(f)) if (v) p.set(k, v); return p; };
  const row = (e) => {
    const tr = h('tr', { tabindex: '0', 'aria-selected': 'false' }, h('td', { class: 'mono nowrap', text: e.ts.replace('T', ' ').replace('Z', '') }), h('td', {}, h('span', { class: `lv lv-${e.level.toLowerCase()}`, text: e.level })), h('td', { class: 'nowrap', text: e.component }), h('td', { class: 'nowrap', text: e.module }), h('td', { class: 'clip wide', title: e.message, text: e.message }), h('td', { class: 'mono clip', text: e.run_id || '—' }));
    const open = () => { if (selected) selected.setAttribute('aria-selected', 'false'); selected = tr; tr.setAttribute('aria-selected', 'true'); sheet.hidden = false;
      const close = h('button', { type: 'button', class: 'btn btn-sm btn-ghost', 'aria-label': t('close') }, icon('x')); close.addEventListener('click', () => { sheet.hidden = true; tr.setAttribute('aria-selected', 'false'); tr.focus(); });
      put(sheet, h('div', { class: 'flex-between' }, h('h2', { text: t('lg_detail') }), close), h('dl', { class: 'kv kv-tight' }, ...FIELDS.filter((k) => e[k] !== null && e[k] !== undefined).flatMap((k) => [h('dt', { text: k }), h('dd', { class: k.endsWith('_id') || k === 'ts' || k === 'evidence_ref' ? 'mono' : '', text: String(e[k]) })])),
        e.run_id ? h('a', { class: 'btn btn-sm', href: `#/logs?run_id=${encodeURIComponent(e.run_id)}`, text: t('lg_this_run') }) : null); };
    tr.addEventListener('click', open); tr.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); open(); } });
    return tr;
  };
  async function load(append) {
    const mine = ++seq; if (!append) { before = null; put(tbody); }
    const r = await api('GET', `/api/intel/events?${params(before ? { before } : {})}`); if (mine !== seq) return;
    if (r.status !== 200) { status.textContent = failure(r, t('err_generic')); return; }
    if (!append) head_id = r.data.head; for (const e of r.data.items) tbody.append(row(e));
    if (!r.data.items.length && !append) put(tbody, h('tr', {}, h('td', { colspan: 6, class: 'empty-cell' }, t('lg_none'))));
    before = r.data.next_before; put(more, before ? h('button', { type: 'button', class: 'btn btn-sm', onclick: () => load(true) }, t('ix_more')) : null);
    status.textContent = t('lg_status', { n: tbody.querySelectorAll('tr[tabindex]').length, head: head_id });
  }
  async function poll() {
    if (!live.checked || !root.isConnected) return;
    const r = await api('GET', `/api/intel/events?${params({ after: String(head_id) })}`);
    if (r.status === 200 && r.data.items.length) { if (r.data.truncated) { await load(false); } else { head_id = r.data.head; const first = tbody.firstChild; for (const e of r.data.items.slice().reverse()) tbody.insertBefore(row(e), first && first.tabIndex === 0 ? tbody.firstChild : null); status.textContent = t('lg_status', { n: tbody.querySelectorAll('tr[tabindex]').length, head: head_id }); } }
    else if (r.status !== 200) status.textContent = t('lg_gap', { why: failure(r, '') });   // an interruption is said, never hidden: the stream may have a gap
  }
  function reload() { history.replaceState(null, '', url()); load(false); }
  live.addEventListener('change', () => { status.textContent = live.checked ? status.textContent : t('lg_paused'); });
  timer = setInterval(() => { if (!root.isConnected) { clearInterval(timer); return; } poll(); }, POLL_MS);
  root.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !sheet.hidden) { sheet.hidden = true; if (selected) { selected.setAttribute('aria-selected', 'false'); selected.focus(); } } });
  document.title = `${t('lg_title')} · MacGuard Quarantine`;
  await load(false);
}
