// Quarantine list: filters, search, per-state counts, single and batch selection. Rows are cards, never an overflowing table.
import { t } from '../i18n.js';
import { h, icon, clear, stateBadge, reasonLabel, fmtDate, shortSha, copyButton, put, pillGroup, can } from '../ui.js';
import { api, failure } from '../api.js';
import { decide } from './decide.js';
import { loadIntelStats, retainedTable } from './intel_summary.js';

const STATES = ['PENDING', 'UNDER_REVIEW', 'APPROVED_PENDING_VALIDATION', 'REJECTED'];   // published rules are not in quarantine: they have their own inventory (#/published)
const SIZE = 25;
const selection = new Map();

export async function renderQuarantine(ctx) {
  const { root, me, query, go } = ctx, canDecide = can(me, 'quarantine.decide');
  const f = { state: STATES.includes(query.get('state')) ? query.get('state') : '', q: query.get('q') || '', source: query.get('source') || '', synthetic: query.get('synthetic') === '1' ? '1' : '', page: Math.max(1, +query.get('page') || 1) };
  const hash = (o) => { const p = new URLSearchParams(); for (const k of ['state', 'q', 'source', 'synthetic']) if (o[k]) p.set(k, o[k]); if (o.page > 1) p.set('page', o.page); const s = p.toString(); return `#/quarantine${s ? `?${s}` : ''}`; };
  const apply = (patch) => { selection.clear(); go(hash({ ...f, page: 1, ...patch }), true); };

  const refresh = h('button', { type: 'button', class: 'btn btn-sm', onclick: () => ctx.rerender() }, icon('refresh'), t('refresh'));
  const otherFamilies = h('div', { class: 'minw0' }); loadIntelStats(me).then((st) => { const n = retainedTable(st, false); if (n) put(otherFamilies, n); });
  const pills = h('div'), srcPills = h('div'), synBox = h('div'), listBox = h('div', { 'aria-live': 'polite' }), bar = h('div');
  const search = h('input', { class: 'input', id: 'q-search', type: 'search', autocomplete: 'off', value: f.q, placeholder: '' });
  let timer; search.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(() => { selection.clear(); f.q = search.value.trim(); f.page = 1; history.replaceState(null, '', hash(f)); load(); }, 300); });   // only the list reloads: the input keeps its node, focus, caret and selection

  put(root, 
    h('div', { class: 'page-head' }, h('div', {}, h('h1', { id: 'page-title', tabindex: '-1', text: t('q_title') }), h('p', { text: t('q_lead') })), h('div', { class: 'actions' }, refresh)),
    pills, h('div', { class: 'field' }, h('label', { for: 'q-search', text: t('q_search') }), search), srcPills, synBox,
    listBox, bar, otherFamilies);

  const stats = await api('GET', '/api/stats');
  if (stats.status === 200) {
    const c = stats.data.counts || {}, total = STATES.reduce((a, s) => a + (c[s] || 0), 0);
    put(pills, pillGroup(t('q_state'), [['', t('all'), total], ...STATES.map((s) => [s, t(`st_short_${s}`), c[s] || 0])], f.state, (v) => apply({ state: v })));
    if (stats.data.synthetic) { const box = h('input', { type: 'checkbox', id: 'q-syn', checked: f.synthetic === '1' }); box.addEventListener('change', () => apply({ synthetic: box.checked ? '1' : '' })); put(synBox, h('div', { class: 'field' }, h('label', { class: 'flex-8 center', for: 'q-syn' }, box, h('span', { text: t('q_synthetic', { n: stats.data.synthetic }) })))); }
    const names = Object.keys(stats.data.sources || {}).sort();
    if (names.length > 1) put(srcPills, h('div', { class: 'field' }, h('span', { text: t('q_source') }), pillGroup(t('q_source'), [['', t('q_all_sources')], ...names.map((s) => [s, s, stats.data.sources[s]])], f.source, (v) => apply({ source: v }))));
  }

  let seq = 0;
  async function load() {
  const mine = ++seq;
  const q = new URLSearchParams({ page: f.page, pageSize: SIZE }); for (const k of ['state', 'q', 'source', 'synthetic']) if (f[k]) q.set(k, f[k]);
  listBox.setAttribute('aria-busy', 'true'); put(listBox, ...[0, 1, 2].map(() => h('div', { class: 'skeleton sk-row' })));
  const r = await api('GET', `/api/candidates?${q}`);
  if (mine !== seq) return;
  listBox.removeAttribute('aria-busy');
  if (r.status !== 200) { put(listBox, h('div', { class: 'alert alert-bad', role: 'alert' }, icon('alert'), failure(r, t('err_generic')))); return; }
  const { items, total } = r.data;
  if (!items.length) {
    const filtered = f.state || f.q || f.source;
    const clearBtn = filtered ? h('button', { type: 'button', class: 'btn', text: t('q_clear'), onclick: () => apply({ state: '', q: '', source: '' }) }) : null;
    put(listBox, h('div', { class: 'card empty' }, icon('quarantine'), h('h2', { text: filtered ? t('q_nomatch_h') : t('q_empty_h') }), h('p', { text: filtered ? t('q_nomatch_p') : t('q_empty_p') }), clearBtn)); return;
  }
  const blocked = new Set(items.filter((c) => c.approvable === false).map((c) => c.id));
  const rows = items.map((c) => {
    const box = canDecide ? h('input', { type: 'checkbox', 'aria-label': t('q_select', { name: c.name }), checked: selection.has(c.id) }) : null;
    const li = h('li', { class: `rule ${selection.has(c.id) ? 'selected' : ''}` });
    if (box) box.addEventListener('change', () => { if (box.checked) selection.set(c.id, c.version); else selection.delete(c.id); li.classList.toggle('selected', box.checked); drawBar(); });
    const why = (c.approvable === false ? [h('span', { class: 'chip', text: t('q_blocked_chip') })] : []).concat(c.reasons.slice(0, 3).map((x) => h('span', { class: 'chip', text: reasonLabel(x) }))); if (c.reasons.length > 3) why.push(h('span', { class: 'chip', text: t('q_more', { n: c.reasons.length - 3 }) }));
    li.append(box ? h('div', { class: 'pick' }, box) : null, h('div', { class: 'rule-main' },
      h('a', { class: 'rule-title', href: `#/rules/${c.id}`, text: c.name }), h('div', { class: 'rule-path', text: c.path }), why.length ? h('div', { class: 'reasons' }, why) : null,
      h('div', { class: 'rule-meta' }, stateBadge(c.state), h('span', { text: c.source }), h('span', { text: t('q_detected', { date: fmtDate(c.detected_at) }) }), h('span', { class: 'sha', title: c.sha256 }, shortSha(c.sha256), copyButton(c.sha256, `${t('copy')} SHA-256`)))));
    return li;
  });
  const pages = Math.max(1, Math.ceil(total / SIZE)), from = (f.page - 1) * SIZE + 1;
  const prev = h('button', { type: 'button', class: 'btn btn-sm', disabled: f.page <= 1, onclick: () => go(hash({ ...f, page: f.page - 1 })) }, icon('back'), t('q_prev'));
  const next = h('button', { type: 'button', class: 'btn btn-sm', disabled: f.page >= pages, onclick: () => go(hash({ ...f, page: f.page + 1 })) }, t('q_next'), icon('chevron'));
  const selPage = canDecide ? h('button', { type: 'button', class: 'btn btn-sm', text: t('q_select_page'), onclick: () => { items.forEach((c) => selection.set(c.id, c.version)); ctx.rerender(); } }) : null;
  put(listBox, h('ul', { class: 'rules' }, rows), h('div', { class: 'pager mt-14' }, h('span', { text: t('q_showing', { from, to: from + items.length - 1, total }) }), h('div', { class: 'flex-8' }, selPage, prev, next)));

  function drawBar() {
    clear(bar); const n = selection.size; if (!n) return;
    const done = () => { selection.clear(); ctx.rerender(); };
    const noApprove = [...selection.keys()].some((id) => blocked.has(id));
    bar.append(h('div', { class: 'bulkbar', role: 'region', 'aria-label': t('q_bulk') }, h('span', { class: 'count', text: n === 1 ? t('q_selected_one') : t('q_selected_n', { n }) }),
      h('button', { type: 'button', class: 'btn btn-sm btn-ghost', text: t('q_clear_sel'), onclick: () => { selection.clear(); ctx.rerender(); } }),
      noApprove ? h('span', { class: 'note', id: 'bulk-not-approvable', text: t('q_not_approvable') }) : null,
      h('div', { class: 'btns' }, h('button', { type: 'button', class: 'btn btn-sm btn-ok', disabled: noApprove, ...(noApprove ? { 'aria-describedby': 'bulk-not-approvable' } : {}), onclick: () => decide('approve', new Map(selection), done) }, icon('check'), t('act_approve')),
        h('button', { type: 'button', class: 'btn btn-sm btn-bad', onclick: () => decide('reject', new Map(selection), done) }, icon('x'), t('act_reject')),
        h('button', { type: 'button', class: 'btn btn-sm', onclick: () => decide('hold', new Map(selection), done) }, icon('pause'), t('act_hold')))));
  }
  drawBar();
  }
  await load();
}
