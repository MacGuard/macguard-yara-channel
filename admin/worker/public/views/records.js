// One browser for the records of every family but YARA, used by Quarantine, Published and Intelligence: the same filters, the same search, the same side sheet (content, metadata, evidence, history)
// and the same actions, whatever the family. The page only chooses a scope (what belongs to it) and the families it covers. Actions are decisions recorded by the server (hold, quarantine, reject,
// approve for the next publication); "approve" says why it is blocked when the evidence does not allow it. Nothing here publishes: PUBLISHED is set only by the signing pipeline.
import { t, has } from '../i18n.js';
import { h, icon, put, clear, pillGroup, modal, reasonField, toast, can } from '../ui.js';
import { api, failure } from '../api.js';
import { detailBody, cell, label, num } from './intel.js';

const rid = () => `req_${(crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2) + Date.now().toString(36)).replace(/[^A-Za-z0-9_-]/g, '')}`;
const VARIANT = { hold: 'primary', quarantine: 'primary', reject: 'bad', approve: 'ok' };
const ICON = { hold: 'pause', quarantine: 'quarantine', reject: 'x', approve: 'check' };
export const MIXED = [['key', 'ix_c_id'], ['title', 'ix_c_name'], ['family', 'ix_d_family'], ['source_id', 'ix_c_source'], ['severity', 'ix_c_class'], ['state', 'ix_c_state'], ['updated_at', 'ix_c_updated']];
const famLabel = (f) => label('ix_f_', f);
const actionsFor = (state, scope) => (scope === 'published' ? ['quarantine', 'hold', 'reject'] : state === 'APPROVED' ? ['quarantine', 'hold', 'reject'] : ['approve', 'quarantine', 'reject', 'hold']).filter((a) => !(a === 'hold' && state === 'RETENIDA') && !(a === 'quarantine' && state === 'QUARANTINED') && !(a === 'reject' && state === 'REJECTED') && !(a === 'approve' && state === 'APPROVED'));
const blockedWhy = (reasons) => reasons.map((r) => (has(`ix_ap_${r.code}`) ? t(`ix_ap_${r.code}`, { d: r.detail || '' }) : r.code)).join(' · ');

/** selection: Map(record id -> state seen). Resolves through done() when the server applied the change. */
export function decideRecords(action, selection, done, extraBody) {
  const n = selection.size, reason = reasonField();
  const body = h('div', { class: 'grid-12' }, h('p', { class: 'alert alert-info', text: t('ix_act_affects', { n: String(n) }) }), h('p', { class: 'note', text: t(`ix_act_${action}_p`) }), extraBody || null, reason.node);
  modal({
    title: t(`ix_act_${action}_h`, { n: String(n) }), body, confirmLabel: t(`ix_act_${action}`), variant: VARIANT[action],
    validate: () => (reason.value.length < 5 ? t('reason_short') : null),
    async submit() {
      const r = await api('POST', '/api/intel/decisions', { action, ids: [...selection.keys()], reason: reason.value, request_id: rid(), expect: Object.fromEntries(selection) });
      if (r.status === 200) { toast(t('ix_done', { n: String(r.data.changed) })); if (done) done(); return null; }
      if (r.status === 409 && r.data.blocked) return `${t('ix_blocked_h')}: ${r.data.blocked.map((b) => `${b.id} — ${blockedWhy(b.reasons)}`).join(' | ')}`;
      if (r.status === 409 && r.data.stale) { if (done) done(); return t('ix_stale', { n: String(r.data.stale.length) }); }
      return t('failed', { msg: failure(r, t('err_generic')) });
    },
  });
}

function historyList(list) {
  if (!list.length) return h('p', { class: 'note', text: t('ix_hist_none') });
  return h('ul', { class: 'in-counts' }, ...list.map((x) => h('li', {}, h('strong', { text: `${x.at.replace('T', ' ').replace('Z', '')} · ${x.actor}` }), ` — ${t(`ix_act_${x.action}`)}: ${x.from_state || '—'} → ${x.to_state}. `, x.reason, x.audited ? null : h('span', { class: 'chip chip-warn', text: t('ix_unaudited') }))));
}

/** mount: where to draw. opts: { ctx, scope: 'quarantine' | 'published' | null, families: [...], cols, query, urlFor(f) } */
export async function recordsBrowser(mount, opts) {
  const { ctx, scope, families, cols = MIXED, query, urlFor } = opts, canDecide = can(ctx.me, 'intel.decide') || can(ctx.me, 'intel.approve'), allowed = (a) => can(ctx.me, a === 'approve' ? 'intel.approve' : 'intel.decide');
  const f = { family: families.includes(query.get('family')) ? query.get('family') : '', source: query.get('source') || '', state: query.get('state') || '', q: query.get('q') || '' };
  put(mount, h('div', { class: 'skeleton sk-block' }));
  const [src, stats] = await Promise.all([api('GET', '/api/intel/sources'), api('GET', '/api/intel/stats')]);
  if (src.status === 503) { put(mount, h('p', { class: 'alert alert-warn', role: 'status' }, icon('alert'), t('ix_unbound'))); return; }
  if (src.status !== 200) { put(mount, h('p', { class: 'alert alert-bad', role: 'alert' }, icon('alert'), failure(src, t('err_generic')))); return; }
  const sources = src.data.sources.filter((s) => families.includes(s.family));
  const stateCounts = {}; if (stats.status === 200) for (const r of stats.data.by_state) if (families.includes(r.family)) { const pub = r.state === 'APPROVED' || r.state === 'PUBLISHED'; if (!scope || (scope === 'published') === pub) stateCounts[r.state] = (stateCounts[r.state] || 0) + r.n; }
  const famCounts = {}; if (stats.status === 200) for (const r of stats.data.by_state) if (families.includes(r.family)) { const pub = r.state === 'APPROVED' || r.state === 'PUBLISHED'; if (!scope || (scope === 'published') === pub) famCounts[r.family] = (famCounts[r.family] || 0) + r.n; }
  const famPills = pillGroup(t('ix_d_family'), [['', t('all'), Object.values(famCounts).reduce((a, b) => a + b, 0)], ...families.filter((x) => famCounts[x] !== undefined).map((x) => [x, famLabel(x), famCounts[x]])], f.family, (v) => { f.family = v; famPills.redraw(v); reload(); });
  const statePills = pillGroup(t('ix_c_state'), [['', t('all')], ...Object.keys(stateCounts).sort().map((s) => [s, label('ix_st_', s), stateCounts[s]])], f.state, (v) => { f.state = v; statePills.redraw(v); reload(); });
  const inFam = () => sources.filter((s) => !f.family || s.family === f.family);
  const srcBox = h('div'); const drawSrc = () => { const list = inFam().filter((s) => s.records); put(srcBox, list.length > 1 ? h('div', { class: 'filter-row' }, h('span', { class: 'fl', text: t('ix_c_source') }), pillGroup(t('ix_c_source'), [['', t('all')], ...list.map((s) => [s.id, s.name, s.records])], f.source, (v) => { f.source = v; reload(); })) : null); };
  const search = h('input', { class: 'input', id: 'ix-search', type: 'search', autocomplete: 'off', value: f.q, placeholder: '' });
  const total = h('p', { class: 'note', 'aria-live': 'polite' }), tbody = h('tbody', {}), more = h('div', { class: 'pager' }), bar = h('div'), sheet = h('aside', { class: 'sheet-side', 'aria-label': t('ix_d_title'), hidden: true });
  const selection = new Map();
  const head = h('tr', {}, canDecide ? h('th', { scope: 'col', class: 'sel' }, h('span', { class: 'sr', text: t('q_select_page') })) : null, ...cols.map(([, k]) => h('th', { scope: 'col', text: t(k) })));
  const table = h('div', { class: 'dt-wrap', role: 'region', 'aria-label': t(scope === 'published' ? 'pub_title' : scope === 'quarantine' ? 'q_title' : 'ix_title'), tabindex: '0' }, h('table', { class: 'dt dt-sel' }, h('caption', { class: 'sr', text: t(scope === 'published' ? 'pub_title' : scope === 'quarantine' ? 'q_title' : 'ix_title') }), h('thead', {}, head), tbody));
  const row = (lab, node) => h('div', { class: 'filter-row' }, h('span', { class: 'fl', text: lab }), node);
  put(mount, h('div', { class: 'toolbar' }, h('div', { class: 'field grow' }, h('label', { for: 'ix-search', text: t('ix_search') }), search)), row(t('ix_d_family'), famPills), srcBox, row(t('ix_c_state'), statePills), total, h('div', { class: 'master-detail' }, h('div', { class: 'minw0' }, table, more, bar), sheet));
  drawSrc();

  let seq = 0, cursor = null, selected = null;
  const drawBar = () => {
    clear(bar); const n = selection.size; if (!n) return;
    const states = new Set(selection.values()), acts = ['approve', 'quarantine', 'reject', 'hold'].filter((a) => allowed(a) && (scope === 'published' ? a !== 'approve' : true));
    bar.append(h('div', { class: 'bulkbar', role: 'region', 'aria-label': t('q_bulk') }, h('span', { class: 'count', text: n === 1 ? t('q_selected_one') : t('q_selected_n', { n }) }),
      h('button', { type: 'button', class: 'btn btn-sm btn-ghost', text: t('q_clear_sel'), onclick: () => { selection.clear(); for (const cb of tbody.querySelectorAll('input[type=checkbox]')) cb.checked = false; drawBar(); } }),
      h('div', { class: 'btns' }, ...acts.filter((a) => [...states].some((s) => actionsFor(s, scope).includes(a))).map((a) => h('button', { type: 'button', class: `btn btn-sm btn-${VARIANT[a] === 'primary' ? 'ghost' : VARIANT[a]}`, onclick: () => decideRecords(a, new Map(selection), () => { selection.clear(); reload(); }) }, icon(ICON[a]), t(`ix_act_${a}`))))));
  };
  async function load(append) {
    const mine = ++seq; if (!append) { cursor = null; put(tbody); }
    const p = new URLSearchParams({ limit: '50', family: f.family || families.join(',') }); if (scope) p.set('scope', scope); if (f.source) p.set('source', f.source); if (f.state) p.set('state', f.state); if (f.q) p.set('q', f.q); if (cursor) p.set('cursor', cursor);
    const r = await api('GET', `/api/intel/records?${p}`); if (mine !== seq) return;
    if (r.status !== 200) { total.textContent = failure(r, t('err_generic')); return; }
    total.textContent = t('ix_total', { n: num(r.data.total) });
    if (!r.data.items.length && !append) put(tbody, h('tr', {}, h('td', { colspan: cols.length + (canDecide ? 1 : 0), class: 'empty-cell' }, scope === 'published' && !f.q && !f.state && !f.source ? t('ix_none_published') : t('ix_none'))));
    for (const rec of r.data.items) {
      const box = canDecide ? h('input', { type: 'checkbox', 'aria-label': t('q_select', { name: rec.title || rec.key }), checked: selection.has(rec.id) }) : null;
      const tr = h('tr', { tabindex: '0', 'aria-selected': 'false', 'data-id': rec.id }, canDecide ? h('td', { class: 'sel' }, box) : null, ...cols.map(([c]) => (c === 'family' ? h('td', { text: famLabel(rec.family) }) : cell(rec, c))));
      if (box) { box.addEventListener('click', (e) => e.stopPropagation()); box.addEventListener('change', () => { if (box.checked) selection.set(rec.id, rec.state); else selection.delete(rec.id); drawBar(); }); }
      const open = () => openSheet(rec.id, tr); tr.addEventListener('click', open); tr.addEventListener('keydown', (e) => { if ((e.key === 'Enter' || e.key === ' ') && e.target === tr) { e.preventDefault(); open(); } });
      tbody.append(tr);
    }
    cursor = r.data.next_cursor; put(more, cursor ? h('button', { type: 'button', class: 'btn btn-sm', onclick: () => load(true) }, t('ix_more')) : null);
  }
  async function openSheet(id, tr) {
    if (selected) selected.setAttribute('aria-selected', 'false'); selected = tr; tr.setAttribute('aria-selected', 'true'); sheet.hidden = false; put(sheet, h('div', { class: 'skeleton sk-block' }));
    const r = await api('GET', `/api/intel/records/${encodeURIComponent(id)}`);
    if (r.status !== 200) { put(sheet, h('p', { class: 'alert alert-bad', role: 'alert' }, failure(r, t('err_generic')))); return; }
    const d = r.data, rec = d.record, close = h('button', { type: 'button', class: 'btn btn-sm btn-ghost', 'aria-label': t('close') }, icon('x')); close.addEventListener('click', () => { sheet.hidden = true; tr.setAttribute('aria-selected', 'false'); tr.focus(); });
    const acts = canDecide ? actionsFor(rec.state, scope).filter(allowed).map((a) => {
      const blocked = a === 'approve' && !d.approvable.ok;
      return h('button', { type: 'button', class: `btn btn-sm btn-${VARIANT[a] === 'primary' ? 'ghost' : VARIANT[a]}`, disabled: blocked, 'aria-describedby': blocked ? 'ix-block-why' : null, onclick: () => decideRecords(a, new Map([[rec.id, rec.state]]), () => { reload(); openSheet(id, tr); }) }, icon(ICON[a]), t(`ix_act_${a}`));
    }) : [];
    put(sheet, h('div', { class: 'flex-between' }, h('h2', { id: 'ix-sheet-title', text: rec.title || rec.key }), close),
      canDecide ? h('div', { class: 'btns' }, ...acts) : null,
      canDecide && !d.approvable.ok && rec.state !== 'APPROVED' ? h('p', { class: 'note', id: 'ix-block-why' }, icon('alert'), ` ${t('ix_blocked_h')}: ${blockedWhy(d.approvable.reasons)}`) : null,
      ...detailBody(d), h('h3', { text: t('ix_hist_h') }), historyList(d.history));
    sheet.setAttribute('aria-labelledby', 'ix-sheet-title');
  }
  function reload() { const u = urlFor(f); if (u) history.replaceState(null, '', u); drawSrc(); load(false); }
  let timer; search.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(() => { const v = search.value.trim(); if (v.length === 1) return; f.q = v; reload(); }, 300); });
  mount.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !sheet.hidden) { sheet.hidden = true; if (selected) { selected.setAttribute('aria-selected', 'false'); selected.focus(); } } });
  await load(false);
}

export const OTHER_FAMILIES = ['suricata', 'sigma', 'ioc', 'hash', 'cve', 'kev', 'advisory', 'attack', 'epss'];
/** The switch between the YARA workflow and every other family, shared by Quarantine and Published. */
export function familyMode(current, base, go) {
  return pillGroup(t('ix_d_family'), [['yara', famLabel('yara')], ['other', t('ix_f_other')]], current, (v) => go(v === 'yara' ? `#/${base}` : `#/${base}?fam=other`, true));
}
/** Renders the other-families side of a page. */
export async function otherFamiliesPage(ctx, { base, scope, titleKey, leadKey, refresh }) {
  const { root, query } = ctx, mount = h('div', { class: 'minw0' });
  put(root, h('div', { class: 'page-head' }, h('div', {}, h('h1', { id: 'page-title', tabindex: '-1', text: t(titleKey) }), h('p', { text: t(leadKey) })), h('div', { class: 'actions' }, refresh)), h('div', { class: 'field' }, familyMode('other', base, ctx.go)), mount);
  await recordsBrowser(mount, { ctx, scope, families: OTHER_FAMILIES, query, urlFor: (f) => { const p = new URLSearchParams({ fam: 'other' }); for (const k of ['family', 'source', 'state', 'q']) if (f[k]) p.set(k, f[k]); return `#/${base}?${p}`; } });
}
