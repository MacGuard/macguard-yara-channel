// The intelligence families, each with its real state, on its own tab: detections, indicators, vulnerabilities, context. A family is never shown as YARA and never as "fine" without data:
// PUBLISHED only for what the signed release lists, RETENIDA (held by policy) with its concrete causes, NO_DATA, BLOCKED, NOT_RUN.
import { t, has } from '../i18n.js';
import { h, icon, put, pillGroup, fmtDate, fmtDateTime, copyButton } from '../ui.js';
import { api, failure } from '../api.js';

const GROUPS = ['detections', 'indicators', 'vulnerabilities', 'context'];
const PUB_CLASS = { PUBLISHED: 'chip chip-ok', RETENIDA: 'chip chip-warn', NO_DATA: 'chip', BLOCKED: 'chip chip-bad', NOT_RUN: 'chip', NOT_APPLICABLE: 'chip' };
const label = (prefix, k) => (has(`${prefix}${k}`) ? t(`${prefix}${k}`) : k);
const num = (n) => Number(n).toLocaleString(document.documentElement.lang === 'en' ? 'en-US' : 'es-ES');

export async function renderIntel(ctx) {
  const { root, query, go } = ctx, group = GROUPS.includes(query.get('group')) ? query.get('group') : 'detections';
  put(root, h('div', { class: 'page-head' }, h('div', {}, h('h1', { id: 'page-title', tabindex: '-1', text: t('ix_title' ) }), h('p', { text: t('ix_lead') }))), h('div', { class: 'skeleton sk-block' }));
  const r = await api('GET', '/api/intel/families');
  const head = h('div', { class: 'page-head' }, h('div', {}, h('h1', { id: 'page-title', tabindex: '-1', text: t('ix_title') }), h('p', { text: t('ix_lead') })));
  if (r.status !== 200) { put(root, head, h('p', { class: 'alert alert-bad', role: 'alert' }, icon('alert'), failure(r, t('err_generic')))); return; }
  const d = r.data, fams = d.families.filter((f) => f.group === group), all = d.families;
  const tabs = pillGroup(t('ix_group'), GROUPS.map((g) => [g, t(`ix_g_${g}`), all.filter((f) => f.group === g).length]), group, (v) => go(`#/intel?group=${v}`, true));

  const notes = [];
  if (d.declared) notes.push(h('p', { class: 'note' }, t('ix_declared', { date: d.declared.as_of || '—' }), ' ', d.declared.evidence && d.declared.evidence.doc ? t('ix_evidence', { doc: d.declared.evidence.doc, commit: d.declared.evidence.commit || '—' }) : '', d.declared.evidence && d.declared.evidence.in_main === false ? ` ${t('ix_not_main')}` : ''));
  if (d.catalogue_error) notes.push(h('p', { class: 'alert alert-warn', role: 'status' }, icon('alert'), t('ix_catalogue_error', { why: d.catalogue_error })));
  if (d.live_error) notes.push(h('p', { class: 'alert alert-warn', role: 'status' }, icon('alert'), t('ix_live_error')));
  if (d.declared && d.declared.dropped.length) notes.push(h('p', { class: 'alert alert-warn', role: 'status' }, icon('alert'), t('ix_dropped', { list: d.declared.dropped.join(', ') })));

  const row = (f) => h('tr', {},
    h('th', { scope: 'row' }, h('strong', { text: f.name }), f.live ? h('span', { class: 'chip chip-ok', text: ` ${t('ix_live')}` }) : null),
    h('td', { text: f.source || '—' }),
    h('td', {}, Object.keys(f.counts).length ? h('ul', { class: 'in-counts' }, ...Object.entries(f.counts).map(([k, v]) => h('li', { text: `${label('ix_cnt_', k)}: ${num(v)}` }))) : t('ix_nodata_counts')),
    h('td', { text: t(`ix_int_${f.integration}`) }),
    h('td', {}, h('span', { class: PUB_CLASS[f.publication] || 'chip', text: t(`ix_pub_${f.publication}`) })),
    h('td', {}, f.causes.length ? h('ul', { class: 'in-causes' }, ...f.causes.map((c) => h('li', { text: label('ix_cause_', c) }))) : '—'),
    h('td', {}, f.evidence_head ? h('span', { class: 'sha', title: f.evidence_head }, f.evidence_head.slice(0, 12), copyButton(f.evidence_head, `${t('copy')} ${t('ix_evidence_head')}`)) : f.live ? h('a', { href: '#/published', text: t('ix_open_published') }) : '—'));
  const table = fams.length ? h('div', { class: 'rs-tablewrap', role: 'region', 'aria-label': t(`ix_g_${group}`), tabindex: '0' }, h('table', { class: 'rs-table in-table' },
    h('caption', { class: 'sr', text: t(`ix_g_${group}`) }),
    h('thead', {}, h('tr', {}, ...['ix_h_family', 'ix_h_source', 'ix_h_counts', 'ix_h_integration', 'ix_h_publication', 'ix_h_causes', 'ix_h_evidence'].map((k) => h('th', { scope: 'col', text: t(k) })))), h('tbody', {}, ...fams.map(row))))
    : h('div', { class: 'card empty' }, icon('file'), h('h2', { text: t('ix_empty') }));
  put(root, head, h('div', { class: 'field' }, tabs), ...notes, table, h('p', { class: 'note', text: t('ix_legend') }));
  document.title = `${t('ix_title')} · MacGuard Quarantine`;
}
