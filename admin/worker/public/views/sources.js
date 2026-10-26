// Upstream YARA sources: the allow-list, the commit each run pinned, when it was last fetched, and what this panel can honestly say per source.
import { t } from '../i18n.js';
import { h, icon, put, fmtDateTime, copyButton, can } from '../ui.js';
import { api } from '../api.js';
import { loadOps, freshness, ago } from './ops.js';
import { proposalsSection } from './proposals.js';
import { sourcesTable } from './intel.js';

export async function renderSources(ctx) {
  const { root } = ctx;
  const head = h('div', { class: 'page-head' }, h('div', {}, h('h1', { id: 'page-title', tabindex: '-1', text: t('sr_title') }), h('p', { text: t('sr_lead') })), h('div', { class: 'actions' }, h('button', { type: 'button', class: 'btn btn-sm', onclick: () => ctx.rerender() }, icon('refresh'), t('refresh'))));
  put(root, head, h('div', { class: 'skeleton sk-block', 'aria-hidden': 'true' }));
  const [ops, stats] = await Promise.all([loadOps(), api('GET', '/api/stats')]); const inq = (stats.status === 200 && stats.data.sources) || {};
  if (!ops.ok) { put(root, head, h('p', { class: 'alert alert-bad', role: 'alert' }, icon('alert'), `${t('db_ops_fail')} ${ops.error}`)); return; }
  const o = ops.data, od = o.latest.observed_day;
  const card = (s) => {
    const fresh = s.fetched_at && Date.now() - Date.parse(s.fetched_at) < 72 * 3600 * 1000;
    return h('li', { class: 'person' }, h('div', { class: 'person-head' }, h('div', { class: 'badge-ic k-source' }, icon('source')), h('div', {}, h('strong', { text: s.id }), h('a', { class: 'faint', href: `https://github.com/${s.repo}`, target: '_blank', rel: 'noopener noreferrer' }, s.repo, icon('external')))),
      h('div', { class: 'person-badges' }, h('span', { class: 'badge badge-neutral', text: t(`sk_${s.kind}`) }), s.commit ? h('span', { class: `badge ${fresh ? 'badge-day-ok' : 'badge-day-warn'}` }, t(fresh ? 'sr_synced' : 'sr_stale')) : h('span', { class: 'badge badge-neutral', text: t('nodata') })),
      h('dl', { class: 'kv' }, h('dt', { text: t('sr_commit') }), h('dd', {}, s.commit ? h('span', { class: 'sha' }, h('a', { class: 'mono', href: `https://github.com/${s.repo}/commit/${s.commit}`, target: '_blank', rel: 'noopener noreferrer', text: s.commit.slice(0, 10) }), copyButton(s.commit, t('copy'))) : h('span', { class: 'nodata', text: t('nodata') })),
        h('dt', { text: t('sr_fetched') }), h('dd', { text: s.fetched_at ? `${fmtDateTime(s.fetched_at)} · ${ago(s.fetched_at)}` : t('nodata') }),
        h('dt', { text: t('sr_paths') }), h('dd', {}, s.paths.length ? h('span', { class: 'reasons' }, ...s.paths.map((p) => h('span', { class: 'chip mono', text: p }))) : t('sr_nopaths')),
        s.kind === 'rules' ? [h('dt', { text: t('sr_inq') }), h('dd', { text: String(inq[s.id] || 0) })] : null));
  };
  const proposals = await proposalsSection(ctx);   // null when the feature is off
  const isrc = !can(ctx.me, 'intel.sources.read') ? null : await api('GET', '/api/intel/sources');   // every other intelligence source, with the real last run of each
  const intelSection = isrc && isrc.status === 200 ? h('section', { class: 'card minw0', 'aria-labelledby': 'h-isrc' }, h('div', { class: 'flex-between' }, h('h2', { id: 'h-isrc', text: t('sr_intel_h') }), h('a', { class: 'btn btn-sm', href: '#/intel?group=sources', text: t('sr_intel_open') })), h('p', { class: 'note', text: t('sr_intel_p') }), sourcesTable(isrc.data.sources, null)) : null;
  put(root, head, freshness(o), proposals, intelSection, o.sources.length ? h('ul', { class: 'people' }, o.sources.map(card)) : h('div', { class: 'card empty' }, icon('source'), h('h2', { text: t('nodata') }), h('p', { text: t('sr_none') })),
    h('section', { class: 'card', 'aria-labelledby': 'h-persrc' }, h('h2', { id: 'h-persrc', text: t('sr_perrun') }), od ? h('dl', { class: 'kv' }, h('dt', { text: t('kpi_observed') }), h('dd', { text: od.date }), h('dt', { text: t('rl_examined') }), h('dd', { text: String(od.examined) }), h('dt', { text: t('rl_accepted') }), h('dd', { text: String(od.accepted) }), h('dt', { text: t('rl_quarantined') }), h('dd', { text: String(od.quarantined ?? '—') }), h('dt', { text: t('rl_rejected') }), h('dd', { text: String(od.rejected) })) : h('p', { class: 'nodata', text: t('nodata') }),
      h('p', { class: 'alert alert-info' }, icon('info'), t('sr_split_note'))));
}
