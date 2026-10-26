// The inventory of the current signed release, read from the manifest the Worker verified and reconciled with the panel's records. Quarantine lives elsewhere.
import { t } from '../i18n.js';
import { h, icon, put, pillGroup, shortSha, copyButton, fmtDateTime, bytes } from '../ui.js';
import { api, failure } from '../api.js';
import { polChip } from './policy.js';
import { loadIntelStats, retainedTable } from './intel_summary.js';

const SIZE = 50, STATUS = ['published', 'newer_in_review'];

export async function renderPublished(ctx) {
  const { root, query, go, me } = ctx; const otherFamilies = h('div', { class: 'minw0' }); loadIntelStats(me).then((st) => { const n = retainedTable(st, true); if (n) put(otherFamilies, n); });
  const f = { status: STATUS.includes(query.get('status')) ? query.get('status') : '', q: query.get('q') || '', source: query.get('source') || '', page: Math.max(1, +query.get('page') || 1) };
  const hash = (o) => { const p = new URLSearchParams(); for (const k of ['status', 'q', 'source']) if (o[k]) p.set(k, o[k]); if (o.page > 1) p.set('page', o.page); const s = p.toString(); return `#/published${s ? `?${s}` : ''}`; };
  const apply = (patch) => go(hash({ ...f, page: 1, ...patch }), true);

  const refresh = h('button', { type: 'button', class: 'btn btn-sm', onclick: () => ctx.rerender() }, icon('refresh'), t('refresh'));
  const head = h('div'), pills = h('div'), srcPills = h('div'), listBox = h('div', { 'aria-live': 'polite' });
  const search = h('input', { class: 'input', id: 'p-search', type: 'search', autocomplete: 'off', value: f.q, placeholder: '' });
  let timer; search.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(() => { f.q = search.value.trim(); f.page = 1; history.replaceState(null, '', hash(f)); load(); }, 300); });   // only the list reloads: the input keeps its node, focus, caret and selection
  put(root, h('div', { class: 'page-head' }, h('div', {}, h('h1', { id: 'page-title', tabindex: '-1', text: t('pub_title') }), h('p', { text: t('pub_lead') })), h('div', { class: 'actions' }, refresh)),
    head, pills, h('div', { class: 'field' }, h('label', { for: 'p-search', text: t('pub_search') }), search), srcPills, listBox, otherFamilies);

  let seq = 0;
  async function load() {
  const mine = ++seq;
  const q = new URLSearchParams({ page: f.page, pageSize: SIZE }); for (const k of ['status', 'q', 'source']) if (f[k]) q.set(k, f[k]);
  listBox.setAttribute('aria-busy', 'true'); put(listBox, ...[0, 1, 2].map(() => h('div', { class: 'skeleton sk-row' })));
  const r = await api('GET', `/api/published?${q}`);
  if (mine !== seq) return;
  listBox.removeAttribute('aria-busy');
  if (r.status !== 200) { put(listBox, h('div', { class: 'alert alert-bad', role: 'alert' }, icon('alert'), h('span', {}, h('strong', { text: `${t('pub_err')}. ` }), failure(r, t('err_generic'))))); return; }
  const { release: rel, items, total, counts, sources } = r.data;

  put(head, h('section', { class: 'card', 'aria-labelledby': 'h-rel' }, h('h2', { id: 'h-rel', text: t('pub_release') }),
    h('dl', { class: 'kv' },
      h('dt', { text: t('pub_release_tag') }), h('dd', {}, h('a', { class: 'mono', href: rel.url, target: '_blank', rel: 'noopener noreferrer', title: t('pub_open_release'), text: rel.tag })),
      h('dt', { text: t('pub_published_at') }), h('dd', {}, h('time', { datetime: rel.published_at, text: fmtDateTime(rel.published_at) })),
      h('dt', { text: t('pub_files') }), h('dd', { text: String(rel.files) }),
      h('dt', { text: t('pub_root') }), h('dd', { class: 'sha', title: rel.rules_root }, shortSha(rel.rules_root), copyButton(rel.rules_root, `${t('copy')} ${t('pub_root')}`)),
      h('dt', { text: t('pub_manifest') }), h('dd', { class: 'sha', title: rel.manifest_sha256 }, shortSha(rel.manifest_sha256), copyButton(rel.manifest_sha256, `${t('copy')} SHA-256`))),
    h('p', { class: 'note mt-10', text: `${t('pub_read_at', { when: fmtDateTime(rel.read_at) })}. ${t('pub_refresh_note')}` }),
    counts.without_record ? h('p', { class: 'note mt-6', id: 'pub-norecord', text: t('pub_without_record', { n: counts.without_record }) }) : null));
  put(pills, pillGroup(t('pub_state'), [['', t('all'), counts.total], ['published', t('pub_pill_published'), counts.published], ['newer_in_review', t('pub_pill_newer'), counts.newer_in_review]], f.status, (v) => apply({ status: v })));
  const names = Object.keys(sources).sort();
  if (names.length > 1) put(srcPills, h('div', { class: 'field' }, h('span', { text: t('q_source') }), pillGroup(t('q_source'), [['', t('q_all_sources')], ...names.map((s) => [s, s, sources[s]])], f.source, (v) => apply({ source: v }))));

  if (!items.length) { put(listBox, h('div', { class: 'card empty' }, icon('check'), h('h2', { text: t('pub_empty_h') }), h('p', { text: t('pub_empty_p') }), f.status || f.q || f.source ? h('button', { type: 'button', class: 'btn', text: t('q_clear'), onclick: () => apply({ status: '', q: '', source: '' }) }) : null)); return; }
  const rows = items.map((x) => {
    const name = x.path.split('/').pop();
    const title = h('a', { class: 'rule-title', href: `#/published/rule?path=${encodeURIComponent(x.path)}`, text: name });
    return h('li', { class: 'rule' }, h('div', { class: 'rule-main' }, title, h('div', { class: 'rule-path', text: x.path }),
      h('div', { class: 'reasons' }, h('span', { class: x.status === 'published' ? 'chip chip-ok' : 'chip chip-warn', text: t(`pub_s_${x.status}`) }), h('span', { class: 'chip', text: x.candidate_id ? t('pub_recorded') : t('pub_norecord') }), x.policy ? polChip(x.policy.publication) : null),
      x.status === 'newer_in_review' ? h('p', { class: 'note', text: t('pub_in_quarantine') }) : null,
      h('div', { class: 'rule-meta' }, h('span', { text: x.source || '—' }), h('span', { text: x.release_tag || rel.tag }), x.bytes !== null ? h('span', { text: bytes(x.bytes) }) : null,
        h('span', { class: 'sha', title: x.sha256 }, shortSha(x.sha256), copyButton(x.sha256, `${t('copy')} SHA-256`)))));
  });
  const pages = Math.max(1, Math.ceil(total / SIZE)), from = (f.page - 1) * SIZE + 1;
  const prev = h('button', { type: 'button', class: 'btn btn-sm', disabled: f.page <= 1, onclick: () => go(hash({ ...f, page: f.page - 1 })) }, icon('back'), t('q_prev'));
  const next = h('button', { type: 'button', class: 'btn btn-sm', disabled: f.page >= pages, onclick: () => go(hash({ ...f, page: f.page + 1 })) }, t('q_next'), icon('chevron'));
  put(listBox, h('ul', { class: 'rules' }, rows), h('div', { class: 'pager mt-14' }, h('span', { text: t('pub_showing', { from, to: from + items.length - 1, total }) }), h('div', { class: 'flex-8' }, prev, next)));
  }
  await load();
}
