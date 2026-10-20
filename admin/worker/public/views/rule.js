// One rule: what it is, why it is here, what was measured, its code, who decided what, and the safe ways to decide.
import { t } from '../i18n.js';
import { h, icon, stateBadge, reasonLabel, fmtDate, fmtDateTime, bytes, copyButton, shaFull, copyText, put } from '../ui.js';
import { api, failure } from '../api.js';
import { decide, retest } from './decide.js';

export async function renderRule(ctx, id) {
  const { root, me } = ctx;
  put(root, h('div', { class: 'skeleton sk-title' }), h('div', { class: 'skeleton sk-block' }));
  const r = await api('GET', `/api/candidates/${encodeURIComponent(id)}`);
  const back = h('p', { class: 'crumbs' }, h('a', { href: '#/quarantine' }, icon('back'), t('nav_quarantine')));
  if (r.status !== 200) { put(root, back, h('div', { class: 'card empty' }, icon('file'), h('h1', { id: 'page-title', tabindex: '-1', text: r.status === 404 ? t('r_notfound') : failure(r, t('err_generic')) }))); return; }
  const c = r.data, m = c.metrics || {}, canDecide = me.role !== 'VIEWER';
  const prevM = ((c.history || []).filter((x) => x.metrics && typeof x.metrics.cpu_s === 'number')[0] || {}).metrics || {};
  const reload = () => ctx.rerender();

  const meters = [['cpu', 'cpu_s'], ['rss', 'rss_mb'], ['compile', 'compile_s'], ['scan', 'scan_p95_s']].filter(([, k]) => typeof m[k] === 'number');
  const max = Math.max(1, ...meters.map(([, k]) => Math.max(m[k], prevM[k] || 0)));
  const metersNode = meters.length ? h('div', { class: 'grid-14' }, ...meters.map(([lab, k]) => h('div', { class: 'meter' }, h('span', { text: t(lab) }), h('b', { text: `${m[k]}${typeof prevM[k] === 'number' ? ` · ${t('r_vs_prev', { v: prevM[k] })}` : ''}` }), h('div', { class: 'bar', role: 'img', 'aria-label': `${t(lab)} ${m[k]}` }, h('i', { class: `w${Math.max(5, Math.round((m[k] / max) * 20) * 5)}` })))))
    : h('p', { class: 'muted', text: t('r_resources_none') });

  const codeText = c.content === null ? null : c.content.slice(0, 200000);
  const decisions = (c.decisions || []).length ? h('ol', { class: 'timeline' }, ...c.decisions.slice().reverse().map((d) => h('li', {}, h('time', { datetime: d.at, text: fmtDateTime(d.at) }), h('strong', { text: `${d.actor} · ${t(`act_${d.action}`) || d.action}` }), h('div', { class: 'note', text: `${t(`st_${d.from_state}`)} → ${t(`st_${d.to_state}`)}` }), h('div', { class: 'quote', text: d.reason })))) : h('p', { class: 'muted', text: t('r_decisions_none') });

  const actions = canDecide ? h('div', { class: 'card' }, h('h2', { text: t('r_actions') }), h('p', { class: 'note mt-8 mb-14', text: t('r_actions_note') }), c.approvable === false ? h('p', { class: 'alert alert-info', id: 'not-approvable' }, icon('lock'), t('r_not_approvable', { reasons: c.blocking.map(reasonLabel).join(', ') })) : null, h('div', { class: 'actions-col' },
    h('button', { type: 'button', class: 'btn btn-ok', disabled: c.approvable === false, ...(c.approvable === false ? { 'aria-describedby': 'not-approvable' } : {}), onclick: () => decide('approve', new Map([[c.id, c.version]]), reload) }, icon('check'), t('act_approve')),
    h('button', { type: 'button', class: 'btn btn-bad', onclick: () => decide('reject', new Map([[c.id, c.version]]), reload) }, icon('x'), t('act_reject')),
    h('button', { type: 'button', class: 'btn', onclick: () => decide('hold', new Map([[c.id, c.version]]), reload) }, icon('pause'), t('act_hold')),
    h('button', { type: 'button', class: 'btn btn-ghost', onclick: () => retest(c.id) }, icon('refresh'), t('act_retest'))))
    : h('div', { class: 'card' }, h('p', { class: 'alert alert-info' }, icon('lock'), t('r_viewer_note')));

  const kv = h('dl', { class: 'kv' }, h('dt', { text: t('r_source') }), h('dd', { text: c.source }), c.upstream_commit ? [h('dt', { text: t('r_commit') }), h('dd', { class: 'mono', text: c.upstream_commit.slice(0, 12) })] : null,
    h('dt', { text: t('r_size') }), h('dd', { text: bytes(c.bytes) }), h('dt', { text: t('r_detected') }), h('dd', { text: fmtDateTime(c.detected_at) }), h('dt', { text: t('r_version') }), h('dd', { text: `v${c.version}` }),
    c.release_tag ? [h('dt', { text: t('r_release') }), h('dd', { text: c.release_tag })] : null);

  put(root, back,
    h('div', { class: 'page-head' }, h('div', {}, h('h1', { id: 'page-title', tabindex: '-1', text: c.name }), h('p', { class: 'rule-path mt-6', text: c.path })), h('div', { class: 'actions' }, stateBadge(c.state))),
    c.state === 'APPROVED_PENDING_VALIDATION' ? h('p', { class: 'alert alert-ok' }, icon('info'), t('st_hint_APPROVED_PENDING_VALIDATION')) : null,
    c.revalidation_failed ? h('p', { class: 'alert alert-bad', role: 'alert' }, icon('alert'), t('r_revfail', { why: c.revalidation_failed })) : null,
    h('div', { class: 'sheet' },
      h('div', { class: 'stack' },
        h('section', { class: 'card', 'aria-labelledby': 'h-sum' }, h('h2', { id: 'h-sum', text: t('r_summary') }), h('div', {}, h('div', { class: 'field' }, h('span', { text: t('r_sha') }), h('div', { class: 'flex-8 center' }, shaFull(c.sha256), copyButton(c.sha256, `${t('copy')} SHA-256`)))), kv),
        h('section', { class: 'card', 'aria-labelledby': 'h-why' }, h('h2', { id: 'h-why', text: t('r_why') }), h('div', { class: 'reasons' }, ...c.reasons.map((x) => h('span', { class: 'chip', title: x, text: reasonLabel(x) }))), (c.depends_on || []).length ? h('p', { class: 'note mt-10', text: `${t('r_deps')}: ${c.depends_on.join(', ')}` }) : null),
        h('section', { class: 'card', 'aria-labelledby': 'h-res' }, h('h2', { id: 'h-res', text: t('r_resources') }), metersNode),
        h('section', { class: 'card', 'aria-labelledby': 'h-code' }, h('div', { class: 'flex-between' }, h('h2', { id: 'h-code', text: t('r_code') }), codeText !== null ? h('button', { type: 'button', class: 'btn btn-sm', onclick: () => copyText(codeText) }, icon('copy'), t('copy')) : null),
          h('p', { class: 'note mt-6 mb-10', text: t('r_code_note') }), codeText !== null ? h('pre', { class: 'code', tabindex: '0', 'aria-label': t('r_code'), text: codeText }) : h('p', { class: 'muted', text: t('r_code_none') }))),
      h('div', { class: 'stack sticky' }, actions,
        h('section', { class: 'card', 'aria-labelledby': 'h-dec' }, h('h2', { id: 'h-dec', text: t('r_decisions') }), decisions),
        (c.history || []).length ? h('section', { class: 'card', 'aria-labelledby': 'h-rel' }, h('h2', { id: 'h-rel', text: t('r_related') }), h('ul', { class: 'history' }, ...c.history.map((x) => h('li', {}, h('a', { href: `#/rules/${x.id}`, class: 'mono', text: x.sha256.slice(0, 12) }), ' ', stateBadge(x.state), ' ', h('span', { class: 'faint', text: fmtDate(x.detected_at) }))))) : null)));
  document.title = `${c.name} · MacGuard Quarantine`;
}
