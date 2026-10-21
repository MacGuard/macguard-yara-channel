// One rule: what it is, why it is here, what was measured, its code, who decided what, and the safe ways to decide.
import { t, has } from '../i18n.js';
import { h, icon, stateBadge, reasonLabel, fmtDate, fmtDateTime, bytes, copyButton, shaFull, copyText, put } from '../ui.js';
import { api, failure } from '../api.js';
import { decide, retest } from './decide.js';
import { policyCard } from './policy.js';

/** For every finding: what the control checks, whether it blocks (no human approval skips it) or only needs a judgement, and what would have to happen. */
const SEV_KEY = { review: 'fe_sev_review', block: 'fe_sev_block', reject: 'fe_sev_reject', corrupt: 'fe_sev_corrupt', truncated: 'fe_sev_truncated' };
const val = (v, unit) => `${v}${unit ? ` ${unit}` : ''}`;
/** What the pipeline measured for one finding of this exact content (contract findings_schema 1): the check, its severity, the observed value, the threshold applied, the detail. */
function evidenceOf(e, blockingNow) {
  const rows = [h('dt', { text: t('fe_check') }), h('dd', { class: 'mono', text: e.code }), h('dt', { text: t('fe_severity') }), h('dd', { text: `${has(SEV_KEY[e.severity]) ? t(SEV_KEY[e.severity]) : e.severity} · ${blockingNow ? t('rx_block') : t('rx_review')}` })];
  if (e.observed !== undefined) rows.push(h('dt', { text: t('fe_observed') }), h('dd', { text: val(e.observed, e.unit) }));
  if (e.threshold !== undefined) rows.push(h('dt', { text: t('fe_threshold') }), h('dd', { text: val(e.threshold, e.unit) }));
  if (e.detail) rows.push(h('dt', { text: t('fe_detail') }), h('dd', { class: 'mono', text: e.detail }));
  return h('dl', { class: 'kv mt-6' }, ...rows);
}
function findingsCard(c) {
  const codes = (c.reasons || []).filter((x) => x !== 'waived-by-review'); if (!codes.length || c.state === 'RELEASED') return null;
  const blocking = new Set(c.blocking || []), key = (x) => String(x).replace(/[^a-z0-9]+/gi, '_');
  const m = c.metrics || {}, measured = m.findings_schema === 1 && Array.isArray(m.findings) ? m.findings : [];
  const item = (x) => {
    const k = key(x), known = has(`rx_${k}`), block = blocking.has(x);
    return h('li', {}, h('div', { class: 'flex-8 center' }, h('span', { class: block ? 'chip chip-bad' : 'chip', text: block ? t('rx_block') : t('rx_review') }), h('strong', { text: reasonLabel(x) })),
      h('p', { class: 'note mt-6', text: known ? t(`rx_${k}`) : t('rx_unknown') }),
      known ? h('p', { class: 'note mt-6' }, h('b', { text: `${block ? t('rx_fix_block') : t('rx_fix_review')}: ` }), t(`rf_${k}`)) : null,
      ...(measured.filter((e) => e.code === x).map((e) => evidenceOf(e, block))));
  };
  const blocked = codes.filter((x) => blocking.has(x)), others = codes.filter((x) => !blocking.has(x));
  return h('section', { class: 'card', 'aria-labelledby': 'h-find', id: 'findings' }, h('h2', { id: 'h-find', text: t('rx_h') }),
    blocked.length ? h('p', { class: 'note mb-10', text: t('rx_blocked_lead') }) : null, blocked.length ? h('ul', { class: 'deplist' }, ...blocked.map(item)) : null,
    others.length ? h('p', { class: 'note mt-10 mb-10', text: t('rx_review_lead') }) : null, others.length ? h('ul', { class: 'deplist' }, ...others.map(item)) : null,
    h('p', { class: 'note mt-14', id: 'findings-source', text: measured.length || m.findings_schema === 1 ? t('fe_report', { sha: c.sha256.slice(0, 12), run: m.findings_run ? m.findings_run.run_id : '—', attempt: m.findings_run && m.findings_run.run_attempt ? t('fe_attempt', { n: m.findings_run.run_attempt }) : '', engine: m.engine ? t('fe_engine', { engine: m.engine }) : '', dropped: m.findings_dropped ? t('fe_dropped', { n: m.findings_dropped }) : '' }) : t('fe_old') }));
}

/** What this rule needs, what needs it, and whether approving it will take effect (computed by the server from the same rules decide.py applies). */
function dependencyCard(c) {
  const d = c.dependencies; if (!d) return null;
  if (!d.required.length && !d.dependents.length) return h('section', { class: 'card', 'aria-labelledby': 'h-dep' }, h('h2', { id: 'h-dep', text: t('dep_h') }), h('p', { class: 'muted', text: t('dep_none') }));
  const link = (x) => (x.id ? h('a', { href: `#/rules/${x.id}`, class: 'rule-path', text: x.path }) : h('span', { class: 'rule-path', text: x.path }));
  const chips = (codes) => (codes.length ? h('div', { class: 'reasons' }, ...codes.map((x) => h('span', { class: 'chip', title: x, text: reasonLabel(x) }))) : null);
  const effect = d.effect === 'effective' ? h('p', { class: 'alert alert-ok', id: 'dep-effect' }, icon('info'), t('dep_effect_effective'))
    : d.effect === 'conditional' ? h('p', { class: 'alert alert-info', id: 'dep-effect' }, icon('info'), t('dep_effect_conditional', { list: t('dep_approve_with', { list: d.needs_approval_of.join(', ') }) }))
    : d.effect === 'ineffective' ? h('p', { class: 'alert alert-bad', id: 'dep-effect', role: 'alert' }, icon('alert'), t('dep_effect_ineffective', { path: d.blocked_by })) : null;
  const required = d.required.length ? [h('h3', { class: 'dep-sub', text: t('dep_required') }), h('ul', { class: 'deplist' }, ...d.required.map((x) => h('li', {}, link(x), h('span', { class: 'note', text: t(`dep_s_${x.status}`) }), chips(x.reasons),
    x.status === 'blocked' && x.blocked_by ? h('span', { class: 'note', text: t('dep_blocked_by', { path: x.blocked_by }) }) : null, x.status === 'needs_approval' && x.needs_approval_of.length ? h('span', { class: 'note', text: t('dep_needs_too', { list: x.needs_approval_of.join(', ') }) }) : null)))] : [];
  const dependents = d.dependents.length ? [h('h3', { class: 'dep-sub', text: t('dep_dependents') }), h('ul', { class: 'deplist' }, ...d.dependents.map((x) => h('li', {}, link(x), stateBadge(x.state), chips(x.reasons.filter((r) => r !== 'dependency-not-validated')),
    x.returns ? h('span', { class: 'note', text: t('dep_returns') }) : x.own_blockers.length ? h('span', { class: 'note', text: t('dep_own', { why: x.own_blockers.map(reasonLabel).join(', ') }) }) : null)))] : [];
  const back = h('h3', { class: 'dep-sub', text: t('dep_would_return') });
  const returning = d.would_return.length ? h('ul', { class: 'deplist' }, ...d.would_return.map((x) => h('li', {}, link(x)))) : h('p', { class: 'muted', text: t('dep_nothing_returns') });
  return h('section', { class: 'card', 'aria-labelledby': 'h-dep' }, h('h2', { id: 'h-dep', text: t('dep_h') }), effect, ...required, ...dependents, ...(d.effect === 'effective' || d.effect === 'conditional' ? [back, returning] : []));
}

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

  const actions = c.state === 'RELEASED' ? h('div', { class: 'card' }, h('p', { class: 'alert alert-ok' }, icon('check'), t('r_released_note')))
    : canDecide ? h('div', { class: 'card' }, h('h2', { text: t('r_actions') }), h('p', { class: 'note mt-8 mb-14', text: t('r_actions_note') }), c.approvable === false ? h('p', { class: 'alert alert-info', id: 'not-approvable' }, icon('lock'), t('r_not_approvable', { reasons: c.blocking.map(reasonLabel).join(', ') })) : null, h('div', { class: 'actions-col' },
    h('button', { type: 'button', class: 'btn btn-ok', disabled: c.approvable === false || (c.dependencies && c.dependencies.effect === 'ineffective'), ...(c.approvable === false ? { 'aria-describedby': 'not-approvable' } : c.dependencies && c.dependencies.effect === 'ineffective' ? { 'aria-describedby': 'dep-effect' } : {}), onclick: () => decide('approve', new Map([[c.id, c.version]]), reload) }, icon('check'), t('act_approve')),
    h('button', { type: 'button', class: 'btn btn-bad', onclick: () => decide('reject', new Map([[c.id, c.version]]), reload) }, icon('x'), t('act_reject')),
    h('button', { type: 'button', class: 'btn', onclick: () => decide('hold', new Map([[c.id, c.version]]), reload) }, icon('pause'), t('act_hold')),
    h('button', { type: 'button', class: 'btn btn-ghost', onclick: () => retest(c.id) }, icon('refresh'), t('act_retest'))))
    : h('div', { class: 'card' }, h('p', { class: 'alert alert-info' }, icon('lock'), t('r_viewer_note')));

  const kv = h('dl', { class: 'kv' }, h('dt', { text: t('r_source') }), h('dd', { text: c.source }), c.upstream_commit ? [h('dt', { text: t('r_commit') }), h('dd', { class: 'mono', text: c.upstream_commit.slice(0, 12) })] : null,
    h('dt', { text: t('r_size') }), h('dd', { text: bytes(c.bytes) }), h('dt', { text: t('r_detected') }), h('dd', { text: fmtDateTime(c.detected_at) }), h('dt', { text: t('r_version') }), h('dd', { text: `v${c.version}` }),
    c.release_tag ? [h('dt', { text: t('r_release') }), h('dd', { text: c.release_tag })] : null,
    c.release ? [h('dt', { text: t('r_release_basis') }), h('dd', { text: t(`rel_basis_${c.release.basis}`) }), h('dt', { text: t('r_release_proof') }), h('dd', { class: 'mono', title: c.release.manifest_sha256, text: `${String(c.release.manifest_sha256).slice(0, 12)}…` }),
      c.release.token_run_id ? [h('dt', { text: t('r_release_runlabel') }), h('dd', { text: t('r_release_run', { run: c.release.token_run_id, attempt: c.release.run_attempt ?? '?' }) })] : null] : null);

  put(root, back,
    h('div', { class: 'page-head' }, h('div', {}, h('h1', { id: 'page-title', tabindex: '-1', text: c.name }), h('p', { class: 'rule-path mt-6', text: c.path })), h('div', { class: 'actions' }, stateBadge(c.state))),
    c.state === 'APPROVED_PENDING_VALIDATION' ? h('p', { class: 'alert alert-ok' }, icon('info'), t('st_hint_APPROVED_PENDING_VALIDATION')) : null,
    c.revalidation_failed ? h('p', { class: 'alert alert-bad', role: 'alert' }, icon('alert'), t('r_revfail', { why: c.revalidation_failed })) : null,
    h('div', { class: 'sheet' },
      h('div', { class: 'stack' },
        h('section', { class: 'card', 'aria-labelledby': 'h-sum' }, h('h2', { id: 'h-sum', text: t('r_summary') }), h('div', {}, h('div', { class: 'field' }, h('span', { text: t('r_sha') }), h('div', { class: 'flex-8 center' }, shaFull(c.sha256), copyButton(c.sha256, `${t('copy')} SHA-256`)))), kv),
        h('section', { class: 'card', 'aria-labelledby': 'h-why' }, h('h2', { id: 'h-why', text: t('r_why') }), h('div', { class: 'reasons' }, ...c.reasons.map((x) => h('span', { class: 'chip', title: x, text: reasonLabel(x) }))), (c.depends_on || []).length ? h('p', { class: 'note mt-10', text: `${t('r_deps')}: ${c.depends_on.join(', ')}` }) : null),
        findingsCard(c),
        dependencyCard(c),
        h('section', { class: 'card', 'aria-labelledby': 'h-res' }, h('h2', { id: 'h-res', text: t('r_resources') }), metersNode),
        h('section', { class: 'card', 'aria-labelledby': 'h-code' }, h('div', { class: 'flex-between' }, h('h2', { id: 'h-code', text: t('r_code') }), codeText !== null ? h('button', { type: 'button', class: 'btn btn-sm', onclick: () => copyText(codeText) }, icon('copy'), t('copy')) : null),
          h('p', { class: 'note mt-6 mb-10', text: t('r_code_note') }), codeText !== null ? h('pre', { class: 'code', tabindex: '0', 'aria-label': t('r_code'), text: codeText }) : h('p', { class: 'muted', text: t('r_code_none') }))),
      h('div', { class: 'stack sticky' }, actions, policyCard(c, me, reload),
        h('section', { class: 'card', 'aria-labelledby': 'h-dec' }, h('h2', { id: 'h-dec', text: t('r_decisions') }), decisions),
        (c.history || []).length ? h('section', { class: 'card', 'aria-labelledby': 'h-rel' }, h('h2', { id: 'h-rel', text: t('r_related') }), h('ul', { class: 'history' }, ...c.history.map((x) => h('li', {}, h('a', { href: `#/rules/${x.id}`, class: 'mono', text: x.sha256.slice(0, 12) }), ' ', stateBadge(x.state), ' ', h('span', { class: 'faint', text: fmtDate(x.detected_at) }))))) : null)));
  document.title = `${c.name} · MacGuard Quarantine`;
}
