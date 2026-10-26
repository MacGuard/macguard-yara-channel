// Withdrawal of a published rule: what the sheet shows (pending / confirmed / lifted) and the one form an ADMIN uses to request it. Lifting is done through the API for now.
import { t } from '../i18n.js';
import { h, icon, modal, radioGroup, reasonField, toast, fmtDateTime, can } from '../ui.js';
import { api, failure } from '../api.js';

const rid = () => `req_${(crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2) + Date.now().toString(36)).replace(/[^A-Za-z0-9_-]/g, '')}`;
export const polChip = (publication) => h('span', { class: publication === 'withdrawn' ? 'chip chip-bad' : 'chip chip-warn', text: t(`pol_chip_${publication}`) });

export async function requestWithdrawal(c, reload, preset = {}) {
  const pre = await api('GET', `/api/policies/preview?candidate_id=${encodeURIComponent(c.id)}&scope=path`);
  if (pre.status !== 200) { toast(t('failed', { msg: failure(pre, t('err_generic')) }), true); return; }
  const n = pre.data.collateral.length, reason = reasonField();
  const scope = radioGroup(t('pol_scope'), 'pol-scope', [['path', t('pol_scope_path'), t('pol_scope_path_h')], ['content', t('pol_scope_content'), t('pol_scope_content_h')]], preset.scope || 'path');
  const crit = radioGroup(t('pol_crit'), 'pol-crit', [['CRITICAL', t('pol_crit_critical'), t('pol_crit_critical_h')], ['STANDARD', t('pol_crit_standard'), t('pol_crit_standard_h')]], preset.crit || 'CRITICAL');
  const ack = h('input', { type: 'checkbox', id: 'pol-ack' });
  const collateral = n ? h('div', { class: 'field' }, h('p', { class: 'alert alert-info', text: t('pol_collateral', { n, list: pre.data.collateral.map((x) => x.path).join(', ') }) }), h('label', { class: 'radio', for: 'pol-ack' }, ack, h('span', {}, h('strong', { text: t('pol_collateral_ack', { n }) })))) : h('p', { class: 'note', text: t('pol_collateral_none') });
  modal({
    title: t('pol_req_h'), intro: t('pol_req_intro'), body: h('div', { class: 'grid-12' }, h('p', { class: 'note', text: t('pol_baseline', { tag: pre.data.baseline.tag }) }), scope.node, crit.node, collateral, reason.node), confirmLabel: t('pol_request'), variant: 'bad',
    validate: () => (reason.value.length < 5 ? t('reason_short') : n && !ack.checked ? t('pol_collateral_need') : null),
    async submit() {
      const r = await api('POST', '/api/policies/withdrawals', { candidate_id: c.id, scope: scope.value, criticality: crit.value, reason: reason.value, request_id: rid(), expect_version: c.version, confirm_collateral: n });
      if (r.status === 200) { toast(t('pol_done')); if (reload) reload(); return null; }
      return t('failed', { msg: failure(r, t('err_generic')) });
    },
  });
}

/** The card of the rule sheet: nothing for a rule that is not published and has no policy. */
export function policyCard(c, me, reload) {
  const v = c.publication, p = v && v.policy;
  if (p) {
    const lines = [h('dt', { text: t('pol_scope') }), h('dd', { text: t(`pol_scope_${p.scope}`) }), h('dt', { text: t('pol_crit') }), h('dd', { text: t(`pol_crit_${p.criticality.toLowerCase()}`) }), h('dt', { text: t('pol_by') }), h('dd', { text: `${p.author} · ${fmtDateTime(p.created_at)}` }), h('dt', { text: t('reason') }), h('dd', { text: p.reason })];
    if (p.withdrawal === 'CONFIRMED') lines.push(h('dt', { text: t('pol_confirmed_in') }), h('dd', { class: 'mono', text: p.confirmed_tag }));
    if (p.status === 'LIFTED') lines.push(h('dt', { text: t('pol_lifted_by') }), h('dd', { text: `${p.lifted_by} · ${fmtDateTime(p.lifted_at)} · ${t(`pol_via_${p.lifted_via}`)}` }));
    const open = (v.lifts || []).find((l) => l.effective_state === 'REQUESTED');
    return h('section', { class: 'card', 'aria-labelledby': 'h-pol' }, h('h2', { id: 'h-pol', text: t('pol_h') }),
      h('p', { class: p.status === 'LIFTED' ? 'alert alert-info' : 'alert alert-bad', role: 'status' }, icon(p.status === 'LIFTED' ? 'info' : 'lock'), t(`pol_${v.publication === 'lifted' ? 'lifted' : v.publication === 'withdrawn' ? 'confirmed' : 'pending'}_p`, { tag: p.confirmed_tag || '' })),
      open ? h('p', { class: 'note', text: t('pol_lift_open', { kind: t(`pol_via_${open.kind}`) }) }) : null, h('dl', { class: 'kv' }, ...lines));
  }
  if (c.state !== 'RELEASED' || !can(me, 'publication.withdraw.request')) return null;
  return h('section', { class: 'card', 'aria-labelledby': 'h-pol' }, h('h2', { id: 'h-pol', text: t('pol_h') }), h('p', { class: 'note mb-10', text: t('pol_none_p') }),
    h('button', { type: 'button', class: 'btn btn-bad', onclick: () => requestWithdrawal(c, reload) }, icon('x'), t('pol_request')));
}
