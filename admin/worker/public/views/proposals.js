// Proposed sources, inside the Sources page: anyone with the REVIEWER role proposes and verifies, only an ADMIN authorizes. The server enforces the roles; the buttons only follow them.
import { t } from '../i18n.js';
import { h, icon, put, fmtDateTime, modal, reasonField, toast, shortSha } from '../ui.js';
import { api, failure } from '../api.js';

const rid = () => `ui_${crypto.randomUUID().replace(/-/g, '')}`;
const BADGE = { proposed: 'neutral', verified: 'day-info', approved: 'day-ok', rejected: 'day-bad', pr_open: 'day-warn', active: 'day-ok', retired: 'day-neutral' };

/** The section for the Sources page, or null when the feature is off (404) or the call fails: the page then looks exactly as before. */
export async function proposalsSection(ctx) {
  const r = await api('GET', '/api/source-proposals'); if (r.status !== 200) return null;
  const { proposals, can_propose: canPropose, can_authorize: canAuthorize } = r.data;
  const done = (res, ok) => { if (res.status === 200) { toast(ok || t('src_p_done')); ctx.rerender(); return null; } return t('failed', { msg: failure(res, t('err_generic')) }); };

  function proposeDialog() {
    const url = h('input', { class: 'input', id: 'sp-url', type: 'url', autocomplete: 'off', spellcheck: 'false', 'aria-describedby': 'sp-url-h', placeholder: 'https://github.com/owner/repository' });
    const id = h('input', { class: 'input', id: 'sp-id', autocomplete: 'off', spellcheck: 'false', maxlength: '32', 'aria-describedby': 'sp-id-h' });
    const paths = h('textarea', { class: 'textarea', id: 'sp-paths', rows: '3', spellcheck: 'false', 'aria-describedby': 'sp-paths-h' });
    const reason = reasonField();
    url.addEventListener('input', () => { if (!id.dataset.touched) { const m = url.value.match(/github\.com\/[^/]+\/([A-Za-z0-9._-]+?)(?:\.git)?\/?$/); if (m) id.value = m[1].toLowerCase().replace(/[^a-z0-9-]+/g, '-').slice(0, 32); } });
    id.addEventListener('input', () => { id.dataset.touched = '1'; });
    const body = h('div', { class: 'grid-12' },
      h('div', { class: 'field' }, h('label', { for: 'sp-url', text: t('src_p_url') }), url, h('p', { id: 'sp-url-h', class: 'note', text: t('src_p_url_hint') })),
      h('div', { class: 'field' }, h('label', { for: 'sp-id', text: t('src_p_id') }), id, h('p', { id: 'sp-id-h', class: 'note', text: t('src_p_id_hint') })),
      h('div', { class: 'field' }, h('label', { for: 'sp-paths', text: t('src_p_paths') }), paths, h('p', { id: 'sp-paths-h', class: 'note', text: t('src_p_paths_hint') })), reason.node);
    modal({ title: t('src_p_propose'), body, confirmLabel: t('src_p_propose'), validate: () => (reason.value.length < 5 ? t('reason_short') : null),
      async submit() {
        const res = await api('POST', '/api/source-proposals', { request_id: rid(), url: url.value.trim(), source_id: id.value.trim(), paths: paths.value.split('\n').map((x) => x.trim()).filter(Boolean), reason: reason.value });
        return done(res);
      } });
  }
  async function verify(p, btn) { btn.disabled = true; const res = await api('POST', `/api/source-proposals/${p.id}/verify`, { request_id: rid(), expect_version: p.version }); btn.disabled = false; const e = done(res); if (e) toast(e, true); }

  function authorizeDialog(p) {
    const warn = (p.findings || []).filter((f) => f.severity === 'warn');
    const boxes = warn.map((f) => { const cb = h('input', { type: 'checkbox', id: `sp-ack-${f.code}`, value: f.code }); return { f, cb, node: h('label', { class: 'radio', for: cb.id }, cb, h('span', {}, h('strong', { class: 'mono', text: f.code }), h('small', { text: t('src_p_ack', { code: f.code }) }))) }; });
    const confirm = h('input', { class: 'input', id: 'sp-confirm', autocomplete: 'off', spellcheck: 'false' }); const reason = reasonField();
    const body = h('div', { class: 'grid-12' }, h('p', { class: 'alert alert-info' }, icon('info'), t('src_p_auth_p')), boxes.map((b) => b.node),
      h('div', { class: 'field' }, h('label', { for: 'sp-confirm', text: t('src_p_confirm', { repo: p.repo }) }), confirm), reason.node);
    modal({ title: t('src_p_auth_h', { repo: p.repo }), body, confirmLabel: t('src_p_authorize'), variant: 'ok',
      validate: () => (confirm.value.trim() !== p.repo ? t('src_p_confirm_bad') : reason.value.length < 5 ? t('reason_short') : null),
      async submit() { return done(await api('POST', `/api/source-proposals/${p.id}/authorize`, { request_id: rid(), expect_version: p.version, acks: boxes.filter((b) => b.cb.checked).map((b) => b.f.code), confirm_repo: confirm.value.trim(), reason: reason.value })); } });
  }
  function closeDialog(p, op) {
    const reason = reasonField();
    modal({ title: t(op === 'reject' ? 'src_p_reject_h' : 'src_p_retire_h', { repo: p.repo }), body: reason.node, confirmLabel: t(op === 'reject' ? 'src_p_reject' : 'src_p_retire'), variant: 'bad', validate: () => (reason.value.length < 5 ? t('reason_short') : null),
      async submit() { return done(await api('POST', `/api/source-proposals/${p.id}/${op}`, { request_id: rid(), expect_version: p.version, reason: reason.value })); } });
  }

  const card = (p) => {
    const verifyBtn = h('button', { type: 'button', class: 'btn btn-sm', text: t('src_p_verify') }); verifyBtn.addEventListener('click', () => verify(p, verifyBtn));
    const acts = [];
    if (canPropose && ['proposed', 'verified'].includes(p.state)) acts.push(verifyBtn);
    if (canAuthorize && p.state === 'verified') acts.push(h('button', { type: 'button', class: 'btn btn-sm btn-ok', onclick: () => authorizeDialog(p), text: t('src_p_authorize') }));
    if (canAuthorize && ['proposed', 'verified', 'approved'].includes(p.state)) acts.push(h('button', { type: 'button', class: 'btn btn-sm', onclick: () => closeDialog(p, 'reject'), text: t('src_p_reject') }));
    if (canAuthorize && ['approved', 'pr_open', 'active'].includes(p.state)) acts.push(h('button', { type: 'button', class: 'btn btn-sm', onclick: () => closeDialog(p, 'retire'), text: t('src_p_retire') }));
    const f = p.findings || [];
    return h('li', { class: 'person' },
      h('div', { class: 'person-head' }, h('div', { class: 'badge-ic k-source' }, icon('source')), h('div', {}, h('strong', { text: p.source_id }), h('a', { class: 'faint', href: `https://github.com/${p.repo}`, target: '_blank', rel: 'noopener noreferrer' }, p.repo, icon('external')))),
      h('div', { class: 'person-badges' }, h('span', { class: `badge badge-${BADGE[p.state] || 'neutral'}`, text: t(`src_p_state_${p.state}`) }), h('span', { class: 'faint', text: `${t('src_p_by', { login: p.proposer })} · ${fmtDateTime(p.created_at)}` })),
      h('dl', { class: 'kv' }, h('dt', { text: t('sr_paths') }), h('dd', {}, h('span', { class: 'reasons' }, ...p.paths.map((x) => h('span', { class: 'chip mono', text: x })))),
        h('dt', { text: t('src_p_license') }), h('dd', { text: p.license_spdx || (p.verified_at ? '—' : t('src_p_notverified')) }),
        p.verified_commit ? [h('dt', { text: t('src_p_commit') }), h('dd', {}, h('span', { class: 'mono', text: shortSha(p.verified_commit) }))] : null,
        p.pr_url ? [h('dt', { text: t('src_p_pr') }), h('dd', {}, h('a', { href: p.pr_url, target: '_blank', rel: 'noopener noreferrer' }, `#${p.pr_number}`, icon('external')))] : null,
        h('dt', { text: t('src_p_findings') }), h('dd', {}, f.length ? h('span', { class: 'reasons' }, ...f.map((x) => h('span', { class: `chip mono ${x.severity === 'block' ? 'chip-bad' : ''}`, title: t(`src_p_sev_${x.severity}`), text: `${t(`src_p_sev_${x.severity}`)}: ${x.code}` }))) : p.verified_at ? t('src_p_nofind') : t('src_p_notverified'))),
      acts.length ? h('div', { class: 'actions' }, ...acts) : null);
  };
  return h('section', { class: 'card', 'aria-labelledby': 'h-props' },
    h('div', { class: 'page-head' }, h('div', {}, h('h2', { id: 'h-props', text: t('src_p_h') }), h('p', { text: t('src_p_lead') })), canPropose ? h('div', { class: 'actions' }, h('button', { type: 'button', class: 'btn btn-primary btn-sm', onclick: proposeDialog }, icon('plus'), t('src_p_propose'))) : null),
    proposals.length ? h('ul', { class: 'people' }, proposals.map(card)) : h('p', { class: 'nodata', text: t('src_p_none') }));
}
