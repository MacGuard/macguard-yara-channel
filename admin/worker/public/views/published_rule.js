// One published rule: identity, signed content, provenance and licence, what was and was not measured for it, the signatures of its release, and the ways an ADMIN can take it out of distribution.
// Every block says where its data comes from; what no source provides is NO_DATA, never a guess.
import { t } from '../i18n.js';
import { h, icon, put, copyButton, copyText, shaFull, fmtDateTime, bytes, toast, can } from '../ui.js';
import { api, failure } from '../api.js';
import { requestWithdrawal } from './policy.js';

const rid = () => `req_${(crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2) + Date.now().toString(36)).replace(/[^A-Za-z0-9_-]/g, '')}`;
const ext = (href, text) => h('a', { href, target: '_blank', rel: 'noopener noreferrer', text });
const row = (k, v) => [h('dt', { text: k }), h('dd', {}, v)];

export async function renderPublishedRule(ctx) {
  const { root, me, query } = ctx, path = query.get('path') || '';
  put(root, h('div', { class: 'skeleton sk-title' }), h('div', { class: 'skeleton sk-block' }));
  const back = h('p', { class: 'crumbs' }, h('a', { href: '#/published' }, icon('back'), t('nav_published')));
  const r = await api('GET', `/api/published/file?path=${encodeURIComponent(path)}`);
  if (r.status !== 200) { put(root, back, h('div', { class: 'card empty' }, icon('file'), h('h1', { id: 'page-title', tabindex: '-1', text: r.status === 404 ? t('pf_notfound') : failure(r, t('err_generic')) }), h('p', { text: r.status === 404 ? t('pf_notfound_p') : '' }))); return; }
  const d = r.data, f = d.file, rel = d.release, rec = d.record, pub = d.publication || {}, pol = pub.policy, canAdopt = can(me, 'publication.adopt'), canWithdraw = can(me, 'publication.withdraw.request'), canRevoke = can(me, 'publication.revoke.request'), reload = () => ctx.rerender();
  const c = d.content;

  const adopt = async () => { const x = await api('POST', '/api/published/adopt', { path: f.path, request_id: rid() }); if (x.status === 200) { toast(t('pf_adopted')); reload(); } else toast(t('failed', { msg: failure(x, t('err_generic')) }), true); };
  const withdraw = (preset) => requestWithdrawal({ id: rec.id, version: rec.version }, reload, preset);

  const state = pub.publication || 'published', stateChip = h('span', { class: state === 'withdrawn' ? 'chip chip-bad' : state === 'published' ? 'chip chip-ok' : 'chip chip-warn', text: t(`pf_state_${state}`) });

  const contentBlock = c.status === 'VERIFIED'
    ? [h('p', { class: 'note mt-6 mb-10', text: t('pf_content_ok') }), h('pre', { class: 'code', tabindex: '0', 'aria-label': t('pf_content'), text: c.content })]
    : [h('p', { class: c.status === 'MISMATCH' ? 'alert alert-bad' : 'alert alert-warn', role: 'status' }, icon('alert'), `${t(`pf_content_${c.status}`)} ${c.error || ''}`)];

  const prov = d.provenance, lic = prov.license;
  const provCard = h('section', { class: 'card', 'aria-labelledby': 'h-prov' }, h('h2', { id: 'h-prov', text: t('pf_prov') }), h('dl', { class: 'kv' },
    ...row(t('r_source'), prov.source || '—'), ...row(t('pf_repo'), prov.repository ? ext(`https://github.com/${prov.repository}`, prov.repository) : t('pf_nodata')),
    ...row(t('pf_commit'), prov.commit ? h('span', { class: 'mono', text: prov.commit.slice(0, 12) }) : t('pf_nodata')),
    ...row(t('pf_license'), lic ? `${lic.detail}${lic.spdx_reported ? ` · SPDX ${lic.spdx_reported}` : ''}` : t('pf_nodata')), ...row(t('pf_redistribution'), lic ? lic.redistribution : t('pf_nodata'))),
    h('p', { class: 'note mt-6', text: t('pf_prov_src') }));

  const m = rec ? rec.metrics || {} : {};
  const meas = rec && Object.keys(m).some((k) => typeof m[k] === 'number')
    ? h('dl', { class: 'kv' }, ...[['cpu_s', 'cpu'], ['rss_mb', 'rss'], ['compile_s', 'compile'], ['scan_p95_s', 'scan']].filter(([k]) => typeof m[k] === 'number').flatMap(([k, lab]) => row(t(lab), String(m[k]))))
    : h('p', { class: 'muted', text: t('pf_tests_nodata') });
  const qual = h('section', { class: 'card', 'aria-labelledby': 'h-q' }, h('h2', { id: 'h-q', text: t('pf_quality') }), meas,
    h('h3', { class: 'dep-sub', text: t('pf_set_h') }), h('dl', { class: 'kv' },
      ...row(t('pf_set_validation'), d.set_validation ? t('pf_set_validation_v', { engine: d.set_validation.engine, n: d.set_validation.checked }) : t('pf_nodata')),
      ...row(t('pf_set_dynamic'), d.set_dynamic ? t('pf_set_dynamic_v', { v: d.set_dynamic.verdict, c: d.set_dynamic.canaries, e: d.set_dynamic.engine }) : t('pf_nodata')),
      ...row(t('pf_fp'), t('pf_nodata')), ...row(t('pf_engines'), t('pf_engines_v'))),
    h('p', { class: 'note mt-6', text: t('pf_set_scope') }));

  const sig = h('section', { class: 'card', 'aria-labelledby': 'h-sig' }, h('h2', { id: 'h-sig', text: t('pf_sig') }), h('dl', { class: 'kv' },
    ...row(t('r_release'), ext(rel.url, rel.tag)), ...row(t('pub_published_at'), h('time', { datetime: rel.published_at, text: fmtDateTime(rel.published_at) })),
    ...row(t('pub_manifest'), h('span', { class: 'sha' }, rel.manifest_sha256.slice(0, 16), copyButton(rel.manifest_sha256, `${t('copy')} SHA-256`))), ...row(t('pub_root'), h('span', { class: 'sha' }, rel.rules_root.slice(0, 16), copyButton(rel.rules_root, `${t('copy')} ${t('pub_root')}`))),
    ...row(t('pf_sig_manifest'), ext(rel.signatures.manifest, 'manifest.sigstore.json')), ...row(t('pf_sig_checkpoint'), ext(rel.signatures.checkpoint, 'checkpoint.sigstore.json')), ...row(t('pf_sig_inclusion'), ext(rel.signatures.inclusion_proof, 'inclusion-proof.json')),
    ...(rel.publish_run_url ? row(t('pf_run'), ext(rel.publish_run_url, rel.publish_run_url.split('/').pop())) : [])),
    h('p', { class: 'note mt-6', text: t('pf_sig_note') }));

  const dist = (() => {
    const stage = (label, ok, text) => h('li', {}, h('span', { class: ok === true ? 'chip chip-ok' : ok === false ? 'chip' : 'chip chip-warn', text: ok === true ? t('pf_done') : ok === false ? t('pf_pending') : t('pf_unmeasurable') }), h('strong', { text: ` ${label} ` }), h('span', { class: 'note', text: text }));
    const items = [stage(t('pf_st_requested'), !!pol, pol ? `${pol.author} · ${fmtDateTime(pol.created_at)} · ${t(`pol_crit_${pol.criticality.toLowerCase()}`)}` : t('pf_st_requested_none')),
      stage(t('pf_st_confirmed'), pol ? pol.withdrawal === 'CONFIRMED' : false, pol && pol.withdrawal === 'CONFIRMED' ? `${pol.confirmed_tag} · ${fmtDateTime(pol.confirmed_at)}` : t('pf_st_confirmed_p')),
      stage(t('pf_st_clients'), null, t('pf_st_clients_p'))];
    return h('section', { class: 'card', 'aria-labelledby': 'h-dist' }, h('h2', { id: 'h-dist', text: t('pf_dist') }), h('ol', { class: 'deplist' }, ...items), h('p', { class: 'note mt-6', text: t('pf_dist_note') }));
  })();

  const actions = (() => {
    if (state === 'withdrawn' || state === 'withdrawal_pending') return h('section', { class: 'card', 'aria-labelledby': 'h-act' }, h('h2', { id: 'h-act', text: t('pf_actions') }), h('p', { class: 'alert alert-info' }, icon('lock'), t(`pf_act_${state}`)), h('p', { class: 'note', text: t('pf_act_lift') }));
    if (!canAdopt && !canWithdraw && !canRevoke) return h('section', { class: 'card', 'aria-labelledby': 'h-act' }, h('h2', { id: 'h-act', text: t('pf_actions') }), h('p', { class: 'alert alert-info' }, icon('lock'), t('pf_act_admin')));
    if (!rec && !canAdopt) return h('section', { class: 'card', 'aria-labelledby': 'h-act' }, h('h2', { id: 'h-act', text: t('pf_actions') }), h('p', { class: 'alert alert-info' }, icon('lock'), t('pf_act_admin')));
    if (!rec) return h('section', { class: 'card', 'aria-labelledby': 'h-act' }, h('h2', { id: 'h-act', text: t('pf_actions') }), h('p', { class: 'note mb-10', text: t('pf_adopt_p') }), h('button', { type: 'button', class: 'btn btn-primary', id: 'pf-adopt', onclick: adopt }, icon('check'), t('pf_adopt')));
    return h('section', { class: 'card', 'aria-labelledby': 'h-act' }, h('h2', { id: 'h-act', text: t('pf_actions') }), h('p', { class: 'note mb-10', text: t('pf_act_p') }),
      h('div', { class: 'stack' },
        canWithdraw ? [h('button', { type: 'button', class: 'btn btn-bad', id: 'pf-withdraw', onclick: () => withdraw({ scope: 'path', crit: 'STANDARD' }) }, icon('x'), t('pf_withdraw')), h('p', { class: 'note', text: t('pf_withdraw_h') })] : null,
        canRevoke ? [h('button', { type: 'button', class: 'btn btn-bad', id: 'pf-revoke', onclick: () => withdraw({ scope: 'content', crit: 'CRITICAL' }) }, icon('alert'), t('pf_revoke')), h('p', { class: 'note', text: t('pf_revoke_h') })] : null),
      (d.newer_versions || []).length ? h('p', { class: 'note mt-10' }, t('pf_newer'), ' ', ...d.newer_versions.flatMap((x) => [h('a', { href: `#/rules/${x.id}`, class: 'mono', text: x.sha256.slice(0, 10) }), ' '])) : h('p', { class: 'note mt-10', text: t('pf_replace_h') }));
  })();

  const decisions = rec && rec.decisions.length ? h('ol', { class: 'timeline' }, ...rec.decisions.slice().reverse().map((x) => h('li', {}, h('time', { datetime: x.at, text: fmtDateTime(x.at) }), h('strong', { text: `${x.actor} · ${x.action}` }), h('span', { class: 'note', text: `${x.from_state} → ${x.to_state}` }), x.reason ? h('div', { class: 'quote', text: x.reason }) : null))) : h('p', { class: 'muted', text: rec ? t('pf_hist_none') : t('pf_hist_norecord') });

  put(root, back,
    h('div', { class: 'page-head' }, h('div', {}, h('h1', { id: 'page-title', tabindex: '-1', text: f.name }), h('p', { class: 'rule-path mt-6', text: f.path })), h('div', { class: 'actions' }, rec ? h('a', { id: 'pf-sheet', class: 'btn btn-sm', href: `#/rules/${rec.id}`, text: t('pf_sheet') }) : null, stateChip)),
    h('div', { class: 'sheet' },
      h('div', { class: 'stack' },
        h('section', { class: 'card', 'aria-labelledby': 'h-id' }, h('h2', { id: 'h-id', text: t('pf_identity') }), h('div', { class: 'field' }, h('span', { text: t('r_sha') }), h('div', { class: 'flex-8 center' }, shaFull(f.sha256), copyButton(f.sha256, `${t('copy')} SHA-256`))),
          h('dl', { class: 'kv' }, ...row(t('r_source'), f.source || '—'), ...row(t('r_size'), f.bytes === null ? '—' : bytes(f.bytes)), ...row(t('r_version'), rec ? `v${rec.version}` : t('pf_nodata')), ...row(t('pf_record'), rec ? `${rec.state} · ${rec.id.slice(0, 8)}` : t('pf_norecord')))),
        provCard, qual,
        h('section', { class: 'card', 'aria-labelledby': 'h-code' }, h('div', { class: 'flex-between' }, h('h2', { id: 'h-code', text: t('pf_content') }), c.status === 'VERIFIED' ? h('button', { type: 'button', class: 'btn btn-sm', onclick: () => copyText(c.content) }, icon('copy'), t('copy')) : null), ...contentBlock),
        sig),
      h('div', { class: 'stack sticky' }, actions, dist, h('section', { class: 'card', 'aria-labelledby': 'h-hist' }, h('h2', { id: 'h-hist', text: t('pf_history') }), decisions))));
  document.title = `${f.name} · MacGuard Quarantine`;
}
