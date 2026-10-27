// "Restauración y recuperación": recovery status from real records, the step-by-step assistant and the inventory of copies. The panel shows instructions and records progress; it executes nothing and never receives a private key:
// commands are run by the operator on their own machine, step outputs are checked here against what the real verifiers print, and only identifiers (procedure, step, a random run id) reach the server's audit log.
import { backupAlertCard, recoveryVerdict } from './backup_alerts.js';
import { t, getLang } from '../i18n.js';
import { h, icon, put, fmtDateTime, copyButton, toast, bytes, shortSha, modal, can } from '../ui.js';
import { api, failure } from '../api.js';
import { createEngine, reviveParams } from '../restore/engine.js';

const STATE_ICON = { VERIFIED: 'check', FAILED: 'x', STALE: 'clock', UNKNOWN: 'minus', NOT_RUN: 'pause' };
const STATE_CLASS = { VERIFIED: 'ok', FAILED: 'bad', STALE: 'warn', UNKNOWN: 'none', NOT_RUN: 'neutral', AUTHENTICATED: 'info', PROVEN: 'ok', NOT_VERIFIED: 'none' };
const lang = () => (getLang() === 'en' ? 'en' : 'es');
const L = (o) => (o ? o[lang()] || o.es || '' : '');
export const stateBadge = (s) => h('span', { class: `badge badge-day-${STATE_CLASS[s] || 'none'}` }, STATE_ICON[s] ? icon(STATE_ICON[s]) : null, t(`rs_st_${s}`) === `rs_st_${s}` ? s : t(`rs_st_${s}`));
const dash = '—';
const when = (iso) => (iso ? fmtDateTime(iso) : dash);
const dur = (s) => (s === null || s === undefined ? dash : s >= 86400 ? `${(s / 86400).toFixed(1)} d` : s >= 3600 ? `${Math.floor(s / 3600)} h ${Math.round((s % 3600) / 60)} min` : s >= 60 ? `${Math.round(s / 60)} min` : `${s} s`);

// ---- stored progress: identifiers, parameter values and step states only (never output text, never a secret) ----
const KEY = (p) => `mg_restore_v1_${p}`;
const load = (p) => { try { const v = JSON.parse(localStorage.getItem(KEY(p)) || 'null'); return v && typeof v === 'object' && v.steps ? v : null; } catch { return null; } };
const save = (p, s) => { try { localStorage.setItem(KEY(p), JSON.stringify({ run: s.run, values: s.values, steps: s.steps, idx: s.idx, read: s.read || {}, mode: s.mode || 'guide' })); } catch { /* progress just will not survive a reload */ } };
const newRun = () => (crypto.randomUUID ? crypto.randomUUID() : `r${Date.now().toString(36)}${Math.random().toString(36).slice(2, 10)}`);

export async function renderRestore(ctx) {
  const { root, me, query } = ctx; let tab = ['status', 'assistant', 'inventory'].includes(query.get('tab')) ? query.get('tab') : 'status';
  const panel = h('div', { class: 'rs-panel', id: 'rs-panel', role: 'tabpanel', tabindex: '-1' }); const tabs = h('div', { class: 'rs-tabs', role: 'tablist', 'aria-label': t('rs_tabs') });
  let status = null, bundle = null, statusErr = null;
  const loadStatus = async (force) => { if (status && !force) return; const r = await api('GET', '/api/restore/status'); if (r.status === 200) { status = r.data; statusErr = null; } else statusErr = failure(r, t('err_generic')); };
  const loadBundle = async () => { if (bundle) return; const r = await api('GET', '/api/restore/procedures'); if (r.status === 200) { const d = r.data; const params = reviveParams(d.params); bundle = { ...d, params, engine: createEngine({ PARAMS: params, STEPS: d.steps, PROCEDURES: d.procedures }) }; } };
  const draw = async () => {
    for (const b of tabs.querySelectorAll('[role=tab]')) { const on = b.dataset.tab === tab; b.setAttribute('aria-selected', on ? 'true' : 'false'); b.setAttribute('tabindex', on ? '0' : '-1'); b.classList.toggle('on', on); }
    put(panel, h('p', { class: 'note', role: 'status', text: t('loading') }));
    try { await loadStatus(); if (tab === 'assistant') await loadBundle(); } catch (e) { console.error(e); }
    if (tab === 'status') put(panel, statusView(status, statusErr, () => draw_(true)));
    else if (tab === 'inventory') put(panel, inventoryView(status, statusErr));
    else put(panel, bundle ? assistantView({ bundle, status, me, query, panel }) : h('p', { class: 'alert alert-bad', role: 'alert' }, icon('alert'), t('rs_bundle_err')));
  };
  const draw_ = async (force) => { if (force) { status = null; } await draw(); };
  for (const [id, label] of [['status', 'rs_tab_status'], ['assistant', 'rs_tab_assistant'], ['inventory', 'rs_tab_inventory']]) {
    const b = h('button', { type: 'button', role: 'tab', id: `rs-tab-${id}`, 'data-tab': id, 'aria-controls': 'rs-panel', class: 'rs-tab' }, t(label));
    b.addEventListener('click', () => { tab = id; history.replaceState(null, '', `#/restore?tab=${id}`); draw(); });
    b.addEventListener('keydown', (e) => { const order = ['status', 'assistant', 'inventory'], i = order.indexOf(tab); if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') { tab = order[(i + (e.key === 'ArrowRight' ? 1 : 2)) % 3]; draw(); tabs.querySelector(`[data-tab=${tab}]`).focus(); } });
    tabs.append(b);
  }
  put(root, h('div', { class: 'page-head' }, h('div', {}, h('h1', { id: 'page-title', tabindex: '-1', text: t('rs_title') }), h('p', { text: t('rs_lead') }))), h('p', { class: 'alert alert-info', role: 'note' }, icon('alert'), t('rs_boundary')), tabs, panel);
  await draw();
}

// ---------------------------------------------------------------- A. status
function statusView(s, err, refresh) {
  if (!s) return h('div', {}, h('p', { class: 'alert alert-bad', role: 'alert' }, icon('alert'), err || t('err_generic')));
  const ids = ['last_backup', 'last_signed', 'checkpoint_produced', 'checkpoint_external', 'last_restore', 'rpo_observed', 'rto_observed', 'provider_b2', 'provider_scaleway', 'provider_r2', 'copies_verified', 'panel_last_backup', 'panel_last_signed', 'panel_copies_verified', 'intel_last_backup', 'intel_last_signed', 'intel_copies_verified', 'signature_chain', 'verifiers', 'secrets', 'next_backup', 'next_drill'];
  const val = (i) => (i.id === 'rpo_observed' || i.id === 'rto_observed' ? dur(i.value) : i.id === 'copies_verified' || i.id === 'panel_copies_verified' || i.id === 'intel_copies_verified' ? `${i.value ?? 0} / 3` : i.id === 'verifiers' && i.value !== null ? `${i.value} / ${s.tools.length}` : typeof i.value === 'number' && i.id.startsWith('last_') ? `#${i.value}` : i.value ?? dash);
  const cards = ids.map((id) => s.indicators.find((i) => i.id === id)).filter(Boolean).map((i) => h('li', { class: 'rs-ind' },
    h('div', { class: 'rs-ind-head' }, h('h3', { text: t(`rs_ind_${i.id}`) }), stateBadge(i.state)), h('strong', { class: 'rs-ind-val', text: String(val(i)) }),
    h('p', { class: 'note' }, `${t('rs_observed')}: ${when(i.observed_at)} · ${t('rs_source')}: ${i.source || dash}`), i.note ? h('p', { class: 'note', text: i.note }) : null));
  const miss = (s.unavailable || []).map((u) => `${u.source} (${u.reason})`);
  return h('div', { class: 'grid-10' },
    h('p', { class: 'freshness note' }, `${t('rs_generated')}: ${when(s.generated_at)}`, ' · ', s.cache && s.cache.hit ? t('fr_cached', { s: s.cache.age_s }) : t('fr_live'), ' · ', h('button', { type: 'button', class: 'btn btn-ghost btn-sm', onclick: refresh }, icon('refresh'), t('rs_refresh'))),
    miss.length ? h('p', { class: 'alert alert-warn', role: 'status' }, icon('alert'), t('rs_partial', { list: miss.join(', ') })) : null,
    recoveryVerdict(s),
    ...(s.failures || []).map((f) => backupAlertCard(f, s)),
    h('ul', { class: 'rs-grid', 'aria-label': t('rs_tab_status') }, cards),
    h('p', { class: 'note', text: t('rs_legend') }),
    s.policy ? h('section', { class: 'card', 'aria-labelledby': 'rs-pol' }, h('h2', { id: 'rs-pol', text: t('rs_policy') }), h('dl', { class: 'rs-dl' },
      h('dt', { text: t('rs_pol_age') }), h('dd', {}, h('code', { text: s.policy.age_recipient || dash })), h('dt', { text: t('rs_pol_ed') }), h('dd', {}, h('code', { text: s.policy.ed25519.fingerprint || dash }), ` · ${t('rs_pol_frozen', { n: s.policy.ed25519.frozen_at_sequence })}`),
      h('dt', { text: t('rs_pol_sig') }), h('dd', {}, h('code', { text: s.policy.sigstore ? s.policy.sigstore.identity : dash })), h('dt', { text: t('rs_pol_issuer') }), h('dd', {}, h('code', { text: s.policy.sigstore ? s.policy.sigstore.issuer || 'https://token.actions.githubusercontent.com' : dash })))) : null);
}

// ---------------------------------------------------------------- C. inventory
function inventoryView(s, err) {
  if (!s) return h('p', { class: 'alert alert-bad', role: 'alert' }, icon('alert'), err || t('err_generic'));
  const f = { provider: '', state: '', minSeq: '', from: '', service: '' }; const body = h('tbody');
  const sel = (id, label, opts, key) => { const el = h('select', { id, class: 'input', 'aria-label': label }, ...opts.map(([v, l]) => h('option', { value: v, text: l }))); el.addEventListener('change', () => { f[key] = el.value; fill(); }); return h('label', { class: 'rs-filter', for: id }, h('span', { text: label }), el); };
  const inp = (id, label, type, key) => { const el = h('input', { id, class: 'input', type, 'aria-label': label }); el.addEventListener('input', () => { f[key] = el.value; fill(); }); return h('label', { class: 'rs-filter', for: id }, h('span', { text: label }), el); };
  const rows = () => s.inventory.filter((r) => (!f.provider || r.provider === f.provider) && (!f.state || r.recoverable === f.state) && (!f.minSeq || (r.sequence !== null && r.sequence >= +f.minSeq)) && (!f.from || (r.at && r.at.slice(0, 10) >= f.from)) && (!f.service || r.service === f.service));
  const cell = (v) => (v === null || v === undefined || v === '' ? h('span', { class: 'nodata', text: dash, title: t('rs_unknown_tip') }) : v);
  function fill() {
    const rs = rows(); put(body, rs.length ? rs.map((r) => h('tr', {},
      h('td', {}, when(r.at)), h('td', { text: r.service }), h('td', {}, cell(r.sequence)), h('td', {}, cell(r.id ? h('code', { text: r.id }) : null)), h('td', { text: r.provider }), h('td', {}, cell(r.bytes !== null && r.bytes !== undefined ? bytes(r.bytes) : null)), h('td', {}, cell(r.sha256 ? h('code', { text: shortSha(r.sha256), title: r.sha256 }) : null)),
      h('td', {}, cell(r.signature_type)), h('td', {}, cell(r.signer_identity ? h('code', { class: 'rs-wrap', text: r.signer_identity.replace('https://github.com/', '') }) : null)), h('td', {}, stateBadge(r.sigstore_state)), h('td', {}, r.transparency_log.state === 'VERIFIED' ? `#${r.transparency_log.index}` : stateBadge(r.transparency_log.state)),
      h('td', {}, stateBadge(r.checkpoint_state)), h('td', {}, when(r.last_download)), h('td', {}, when(r.last_restore)), h('td', {}, r.last_drill ? `${t('rs_ok')} · ${dur(r.last_drill.duration_s)}` : stateBadge('NOT_RUN')),
      h('td', {}, cell(r.schema_version)), h('td', {}, h('span', { class: `badge badge-day-${STATE_CLASS[r.recoverable] || 'none'}`, text: t(`rs_rec_${r.recoverable}`) })), h('td', {}, h('a', { href: r.run_url, target: '_blank', rel: 'noopener noreferrer' }, `#${r.run_id}`)))) : h('tr', {}, h('td', { colspan: 18, text: s.inventory.length ? t('rs_inv_none_filtered') : t('rs_inv_none') })));
  }
  const head = ['rs_c_when', 'rs_f_service', 'rs_c_seq', 'rs_c_id', 'rs_c_provider', 'rs_c_size', 'rs_c_hash', 'rs_c_sigtype', 'rs_c_signer', 'rs_c_sigstore', 'rs_c_tlog', 'rs_c_checkpoint', 'rs_c_download', 'rs_c_restore', 'rs_c_drill', 'rs_c_schema', 'rs_c_recoverable', 'rs_c_run'];
  fill();
  return h('div', { class: 'grid-10' }, h('p', { class: 'alert alert-info', role: 'note' }, icon('alert'), t('rs_inv_note')),
    h('div', { class: 'rs-filters', role: 'search' }, sel('f-prov', t('rs_c_provider'), [['', t('rs_all')], ['b2', 'B2'], ['scaleway', 'Scaleway'], ['r2', 'R2']], 'provider'), sel('f-state', t('rs_c_recoverable'), [['', t('rs_all')], ['PROVEN', t('rs_rec_PROVEN')], ['AUTHENTICATED', t('rs_rec_AUTHENTICATED')], ['NOT_VERIFIED', t('rs_rec_NOT_VERIFIED')], ['FAILED', t('rs_rec_FAILED')]], 'state'),
      inp('f-seq', t('rs_f_minseq'), 'number', 'minSeq'), inp('f-from', t('rs_f_from'), 'date', 'from'), sel('f-svc', t('rs_f_service'), [['', t('rs_all')], ['gateway', 'gateway'], ['panel', 'panel']], 'service')),
    h('div', { class: 'rs-tablewrap', role: 'region', 'aria-label': t('rs_tab_inventory'), tabindex: '0' }, h('table', { class: 'rs-table' }, h('caption', { class: 'sr', text: t('rs_tab_inventory') }), h('thead', {}, h('tr', {}, head.map((k) => h('th', { scope: 'col', text: t(k) })))), body)));
}

// ---------------------------------------------------------------- B. assistant
function assistantView({ bundle, status, me, query, panel }) {
  const { engine, procedures, steps: STEPS, params: PARAMS } = bundle; let procId = query.get('proc') && procedures[query.get('proc')] ? query.get('proc') : null;
  const wrap = h('div', { class: 'grid-10' });
  const redraw = () => (procId ? put(wrap, runView(procId)) : put(wrap, picker()));
  function picker() {
    return h('div', { class: 'grid-10' }, h('p', { class: 'note', text: t('rs_pick_lead') }), h('ul', { class: 'rs-procs' }, Object.values(procedures).map((p) => {
      const saved = load(p.id), done = saved ? Object.values(saved.steps).filter((x) => x.state === 'done' || x.state === 'skipped').length : 0, locked = p.protected && !can(me, 'restore.real.record');
      const b = h('button', { type: 'button', class: 'btn btn-primary', 'aria-describedby': `pp-${p.id}` }, saved ? t('rs_resume') : locked ? t('rs_view') : t('rs_start')); b.addEventListener('click', () => { procId = p.id; history.replaceState(null, '', `#/restore?tab=assistant&proc=${p.id}`); redraw(); });
      return h('li', { class: 'card' }, h('h2', { text: L(p.title) }), h('p', { id: `pp-${p.id}`, text: L(p.summary) }), h('p', { class: 'note' }, `${p.steps.length} ${t('rs_steps')}${saved ? ` · ${done}/${p.steps.length}` : ''}`),
        p.protected ? h('p', { class: 'badge badge-admin' }, locked ? t('rs_admin_only') : t('rs_protected')) : h('p', { class: 'badge badge-day-ok', text: t('rs_no_prod') }), h('div', {}, b));
    })));
  }
  function runView(pid) {
    const proc = procedures[pid], list = engine.stepsOf(pid), readOnly = proc.protected && !can(me, 'restore.real.record');
    const st = load(pid) || { run: newRun(), values: {}, steps: {}, idx: 0 }; st.out = {}; st.posted = {}; st.read = st.read || {}; st.mode = st.mode || (Object.keys(st.steps).length ? 'run' : 'guide');
    const canRun = !readOnly, isGuide = () => st.mode === 'guide' || !canRun;      // GUIDE: read through, nothing executes and nothing is recorded as done. RUN (drill or real recovery): each step needs its real evidence
    const done = () => st.steps; const isDone = (id) => st.steps[id] && (st.steps[id].state === 'done');
    const authorisation = async () => {   // a real recovery is recorded only under an authorisation by two identities, bound to this procedure and this run
      const r = await api('GET', '/api/approvals?op=restore.real'); if (r.status !== 200) return null;
      const ok = (r.data.items || []).find((x) => x.params.procedure === pid && x.params.run === st.run && ((x.mode === 'DUAL' && x.state === 'APPROVED') || (x.mode === 'BREAKGLASS' && x.state === 'EXECUTED'))); return ok ? ok.id : null;
    };
    const post = async (event, step, via) => {
      let authorization_id; if (proc.protected) { authorization_id = await authorisation(); if (!authorization_id) { toast(`${t('rs_not_recorded')}: ${t('rs_need_auth')} (${st.run})`, true); return false; } }
      const r = await api('POST', '/api/restore/event', { event, procedure: pid, run: st.run, ...(authorization_id ? { authorization_id } : {}), ...(step ? { step } : {}), ...(via ? { via } : {}) }); if (r.status !== 200) { toast(`${t('rs_not_recorded')}: ${failure(r, '')}`, true); return false; } return true; };
    const persist = () => save(pid, st);
    const main = h('div', { class: 'rs-run' }), nav = h('ol', { class: 'rs-steps', 'aria-label': t('rs_steps') }), detail = h('section', { class: 'rs-detail', 'aria-live': 'polite' }), bar = h('progress', { class: 'rs-progress', max: list.length, value: 0, 'aria-label': t('rs_progress') });
    const count = h('span', { class: 'note' });
    function summary() { const n = isGuide() ? list.filter((s) => st.read[s.id]).length : list.filter((s) => done()[s.id] && (done()[s.id].state === 'done' || done()[s.id].state === 'skipped')).length; bar.value = n; count.textContent = `${n} / ${list.length}`; }
    function drawNav() {
      put(nav, list.map((s, i) => { const x = done()[s.id], state = isGuide() ? (st.read[s.id] ? 'read' : 'todo') : x ? x.state : engine.blockedBy(pid, s.id, done()).length ? 'blocked' : 'todo'; const a = h('button', { type: 'button', class: `rs-step-link st-${state}`, 'aria-current': i === st.idx ? 'step' : null }, h('span', { class: 'rs-n', text: String(i + 1) }), h('span', { text: L(s.title) }), h('span', { class: 'sr', text: ` — ${t(`rs_s_${state}`)}` }), state === 'done' || state === 'read' ? icon('check') : state === 'failed' ? icon('x') : state === 'blocked' ? icon('pause') : null);
        a.addEventListener('click', () => { st.idx = i; persist(); drawNav(); drawStep(); }); return h('li', {}, a); }));
    }
    function paramsBlock(s) {
      const names = [...new Set([...(s.params || [])])]; if (!names.length) return null;
      return h('fieldset', { class: 'rs-params' }, h('legend', { text: t('rs_params') }), names.map((n) => {
        const p = PARAMS[n], id = `pv-${pid}-${n}`, cur = st.values[n] ?? '', bad = cur !== '' && !p.re.test(cur);
        const inpt = h('input', { id, class: 'input', type: 'text', value: cur, spellcheck: 'false', autocomplete: 'off', placeholder: p.example, 'aria-describedby': `${id}-h`, 'aria-invalid': bad ? 'true' : 'false' });
        const msg = h('span', { id: `${id}-h`, class: bad ? 'rs-bad' : 'note', text: bad ? t('rs_param_bad') : L(p.help), role: bad ? 'alert' : null });
        inpt.addEventListener('input', () => { if (inpt.value === '') delete st.values[n]; else st.values[n] = inpt.value.trim(); persist(); drawStep(); });
        return h('div', { class: 'rs-param' }, h('label', { for: id, text: L(p.label) }), inpt, msg);
      }));
    }
    function commandBlock(s) {
      if (!s.command) return h('p', { class: 'note', text: t('rs_no_command') });
      const missing = (s.params || []).filter((n) => !st.values[n] || !PARAMS[n].re.test(st.values[n]));
      if (missing.length) return h('p', { class: 'alert alert-warn', role: 'status' }, icon('alert'), t('rs_fill_params', { list: missing.map((n) => L(PARAMS[n].label)).join(', ') }));
      let cmd; try { cmd = engine.renderCommand(s.command, st.values); } catch (e) { return h('p', { class: 'alert alert-bad', role: 'alert' }, icon('alert'), String(e.message)); }
      return h('div', { class: 'rs-cmd' }, h('div', { class: 'rs-cmd-head' }, h('strong', { text: t('rs_command') }), copyButton(cmd, t('rs_copy_cmd'))), h('pre', { class: 'rs-code', tabindex: '0' }, h('code', { text: cmd })));
    }
    async function finish(s, state, via) {
      st.steps[s.id] = { state, at: new Date().toISOString(), via: via || null }; persist(); summary(); drawNav(); drawStep();         // the screen reflects the new state at once; recording it in the audit log follows
      if (state === 'done') { const first = Object.values(st.steps).filter((x) => x.state === 'done').length === 1; if (first && !st.posted.start) { st.posted.start = true; await post('procedure_started'); } await post('step_done', s.id, via || 'none'); }
      if (state === 'failed') await post('step_failed', s.id);
    }
    function checkBlock(s) {
      const x = done()[s.id];
      if (isGuide()) { if (st.read[s.id]) return h('p', { class: 'alert alert-ok', role: 'status' }, icon('check'), t('rs_read_ok')); const rb = h('button', { type: 'button', class: 'btn btn-primary', id: 'rs-read' }, icon('check'), t('rs_read')); rb.addEventListener('click', () => { st.read[s.id] = true; persist(); summary(); drawNav(); drawStep(); }); return h('div', {}, h('p', { class: 'alert alert-info', role: 'note' }, icon('alert'), readOnly ? t('rs_readonly') : t('rs_guide_note')), rb); }
      if (x && x.state === 'done') return h('p', { class: 'alert alert-ok', role: 'status' }, icon('check'), `${t('rs_s_done')} · ${when(x.at)}`, x.via ? ` · ${t(`rs_via_${x.via}`)}` : '');
      if (s.check.kind === 'output') {
        const ta = h('textarea', { id: `ob-${s.id}`, class: 'input rs-obs', rows: 5, spellcheck: 'false', 'aria-describedby': `ob-${s.id}-h`, placeholder: t('rs_paste_ph') }); ta.value = st.out[s.id] || '';
        const res = h('div', { class: 'rs-result', role: 'status', 'aria-live': 'polite' });
        const btn = h('button', { type: 'button', class: 'btn btn-primary' }, icon('check'), t('rs_check')); btn.addEventListener('click', () => {
          st.out[s.id] = ta.value; const r = engine.checkOutput(s, ta.value);
          if (r.ok) { put(res, h('p', { class: 'alert alert-ok' }, icon('check'), t('rs_match'))); finish(s, 'done', 'output'); return; }
          const why = r.reason === 'secret_in_output' ? t('rs_secret_pasted') : r.reason === 'empty' ? t('rs_empty') : t('rs_mismatch');
          ta.value = r.reason === 'secret_in_output' ? '' : ta.value; st.out[s.id] = r.reason === 'secret_in_output' ? '' : ta.value;
          put(res, h('div', { class: 'alert alert-bad', role: 'alert' }, icon('x'), why), h('div', { class: 'rs-cmp' }, h('div', {}, h('strong', { text: t('rs_expected') }), h('pre', { class: 'rs-code' }, h('code', { text: s.expected.text }))), h('div', {}, h('strong', { text: t('rs_observed_out') }), h('pre', { class: 'rs-code' }, h('code', { text: r.reason === 'secret_in_output' ? t('rs_discarded') : ta.value.slice(0, 2000) })))), h('p', {}, h('strong', { text: `${t('rs_if_fails')}: ` }), L(s.onFail)));
        });
        const fail = h('button', { type: 'button', class: 'btn btn-ghost' }, t('rs_mark_failed')); fail.addEventListener('click', () => finish(s, 'failed'));
        return h('div', {}, h('label', { for: `ob-${s.id}`, text: t('rs_paste') }), h('p', { id: `ob-${s.id}-h`, class: 'note', text: t('rs_paste_help') }), ta, h('div', { class: 'actions' }, btn, fail), res);
      }
      if (s.check.kind === 'attest') {
        const boxes = s.check.statements.map((q, i) => { const id = `at-${s.id}-${i}`; return h('label', { class: 'rs-check', for: id }, h('input', { id, type: 'checkbox' }), h('span', { text: L(q) })); });
        const word = s.id === 'real_authorisation' ? `${lang() === 'en' ? 'RESTORE' : 'RESTAURAR'} ${st.values.prodD1 || ''}`.trim() : lang() === 'en' ? 'CONFIRM' : 'CONFIRMO';
        const confirm = s.check.requireConfirmText ? h('div', {}, h('label', { for: `cf-${s.id}`, text: t('rs_type_confirm', { word }) }), h('input', { id: `cf-${s.id}`, class: 'input', type: 'text', autocomplete: 'off', spellcheck: 'false' })) : null;
        const err = h('p', { class: 'rs-bad', role: 'alert' }); const btn = h('button', { type: 'button', class: 'btn btn-primary' }, icon('check'), t('rs_attest'));
        btn.addEventListener('click', () => { const all = [...detail.querySelectorAll('input[type=checkbox]')].every((c) => c.checked); const typed = confirm ? detail.querySelector(`#cf-${s.id}`).value.trim() : word; const needD1 = s.id === 'real_authorisation' && !st.values.prodD1;
          if (!all) { err.textContent = t('rs_attest_all'); return; } if (needD1) { err.textContent = t('rs_fill_params', { list: L(PARAMS.prodD1.label) }); return; } if (typed !== word) { err.textContent = t('rs_confirm_mismatch', { word }); return; } err.textContent = ''; finish(s, 'done', 'attest'); });
        return h('fieldset', { class: 'rs-attest' }, h('legend', { text: t('rs_attest_legend') }), boxes, confirm, err, btn);
      }
      const btn = h('button', { type: 'button', class: 'btn btn-primary' }, icon('check'), t('rs_done_manual')); btn.addEventListener('click', () => finish(s, 'done', 'none')); return btn;
    }
    function drawStep() {
      const ae = document.activeElement, keep = ae && ae.id && detail.contains(ae) ? { id: ae.id, a: ae.selectionStart, b: ae.selectionEnd } : null;      // typing re-renders the command: keep the caret where it was
      const s = list[st.idx], blocked = isGuide() ? [] : engine.blockedBy(pid, s.id, done()), x = done()[s.id];
      const nextOk = isGuide() ? !!st.read[s.id] : x && (x.state === 'done' || x.state === 'skipped'), last = st.idx >= list.length - 1;
      const why = nextOk ? (last ? t('rs_nx_last') : '') : last ? t('rs_nx_last') : isGuide() ? t('rs_nx_guide') : blocked.length ? t('rs_nx_blocked') : s.check.kind === 'output' ? t('rs_nx_output') : s.check.kind === 'attest' ? t('rs_nx_attest') : t('rs_nx_manual');
      const kind = s.check.kind === 'attest' ? 'approval' : s.check.kind === 'output' ? (s.id.includes('restore') ? 'restore' : 'check') : s.command ? 'local' : 'info';
      const skip = h('button', { type: 'button', class: 'btn btn-ghost btn-sm', disabled: s.gate || readOnly ? true : null, title: s.gate ? t('rs_cannot_skip') : '' }, t('rs_skip')); skip.addEventListener('click', () => finish(s, 'skipped'));
      const prev = h('button', { type: 'button', class: 'btn', disabled: st.idx === 0 ? true : null }, icon('back'), t('rs_prev')); prev.addEventListener('click', () => { st.idx--; persist(); drawNav(); drawStep(); detail.focus(); });
      const next = h('button', { type: 'button', class: 'btn btn-primary', disabled: nextOk && !last ? null : true, 'aria-describedby': 'rs-next-h' }, t('rs_next')); next.addEventListener('click', () => { st.idx++; persist(); drawNav(); drawStep(); detail.focus(); });
      put(detail, h('div', { class: 'rs-step-head' }, h('p', { class: 'note', text: `${t('rs_step')} ${st.idx + 1} / ${list.length} · ${t(`rs_ph_${s.phase}`)}` }), h('h2', { id: 'rs-step-title', tabindex: '-1', text: L(s.title) }),
        h('p', { class: 'rs-badges' }, h('span', { class: `badge badge-day-${s.danger === 'destructive' ? 'bad' : s.danger === 'caution' ? 'warn' : 'ok'}`, text: t(`rs_danger_${s.danger}`) }), s.gate ? h('span', { class: 'badge badge-day-info', text: t('rs_gate') }) : null, h('span', { class: 'badge badge-day-info', text: t(`rs_kind_${kind}`) }), h('span', { class: 'badge badge-day-neutral', text: s.os.map((o) => (o === 'macos' ? 'macOS' : 'Linux')).join(' · ') }))),
        blocked.length ? h('p', { class: 'alert alert-warn', role: 'status' }, icon('pause'), t('rs_blocked', { list: blocked.map((b) => L(STEPS[b].title)).join('; ') })) : null,
        h('h3', { text: t('rs_goal') }), h('p', { text: L(s.goal) }), h('h3', { text: t('rs_explain') }), h('p', { text: L(s.explain) }),
        s.prereq.length ? h('p', { class: 'note' }, `${t('rs_prereq')}: ${s.prereq.filter((p) => procedures[pid].steps.includes(p)).map((p) => L(STEPS[p].title)).join('; ') || dash}`) : null,
        s.risks.length ? h('div', { class: 'alert alert-warn' }, icon('alert'), h('div', {}, h('strong', { text: `${t('rs_risks')}: ` }), s.risks.map((r) => h('span', { class: 'rs-risk', text: L(r) })))) : null,
        s.cwd ? h('p', { class: 'note' }, `${t('rs_cwd')}: `, L(s.cwd)) : null,
        blocked.length && !isGuide() ? (s.command ? h('p', { class: 'note', text: t('rs_locked_cmd') }) : null) : [paramsBlock(s), commandBlock(s),
          s.expected ? h('div', {}, h('strong', { text: t('rs_expected') }), h('pre', { class: 'rs-code' }, h('code', { text: s.expected.text }))) : null, checkBlock(s)],
        h('p', { class: 'note' }, `${t('rs_evidence')}: ${L(s.evidence)}`),
        s.onFail && L(s.onFail) ? h('details', { class: 'rs-fix' }, h('summary', { text: t('rs_if_fails') }), h('p', { text: L(s.onFail) })) : null,
        h('div', { class: 'actions rs-nav' }, prev, next, !s.gate && !isGuide() ? skip : null), h('p', { id: 'rs-next-h', class: nextOk ? 'note' : 'rs-why', text: why }));
      if (keep) { const n = detail.querySelector(`#${CSS.escape(keep.id)}`); if (n) { n.focus({ preventScroll: true }); try { n.setSelectionRange(keep.a, keep.b); } catch { /* not a text field */ } } }
    }
    const back = h('button', { type: 'button', class: 'btn' }, icon('back'), t('rs_all_procs')); back.addEventListener('click', () => { procId = null; history.replaceState(null, '', '#/restore?tab=assistant'); redraw(); });
    const restart = h('button', { type: 'button', class: 'btn btn-ghost' }, icon('refresh'), t('rs_restart')); restart.addEventListener('click', () => modal({ title: t('rs_restart'), body: h('p', { text: t('rs_restart_confirm') }), confirmLabel: t('rs_restart'), variant: 'bad', submit: async () => { try { localStorage.removeItem(KEY(pid)); } catch { /* ignore */ } procId = pid; redraw(); return null; } }));
    const exp = h('button', { type: 'button', class: 'btn' }, icon('export'), t('rs_export')); exp.addEventListener('click', () => {
      const rep = { schema: 'macguard.restore-report/1', procedure: pid, procedure_version: bundle.version, run: st.run, operator: me.login, role: me.role, exported_at: new Date().toISOString(), values: st.values, steps: list.map((s) => ({ id: s.id, title: L(s.title), state: (done()[s.id] || {}).state || 'todo', at: (done()[s.id] || {}).at || null, via: (done()[s.id] || {}).via || null, observed_output: st.out[s.id] ? String(st.out[s.id]).slice(0, 2000) : null })), note: 'No secrets and no SQL are stored; outputs are those pasted in this session only.' };
      const a = h('a', { href: URL.createObjectURL(new Blob([JSON.stringify(rep, null, 2)], { type: 'application/json' })), download: `restore-report-${pid}-${st.run.slice(0, 8)}.json` }); document.body.append(a); a.click(); a.remove(); });
    const modeBox = h('div', { class: 'rs-modes', role: 'group', 'aria-label': t('rs_mode') }), modeNote = h('p', { class: 'note', id: 'rs-mode-note' });
    function drawMode() {
      const runLabel = proc.protected ? t('rs_mode_real') : t('rs_mode_drill');
      const mk = (m, label, off) => { const b = h('button', { type: 'button', class: 'pill', 'aria-pressed': String(st.mode === m || (m === 'guide' && !canRun)), disabled: off ? true : null }, label); b.addEventListener('click', () => { st.mode = m; persist(); summary(); drawMode(); drawNav(); drawStep(); }); return b; };
      put(modeBox, mk('guide', t('rs_mode_guide')), mk('run', runLabel, !canRun)); modeNote.textContent = !canRun ? t('rs_mode_admin_only') : isGuide() ? t('rs_mode_guide_h') : proc.protected ? t('rs_mode_real_h') : t('rs_mode_drill_h');
    }
    put(main, h('div', { class: 'rs-run-head' }, back, h('h2', { text: L(proc.title) }), h('div', { class: 'rs-prog' }, bar, count), modeBox, modeNote), h('div', { class: 'actions' }, exp, restart), h('div', { class: 'rs-split' }, h('nav', { 'aria-label': t('rs_steps') }, nav), detail));
    persist(); drawMode(); summary(); drawNav(); drawStep(); return main;
  }
  redraw(); return wrap;
}
