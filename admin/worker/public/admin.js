/* Admin panel. All dynamic content is inserted with textContent / attributes: rule code and names are untrusted data. */
(function () {
'use strict';
var $ = function (i) { return document.getElementById(i); };
var T = { es: {}, en: { skip: 'Skip to content', title: 'Quarantine panel', logout: 'Sign out', login_h: 'Restricted access', login_p: 'This panel is private. Sign in with GitHub; your real repository permissions will be checked.', login_b: 'Sign in with GitHub', denied_h: 'No access', denied_p: 'Your GitHub account has no permission for this panel. Ask an administrator for access.', tab_q: 'Quarantine', tab_a: 'Audit', tab_m: 'Members', f_q: 'Search', f_state: 'State', f_src: 'Source', selall: 'Select page', b_approve: 'Approve selection (publish on the next run)', b_reject: 'Delete selection (reject)', b_hold: 'Keep selection in quarantine', cap: 'Quarantined rules', sel: 'Select', c_file: 'File', c_state: 'State', c_why: 'Reasons', c_src: 'Source', c_when: 'Detected', prev: 'Previous', next: 'Next', verify_chain: 'Verify the audit chain', c_actor: 'Who', c_action: 'Action', c_target: 'Target', m_role: 'Role', m_save: 'Save', m_note: 'Write access to the repository gives REVIEWER and repository admin gives ADMIN; here VIEWER is granted or an explicit grant is removed. Read access to a public repository gives nothing.', reason: 'Reason (required)', cancel: 'Cancel', confirm: 'Confirm' } };
var S = { me: null, page: 1, total: 0, size: 25, items: [], selected: {}, tab: 'q' };
var L = function () { return $('lang').value; };
function tr(k, es) { var d = T[L()] || {}; return d[k] !== undefined ? d[k] : es; }
function applyLang() { document.documentElement.lang = L(); document.querySelectorAll('[data-t]').forEach(function (e) { if (!e.dataset.es) e.dataset.es = e.textContent; var d = T[L()] || {}; e.textContent = d[e.dataset.t] !== undefined ? d[e.dataset.t] : e.dataset.es; }); }
function el(tag, attrs, kids) { var e = document.createElement(tag); for (var k in (attrs || {})) { if (k === 'text') e.textContent = attrs[k]; else e.setAttribute(k, attrs[k]); } (kids || []).forEach(function (c) { e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); }); return e; }
function say(m, bad) { var s = $('status'); s.textContent = m || ''; s.className = bad ? 'badmsg' : 'muted'; }
function api(method, path, body) {
  var h = { Accept: 'application/json' }; if (body !== undefined) h['Content-Type'] = 'application/json'; if (S.me && method !== 'GET') h['X-CSRF-Token'] = S.me.csrf;
  return fetch(path, { method: method, headers: h, credentials: 'same-origin', body: body === undefined ? undefined : JSON.stringify(body) }).then(function (r) { return r.json().catch(function () { return {}; }).then(function (d) { return { status: r.status, data: d }; }); });
}
function newRequestId() { return 'req_' + (crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2) + Date.now().toString(36)).replace(/[^A-Za-z0-9_-]/g, ''); }

function boot() {
  try { var v = localStorage.getItem('lang'); if (v === 'en') $('lang').value = 'en'; if (localStorage.getItem('theme') === 'dark') document.body.classList.add('dark'); } catch (e) {}
  applyLang();
  api('GET', '/api/me').then(function (r) {
    if (r.status === 401) { $('login').hidden = false; return; }
    if (r.status === 403) { $('denied').hidden = false; return; }
    S.me = r.data; $('app').hidden = false; $('who').textContent = S.me.login; $('role').hidden = false; $('role').textContent = S.me.role; $('logout').hidden = false;
    var rank = { VIEWER: 1, REVIEWER: 2, ADMIN: 3 }[S.me.role];
    document.querySelector('[data-tab=a]').hidden = rank < 2; document.querySelector('[data-tab=m]').hidden = rank < 3; $('verify-chain').hidden = rank < 3;
    $('bulk-approve').hidden = $('bulk-reject').hidden = $('bulk-hold').hidden = rank < 2; loadStats(); loadList();
  });
}
function loadStats() {
  api('GET', '/api/stats').then(function (r) { var box = $('cards'); box.textContent = ''; var c = (r.data && r.data.counts) || {};
    ['PENDING', 'UNDER_REVIEW', 'APPROVED_PENDING_VALIDATION', 'REJECTED', 'RELEASED'].forEach(function (s) { var b = el('button', { type: 'button', 'data-state': s }, [el('strong', { text: String(c[s] || 0) }), el('span', { text: s })]); b.addEventListener('click', function () { $('state').value = s; S.page = 1; loadList(); }); box.appendChild(b); }); });
}
function loadList() {
  var q = new URLSearchParams({ page: S.page, pageSize: S.size }); if ($('state').value) q.set('state', $('state').value); if ($('q').value.trim()) q.set('q', $('q').value.trim()); if ($('source').value.trim()) q.set('source', $('source').value.trim());
  say('…'); api('GET', '/api/candidates?' + q).then(function (r) {
    if (r.status !== 200) { say((r.data && r.data.error) || 'error', true); return; } say('');
    S.items = r.data.items; S.total = r.data.total; S.selected = {}; renderList(); });
}
function renderList() {
  var tb = document.querySelector('#list tbody'); tb.textContent = '';
  S.items.forEach(function (c) {
    var tr_ = el('tr'), cb = el('input', { type: 'checkbox', 'aria-label': c.path }); cb.disabled = !S.me || S.me.role === 'VIEWER';
    cb.addEventListener('change', function () { if (cb.checked) S.selected[c.id] = c.version; else delete S.selected[c.id]; tr_.className = cb.checked ? 'sel' : ''; syncBulk(); });
    tr_.appendChild(el('td', {}, [cb]));
    var name = el('button', { type: 'button', text: c.path, class: 'linkish' }); name.addEventListener('click', function () { openDetail(c.id); });
    tr_.appendChild(el('td', { class: 'path' }, [name, el('div', { class: 'mono muted', text: c.sha256 })]));
    tr_.appendChild(el('td', {}, [el('span', { class: 'st st-' + c.state, text: c.state })]));
    var why = el('td'); c.reasons.forEach(function (x) { why.appendChild(el('span', { class: 'chip', text: x })); }); tr_.appendChild(why);
    tr_.appendChild(el('td', { text: c.source })); tr_.appendChild(el('td', { text: (c.detected_at || '').slice(0, 10) })); tb.appendChild(tr_); });
  var pages = Math.max(1, Math.ceil(S.total / S.size)); $('pageinfo').textContent = S.page + ' / ' + pages + ' · ' + S.total; $('prev').disabled = S.page <= 1; $('next').disabled = S.page >= pages; syncBulk();
}
function syncBulk() { var n = Object.keys(S.selected).length; $('selcount').textContent = n ? String(n) : ''; $('bulk-approve').disabled = $('bulk-reject').disabled = $('bulk-hold').disabled = n === 0; }
$('selall').addEventListener('click', function () { document.querySelectorAll('#list tbody input[type=checkbox]').forEach(function (cb, i) { if (!cb.disabled && !cb.checked) { cb.checked = true; S.selected[S.items[i].id] = S.items[i].version; cb.closest('tr').className = 'sel'; } }); syncBulk(); });
['q', 'state', 'source'].forEach(function (i) { $(i).addEventListener(i === 'state' ? 'change' : 'input', function () { S.page = 1; clearTimeout(S.t); S.t = setTimeout(loadList, 250); }); });
$('prev').addEventListener('click', function () { S.page--; loadList(); }); $('next').addEventListener('click', function () { S.page++; loadList(); });

function barChart(rows) {   // rows: [label, newValue, oldValue|null]
  var W = 520, rowH = 34, H = rows.length * rowH + 8, ns = 'http://www.w3.org/2000/svg', svg = document.createElementNS(ns, 'svg'); svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H); svg.setAttribute('class', 'bars'); svg.setAttribute('role', 'img');
  var max = Math.max.apply(null, rows.map(function (r) { return Math.max(r[1] || 0, r[2] || 0); }).concat([1]));
  rows.forEach(function (r, i) { var y = 4 + i * rowH;
    function bar(v, cls, dy) { var w = Math.max(1, (v / max) * (W - 190)); var b = document.createElementNS(ns, 'rect'); b.setAttribute('x', 150); b.setAttribute('y', y + dy); b.setAttribute('width', w); b.setAttribute('height', 11); b.setAttribute('class', cls); svg.appendChild(b); var t = document.createElementNS(ns, 'text'); t.setAttribute('x', 154 + w); t.setAttribute('y', y + dy + 10); t.textContent = String(Math.round(v * 100) / 100); svg.appendChild(t); }
    var lb = document.createElementNS(ns, 'text'); lb.setAttribute('x', 0); lb.setAttribute('y', y + 18); lb.textContent = r[0]; svg.appendChild(lb);
    bar(r[1] || 0, 'bar-new', 2); if (r[2] !== null && r[2] !== undefined) bar(r[2], 'bar-old', 16); });
  svg.setAttribute('aria-label', rows.map(function (r) { return r[0] + ' ' + r[1] + (r[2] != null ? ' (previous ' + r[2] + ')' : ''); }).join('; ')); return svg;
}
function openDetail(id) {
  api('GET', '/api/candidates/' + id).then(function (r) {
    if (r.status !== 200) { say(r.data.error || 'error', true); return; } var c = r.data, d = $('detail'); d.textContent = ''; d.hidden = false;
    var close = el('button', { type: 'button', text: '✕', 'aria-label': 'Close' }); close.addEventListener('click', function () { d.hidden = true; }); d.appendChild(close);
    d.appendChild(el('h2', { text: c.name })); d.appendChild(el('p', { class: 'mono', text: c.path + '\n' + c.sha256 }));
    d.appendChild(el('p', {}, [el('span', { class: 'st st-' + c.state, text: c.state }), ' · v' + c.version + ' · ' + c.source + (c.upstream_commit ? ' @ ' + c.upstream_commit.slice(0, 10) : '') + ' · ' + c.bytes + ' B']));
    var why = el('p'); c.reasons.forEach(function (x) { why.appendChild(el('span', { class: 'chip', text: x })); }); d.appendChild(why);
    if (c.revalidation_failed) d.appendChild(el('p', { class: 'badmsg', text: 'Revalidation failed: ' + c.revalidation_failed }));
    var m = c.metrics || {}, prev = ((c.history || []).filter(function (h) { return h.metrics && typeof h.metrics.cpu_s === 'number'; })[0] || {}).metrics || {};
    var rows = [['CPU (s)', m.cpu_s, prev.cpu_s], ['RAM (MB)', m.rss_mb, prev.rss_mb], ['Compile (s)', m.compile_s, prev.compile_s], ['Scan p95 (s)', m.scan_p95_s, prev.scan_p95_s]].filter(function (x) { return typeof x[1] === 'number'; });
    if (rows.length) { d.appendChild(el('h3', { text: 'Resources' })); d.appendChild(barChart(rows)); }
    if (c.depends_on && c.depends_on.length) d.appendChild(el('p', { text: 'Depends on: ' + c.depends_on.join(', ') }));
    d.appendChild(el('h3', { text: 'Rule source (untrusted text, shown as data)' })); d.appendChild(el('pre', { class: 'code', tabindex: '0', text: c.content === null ? '(content not stored)' : c.content.slice(0, 200000) }));
    if (c.related && c.related.length) { d.appendChild(el('h3', { text: 'Related' })); var ul = el('ul'); c.related.forEach(function (x) { ul.appendChild(el('li', { text: x.relation + ': ' + x.state + ' ' + x.sha256.slice(0, 12) })); }); d.appendChild(ul); }
    d.appendChild(el('h3', { text: 'Decisions' })); var dl = el('ul'); (c.decisions || []).forEach(function (x) { dl.appendChild(el('li', { text: x.at.slice(0, 16) + ' · ' + x.actor + ' (' + x.role + ') · ' + x.action + ' → ' + x.to_state + ' · ' + x.reason })); }); if (!(c.decisions || []).length) dl.appendChild(el('li', { text: '—' })); d.appendChild(dl);
    if (c.release_tag) d.appendChild(el('p', { text: 'Release: ' + c.release_tag }));
    if (S.me.role !== 'VIEWER') { var row = el('p'); [['approve', 'Approve: publish on the next run', 'ok'], ['reject', 'Delete (reject for good)', 'bad'], ['hold', 'Keep in quarantine', '']].forEach(function (a) { var b = el('button', { type: 'button', class: 'btn ' + a[2], text: a[1] }); b.addEventListener('click', function () { var sel = {}; sel[c.id] = c.version; askDecision(a[0], sel); }); row.appendChild(b); });
      var rb = el('button', { type: 'button', class: 'btn', text: 'Retest' }); rb.addEventListener('click', function () { api('POST', '/api/candidates/' + c.id + '/retest').then(function (x) { say(x.status === 200 ? x.data.note : (x.data.error || 'error'), x.status !== 200); }); }); row.appendChild(rb); d.appendChild(row); }
    close.focus(); });
}
function askDecision(action, selection) {
  var ids = Object.keys(selection), dlg = $('confirm'); $('confirm-h').textContent = ({ approve: 'Approve ', reject: 'Delete (reject) ', hold: 'Keep in quarantine ' }[action]) + ids.length + (ids.length === 1 ? ' rule' : ' rules');
  $('confirm-p').textContent = 'This will change exactly ' + ids.length + ' rule' + (ids.length === 1 ? '' : 's') + '. ' + ({ approve: 'The next run tests it again with every technical check and publishes it only if it passes.', reject: 'Rejected content is never re-added automatically; an edited upstream version would be a new candidate.', hold: 'It stays out of every release until you decide.' }[action]);
  $('confirm-reason').value = ''; $('confirm-err').textContent = ''; S.pending = { action: action, selection: selection, ids: ids };
  if (!dlg.open) dlg.showModal(); $('confirm-reason').focus();
}
// The confirm button is handled here (not by native form validation) so the message is announced and nothing is sent without a reason.
$('confirm-go').addEventListener('click', function (ev) {
  ev.preventDefault(); var p = S.pending; if (!p) return; var reason = $('confirm-reason').value.trim();
  if (reason.length < 5) { $('confirm-err').textContent = 'A reason of at least 5 characters is required.'; $('confirm-reason').focus(); return; }
  var body = { action: p.action, ids: p.ids, reason: reason, request_id: newRequestId(), expect: p.selection }; if (p.ids.length > 1) body.confirm_count = p.ids.length;
  S.pending = null; $('confirm').close('ok');
  api('POST', '/api/decisions', body).then(function (r) { if (r.status === 200) { say((r.data.applied || []).length + ' updated.'); $('detail').hidden = true; loadStats(); loadList(); } else say((r.data.error || 'error') + (r.data.conflicts ? ' (' + r.data.conflicts.length + ' conflicts)' : ''), true); });
});
$('confirm').addEventListener('close', function () { if ($('confirm').returnValue !== 'ok') S.pending = null; });
$('bulk-hold').addEventListener('click', function () { askDecision('hold', Object.assign({}, S.selected)); });
$('bulk-approve').addEventListener('click', function () { askDecision('approve', Object.assign({}, S.selected)); });
$('bulk-reject').addEventListener('click', function () { askDecision('reject', Object.assign({}, S.selected)); });
document.querySelectorAll('.tabs button').forEach(function (b) { b.addEventListener('click', function () { S.tab = b.dataset.tab; document.querySelectorAll('.tabs button').forEach(function (x) { x.setAttribute('aria-selected', x === b ? 'true' : 'false'); }); ['q', 'a', 'm'].forEach(function (t) { $('tab-' + t).hidden = t !== S.tab; }); if (S.tab === 'a') loadAudit(); if (S.tab === 'm') loadMembers(); }); });
function loadAudit() { api('GET', '/api/audit?limit=100').then(function (r) { var tb = document.querySelector('#audit tbody'); tb.textContent = ''; ((r.data && r.data.entries) || []).forEach(function (e) { var tr_ = el('tr'); [e.seq, e.at.replace('T', ' ').slice(0, 19), e.actor + ' (' + e.role + ')', e.action, e.target].forEach(function (x) { tr_.appendChild(el('td', { text: String(x) })); }); tb.appendChild(tr_); }); }); }
$('verify-chain').addEventListener('click', function () { api('GET', '/api/audit/verify').then(function (r) { var o = $('chain-out'); o.textContent = r.data.ok ? '✔ ' + r.data.entries + ' entries, chain intact' : '✘ ' + (r.data.error || 'broken') + (r.data.at ? ' at #' + r.data.at : ''); o.className = r.data.ok ? 'okmsg' : 'badmsg'; }); });
function loadMembers() { api('GET', '/api/members').then(function (r) { var ul = $('members'); ul.textContent = ''; ((r.data && r.data.members) || []).forEach(function (m) { ul.appendChild(el('li', { text: m.login + ' — ' + m.role + ' (' + m.granted_by + ')' })); }); }); }
$('member-form').addEventListener('submit', function (ev) { ev.preventDefault(); api('POST', '/api/members', { login: $('m-login').value.trim(), role: $('m-role').value || null }).then(function (r) { say(r.status === 200 ? 'Saved.' : (r.data.error || 'error'), r.status !== 200); loadMembers(); }); });
$('logout').addEventListener('click', function () { api('POST', '/api/logout').then(function () { location.reload(); }); });
$('lang').addEventListener('change', function () { try { localStorage.setItem('lang', L()); } catch (e) {} applyLang(); });
$('theme').addEventListener('click', function () { document.body.classList.toggle('dark'); try { localStorage.setItem('theme', document.body.classList.contains('dark') ? 'dark' : 'light'); } catch (e) {} });
boot();
})();
