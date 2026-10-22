/* MacGuard Subscriptions and Alerts pages. Same-origin only. Data comes from static files (data/*.json next to the pages, ../../feeds/index.json) and, when a
   backend answers GET /api/v1/health, from /api/v1/*. No framework. Nothing is built from data as HTML: text goes in as text, links are http(s) only.
   Storage: only the language/theme preference that common.js keeps. The session cookie is HttpOnly (JavaScript never sees it); the CSRF token is kept in memory.
   Nothing here decides who may do what: the server does, for every request. The page only hides what the server would refuse. */
(function () {
'use strict';
var MG = window.MG, D = window.ALERTS_I18N, TAX = window.ALERTS_TAX, F = window.MGFilter, el = MG.el;
var page = document.body.getAttribute('data-page'), lang = 'es';
var S = { backend: false, me: null, csrf: null, snapshot: null, sources: null, feeds: null, builder: null, editing: null, matchesBefore: null };
var STATIC = 'data/';

/* ---------------------------------------------------------------- small helpers */
function t(k) { var l = D[lang] || {}; if (l[k] !== undefined) return l[k]; return D.es[k] !== undefined ? D.es[k] : k; }
function txt(s) { return document.createTextNode(s); }
function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); return n; }
function mount(id) { var m = MG.$(id); return m ? clear(m) : null; }
function val(v) { if (v === null || v === undefined || v === '') return el('span', { class: 'muted', text: t('na') }); if (typeof v === 'boolean') return txt(v ? t('yes') : t('no')); return typeof v === 'object' && v.nodeType ? v : txt(String(v)); }
function link(href, text) {
  var ok = /^https?:\/\//.test(href) || /^[a-z0-9_./?=#&-]+$/i.test(href);
  var a = el('a', { href: ok ? href : '#', text: text || href });
  if (/^https?:\/\//.test(href)) { a.setAttribute('rel', 'noopener noreferrer'); a.setAttribute('target', '_blank'); }
  return a;
}
function btn(key, fn, id, cls) { var b = el('button', { type: 'button', 'data-t': key, text: t(key) }); if (id) b.id = id; if (cls) b.className = cls; b.addEventListener('click', fn); return b; }
function dl(rows) {
  var d = el('dl', { class: 'facts' });
  rows.forEach(function (r) { d.appendChild(el('dt', { text: r[0] })); var dd = el('dd'); dd.appendChild(val(r[1])); d.appendChild(dd); });
  return d;
}
function table(caption, heads, rows) {
  var w = el('div', { class: 'tablewrap', tabindex: '0', role: 'region', 'aria-label': caption });
  var tb = el('table', { style: 'min-width:' + (heads.length >= 3 ? heads.length * 130 : 0) + 'px' }), tr = el('tr'), body = el('tbody');
  tb.appendChild(el('caption', { class: 'sr', text: caption }));
  heads.forEach(function (h) { tr.appendChild(el('th', { scope: 'col', text: h })); });
  tb.appendChild(el('thead', {}, [tr]));
  rows.forEach(function (r) { var row = el('tr'); r.forEach(function (c) { var td = el('td'); td.appendChild(val(c)); row.appendChild(td); }); body.appendChild(row); });
  tb.appendChild(body); w.appendChild(tb); return w;
}
function status(id, msg, bad) { var m = MG.$(id); if (m) { m.className = bad ? 'badmsg' : 'muted'; m.textContent = msg || ''; } }
function failure(e) { var m = MG.$('load-state'); if (m) { m.className = 'badmsg'; m.textContent = t('err_load') + ' ' + (e && e.message ? e.message : ''); } }
function loaded() { var m = MG.$('load-state'); if (m) { m.className = 'sr'; m.textContent = t('loaded'); } }
function label(prefix, id) { var k = prefix + String(id).replace(/-/g, '_'); return D.es[k] !== undefined ? t(k) : String(id); }
function taxLabel(kind, id) { return t('tax_' + kind + '_' + id); }
function splitList(s) { return String(s || '').split(',').map(function (x) { return x.trim(); }).filter(function (x) { return x; }); }
function band(b) { return D.es['band_' + b] !== undefined ? t('band_' + b) : String(b); }
function shortDate(s) { return s ? String(s).slice(0, 10) : null; }
var SHAPE = { critical: '▲', high: '▲', medium: '◆', low: '●', none: '○', unknown: '?' };
function sevBadge(b) { var e = el('span', { class: 'badge sev-' + b }); e.appendChild(el('span', { 'aria-hidden': 'true', text: SHAPE[b] || '?' })); e.appendChild(txt(' ' + band(b))); return e; }

/* ---------------------------------------------------------------- data access */
function getJson(url) { return fetch(url, { cache: 'no-store', credentials: 'same-origin' }).then(function (r) { if (!r.ok) throw new Error(url + ' ' + r.status); return r.json(); }); }
function api(method, path, body) {
  var opts = { method: method, credentials: 'same-origin', cache: 'no-store', headers: {} };
  if (body !== undefined) { opts.body = JSON.stringify(body); opts.headers['Content-Type'] = 'application/json'; }
  if (method !== 'GET' && S.csrf) opts.headers['X-CSRF-Token'] = S.csrf;
  return fetch(path, opts).then(function (r) {
    return r.text().then(function (txt2) {
      var data = null; try { data = txt2 ? JSON.parse(txt2) : null; } catch (e) { data = null; }
      return { status: r.status, data: data, text: txt2, headers: r.headers };
    });
  });
}
function errText(r) { return r && r.data && r.data.error ? (r.data.error.message || r.data.error.code) : ('HTTP ' + (r ? r.status : '?')); }
function detectBackend() {
  return api('GET', '/api/v1/health').then(function (r) { S.backend = r.status === 200 && r.data && r.data.ok === true; }, function () { S.backend = false; });
}
function loadMe() {
  if (!S.backend) { S.me = null; return Promise.resolve(); }
  return api('GET', '/api/v1/session').then(function (r) { if (r.status === 200 && r.data && r.data.authenticated) { S.me = r.data; S.csrf = r.data.csrf; } else { S.me = null; S.csrf = null; } });
}
function loadStatic() {
  return Promise.all([getJson(STATIC + 'snapshot.json'), getJson(STATIC + 'sources.json'), getJson('../../feeds/index.json').catch(function () { return null; })]).then(function (v) { S.snapshot = v[0]; S.sources = v[1]; S.feeds = v[2]; });
}
function staleSources() { return ((S.sources && S.sources.sources) || []).filter(function (s) { return s.operational_state === 'stale'; }).map(function (s) { return s.id; }); }

function renderBackend() {
  var b = MG.$('backend'); if (!b) return;
  b.className = S.backend ? 'notice ok' : 'notice';
  b.textContent = S.backend ? t('be_ok') : t('be_none');
}

/* ---------------------------------------------------------------- authentication panel */
function authPanel(onChange) {
  var box = MG.$('auth'), body = MG.$('auth-body'); if (!box || !body) return;
  clear(body);
  if (!S.backend) { box.hidden = false; body.appendChild(el('p', { class: 'muted', text: t('be_needs') })); return; }
  box.hidden = false;
  if (S.me) {
    body.appendChild(el('p', { text: t('au_signed') + ' ' + S.me.user.email + ' · ' + (S.me.mfa_enabled ? t('au_mfa_on') : t('au_mfa_off')) }));
    body.appendChild(btn('au_logout', function () { api('POST', '/api/v1/auth/logout', {}).then(function () { S.me = null; S.csrf = null; authPanel(onChange); onChange(); }); }));
    return;
  }
  body.appendChild(el('p', { class: 'muted', text: t('au_needs') }));
  var f = el('div', { class: 'fields' });
  var em = el('input', { id: 'au-email', type: 'email', autocomplete: 'username', maxlength: '200' }), pw = el('input', { id: 'au-pass', type: 'password', autocomplete: 'current-password', maxlength: '256' }), tp = el('input', { id: 'au-totp', type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: '6' });
  [['au_email', em], ['au_password', pw], ['au_totp', tp]].forEach(function (p) { var l = el('label'); l.appendChild(el('span', { 'data-t': p[0], text: t(p[0]) })); l.appendChild(txt(' ')); l.appendChild(p[1]); f.appendChild(l); });
  body.appendChild(f);
  var msg = el('p', { id: 'au-msg', role: 'status', 'aria-live': 'polite', class: 'muted' });
  function doLogin() {
    api('POST', '/api/v1/auth/login', { email: em.value, password: pw.value, totp: tp.value || undefined }).then(function (r) {
      if (r.status === 200) { pw.value = ''; return loadMe().then(function () { authPanel(onChange); onChange(); }); }
      var code = r.data && r.data.error ? r.data.error.code : 'generic';
      msg.className = 'badmsg'; msg.textContent = D.es['au_err_' + code] !== undefined ? t('au_err_' + code) : t('au_err_generic') + ' ' + errText(r);
    });
  }
  function doRegister() {
    api('POST', '/api/v1/auth/register', { email: em.value, password: pw.value, locale: lang }).then(function (r) {
      msg.className = r.status === 201 ? 'muted' : 'badmsg'; msg.textContent = r.status === 201 ? t('au_registered') : t('au_err_generic') + ' ' + errText(r);
    });
  }
  [em, pw, tp].forEach(function (i) { i.addEventListener('keydown', function (e) { if (e.key === 'Enter') doLogin(); }); });
  var acts = el('div', { class: 'actions' }); acts.appendChild(btn('au_login', doLogin)); acts.appendChild(btn('au_register', doRegister));
  body.appendChild(acts); body.appendChild(msg);
}

/* ---------------------------------------------------------------- reasons and alert cards */
var FIELD_KEY = { region: 'fb_region', sector: 'fb_sector', vendor: 'fb_vendor', product: 'fb_product', product_family: 'fb_family', version: 'fb_version', os: 'fb_os', technology_category: 'fb_category', service: 'fb_service',
  ecosystem: 'fb_ecosystem', id: 'fb_ids', cvss: 'fb_cvss', epss: 'fb_epss', severity: 'fb_severity', exploited: 'fb_exploited', published: 'fb_published', updated: 'fb_updated', ingested_within_days: 'fb_new',
  has_fix: 'fb_fix', exposure: 'fb_exposure', source: 'fb_source', alert_type: 'fb_type', threat_family: 'fb_family_threat', attack_technique: 'fb_technique' };
function short(v) {
  if (v === null || v === undefined) return '?';
  if (Array.isArray(v)) return v.slice(0, 5).map(short).join(', ');
  if (typeof v === 'object') return Object.keys(v).map(function (k) { return k + '=' + short(v[k]); }).join(', ');
  return String(v);
}
function reasonLine(r) {
  if (r.field === 'all') return t('why_empty');
  var name = FIELD_KEY[r.field] ? t(FIELD_KEY[r.field]).split(':')[0].split(',')[0] : r.field;
  return name + (r.negated ? ' ' + t('why_negated') : '') + ' — ' + t('why_expected') + ': ' + short(r.expected) + ' · ' + t('why_observed') + ': ' + short(r.observed) + (r.basis ? ' · ' + t('why_basis') + ': ' + r.basis : '');
}
function alertCard(a, reasons) {
  var li = el('li', { class: 'panel result' });
  var h = el('h3'); h.appendChild(link('alert.html?id=' + encodeURIComponent(a.alert_id), a.title)); li.appendChild(h);
  var line = el('p', { class: 'meta' }); line.appendChild(sevBadge(a.severity.band)); line.appendChild(txt(' '));
  line.appendChild(el('span', { class: 'badge ' + (a.exploitation.status === 'exploited' ? 'expl-yes' : 'expl-no'), text: a.exploitation.status === 'exploited' ? t('r_exploited') + ' ' + a.exploitation.asserted_by.join(', ') : t('r_not_asserted') }));
  li.appendChild(line);
  if (a.description) li.appendChild(el('p', { text: a.description.slice(0, 280) }));
  li.appendChild(dl([[t('r_sources'), Object.keys(a.observations).sort().join(', ')], [t('r_region'), a.region_scope.map(function (r) { return r.region; }).filter(function (x, i, arr) { return arr.indexOf(x) === i; }).join(', ') || null],
    [t('r_cvss'), a.severity.score ? a.severity.score + ' (' + a.severity.rated_by.join(', ') + ')' : t('r_unknown')], [t('r_published'), a.dates.published], [t('r_updated'), shortDate(a.last_changed_utc)], [t('r_type'), label('type_', a.alert_type)],
    [t('r_version'), String(a.record_version)]]));
  if (reasons && reasons.length) {
    var d = el('details'); d.appendChild(el('summary', { text: t('r_why') })); var ul = el('ul', { class: 'dl' });
    reasons.forEach(function (r) { ul.appendChild(el('li', { text: reasonLine(r) })); }); d.appendChild(ul); li.appendChild(d);
  }
  return li;
}

/* ---------------------------------------------------------------- the filter builder (the closed vocabulary of alerts/filters.py, as controls) */
function labelled(key, ctl, note) {
  var l = el('label'); l.appendChild(el('span', { 'data-t': key, text: t(key) })); l.appendChild(txt(' ')); l.appendChild(ctl);
  if (!note) return l;
  var w = el('div', { class: 'field' }); w.appendChild(l); w.appendChild(el('small', { class: 'muted', 'data-t': note, text: t(note) })); return w;
}
function checks(idp, legendKey, values, labelFn, noteKey) {
  var fs = el('fieldset'); fs.appendChild(el('legend', { 'data-t': legendKey, text: t(legendKey) }));
  var wrap = el('div', { class: 'checks' }), boxes = {};
  values.forEach(function (v) {
    var l = el('label', { class: 'check' }), c = el('input', { type: 'checkbox', id: idp + '-' + v, value: v }); boxes[v] = c;
    l.appendChild(c); l.appendChild(txt(' ')); var sp = el('span', { text: labelFn(v) }); sp.dataset.v = v; l.appendChild(sp); wrap.appendChild(l);
  });
  fs.appendChild(wrap); if (noteKey) fs.appendChild(el('small', { class: 'muted', 'data-t': noteKey, text: t(noteKey) }));
  return { node: fs, get: function () { return values.filter(function (v) { return boxes[v].checked; }); }, set: function (arr) { values.forEach(function (v) { boxes[v].checked = (arr || []).indexOf(v) >= 0; }); },
    relabel: function () { fs.querySelectorAll('span[data-v]').forEach(function (s) { s.textContent = labelFn(s.dataset.v); }); } };
}
function tri(id, labelKey, optKeys, noteKey) {
  var s = el('select', { id: id }); optKeys.forEach(function (k, i) { var o = el('option', { value: ['', 'yes', 'no'][i], 'data-t': k, text: t(k) }); s.appendChild(o); });
  return { node: labelled(labelKey, s, noteKey), get: function () { return s.value; }, set: function (v) { s.value = v || ''; } };
}
function text(id, key, ph) { var i = el('input', { id: id, type: 'text', maxlength: '400', autocomplete: 'off' }); if (ph) i.setAttribute('placeholder', ph); return { node: labelled(key, i), get: function () { return i.value; }, set: function (v) { i.value = v || ''; }, input: i }; }
function num(id, key, min, max, step, note) { var i = el('input', { id: id, type: 'number', min: String(min), max: String(max), step: String(step) }); return { node: labelled(key, i, note), get: function () { return i.value; }, set: function (v) { i.value = v === undefined || v === null ? '' : v; } }; }
function date(id, key) { var i = el('input', { id: id, type: 'date' }); return { node: labelled(key, i), get: function () { return i.value; }, set: function (v) { i.value = v || ''; } }; }
function group(titleKey, parts, noteKey) {
  var fs = el('fieldset'); fs.appendChild(el('legend', { 'data-t': titleKey, text: t(titleKey) }));
  parts.forEach(function (p) { fs.appendChild(p.node || p); }); if (noteKey) fs.appendChild(el('small', { class: 'muted', 'data-t': noteKey, text: t(noteKey) })); return fs;
}

function buildFilterUi(container) {
  clear(container);
  var c = {};
  c.region = checks('fr', 'fb_region', TAX.regions, function (v) { return taxLabel('region', v); }, 'fb_region_note');
  c.sector = checks('fs', 'fb_sector', TAX.sectors, function (v) { return taxLabel('sector', v); }, 'fb_sector_note');
  var unk = el('label', { class: 'check' }); var unkBox = el('input', { type: 'checkbox', id: 'fs-unknown' }); unk.appendChild(unkBox); unk.appendChild(txt(' ')); unk.appendChild(el('span', { 'data-t': 'fb_sector_unknown', text: t('fb_sector_unknown') }));
  c.vendor = text('f-vendor', 'fb_vendor'); c.product = text('f-product', 'fb_product'); c.family = text('f-family', 'fb_family');
  c.vv = text('f-ver-vendor', 'fb_version_vendor'); c.vp = text('f-ver-product', 'fb_version_product'); c.vn = text('f-ver-version', 'fb_version_version');
  var ambBox = el('input', { type: 'checkbox', id: 'f-ver-amb' }); var amb = el('label', { class: 'check' }); amb.appendChild(ambBox); amb.appendChild(txt(' ')); amb.appendChild(el('span', { 'data-t': 'fb_version_amb', text: t('fb_version_amb') }));
  c.os = checks('fo', 'fb_os', TAX.os, function (v) { return taxLabel('os', v); });
  var CATS = ['container-platform', 'network-device', 'cloud', 'service-protocol', 'library'], ECO = ['npm', 'pypi', 'maven', 'go', 'cargo', 'nuget', 'rubygems', 'packagist', 'debian', 'ubuntu', 'alpine', 'rpm', 'hex', 'pub', 'swifturl', 'other'];
  c.cat = checks('fc', 'fb_category', CATS, function (v) { return label('cat_', v); });
  c.service = text('f-service', 'fb_service');
  c.eco = checks('fe', 'fb_ecosystem', ECO, function (v) { return label('eco_', v); });
  c.exposure = checks('fx', 'fb_exposure', TAX.exposure, function (v) { return taxLabel('exposure', v); }, 'fb_exposure_note');
  c.ids = text('f-ids', 'fb_ids');
  var sev = el('select', { id: 'f-sev' }); sev.appendChild(el('option', { value: '', 'data-t': 'any_', text: t('any_') })); TAX.bands.slice(1).forEach(function (b) { var o = el('option', { value: b, text: band(b) }); o.dataset.band = b; sev.appendChild(o); });
  c.sev = { node: labelled('fb_severity', sev), get: function () { return sev.value; }, set: function (v) { sev.value = v || ''; }, relabel: function () { sev.querySelectorAll('option[data-band]').forEach(function (o) { o.textContent = band(o.dataset.band); }); } };
  c.cvss = num('f-cvss', 'fb_cvss', 0, 10, 0.1); c.epss = num('f-epss', 'fb_epss', 0, 100, 0.01, 'fb_epss_note');
  c.exploited = tri('f-expl', 'fb_exploited', ['fb_exploited_any', 'fb_exploited_yes', 'fb_exploited_no'], 'fb_exploited_note');
  c.pub = date('f-pub', 'fb_published'); c.upd = date('f-upd', 'fb_updated'); c.newd = num('f-new', 'fb_new', 0, 3650, 1);
  c.fix = tri('f-fix', 'fb_fix', ['any_', 'fb_fix_yes', 'fb_fix_no']);
  var srcIds = ((S.sources && S.sources.sources) || []).map(function (s) { return s.id; });
  c.source = checks('fsrc', 'fb_source', srcIds, function (v) { return v; });
  c.type = checks('ft', 'fb_type', ['vulnerability', 'advisory', 'rule-release'], function (v) { return label('type_', v); });
  c.threat = text('f-threat', 'fb_family_threat'); c.tech = text('f-tech', 'fb_technique'); c.tech.node.appendChild(el('small', { class: 'muted', 'data-t': 'fb_technique_note', text: t('fb_technique_note') }));
  container.appendChild(el('div', { class: 'filtergrid' }, [
    group('fb_region', [c.region]), group('fb_sector', [c.sector, unk]),
    group('fb_tech', [c.vendor, c.product, c.family, group('fb_version', [c.vv, c.vp, c.vn, amb], 'fb_version_note'), c.os, c.cat, c.service, c.eco, c.exposure]),
    group('fb_vuln', [c.ids, c.sev, c.cvss, c.epss, c.exploited, c.pub, c.upd, c.newd, c.fix]), group('fb_other', [c.source, c.type, c.threat, c.tech])]));
  var errBox = el('p', { id: 'f-error', role: 'alert', class: 'badmsg' }); container.appendChild(errBox);
  function leaf(field, op, value, extra) { var o = { field: field, op: op, value: value }; if (extra) for (var k in extra) o[k] = extra[k]; return o; }
  var api2 = {
    read: function () {
      var expr = [], errs = [];
      function chk(ctl, field) { var v = ctl.get(); if (v.length) expr.push(leaf(field, 'in', v)); }
      function lst(ctl, field, norm) { var v = splitList(ctl.get()); if (!v.length) return; if (norm) { var bad = []; v = v.map(function (x) { var n = norm(x); if (!n) bad.push(x); return n || x; }); if (bad.length) errs.push(bad.join(', ')); } expr.push(leaf(field, 'in', v)); }
      chk(c.region, 'region');
      var sec = c.sector.get(); if (sec.length) expr.push(leaf('sector', 'in', sec, unkBox.checked ? { include_unknown: true } : null));
      lst(c.vendor, 'vendor'); lst(c.product, 'product'); lst(c.family, 'product_family');
      var vv = [c.vv.get().trim(), c.vp.get().trim(), c.vn.get().trim()];
      if (vv.some(function (x) { return x; })) { if (vv.every(function (x) { return x; }) && /^[0-9][0-9A-Za-z.\-_+~]*$/.test(vv[2])) expr.push(leaf('version', 'affects', { vendor: vv[0], product: vv[1], version: vv[2] }, ambBox.checked ? { include_ambiguous: true } : null)); else errs.push(t('fb_version')); }
      chk(c.os, 'os'); chk(c.cat, 'technology_category'); lst(c.service, 'service'); chk(c.eco, 'ecosystem'); chk(c.exposure, 'exposure');
      lst(c.ids, 'id', F.normId);
      if (c.sev.get()) expr.push(leaf('severity', 'gte', c.sev.get()));
      [['cvss', c.cvss, 10], ['epss', c.epss, 100]].forEach(function (p) { var v = p[1].get(); if (v !== '') { var n = parseFloat(v); if (isNaN(n) || n < 0 || n > p[2]) errs.push(p[0]); else expr.push(leaf(p[0], 'gte', n)); } });
      if (c.exploited.get()) expr.push(leaf('exploited', 'is', c.exploited.get() === 'yes'));
      [['published', c.pub], ['updated', c.upd]].forEach(function (p) { if (p[1].get()) expr.push(leaf(p[0], 'gte', p[1].get())); });
      if (c.newd.get() !== '') { var d = parseInt(c.newd.get(), 10); if (isNaN(d) || d < 0) errs.push('N'); else expr.push(leaf('ingested_within_days', 'lte', d)); }
      if (c.fix.get()) expr.push(leaf('has_fix', 'is', c.fix.get() === 'yes'));
      chk(c.source, 'source'); chk(c.type, 'alert_type'); lst(c.threat, 'threat_family');
      var tech = splitList(c.tech.get()); if (tech.length) { var badT = tech.filter(function (x) { return !/^T\d{4}(\.\d{3})?$/.test(x); }); if (badT.length) errs.push(badT.join(', ')); else expr.push(leaf('attack_technique', 'in', tech)); }
      errBox.textContent = errs.length ? t('fb_bad') + ' ' + errs.join('; ') : '';
      return errs.length ? null : { schema: 'macguard.subscription-filter/1', version: 1, expr: { all: expr } };
    },
    load: function (spec) {
      Object.keys(c).forEach(function (k) { if (c[k].set) c[k].set(k === 'tech' ? '' : []); });
      var all = (spec && spec.expr && spec.expr.all) || [];
      all.forEach(function (n) {
        var f = n.field, v = n.value;
        if (f === 'region') c.region.set(v); else if (f === 'sector') { c.sector.set(v); unkBox.checked = !!n.include_unknown; } else if (f === 'vendor') c.vendor.set(v.join(', ')); else if (f === 'product') c.product.set(v.join(', '));
        else if (f === 'product_family') c.family.set(v.join(', ')); else if (f === 'version') { c.vv.set(v.vendor); c.vp.set(v.product); c.vn.set(v.version); ambBox.checked = !!n.include_ambiguous; }
        else if (f === 'os') c.os.set(v); else if (f === 'technology_category') c.cat.set(v); else if (f === 'service') c.service.set(v.join(', ')); else if (f === 'ecosystem') c.eco.set(v); else if (f === 'exposure') c.exposure.set(v);
        else if (f === 'id') c.ids.set(v.join(', ')); else if (f === 'severity') c.sev.set(v); else if (f === 'cvss') c.cvss.set(v); else if (f === 'epss') c.epss.set(v); else if (f === 'exploited') c.exploited.set(v ? 'yes' : 'no');
        else if (f === 'published') c.pub.set(v); else if (f === 'updated') c.upd.set(v); else if (f === 'ingested_within_days') c.newd.set(v); else if (f === 'has_fix') c.fix.set(v ? 'yes' : 'no');
        else if (f === 'source') c.source.set(v); else if (f === 'alert_type') c.type.set(v); else if (f === 'threat_family') c.threat.set(v.join(', ')); else if (f === 'attack_technique') c.tech.set(v.join(', '));
      });
    },
    reset: function () { api2.load({ expr: { all: [] } }); errBox.textContent = ''; },
    relabel: function () { ['region', 'sector', 'os', 'cat', 'eco', 'exposure', 'type', 'source'].forEach(function (k) { if (c[k] && c[k].relabel) c[k].relabel(); }); if (c.sev.relabel) c.sev.relabel(); }
  };
  return api2;
}

/* ---------------------------------------------------------------- explore */
function evalSnapshot(spec) {
  var stale = staleSources(), now = Date.now(), out = [];
  (S.snapshot.alerts || []).forEach(function (a) { var r = F.evaluate(spec, a, { now: now, changes: null, stale: stale }); if (r.matched) out.push({ a: a, reasons: r.reasons }); });
  return out;
}
function explore() {
  var ui = MG.$('filter-ui');
  if (!S.builder) { S.builder = buildFilterUi(ui); }
  function empty() {
    var e = mount('empty');
    if (!(S.snapshot.alerts || []).length && !S.backend) { e.appendChild(el('h3', { text: t('empty_title') })); e.appendChild(el('p', { class: 'notice', text: t('empty_why') })); }
  }
  function run() {
    var spec = S.builder.read(); if (!spec) return;
    var list = mount('results');
    if (S.backend) {                       /* the service evaluates with the same engine and the live store; the browser only draws */
      var cursor = null;
      var page1 = function () {
        api('POST', '/api/v1/alerts/search', { filter: spec, limit: 50, cursor: cursor || undefined }).then(function (r) {
          if (r.status !== 200) { MG.$('count').textContent = errText(r); return; }
          r.data.items.forEach(function (a) { list.appendChild(alertCard(a, a.match_reasons)); });
          cursor = r.data.next_cursor; var n = list.children.length;
          MG.$('count').textContent = n ? n + ' ' + t('count_suffix') + (cursor ? ' …' : '') : t('count_none');
          var e = mount('empty'); if (cursor) e.appendChild(btn('more', page1)); else if (!n) { e.appendChild(el('h3', { text: t('empty_title') })); e.appendChild(el('p', { class: 'notice', text: t('empty_why') })); }
        });
      };
      page1(); return;
    }
    var res = evalSnapshot(spec), shown = Math.min(res.length, 50);
    res.slice(0, shown).forEach(function (x) { list.appendChild(alertCard(x.a, x.reasons)); });
    MG.$('count').textContent = res.length ? shown + ' ' + t('count_of') + ' ' + res.length + ' ' + t('count_suffix') : t('count_none');
    empty();
  }
  S.run = run; run();
  var fm = mount('feeds');
  if (!S.feeds) { fm.appendChild(val(null)); } else {
    var idx = S.feeds.feeds, rows = idx.map(function (x) { var cell = el('span'); cell.appendChild(link('../../' + x.file, t('feed_download'))); return [x.id, x.lang, x.items === 0 ? t('feed_empty') : x.items + ' ' + t('feed_items'), x.sha256, cell]; });
    fm.appendChild(table(t('h_feeds'), [t('so_name'), t('feed_lang'), t('feed_items'), t('feed_sha'), ''], rows));
  }
  var sn = mount('snapshot');
  sn.appendChild(dl([[t('snap_info'), S.snapshot.generated_at], [t('snap_count'), String(S.snapshot.count) + (S.snapshot.truncated ? ' ' + t('snap_truncated') : '')], [t('origin'), S.snapshot.data_origin], [t('real'), S.snapshot.what_is_real]]));
}

/* ---------------------------------------------------------------- alert detail */
function renderAlert(a) {
  var m = mount('alert'), id = el('h2', { text: a.title }); m.appendChild(id);
  var line = el('p'); line.appendChild(sevBadge(a.severity.band)); m.appendChild(line);
  if (a.description) m.appendChild(el('p', { text: a.description }));
  var sec = function (key, node) { var s = el('section', { class: 'panel' }); s.appendChild(el('h3', { 'data-t': key, text: t(key) })); s.appendChild(node); m.appendChild(s); };
  sec('a_ids', dl([['CVE', a.ids.cve.join(', ') || null], ['EUVD', a.ids.euvd.join(', ') || null], ['GHSA', a.ids.ghsa.join(', ') || null], [t('r_type'), label('type_', a.alert_type)], [t('r_version'), a.record_version + ' · ' + String(a.record_hash).slice(0, 16) + '…']]));
  sec('a_severity', dl([['CVSS', a.severity.score ? a.severity.score + ' (' + (a.severity.version || '?') + ')' : t('r_unknown')], [t('r_sources'), a.severity.rated_by.join(', ') || null], ['vector', a.severity.vector], ['EPSS', a.epss ? short(a.epss.by_source) : null]]));
  var exRows = Object.keys(a.exploitation.per_source).sort().map(function (s) { var e = a.exploitation.per_source[s]; return [s, e.asserted, e.since, e.basis]; });
  var exNode = el('div'); exNode.appendChild(table(t('a_exploitation'), [t('a_source'), t('a_asserted'), t('a_since'), t('a_basis')], exRows));
  exNode.appendChild(el('p', { class: 'muted', text: t('a_independent') + ': ' + a.exploitation.independent_confirmation + ' — ' + a.exploitation.note })); sec('a_exploitation', exNode);
  sec('a_affected', a.affected.length ? table(t('a_affected'), [t('a_product'), t('a_versions'), t('a_os'), t('r_sources')], a.affected.map(function (r) { return [(r.vendor + ' ' + r.product).trim(), r.versions.map(function (v) { return v.raw; }).join(' · ') || null, r.os.join(', ') || null, r.sources.join(', ')]; })) : val(t('a_none_stated')));
  sec('r_fix', a.fix.available ? table(t('r_fix'), [t('a_product'), 'fixed_in', t('a_source')], a.fix.details.map(function (f) { return [(f.vendor || '') + ' ' + (f.product || ''), f.fixed_in, f.source]; })) : val(t('r_fix_unknown')));
  sec('a_mitig', val(a.mitigations && a.mitigations.length ? a.mitigations.join('; ') : t('a_none_stated')));
  sec('a_dates', dl([[t('r_published'), a.dates.published], [t('r_updated'), a.dates.updated], ['UTC', a.first_ingested_utc]]));
  if (a.discrepancies.length) { var ul = el('ul', { class: 'dl' }); a.discrepancies.forEach(function (d) { ul.appendChild(el('li', { text: d.field + ': ' + short(d.values) })); }); sec('a_discrepancies', ul); }
  var obsNode = el('div');
  Object.keys(a.observations).sort().forEach(function (s) {
    var o = a.observations[s], box = el('details', { open: 'open' }); box.appendChild(el('summary', { text: s }));
    box.appendChild(dl([[t('a_file'), o.evidence.file], [t('a_locator'), o.evidence.locator], [t('a_hash'), o.evidence.file_sha256], [t('r_published'), o.dates.published], [t('r_severity'), o.severity ? o.severity.score : null]]));
    if (o.summary) box.appendChild(el('p', { class: 'muted', text: o.summary })); obsNode.appendChild(box);
  });
  sec('a_obs', obsNode);
  var refs = el('ul', { class: 'dl' }); a.references.forEach(function (u) { var li = el('li'); li.appendChild(/^https?:\/\//.test(u) ? link(u) : txt(u)); refs.appendChild(li); }); sec('a_refs', a.references.length ? refs : val(null));
  var lic = Object.keys(a.license.sources).sort().map(function (s) { var l = a.license.sources[s]; return [s, l.license, l.redistribution_status, l.attribution]; });
  var licNode = el('div'); licNode.appendChild(table(t('a_license'), [t('a_source'), t('so_license'), t('so_redistribution'), t('so_note')], lic)); if (a.license.withheld_sources) licNode.appendChild(el('p', { class: 'muted', text: a.license.withheld_sources + ' ' + t('a_withheld') })); sec('a_license', licNode);
  sec('a_validation', dl([[t('dl_state'), a.validation.state], [t('a_basis'), a.validation.problems.join('; ') || null]]));
}
function alertPage() {
  var id = new URLSearchParams(location.search).get('id') || '';
  var found = (S.snapshot.alerts || []).filter(function (a) { return a.alert_id === id; })[0];
  if (found) { renderAlert(found); return Promise.resolve(); }
  if (S.backend && /^MGA-[0-9a-f]{20}$/.test(id)) return api('GET', '/api/v1/alerts/' + id).then(function (r) { if (r.status === 200) renderAlert(r.data.alert); else mount('alert').appendChild(el('p', { class: 'notice', text: t('a_notfound') })); });
  mount('alert').appendChild(el('p', { class: 'notice', text: t('a_notfound') }));
  return Promise.resolve();
}

/* ---------------------------------------------------------------- sources */
function sourcesPage() {
  var rows = (S.sources.sources || []).map(function (s) {
    var fr = s.freshness ? (s.freshness.state ? label('st_', s.freshness.state === 'never-imported' ? 'never' : s.freshness.state) + (s.freshness.age_days !== null && s.freshness.age_days !== undefined ? ' (' + s.freshness.age_days + ' d)' : '') : null) : null;
    return [s.id + (s.name ? ' — ' + s.name : ''), label('st_', s.operational_state), s.region, s.endpoint, s.format, s.update_expectation_days, s.license, s.redistribution_status, s.owner_confirmed, s.publishable,
      fr, s.freshness ? s.freshness.alerts : null, (s.blocking_reasons || []).join('; ') || null, s.note];
  });
  mount('sources').appendChild(table(t('h_sources'), [t('so_name'), t('so_state'), t('so_region'), t('so_endpoint'), t('so_format'), t('so_freq'), t('so_license'), t('so_redistribution'), t('so_owner'), t('so_publishable'), t('so_fresh'), t('so_alerts'), t('so_blocking'), t('so_note')], rows));
  var lg = mount('legend'); ['so_legend_active', 'so_legend_stale', 'so_legend_implemented', 'so_legend_pending', 'so_legend_blocked'].forEach(function (k) { lg.appendChild(el('li', { 'data-t': k, text: t(k) })); });
}

/* ---------------------------------------------------------------- create / edit a subscription */
function previewNow() {
  var spec = S.builder.read(); if (!spec) return;
  function show(items, how) {
    var pv = mount('pv-results'); items.slice(0, 20).forEach(function (x) { pv.appendChild(alertCard(x.a, x.reasons)); });
    MG.$('pv-count').textContent = items.length + ' ' + t('sb_preview_count') + ' · ' + t(how === 'server' ? 'sb_preview_source_server' : 'sb_preview_source_static');
    MG.$('sb-json').textContent = JSON.stringify(spec, null, 1);
  }
  if (S.backend) {
    api('POST', '/api/v1/alerts/search', { filter: spec, limit: 20 }).then(function (r) {
      if (r.status !== 200) { status('pv-count', errText(r), true); return; }
      show(r.data.items.map(function (a) { return { a: a, reasons: a.match_reasons }; }), 'server');
    });
  } else show(evalSnapshot(spec), 'static');
}
function fillSelect(sel, items, labelFn, withEmpty) {
  clear(sel); if (withEmpty) sel.appendChild(el('option', { value: '', text: '—' }));
  items.forEach(function (i) { sel.appendChild(el('option', { value: i.value, text: i.text })); }); return sel;
}
function subscribePage() {
  var ui = MG.$('filter-ui'); S.builder = buildFilterUi(ui);
  var scope = MG.$('sb-scope'), org = MG.$('sb-org'), unit = MG.$('sb-unit'), grp = MG.$('sb-group'), cust = MG.$('sb-customer');
  var orgs = (S.me && S.me.organizations) || [];
  var scopes = ['PERSONAL'].concat(orgs.length ? ['ORGANIZATION', 'ORGANIZATION_UNIT', 'DEVICE_GROUP', 'MSP_CUSTOMER'] : []);
  fillSelect(scope, scopes.map(function (s) { return { value: s, text: t('scope_' + s) }; }));
  function applyScope() {
    var s = scope.value; MG.$('sb-org-l').hidden = s === 'PERSONAL'; MG.$('sb-unit-l').hidden = s !== 'ORGANIZATION_UNIT'; MG.$('sb-group-l').hidden = s !== 'DEVICE_GROUP'; MG.$('sb-customer-l').hidden = s !== 'MSP_CUSTOMER';
    var wanted = orgs.filter(function (o) { return s === 'MSP_CUSTOMER' ? o.kind === 'msp' : o.kind !== 'msp'; });
    fillSelect(org, wanted.map(function (o) { return { value: o.org_id, text: o.name + ' (' + label('role_', o.role) + ')' }; }));
    loadUnits();
  }
  function loadUnits() {
    if (!org.value || (scope.value !== 'ORGANIZATION_UNIT' && scope.value !== 'DEVICE_GROUP')) return;
    api('GET', '/api/v1/orgs/' + org.value + '/units').then(function (r) {
      if (r.status !== 200) return;
      fillSelect(unit, r.data.units.map(function (u) { return { value: u.unit_id, text: u.name }; })); fillSelect(grp, r.data.device_groups.map(function (g) { return { value: g.group_id, text: g.name }; }));
    });
  }
  scope.addEventListener('change', applyScope); org.addEventListener('change', loadUnits); applyScope();
  fillSelect(MG.$('sb-freq'), ['immediate', 'daily', 'weekly'].map(function (f) { return { value: f, text: t('freq_' + f) }; }));
  var nk = ['new', 'exploitation_added', 'exploitation_source_added', 'fix_available', 'severity_up', 'severity_down', 'scope_added', 'affected_changed', 'mitigation_added'];
  var nb = mount('sb-notify'), nkBoxes = {};
  nk.forEach(function (k) { var l = el('label', { class: 'check' }), c = el('input', { type: 'checkbox', value: k }); c.checked = ['new', 'exploitation_added', 'exploitation_source_added', 'fix_available', 'severity_up'].indexOf(k) >= 0; nkBoxes[k] = c; l.appendChild(c); l.appendChild(txt(' ')); l.appendChild(el('span', { 'data-t': 'nk_' + k, text: t('nk_' + k) })); nb.appendChild(l); });
  var chBox = mount('sb-channels'), chBoxes = {};
  function loadChannels() {
    clear(chBox); chBoxes = {};
    if (!S.backend || !S.me) { chBox.appendChild(el('span', { class: 'muted', text: t('be_needs') })); return Promise.resolve(); }
    return api('GET', '/api/v1/channels').then(function (r) {
      var ok = (r.data && r.data.channels || []).filter(function (c) { return c.state === 'active'; });
      if (!ok.length) { chBox.appendChild(el('span', { class: 'muted', 'data-t': 'sb_channels_none', text: t('sb_channels_none') })); return; }
      ok.forEach(function (c) { var l = el('label', { class: 'check' }), i = el('input', { type: 'checkbox', value: c.channel_id }); chBoxes[c.channel_id] = i; l.appendChild(i); l.appendChild(txt(' ' + c.kind + ' · ' + c.label)); chBox.appendChild(l); });
    });
  }
  function payload(state) {
    var spec = S.builder.read(); if (!spec) return null;
    var body = { name: MG.$('sb-name').value, scope: scope.value, filter: spec, frequency: MG.$('sb-freq').value, critical_immediate: MG.$('sb-critical').checked,
      notify_on: nk.filter(function (k) { return nkBoxes[k].checked; }), channel_ids: Object.keys(chBoxes).filter(function (k) { return chBoxes[k].checked; }) };
    if (state) body.state = state;
    if (scope.value !== 'PERSONAL') body.org_id = org.value;
    if (scope.value === 'ORGANIZATION_UNIT') body.unit_id = unit.value;
    if (scope.value === 'DEVICE_GROUP') body.group_id = grp.value;
    if (scope.value === 'MSP_CUSTOMER') body.customer_org_id = cust.value.trim();
    return body;
  }
  function save(state) {
    if (!S.backend || !S.me) { status('sb-status', t('be_needs'), true); return; }
    var body = payload(state); if (!body) return;
    var req = S.editing ? api('PATCH', '/api/v1/subscriptions/' + S.editing, { name: body.name, filter: body.filter, frequency: body.frequency, notify_on: body.notify_on, critical_immediate: body.critical_immediate, channel_ids: body.channel_ids })
                        : api('POST', '/api/v1/subscriptions', body);
    req.then(function (r) {
      if (r.status === 200 || r.status === 201) { S.editing = r.data.sub_id; status('sb-status', t('sb_saved') + ' ' + r.data.name); MG.$('sb-test').hidden = false; }
      else status('sb-status', errText(r), true);
    });
  }
  MG.$('sb-preview').addEventListener('click', previewNow);
  MG.$('sb-save-draft').addEventListener('click', function () { save('draft'); });
  MG.$('sb-save-active').addEventListener('click', function () { save(S.editing ? undefined : 'active'); });
  MG.$('sb-test').addEventListener('click', function () {
    api('POST', '/api/v1/subscriptions/' + S.editing + '/test', {}).then(function (r) { status('sb-status', r.status === 200 ? t('sb_test_done') + ' ' + JSON.stringify(r.data.results) : errText(r), r.status !== 200); });
  });
  loadChannels().then(function () {
    var id = new URLSearchParams(location.search).get('id');
    if (!id || !S.me) return;
    api('GET', '/api/v1/subscriptions/' + encodeURIComponent(id)).then(function (r) {
      if (r.status !== 200) { status('sb-status', errText(r), true); return; }
      var s = r.data; S.editing = s.sub_id; MG.$('sb-name').value = s.name; MG.$('sb-freq').value = s.frequency; MG.$('sb-critical').checked = s.critical_immediate;
      nk.forEach(function (k) { nkBoxes[k].checked = s.notify_on.indexOf(k) >= 0; }); Object.keys(chBoxes).forEach(function (k) { chBoxes[k].checked = s.channel_ids.indexOf(k) >= 0; });
      S.builder.load(s.filter); scope.value = s.scope; scope.disabled = true; MG.$('sb-test').hidden = false; status('sb-status', t('sb_editing') + ': ' + s.name);
      MG.$('sb-save-draft').hidden = true;
    });
  });
  MG.$('sb-json').textContent = JSON.stringify(S.builder.read() || {}, null, 1);
}

/* ---------------------------------------------------------------- my subscriptions */
function minePage() {
  var m = mount('mine'); if (!S.backend || !S.me) return;
  api('GET', '/api/v1/subscriptions').then(function (r) {
    clear(m);
    var top = el('p'); top.appendChild(link('subscribe.html', t('m_create'))); m.appendChild(top);
    var subs = (r.data && r.data.subscriptions) || [];
    if (!subs.length) { m.appendChild(el('p', { class: 'notice', text: t('m_none') })); return; }
    var ul = el('ul', { class: 'cardlist' });
    subs.forEach(function (s) {
      var li = el('li', { class: 'panel result' }); li.appendChild(el('h3', { text: s.name }));
      li.appendChild(dl([[t('m_state'), label('state_', s.state)], [t('m_scope'), t('scope_' + s.scope)], [t('m_freq'), t('freq_' + s.frequency)], [t('m_version'), String(s.filter_version)], [t('m_channels'), String(s.channel_ids.length)]]));
      var acts = el('div', { class: 'actions' });
      acts.appendChild(el('a', { class: 'button', href: 'subscribe.html?id=' + encodeURIComponent(s.sub_id), text: t('m_edit') }));
      acts.appendChild(btn('m_duplicate', function () { api('POST', '/api/v1/subscriptions/' + s.sub_id + '/duplicate', {}).then(minePage); }));
      acts.appendChild(btn(s.state === 'active' ? 'm_suspend' : 'm_resume', function () { api('POST', '/api/v1/subscriptions/' + s.sub_id + '/' + (s.state === 'active' ? 'suspend' : 'resume'), {}).then(minePage); }));
      var del = btn('m_delete', function () {
        clear(acts2); acts2.appendChild(btn('m_confirm_delete', function () { api('DELETE', '/api/v1/subscriptions/' + s.sub_id).then(minePage); }, null, 'danger')); acts2.appendChild(btn('m_cancel', function () { clear(acts2); acts2.appendChild(del); }));
        acts2.querySelector('button').focus();
      });
      var acts2 = el('span'); acts2.appendChild(del); acts.appendChild(acts2); li.appendChild(acts); ul.appendChild(li);
    });
    m.appendChild(ul);
  });
}

/* ---------------------------------------------------------------- history */
function historyPage() {
  if (!S.backend || !S.me) return;
  var sel = MG.$('hi-sub');
  function loadMatches(append) {
    var q = '?limit=20' + (sel.value ? '&sub_id=' + encodeURIComponent(sel.value) : '') + (MG.$('hi-unread').checked ? '&unread=true' : '') + (append && S.matchesBefore ? '&before=' + encodeURIComponent(S.matchesBefore) : '');
    api('GET', '/api/v1/matches' + q).then(function (r) {
      var m = MG.$('matches'); var box = MG.$('hi-list'); if (!append || !box) { clear(m); m.appendChild(el('div', { id: 'hi-list' })); box = MG.$('hi-list'); m.appendChild(el('div', { id: 'hi-more' })); }
      var items = (r.data && r.data.items) || [];
      if (!items.length && !append) { box.appendChild(el('p', { class: 'notice', text: t('hi_none') })); }
      items.forEach(function (x) {
        var d = el('article', { class: 'panel result' }); var h = el('h3'); h.appendChild(link('alert.html?id=' + encodeURIComponent(x.alert_id), x.key)); d.appendChild(h);
        d.appendChild(dl([[t('hi_sub'), x.sub_name], [t('hi_kind'), label('kind_', x.kind)], [t('hi_changes'), x.changes.join(', ')], [t('hi_when'), x.created_utc], [t('hi_acked'), x.acknowledged_utc]]));
        var det = el('details'); det.appendChild(el('summary', { text: t('r_why') })); var ul = el('ul', { class: 'dl' }); x.reasons.forEach(function (rr) { ul.appendChild(el('li', { text: reasonLine(rr) })); }); det.appendChild(ul); d.appendChild(det);
        var acts = el('div', { class: 'actions' });
        if (!x.read_utc) acts.appendChild(btn('hi_read', function () { api('POST', '/api/v1/matches/' + x.match_id + '/read', {}).then(function () { loadMatches(false); }); }));
        if (!x.acknowledged_utc) acts.appendChild(btn('hi_ack', function () { api('POST', '/api/v1/matches/' + x.match_id + '/ack', {}).then(function () { loadMatches(false); }); }));
        d.appendChild(acts); box.appendChild(d);
      });
      S.matchesBefore = r.data ? r.data.next_before : null;
      var more = MG.$('hi-more'); if (more) { clear(more); if (S.matchesBefore) more.appendChild(btn('more', function () { loadMatches(true); })); }
    });
  }
  api('GET', '/api/v1/subscriptions').then(function (r) {
    fillSelect(sel, ((r.data && r.data.subscriptions) || []).map(function (s) { return { value: s.sub_id, text: s.name }; }), null, true); loadMatches(false);
  });
  sel.onchange = function () { loadMatches(false); }; MG.$('hi-unread').onchange = function () { loadMatches(false); };
  api('GET', '/api/v1/deliveries').then(function (r) {
    var d = (r.data && r.data.deliveries) || [], box = mount('deliveries');
    if (!d.length) { box.appendChild(el('p', { class: 'notice', text: t('dl_none') })); return; }
    box.appendChild(table(t('h_deliveries'), [t('hi_when'), t('dl_mode'), t('dl_state'), t('dl_attempts'), t('dl_sent'), t('dl_error')],
      d.map(function (x) { return [x.created_utc, label('mode_', x.mode) + ' (' + x.matches + ')', label('dstate_', x.state), String(x.attempts), x.sent_utc, x.last_error]; })));
  });
}

/* ---------------------------------------------------------------- delivery preferences */
function prefsPage() {
  if (!S.backend || !S.me) return;
  MG.$('pf-lang').value = S.me.user.locale;
  MG.$('pf-lang').onchange = function () { api('PATCH', '/api/v1/me', { locale: MG.$('pf-lang').value }); };
  function loadChannels() {
    api('GET', '/api/v1/channels').then(function (r) {
      var box = mount('channels'), ch = (r.data && r.data.channels) || [];
      if (!ch.length) { box.appendChild(el('p', { class: 'notice', text: t('ch_none') })); return; }
      var ul = el('ul', { class: 'cardlist' });
      ch.forEach(function (c) {
        var li = el('li', { class: 'panel result' }); li.appendChild(el('h3', { text: c.label }));
        li.appendChild(dl([[t('ch_kind'), c.kind], [t('ch_address'), c.address], [t('ch_state'), c.state === 'pending' ? t('ch_pending') : c.state + (c.disabled_reason ? ' — ' + c.disabled_reason : '')]]));
        var acts = el('div', { class: 'actions' });
        if (c.state === 'active') acts.appendChild(btn('ch_test', function () { api('POST', '/api/v1/channels/' + c.channel_id + '/test', {}).then(function (rr) { status('ch-new', t('ch_test_result') + ' ' + JSON.stringify(rr.data), rr.status !== 200); }); }));
        if (c.kind === 'webhook' && c.state === 'active') acts.appendChild(btn('ch_rotate', function () { api('POST', '/api/v1/channels/' + c.channel_id + '/rotate-key', {}).then(function (rr) { if (rr.status === 200) showSecret(rr.data.secret); else status('ch-new', errText(rr), true); }); }));
        var holder = el('span'); var del = btn('ch_delete', function () {
          clear(holder); holder.appendChild(btn('ch_confirm_delete', function () { api('DELETE', '/api/v1/channels/' + c.channel_id).then(loadChannels); }, null, 'danger')); holder.appendChild(btn('m_cancel', function () { clear(holder); holder.appendChild(del); })); holder.querySelector('button').focus();
        }); holder.appendChild(del); acts.appendChild(holder); li.appendChild(acts); ul.appendChild(li);
      });
      box.appendChild(ul);
    });
  }
  function showSecret(s) { var b = mount('ch-new'); b.className = 'notice'; b.appendChild(el('p', { text: t('ch_secret') })); b.appendChild(el('code', { class: 'cmd', text: s })); }
  MG.$('ch-email-add').onclick = function () {
    api('POST', '/api/v1/channels', { kind: 'email', address: MG.$('ch-email').value, locale: MG.$('ch-email-lang').value }).then(function (r) {
      status('ch-new', r.status === 201 ? t('ch_pending') : errText(r), r.status !== 201); if (r.status === 201) { MG.$('ch-email').value = ''; loadChannels(); }
    });
  };
  MG.$('ch-hook-add').onclick = function () {
    api('POST', '/api/v1/channels', { kind: 'webhook', url: MG.$('ch-url').value }).then(function (r) { if (r.status === 201) { MG.$('ch-url').value = ''; showSecret(r.data.secret); loadChannels(); } else status('ch-new', errText(r), true); });
  };
  function loadTokens() {
    api('GET', '/api/v1/feed-tokens').then(function (r) {
      var box = mount('tokens'), tk = (r.data && r.data.tokens) || [];
      if (!tk.length) { box.appendChild(el('p', { class: 'notice', text: t('tk_none') })); return; }
      box.appendChild(table(t('h_tokens'), [t('tk_name'), t('tk_created'), t('tk_expiry'), t('tk_last'), t('tk_uses'), ''], tk.map(function (x) {
        var cell = el('span');
        if (!x.revoked_utc) {
          cell.appendChild(btn('tk_rotate', function () { api('POST', '/api/v1/feed-tokens/' + x.token_id + '/rotate', {}).then(function (rr) { showUrl(rr); loadTokens(); }); }));
          cell.appendChild(btn('tk_revoke', function () { api('POST', '/api/v1/feed-tokens/' + x.token_id + '/revoke', {}).then(loadTokens); }));
        } else cell.appendChild(txt(t('tk_revoked')));
        return [x.label, x.created_utc, x.expires_utc, x.last_used_utc, String(x.use_count), cell];
      })));
    });
  }
  function showUrl(r) { var b = mount('tk-new'); if (r.status !== 201) { b.className = 'badmsg'; b.textContent = errText(r); return; } b.className = 'notice'; b.appendChild(el('p', { text: t('tk_url') })); b.appendChild(el('code', { class: 'cmd', text: r.data.feed_url })); b.appendChild(el('p', { class: 'badmsg', text: t('tk_warn') })); }
  MG.$('tk-add').onclick = function () { api('POST', '/api/v1/feed-tokens', { label: MG.$('tk-label').value, expires_days: parseInt(MG.$('tk-days').value, 10) || 90 }).then(function (r) { showUrl(r); loadTokens(); }); };
  MG.$('pv-export').onclick = function () {
    api('GET', '/api/v1/me/export').then(function (r) {
      var url = URL.createObjectURL(new Blob([r.text], { type: 'application/json' })), a = el('a', { href: url, download: 'macguard-export.json' }); document.body.appendChild(a); a.click(); document.body.removeChild(a); setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    });
  };
  MG.$('pv-erase').onclick = function () {
    api('POST', '/api/v1/me/erase', { confirm: MG.$('pv-erase-text').value }).then(function (r) { status('pv-status', r.status === 200 ? 'OK' : errText(r), r.status !== 200); if (r.status === 200) { S.me = null; S.csrf = null; authPanel(function () {}); } });
  };
  loadChannels(); loadTokens();
}

/* ---------------------------------------------------------------- organisations */
function orgPage() {
  if (!S.backend) return;
  var mfa = mount('mfa-body');
  if (S.me) {
    if (S.me.mfa_enabled && S.me.mfa_verified) mfa.appendChild(el('p', { class: 'muted', text: t('au_mfa_on') }));
    else if (S.me.mfa_enabled) mfa.appendChild(el('p', { class: 'notice', text: t('mfa_need') }));
    else {
      var out = el('div'); mfa.appendChild(btn('mfa_enroll', function () {
        api('POST', '/api/v1/auth/mfa/enroll', {}).then(function (r) {
          if (r.status !== 200) return; clear(out); out.appendChild(el('p', { text: t('mfa_secret') })); out.appendChild(el('code', { class: 'cmd', text: r.data.secret }));
          var f = el('div', { class: 'fields' }), inp = el('input', { id: 'mfa-code', type: 'text', inputmode: 'numeric', maxlength: '6', autocomplete: 'one-time-code' }); f.appendChild(labelled('mfa_code', inp));
          f.appendChild(btn('mfa_confirm', function () { api('POST', '/api/v1/auth/mfa/confirm', { code: inp.value }).then(function (rr) { clear(out); out.appendChild(el('p', { class: rr.status === 200 ? 'muted' : 'badmsg', text: rr.status === 200 ? t('mfa_done') : errText(rr) })); if (rr.status === 200) { S.me = null; S.csrf = null; authPanel(orgPage); } }); }));
          out.appendChild(f);
        });
      })); mfa.appendChild(out);
    }
  }
  var orgs = (S.me && S.me.organizations) || [], pick = MG.$('og-pick');
  fillSelect(pick, orgs.map(function (o) { return { value: o.org_id, text: o.name }; }));
  fillSelect(MG.$('mb-role'), ['administrator', 'security_manager', 'auditor', 'operator', 'viewer', 'owner'].map(function (r) { return { value: r, text: label('role_', r) }; }));
  fillSelect(MG.$('msp-role'), ['security_manager', 'operator', 'viewer', 'auditor'].map(function (r) { return { value: r, text: label('role_', r) }; }));
  MG.$('og-add').onclick = function () { api('POST', '/api/v1/orgs', { name: MG.$('og-name').value, kind: MG.$('og-kind').value }).then(function (r) { status('og-status', r.status === 201 ? 'OK' : errText(r), r.status !== 201); if (r.status === 201) loadMe().then(orgPage); }); };
  function current() { return pick.value; }
  function refresh() {
    var oid = current(), info = mount('og-info'); if (!oid) { info.appendChild(el('p', { class: 'notice', text: t('og_none') })); return; }
    var me = orgs.filter(function (o) { return o.org_id === oid; })[0];
    info.appendChild(dl([[t('og_role'), label('role_', me.role)], [t('og_perms'), me.permissions.join(', ')], ['id', oid]]));
    api('GET', '/api/v1/orgs/' + oid + '/members').then(function (r) {
      var box = mount('members'); if (r.status !== 200) { box.appendChild(el('p', { class: 'muted', text: errText(r) })); return; }
      box.appendChild(table(t('h_members'), [t('mb_email'), t('og_role'), t('mb_since'), ''], r.data.members.map(function (x) {
        var cell = el('span'); cell.appendChild(btn('mb_remove', function () { api('DELETE', '/api/v1/orgs/' + oid + '/members/' + x.membership_id).then(function (rr) { status('og-status', rr.status === 200 ? 'OK' : errText(rr), rr.status !== 200); refresh(); }); })); return [x.email, label('role_', x.role), x.created_utc, cell];
      })));
    });
    api('GET', '/api/v1/orgs/' + oid + '/units').then(function (r) {
      var box = mount('units'); if (r.status !== 200) { box.appendChild(el('p', { class: 'muted', text: errText(r) })); return; }
      box.appendChild(dl([[t('un_units'), r.data.units.map(function (u) { return u.name + ' (' + u.unit_id + ')'; }).join('; ') || t('un_none')], [t('un_groups'), r.data.device_groups.map(function (g) { return g.name + ' (' + g.group_id + ')'; }).join('; ') || t('un_none')]]));
      fillSelect(MG.$('un-parent'), r.data.units.map(function (u) { return { value: u.unit_id, text: u.name }; }), null, true); fillSelect(MG.$('mb-unit'), r.data.units.map(function (u) { return { value: u.unit_id, text: u.name }; }), null, true);
    });
    api('GET', '/api/v1/orgs/' + oid + '/audit?limit=50').then(function (r) {
      var box = mount('audit'); if (r.status !== 200) { box.appendChild(el('p', { class: 'muted', text: errText(r) })); return; }
      box.appendChild(el('p', { class: 'muted', text: t('au_chain') + ': ' + t(r.data.chain ? 'yes' : 'no') }));
      box.appendChild(table(t('h_audit'), [t('au_when'), t('au_actor'), t('au_action'), t('au_target')], r.data.entries.map(function (e) { return [e.at, e.actor_user_id, e.action, e.target]; })));
    });
  }
  pick.onchange = refresh;
  MG.$('mb-add').onclick = function () { api('POST', '/api/v1/orgs/' + current() + '/members', { email: MG.$('mb-email').value, role: MG.$('mb-role').value, unit_id: MG.$('mb-unit').value || undefined }).then(function (r) { status('og-status', r.status === 201 ? 'OK' : errText(r), r.status !== 201); refresh(); }); };
  MG.$('un-add-unit').onclick = function () { api('POST', '/api/v1/orgs/' + current() + '/units', { name: MG.$('un-name').value, parent_unit_id: MG.$('un-parent').value || undefined }).then(function (r) { status('og-status', r.status === 201 ? 'OK' : errText(r), r.status !== 201); refresh(); }); };
  MG.$('un-add-group').onclick = function () { api('POST', '/api/v1/orgs/' + current() + '/units', { type: 'device_group', name: MG.$('un-name').value, unit_id: MG.$('un-parent').value || undefined }).then(function (r) { status('og-status', r.status === 201 ? 'OK' : errText(r), r.status !== 201); refresh(); }); };
  function msp(act, body) { api('POST', '/api/v1/msp-links/' + act, body).then(function (r) { status('msp-status', r.status < 300 ? 'OK ' + (r.data && r.data.link_id ? r.data.link_id : '') : errText(r), r.status >= 300); }); }
  MG.$('msp-propose').onclick = function () { msp('propose', { msp_org_id: MG.$('msp-org').value.trim(), customer_org_id: MG.$('msp-cust').value.trim(), delegated_role: MG.$('msp-role').value }); };
  MG.$('msp-accept').onclick = function () { msp('accept', { customer_org_id: current(), link_id: MG.$('msp-link').value.trim() }); };
  MG.$('msp-end').onclick = function () { msp('end', { link_id: MG.$('msp-link').value.trim() }); };
  refresh();
}

/* ---------------------------------------------------------------- wiring */
var AUTH_PAGES = { subscribe: 1, mine: 1, history: 1, prefs: 1, org: 1 };
var RENDER = { index: explore, alert: alertPage, sources: sourcesPage, subscribe: subscribePage, mine: minePage, history: historyPage, prefs: prefsPage, org: orgPage };
function applyLang() {
  document.documentElement.lang = lang;
  document.querySelectorAll('[data-t]').forEach(function (e) { if (!e.hasAttribute('data-es')) e.setAttribute('data-es', e.textContent); var k = e.getAttribute('data-t'), v = lang === 'es' ? (D.es[k] !== undefined ? D.es[k] : e.getAttribute('data-es')) : D.en[k]; if (v !== undefined) e.textContent = v; });
  document.querySelectorAll('[data-t-label]').forEach(function (e) { var v = (D[lang] || {})[e.getAttribute('data-t-label')]; if (v !== undefined) e.setAttribute('aria-label', v); });
  document.title = t('t_' + page) + ' · MacGuard Security Intelligence'; renderBackend();
}
function renderPage() {
  var go = function () { try { if (page === 'subscribe') { subscribePage(); } else RENDER[page](); loaded(); } catch (e) { failure(e); } };
  if (AUTH_PAGES[page]) { authPanel(function () { renderPage(); }); }
  go();
}
function init() {
  var params = new URLSearchParams(location.search), sl = MG.$('lang');
  lang = params.get('lang') === 'en' || params.get('lang') === 'es' ? params.get('lang') : MG.lang();
  if (sl) { sl.value = lang; sl.addEventListener('change', function () { lang = sl.value; MG.setLang(lang); applyLang(); if (S.builder && S.builder.relabel) S.builder.relabel(); if (page !== 'subscribe' && page !== 'index') renderPage(); else if (page === 'index' && S.run) S.run(); }); }
  try { if (localStorage.getItem('theme') === 'dark') document.body.classList.add('dark'); } catch (e) { /* storage unavailable: default theme */ }
  if (params.get('theme') === 'dark') document.body.classList.add('dark'); else if (params.get('theme') === 'light') document.body.classList.remove('dark');
  var th = MG.$('theme'); if (th) th.addEventListener('click', function () { document.body.classList.toggle('dark'); try { localStorage.setItem('theme', document.body.classList.contains('dark') ? 'dark' : 'light'); } catch (e) { /* ignore */ } });
  applyLang();
  var needsStatic = page === 'index' || page === 'alert' || page === 'sources' || page === 'subscribe';
  detectBackend().then(function () { return loadMe(); }).then(function () { return needsStatic ? loadStatic().catch(function (e) { if (page !== 'subscribe') throw e; S.snapshot = { alerts: [] }; S.sources = { sources: [] }; }) : null; })
    .then(function () { applyLang(); renderPage(); }, function (e) { applyLang(); failure(e); });
  var apply = MG.$('f-apply'); if (apply) apply.addEventListener('click', function () { if (S.run) S.run(); });
  var reset = MG.$('f-reset'); if (reset) reset.addEventListener('click', function () { if (S.builder) { S.builder.reset(); if (S.run) S.run(); } });
}
init();
})();
