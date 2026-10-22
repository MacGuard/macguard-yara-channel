/* MacGuard Security Intelligence pages. Same-origin only: every fetch reads a static file under ../api/v1/. No framework, and no HTML is built from data (it is
   inserted as text), no storage except the language/theme preference that common.js already keeps. Badges are never written in the HTML:
   they are drawn here from the `status` field of the data files, which the generator copies from intel/status.py. */
(function () {
'use strict';
var MG = window.MG, D = window.INTEL_I18N, el = MG.el;
var page = document.body.getAttribute('data-page'), lang = 'es', cache = {}, data = {};
var KNOWN = { operational: '●', experimental: '◐', planned: '○' };   /* shape + text: colour is never the only carrier */

function t(k) { var l = D[lang] || {}; if (l[k] !== undefined) return l[k]; return D.es[k] !== undefined ? D.es[k] : k; }
function get(p) { if (!cache[p]) cache[p] = MG.get('../api/v1/' + p, true); return cache[p]; }
function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }
function txt(s) { return document.createTextNode(s); }
function na() { return el('span', { class: 'muted', text: t('na') }); }
function badge(s) {
  var known = KNOWN[s] !== undefined;
  var b = el('span', { class: 'badge st-' + (known ? s : 'unknown') });
  b.appendChild(el('span', { 'aria-hidden': 'true', text: known ? KNOWN[s] : '?' }));
  b.appendChild(txt(' ' + (known ? t('st_' + s) : String(s))));
  return b;
}
function code(s) { return el('code', { class: 'cmd', text: s }); }
function list(items) { var u = el('ul', { class: 'dl' }); items.forEach(function (i) { var li = el('li'); li.appendChild(typeof i === 'string' ? txt(i) : i); u.appendChild(li); }); return u; }
function fmt(n) { return typeof n === 'number' ? n.toLocaleString(lang === 'es' ? 'es-ES' : 'en-US') : String(n); }
function val(v) { if (v === null || v === undefined || v === '') return na(); if (typeof v === 'boolean') return txt(v ? t('yes') : t('no')); if (typeof v === 'number') return txt(fmt(v)); return typeof v === 'string' ? txt(v) : v; }
function dl(rows) {
  var d = el('dl', { class: 'facts' });
  rows.forEach(function (r) { d.appendChild(el('dt', { text: r[0] })); var dd = el('dd', r[2] ? { class: 'mono' } : {}); dd.appendChild(val(r[1])); d.appendChild(dd); });
  return d;
}
function link(href, text) { return el('a', { href: href, text: text || href }); }
function table(caption, heads, rows) {
  var w = el('div', { class: 'tablewrap', tabindex: '0', role: 'region', 'aria-label': caption });
  var tb = el('table', { style: 'min-width:' + (heads.length >= 3 ? heads.length * 140 : 0) + 'px' }), th = el('tr'), body = el('tbody');
  tb.appendChild(el('caption', { class: 'sr', text: caption }));
  heads.forEach(function (h) { th.appendChild(el('th', { scope: 'col', text: h })); });
  tb.appendChild(el('thead', {}, [th]));
  rows.forEach(function (r) {
    var tr = el('tr');
    r.forEach(function (c) {
      var td = el('td');
      if (c && c.mono !== undefined) { td.className = 'sha'; td.appendChild(val(c.mono)); } else td.appendChild(val(c));
      tr.appendChild(td);
    });
    body.appendChild(tr);
  });
  tb.appendChild(body); w.appendChild(tb); return w;
}
function mount(id) { var m = MG.$(id); if (m) clear(m); return m; }
function failure(e) { var m = MG.$('load-state'); if (m) { m.className = 'badmsg'; m.textContent = t('err_load') + ' ' + (e && e.message ? e.message : ''); } }
function loaded() { var m = MG.$('load-state'); if (m) { m.className = 'sr'; m.textContent = t('loaded'); } }
var built = {};
function once(key, fn) { if (built[key] !== lang) { fn(); built[key] = lang; } }
function stamp(doc) { return el('p', { class: 'muted', text: t('generated') + ' ' + doc.generated_at + ' · ' + t('origin') + ': ' + doc.data_origin }); }
function real(doc) { return el('p', { class: 'muted', text: t('real') + ': ' + doc.what_is_real }); }
function licLabel(k) { return k === 'no-spdx-terms-text' ? t('lic_nospdx') : k; }
function osLabel(k) { return k === '__none' ? t('os_none') : k; }
function srcLabel(k) { return k === '__none' ? t('none_listed') : k; }
function cardLink(id) { return link('artifacts.html#' + id, id); }
function jsonLink(path) { return link('../api/v1/' + path, 'api/v1/' + path); }

/* ---------------------------------------------------------------- overview */
function cov(k) { return t('cov_' + String(k).replace(/-/g, '_')); }
function legend() {
  var m = mount('legend'); if (!m) return;
  var d = el('dl', { class: 'facts' });
  ['operational', 'experimental', 'planned'].forEach(function (s) { var dt = el('dt'); dt.appendChild(badge(s)); d.appendChild(dt); d.appendChild(el('dd', { text: t('def_' + s) })); });
  m.appendChild(d);
}
var R = {};
R.overview = function () {
  var d = data.channels, m = mount('ov');
  if (!m) return;
  var tiles = el('div', { class: 'tiles' });
  ['operational', 'experimental', 'planned'].forEach(function (s) {
    var ti = el('div', { class: 'tile' });
    ti.appendChild(el('small', {}, [badge(s)])); ti.appendChild(el('strong', { text: fmt(d.counts_by_status[s]) }));
    ti.appendChild(el('small', { text: t('ov_of') + ' ' + fmt(d.channels.length) }));
    tiles.appendChild(ti);
  });
  m.appendChild(tiles);
  m.appendChild(stamp(d)); m.appendChild(real(d));
  var rows = d.channels.map(function (c) { return [c.id, badge(c.status), c.detail]; });
  m.appendChild(table(t('ov_cap'), [t('c_family'), t('c_status'), t('c_detail')], rows));
  legend();
};

/* ---------------------------------------------------------------- explorer */
var F = ['src', 'fam', 'lic', 'os', 'st'];
function sel(k) { return MG.$('f-' + k); }
function uniq(a) { var o = {}; a.forEach(function (x) { o[x] = 1; }); return Object.keys(o).sort(); }
function fill(select, values, label) {
  var keep = select.value; clear(select);
  select.appendChild(el('option', { value: '', text: t('all') }));
  values.forEach(function (v) { select.appendChild(el('option', { value: v, text: label(v) })); });
  if (values.indexOf(keep) >= 0) select.value = keep;
}
function matches(c, f) {
  var q = f.q.toLowerCase();
  if (q && (c.id + ' ' + c.family + ' ' + c.kind + ' ' + c.detail + ' ' + c.sources.join(' ') + ' ' + (c.engine || '')).toLowerCase().indexOf(q) < 0) return false;
  if (f.src && (f.src === '__none' ? c.sources.length : c.sources.indexOf(f.src) < 0)) return false;
  if (f.fam && c.family !== f.fam) return false;
  if (f.lic && (f.lic === '__none' ? c.licenses.length : c.licenses.indexOf(f.lic) < 0)) return false;
  if (f.os && (f.os === '__none' ? c.os.length : c.os.indexOf(f.os) < 0)) return false;
  if (f.st && c.status !== f.st) return false;
  return true;
}
R.explorer = function () {
  var d = data.channels, ch = d.channels;
  once('explorer', function () {
    fill(sel('src'), uniq(ch.reduce(function (a, c) { return a.concat(c.sources); }, [])).concat(['__none']), srcLabel);
    fill(sel('fam'), uniq(ch.map(function (c) { return c.family; })), function (v) { return v; });
    fill(sel('lic'), uniq(ch.reduce(function (a, c) { return a.concat(c.licenses); }, [])).concat(['__none']), function (v) { return v === '__none' ? t('none_listed') : licLabel(v); });
    fill(sel('os'), uniq(ch.reduce(function (a, c) { return a.concat(c.os); }, [])).concat(['__none']), osLabel);
    fill(sel('st'), ['operational', 'experimental', 'planned'].filter(function (s) { return ch.some(function (c) { return c.status === s; }); }), function (v) { return t('st_' + v); });
  });
  var f = { q: MG.$('f-q').value.trim() };
  F.forEach(function (k) { f[k] = sel(k).value; });
  var out = ch.filter(function (c) { return matches(c, f); }), ul = mount('results');
  out.forEach(function (c) {
    var li = el('li', { class: 'panel result' });
    var h = el('h3'); h.appendChild(txt(c.id + ' ')); h.appendChild(badge(c.status)); li.appendChild(h);
    li.appendChild(el('p', { class: 'muted', text: c.kind + (c.engine ? ' · ' + c.engine : '') }));
    li.appendChild(el('p', { text: c.detail }));
    li.appendChild(dl([
      [t('c_sources'), c.sources.length ? c.sources.join(', ') : t('none_listed')],
      [t('c_licenses'), c.licenses.length ? c.licenses.map(licLabel).join(', ') : t('none_listed')],
      [t('c_os'), c.os.length ? c.os.join(', ') : t('os_none')],
      [t('c_pub'), c.publication.text]]));
    if (c.cards.length) { var p = el('p'); p.appendChild(txt(t('cards') + ': ')); c.cards.forEach(function (id, i) { if (i) p.appendChild(txt(', ')); p.appendChild(cardLink(id)); }); li.appendChild(p); }
    ul.appendChild(li);
  });
  var n = MG.$('count'); n.textContent = out.length === 0 ? t('count_none') : fmt(out.length) + ' ' + t('count_of') + ' ' + fmt(ch.length) + ' ' + t('count_suffix');
};

/* ---------------------------------------------------------------- channels */
R.channels = function () {
  var d = data.channels, m = mount('ch');
  legend();
  m.appendChild(stamp(d)); m.appendChild(real(d));
  m.appendChild(table(t('ch_cap'), [t('c_family'), t('c_status'), t('c_type'), t('c_engine'), t('c_sources'), t('c_pub'), t('c_detail'), t('c_evidence')],
    d.channels.map(function (c) { return [c.id, badge(c.status), c.kind, c.engine || na(), c.sources.length ? c.sources.join(', ') : na(),
      c.publication.text + (c.publication.blocking_reasons ? ' \u2014 ' + c.publication.blocking_reasons.join('; ') : ''), c.detail, c.evidence]; })));
};

/* ---------------------------------------------------------------- artifact cards */
function renderCard(c) {
  var s = el('section', { class: 'panel card', id: c.id, 'aria-labelledby': 'h-' + c.id });
  var h = el('h2', { id: 'h-' + c.id }); h.appendChild(txt(c.id + ' ')); h.appendChild(badge(c.status)); s.appendChild(h);
  s.appendChild(el('p', { class: 'muted', text: c.status_detail })); s.appendChild(stamp(c)); s.appendChild(real(c));
  s.appendChild(el('h3', { text: t('k_identity') }));
  var idrows = [[t('k_channel'), c.channel + ' / ' + c.family], [t('k_version'), String(c.version)]];
  if (c.kind === 'legacy-channel') {
    var i = c.identity;
    idrows.push([t('k_published_at'), i.release_published_at], [t('k_engine'), i.engine], [t('k_log_size'), i.log_checkpoint_size], [t('k_log_root'), i.log_checkpoint_root, true],
      [t('k_cand'), fmt(c.latest_candidate.file_count) + ' ' + t('k_files') + ' (' + t('k_examined') + ' ' + fmt(c.latest_candidate.examined) + ', ' + t('k_quarantined') + ' ' + fmt(c.latest_candidate.quarantined) + ', ' + t('k_rejected') + ' ' + fmt(c.latest_candidate.rejected) + ')'],
      [t('k_rules_root'), c.latest_candidate.rules_root, true]);
  } else {
    idrows.push([t('k_created'), c.identity.created_at], [t('k_root'), c.identity.artifacts_root, true], [t('k_platforms'), c.identity.compatibility.platforms.join(', ')]);
  }
  s.appendChild(dl(idrows));
  s.appendChild(el('h3', { text: t('k_hashes') }));
  s.appendChild(table(t('k_hashes'), [t('k_path'), 'SHA-256', t('k_bytes'), t('k_origin'), t('k_role')],
    c.artifacts.map(function (a) { return [a.path, a.sha256 ? { mono: a.sha256 } : t('k_in_manifest'), a.bytes === null ? na() : fmt(a.bytes), t('origin_' + a.origin), a.role]; })));
  if (c.artifacts_note) s.appendChild(el('p', { class: 'muted', text: c.artifacts_note }));
  s.appendChild(el('h3', { text: t('k_source') }));
  (c.source ? [c.source] : c.sources).forEach(function (so) {
    var lic = so.license.spdx ? so.license.spdx + ' — ' + so.license.name : so.license.name;
    s.appendChild(dl([[t('k_source'), so.name + ' (' + so.id + ')'], [t('k_license'), lic], [t('k_redistribution'), so.redistribution_status],
      [t('k_owner_confirmed'), so.owner_confirmed === undefined ? null : so.owner_confirmed], [t('k_attribution'), so.attribution], [t('k_upstream'), link(so.upstream_url)]]));
  });
  if (c.retrieval) {
    var r = c.retrieval;
    s.appendChild(el('h3', { text: t('k_retrieval') }));
    s.appendChild(dl([[t('k_url'), link(r.url)], [t('k_retrieved_at'), r.retrieved_at], [t('k_http'), r.status], ['SHA-256', r.sha256, true], [t('k_bytes'), r.bytes], ['ETag', r.etag],
      ['Last-Modified', r.last_modified], [t('k_redistribution_then'), r.redistribution_status_at_retrieval]]));
    var kn = c.build.key_numbers, rows = Object.keys(kn).sort().map(function (k) { return [k, kn[k]]; });
    s.appendChild(el('h3', { text: t('k_build') })); s.appendChild(dl(rows));
  }
  s.appendChild(el('h3', { text: t('k_approval') }));
  var ap = c.approval;
  s.appendChild(dl([[t('k_state'), ap.state], [t('k_publishable'), ap.publishable]]));
  if (ap.blocking_reasons && ap.blocking_reasons.length) { s.appendChild(el('p', { text: t('k_blocking') + ':' })); s.appendChild(list(ap.blocking_reasons)); }
  if (ap.open_item) s.appendChild(el('p', { class: 'muted', text: ap.open_item }));
  s.appendChild(el('h3', { text: t('k_signature') })); s.appendChild(el('p', { text: c.signature.text }));
  s.appendChild(el('h3', { text: t('k_attestation') })); s.appendChild(el('p', { text: c.attestation.text }));
  s.appendChild(el('h3', { text: t('k_tests') }));
  s.appendChild(list(c.tests.map(function (x) { return x.file + ' — ' + fmt(x.test_functions) + ' ' + t('k_test_fn') + (x.what_it_says ? ': ' + x.what_it_says : ''); })));
  if (c.tests_note) s.appendChild(el('p', { class: 'muted', text: c.tests_note }));
  s.appendChild(el('h3', { text: t('k_download') }));
  var dw = c.download; s.appendChild(el('p', { class: dw.published ? '' : 'notice', text: dw.text }));
  if (dw.release_url) s.appendChild(el('p', {}, [link(dw.release_url)]));
  if (dw.upstream_note) s.appendChild(el('p', { class: 'muted', text: dw.upstream_note }));
  s.appendChild(el('h3', { text: t('k_verify') }));
  s.appendChild(list(c.verify_independently.map(function (v) {
    var li = el('span'); li.appendChild(txt(v.step + ': ')); li.appendChild(code(v.command));
    if (v.expect) li.appendChild(el('span', { class: 'muted', text: ' → ' + t('k_expect') + ': ' + v.expect }));
    if (v.caveat) li.appendChild(el('span', { class: 'muted', text: ' (' + v.caveat + ')' }));
    return li; })));
  var p = el('p'); p.appendChild(txt(t('k_card_json') + ': ')); p.appendChild(jsonLink('cards/' + c.id + '.json')); s.appendChild(p);
  return s;
}
R.artifacts = function () {
  var m = mount('cards'), cards = data.cards;
  var toc = el('ul', { class: 'dl' });
  cards.forEach(function (c) { var li = el('li'); li.appendChild(cardLink(c.id)); li.appendChild(txt(' ')); li.appendChild(badge(c.status)); toc.appendChild(li); });
  m.appendChild(toc);
  cards.forEach(function (c) { m.appendChild(renderCard(c)); });
  if (location.hash) { var e = MG.$(location.hash.slice(1)); if (e && e.scrollIntoView) e.scrollIntoView(); }
};

/* ---------------------------------------------------------------- downloads */
R.downloads = function () {
  var yl = data.cards.filter(function (c) { return c.id === 'yara-legacy'; })[0], m = mount('dl-yara');
  m.appendChild(el('p', { text: yl.download.text }));
  var base = '../', files = yl.download.site_files;
  m.appendChild(list(files.map(function (f) { return link(base + f, f); })));
  m.appendChild(el('p', { class: 'muted', text: yl.download.site_files_note }));
  m.appendChild(el('p', {}, [link(yl.download.release_url)]));
  m.appendChild(el('h3', { text: t('k_verify') }));
  m.appendChild(list(yl.verify_independently.map(function (v) { var s = el('span'); s.appendChild(txt(v.step + ': ')); s.appendChild(code(v.command)); if (v.expect) s.appendChild(el('span', { class: 'muted', text: ' (' + v.expect + ')' })); return s; })));
  var n = mount('dl-new');
  n.appendChild(table(t('dl_new_cap'), [t('c_family'), t('c_status'), t('c_pub'), t('c_blocking')],
    data.channels.channels.filter(function (c) { return c.status !== 'operational'; }).map(function (c) {
      return [c.id, badge(c.status), c.publication.text, c.publication.blocking_reasons ? c.publication.blocking_reasons.join('; ') : na()]; })));
  var x = mount('dl-meta'), idx = data.index;
  x.appendChild(stamp(idx));
  x.appendChild(table(t('dl_meta_cap'), [t('k_path'), 'SHA-256', t('c_detail')], idx.files.map(function (f) { return [jsonLink(f.path), { mono: f.sha256 }, f.description]; })));
};

/* ---------------------------------------------------------------- provenance */
R.provenance = function () {
  var d = data.provenance, b = mount('pv-status');
  var p = el('p'); p.appendChild(badge(d.status)); p.appendChild(txt(' ' + d.status_basis + '. ' + d.mgctl_command + '.')); b.appendChild(p); b.appendChild(stamp(d)); b.appendChild(real(d));
  var f = mount('pv-facts');
  f.appendChild(table(t('pv_facts_cap'), [t('pv_field'), t('pv_question'), t('pv_values')], d.six_facts.map(function (x) { return [x.field, x.question, x.values]; })));
  var r = mount('pv-rules');
  r.appendChild(table(t('pv_rules_cap'), [t('pv_rule_id'), t('pv_rule'), t('pv_consequence')], d.hard_rules.map(function (x) { return [x.id, x.rule, x.consequence]; })));
  once('provenance', function () {
    fill(MG.$('pv-grp'), uniq(d.coverage.managers.map(function (x) { return x.group; })), function (v) { return v; });
    fill(MG.$('pv-cov'), uniq(d.coverage.managers.map(function (x) { return x.coverage; })), function (v) { return cov(v); });
  });
  var g = MG.$('pv-grp').value, cv = MG.$('pv-cov').value;
  var rows = d.coverage.managers.filter(function (x) { return (!g || x.group === g) && (!cv || x.coverage === cv); });
  var cm = mount('pv-cov-table');
  cm.appendChild(table(t('pv_cov_cap'), [t('pv_group'), t('pv_manager'), t('pv_coverage'), t('pv_engine')], rows.map(function (x) { return [x.group, x.name, cov(x.coverage), t('eng_' + x.engine.replace(/-/g, '_'))]; })));
  MG.$('pv-count').textContent = fmt(rows.length) + ' ' + t('count_of') + ' ' + fmt(d.coverage.managers.length);
  var cnt = mount('pv-counts');
  Object.keys(d.coverage.counts).sort().forEach(function (k) { var ti = el('div', { class: 'tile' }); ti.appendChild(el('small', { text: cov(k) })); ti.appendChild(el('strong', { text: fmt(d.coverage.counts[k]) })); cnt.appendChild(ti); });
  var meaning = mount('pv-meaning');
  meaning.appendChild(list(Object.keys(d.coverage.meaning).sort().map(function (k) { return cov(k) + ': ' + d.coverage.meaning[k]; }).concat(Object.keys(d.coverage.engine_meaning).sort().map(function (k) { return t('eng_' + k.replace(/-/g, '_')) + ': ' + d.coverage.engine_meaning[k]; }))));
  var ec = mount('pv-engine-counts');
  Object.keys(d.coverage.engine_counts).sort().forEach(function (k) { var ti = el('div', { class: 'tile' }); ti.appendChild(el('small', { text: t('eng_' + k.replace(/-/g, '_')) })); ti.appendChild(el('strong', { text: fmt(d.coverage.engine_counts[k]) })); ec.appendChild(ti); });
  var sp = mount('pv-still'); sp.appendChild(el('p', { text: t('pv_collectors') + ': ' + Object.keys(d.engine_collectors).map(function (f) { return f + ' (' + d.engine_collectors[f].join(', ') + ')'; }).join('; ') + '. ' + fmt(d.engine_test_functions) + ' ' + t('k_test_fn') + '.' })); sp.appendChild(list(d.still_planned));
  var li = mount('pv-limits'); li.appendChild(list(d.limits));
};

/* ---------------------------------------------------------------- licences */
R.licenses = function () {
  var d = data.licenses, s = data.sources, m = mount('lic-top');
  m.appendChild(stamp(d)); m.appendChild(real(d));
  var cnt = mount('lic-counts');
  d.verdict_legend.forEach(function (k) { var ti = el('div', { class: 'tile' }); ti.appendChild(el('small', { text: k })); ti.appendChild(el('strong', { text: fmt(d.rows_by_verdict_class[k] || 0) })); cnt.appendChild(ti); });
  var rg = mount('lic-registry');
  rg.appendChild(table(t('lic_reg_cap'), [t('c_sources'), 'SPDX', t('k_license'), t('k_redistribution'), t('k_owner_confirmed'), t('lic_publishable')],
    s.sources.map(function (x) { return [x.id + ' — ' + x.name, x.license.spdx || na(), x.license.name, x.redistribution_status, x.owner_confirmed, x.clearance.publishable ? t('yes') : t('no') + ': ' + x.clearance.blocking_reasons.join('; ')]; })));
  once('licenses', function () { fill(MG.$('lic-v'), d.verdict_legend, function (v) { return v; }); });
  var v = MG.$('lic-v').value, q = MG.$('lic-q').value.trim().toLowerCase();
  var rows = d.matrix.filter(function (x) { return (!v || x.verdict_classes.indexOf(v) >= 0) && (!q || (x.source + ' ' + x.license_as_stated + ' ' + x.verdict).toLowerCase().indexOf(q) >= 0); });
  var mt = mount('lic-matrix');
  mt.appendChild(table(t('lic_mx_cap'), ['#', t('c_sources'), t('lic_stated'), t('lic_verdict')], rows.map(function (x) { return [String(x.n), x.source, x.license_as_stated, x.verdict]; })));
  MG.$('lic-count').textContent = fmt(rows.length) + ' ' + t('count_of') + ' ' + fmt(d.matrix.length);
};

/* ---------------------------------------------------------------- vulnerability sources */
var VN_ID = /^(CVE-(19|20)\d{2}-\d{4,}|EUVD-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3})$/;
function vnNorm(raw) { var s = String(raw || '').trim(); var u = s.toUpperCase(); if (/^GHSA-/.test(u)) u = 'GHSA' + s.slice(4).toLowerCase(); return VN_ID.test(u) ? u : null; }
function vnCard(c) {
  var m = mount('vn-card');
  m.appendChild(el('h3', { text: c.key }));
  m.appendChild(dl([['CVE', c.ids.cve.join(', ') || na()], ['EUVD', c.ids.euvd.join(', ') || na()], ['GHSA', c.ids.ghsa.join(', ') || na()]]));
  var rows = Object.keys(c.sources).sort().map(function (sid) {
    var s = c.sources[sid], e = c.exploitation[sid] || { asserted: false };
    var fixes = (s.fixes || []).map(function (f) { return f.product + ' ' + f.fixed_in; }).join('; ');
    return [sid + (s.region ? ' (' + s.region + ')' : ''), s.severity ? s.severity.score + ' ' + (s.severity.version || '') : na(),
      e.asserted ? t('yes') + (e.since ? ' \u00b7 ' + e.since : '') + ' \u2014 ' + e.basis : t('no'), fixes || na(), s.evidence ? s.evidence.file + ' ' + s.evidence.locator : na()];
  });
  m.appendChild(table(c.key, [t('vn_card_src'), t('vn_card_sev'), t('vn_card_expl'), t('vn_card_fix'), t('vn_card_ev')], rows));
}
function vnLookup() {
  var m = mount('vn-card'), id = vnNorm(MG.$('vn-id').value);
  if (!id) { m.appendChild(el('p', { class: 'badmsg', text: t('vn_bad_id') })); return; }
  get('vulns/' + id + '.json').then(function (c) { vnCard(c); }, function () { mount('vn-card').appendChild(el('p', { class: 'notice', text: t('vn_no_card') })); });
}
R.vulns = function () {
  var d = data.vulns, s = d.sources;
  once('vulns', function () {
    fill(MG.$('vn-region'), uniq(s.map(function (x) { return x.region; })), function (v) { return t('reg_' + v); });
    fill(MG.$('vn-integ'), uniq(s.map(function (x) { return x.integration; })), function (v) { return t('integ_' + v.replace(/-/g, '_')); });
  });
  var r = MG.$('vn-region').value, g = MG.$('vn-integ').value, q = MG.$('vn-q').value.trim().toLowerCase();
  var rows = s.filter(function (x) { return (!r || x.region === r) && (!g || x.integration === g) && (!q || (x.id + ' ' + x.name + ' ' + x.license_name).toLowerCase().indexOf(q) >= 0); });
  var m = mount('vn-sources');
  m.appendChild(stamp(d)); m.appendChild(real(d));
  m.appendChild(table(t('h_vn_sources'), [t('c_sources'), t('vn_region'), t('vn_integration'), t('k_license'), t('k_redistribution'), t('k_owner_confirmed'), t('lic_publishable'), t('vn_field'), t('vn_age')],
    rows.map(function (x) { return [x.id + ' \u2014 ' + x.name, t('reg_' + x.region), t('integ_' + x.integration.replace(/-/g, '_')), x.license_name, x.redistribution_status, x.owner_confirmed,
      x.publishable ? t('yes') : t('no') + ': ' + x.blocking_reasons.join('; '), x.exploitation_field, x.max_snapshot_age_days === null || x.max_snapshot_age_days === undefined ? na() : x.max_snapshot_age_days]; })));
  MG.$('vn-count').textContent = fmt(rows.length) + ' ' + t('count_of') + ' ' + fmt(s.length);
  var o = mount('vn-observed');
  o.appendChild(table(t('h_vn_observed'), [t('c_sources'), t('vn_retrieved'), t('vn_accepted'), t('vn_rejected'), t('vn_pages'), t('vn_complete'), t('vn_asserted'), t('c_pub')],
    d.observed.map(function (x) { return [x.source + ' \u2192 ' + x.channel, x.retrieved_at, x.accepted, x.rejected, x.pages, x.complete, x.exploitation_asserted === null || x.exploitation_asserted === undefined ? na() : x.exploitation_asserted, x.publishable ? t('yes') : t('no')]; })));
  var mm = mount('vn-merge');
  if (d.merge) {
    mm.appendChild(table(t('h_vn_merge'), [t('vn_combo'), t('vn_entries')], Object.keys(d.merge.entries_by_source_combination).sort().map(function (k) { return [k.replace(/\+/g, ' + '), d.merge.entries_by_source_combination[k]]; })));
    mm.appendChild(dl([[t('vn_conflicts'), d.merge.conflicts], [t('vn_reading'), d.merge.reading]]));
  } else mm.appendChild(na());
  var ru = mount('vn-rules'); ru.appendChild(list(d.rules.map(function (x) { return x.id + ': ' + x.rule; })));
  if (!MG.$('vn-card').firstChild) {
    var p = new URLSearchParams(location.search).get('id');
    if (p) { MG.$('vn-id').value = p; vnLookup(); } else mount('vn-card').appendChild(el('p', { class: 'muted', text: d.cards.published + ' ' + (d.cards.reason || '') }));
  }
};

/* ---------------------------------------------------------------- security */
R.security = function () {
  var m = mount('sec-sig');
  m.appendChild(table(t('sec_sig_cap'), [t('k_card'), t('k_signature'), t('k_attestation'), t('c_pub')],
    data.cards.map(function (c) { return [cardLink(c.id), c.signature.text, c.attestation.text, c.download.text]; })));
};

/* ---------------------------------------------------------------- roadmap */
R.roadmap = function () {
  var d = data.roadmap, m = mount('rm');
  m.appendChild(stamp(d)); m.appendChild(real(d));
  var byPhase = {}; d.rows.forEach(function (r) { byPhase[r.phase] = r; });
  d.tracks.forEach(function (tr) {
    var s = el('section', { class: 'panel', 'aria-labelledby': 'rm-' + tr.id });
    var h = el('h2', { id: 'rm-' + tr.id }); h.appendChild(txt(tr.name + ' ')); if (tr.status) h.appendChild(badge(tr.status)); s.appendChild(h);
    s.appendChild(el('p', { class: 'muted', text: t('source') + ': ' + tr.source }));
    if (tr.note) s.appendChild(el('p', { class: 'notice', text: tr.note }));
    if (tr.linux_provenance_phase) s.appendChild(dl([[tr.linux_provenance_phase.phase, tr.linux_provenance_phase.scope], [t('rm_why'), tr.linux_provenance_phase.justification]]));
    s.appendChild(table(tr.name, [t('rm_phase') + ' / ' + t('c_status'), t('rm_scope'), t('rm_done'), t('rm_missing'), t('rm_basis')],
      tr.items.map(function (i) { var r = byPhase[i], c = el('div'); c.appendChild(txt(r.phase)); c.appendChild(el('br')); c.appendChild(badge(r.status)); return [c, r.scope, r.done, r.missing, r.status_basis]; })));
    m.appendChild(s);
  });
};

/* ---------------------------------------------------------------- language, theme, wiring */
function applyLang() {
  document.documentElement.lang = lang;
  document.querySelectorAll('[data-t]').forEach(function (e) {
    if (!e.hasAttribute('data-es')) e.setAttribute('data-es', e.textContent);
    var k = e.getAttribute('data-t'), v = lang === 'es' ? (D.es[k] !== undefined ? D.es[k] : e.getAttribute('data-es')) : D.en[k];
    if (v !== undefined) e.textContent = v;
  });
  ['data-t-label:aria-label', 'data-t-ph:placeholder'].forEach(function (pair) {
    var a = pair.split(':');
    document.querySelectorAll('[' + a[0] + ']').forEach(function (e) { var k = e.getAttribute(a[0]); var v = lang === 'es' ? D.es[k] : D.en[k]; if (v !== undefined) e.setAttribute(a[1], v); });
  });
  document.querySelectorAll('a[data-doc]').forEach(function (a) { a.setAttribute('href', '../docs/' + lang + '/' + a.getAttribute('data-doc') + '.html'); });
  document.title = t('title_' + page) + ' · MacGuard Security Intelligence';
  if (data.ready) { try { R[page](); loaded(); } catch (e) { failure(e); } }
}
function init() {
  var params = new URLSearchParams(location.search), sl = MG.$('lang');
  lang = params.get('lang') === 'en' || params.get('lang') === 'es' ? params.get('lang') : MG.lang();   /* ?lang= and ?theme= are for previews and tests; they are not stored */
  if (sl) { sl.value = lang; sl.addEventListener('change', function () { lang = sl.value; MG.setLang(lang); applyLang(); }); }
  try { if (localStorage.getItem('theme') === 'dark') document.body.classList.add('dark'); } catch (e) { /* storage unavailable: default theme */ }
  if (params.get('theme') === 'dark') document.body.classList.add('dark'); else if (params.get('theme') === 'light') document.body.classList.remove('dark');
  var th = MG.$('theme'); if (th) th.addEventListener('click', function () { document.body.classList.toggle('dark'); try { localStorage.setItem('theme', document.body.classList.contains('dark') ? 'dark' : 'light'); } catch (e) { /* ignore */ } });
  var need = { overview: ['channels'], explorer: ['channels'], channels: ['channels'], artifacts: ['cards'], downloads: ['cards', 'channels', 'index'], provenance: ['provenance'],
    licenses: ['licenses', 'sources'], vulns: ['vulns'], security: ['cards'], roadmap: ['roadmap'] }[page] || [];
  var files = { channels: 'channels.json', index: 'index.json', provenance: 'provenance.json', licenses: 'licenses.json', sources: 'sources.json', vulns: 'vulns.json', roadmap: 'roadmap.json' };
  var jobs = need.map(function (k) {
    if (k === 'cards') return get('index.json').then(function (idx) { data.index = idx; return Promise.all(idx.files.filter(function (f) { return f.path.indexOf('cards/') === 0; }).map(function (f) { return get(f.path); })); }).then(function (c) { data.cards = c; });
    return get(files[k]).then(function (v) { data[k] = v; });
  });
  Promise.all(jobs).then(function () { data.ready = true; applyLang(); }, function (e) { applyLang(); failure(e); });
  ['f-q', 'f-src', 'f-fam', 'f-lic', 'f-os', 'f-st', 'pv-grp', 'pv-cov', 'lic-v', 'lic-q', 'vn-region', 'vn-integ', 'vn-q'].forEach(function (id) {
    var e = MG.$(id); if (e) e.addEventListener(e.tagName === 'INPUT' ? 'input' : 'change', function () { if (data.ready) R[page](); });
  });
  var vg = MG.$('vn-go'); if (vg) vg.addEventListener('click', function () { vnLookup(); });
  var rs = MG.$('f-reset'); if (rs) rs.addEventListener('click', function () { MG.$('f-q').value = ''; F.forEach(function (k) { sel(k).value = ''; }); R.explorer(); MG.$('f-q').focus(); });
  applyLang();
}
init();
})();
