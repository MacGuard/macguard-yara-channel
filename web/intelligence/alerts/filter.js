/* The subscription filter evaluator, in the browser. It is the same language as alerts/filters.py and must give the same answers:
   tests/fixtures/alerts/filter-vectors.json is run by BOTH (tests/test_alerts_filters.py and tests/alerts_filter_vectors.mjs).
   It only reads data: no eval, no regular expression built from input, no HTML. A filter that is not valid is refused, never "best effort". */
(function (root) {
'use strict';
var EU = ['AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE'];
var BANDS = ['unknown', 'none', 'low', 'medium', 'high', 'critical'];
var EXPOSURE = {
  'internet': ['network', 'unknown'], 'vpn': ['network', 'adjacent', 'unknown'], 'private-network': ['network', 'adjacent', 'unknown'],
  'internal-service': ['network', 'adjacent', 'local', 'unknown'], 'unknown': ['network', 'adjacent', 'local', 'physical', 'unknown']
};
var MAP_BASIS = 'curated-mapping:technology-map@1';

function slug(t) { return String(t === null || t === undefined ? '' : t).toLowerCase().replace(/[^a-z0-9.+]+/g, ' ').trim(); }
function regionMatches(wanted, scopes) {
  return scopes.some(function (s) {
    if (s === wanted) return true;
    if (wanted === 'EU' && (s === 'ES' || (s.indexOf('country:') === 0 && EU.indexOf(s.slice(8)) >= 0))) return true;
    if (wanted === 'ES' && s === 'country:ES') return true;
    if (wanted === 'OTHER' && s.indexOf('country:') === 0 && EU.indexOf(s.slice(8)) < 0) return true;
    return false;
  });
}
function bandAtLeast(b, min) { return b !== 'unknown' && BANDS.indexOf(b) >= BANDS.indexOf(min); }

/* generic dotted-version comparison: numeric components as numbers, trailing zeros insignificant (alerts/../versions.py compare) */
function split(v) { return String(v).split(/[.\-_+]/).map(function (tok) { var m = /^(\d*)(.*)$/.exec(tok); return [m[1] === '' ? -1 : parseInt(m[1], 10), m[2]]; }); }
function compare(a, b) {
  var pa = split(a), pb = split(b), n = Math.max(pa.length, pb.length);
  while (pa.length < n) pa.push([0, '']);
  while (pb.length < n) pb.push([0, '']);
  for (var i = 0; i < n; i++) {
    if (pa[i][0] !== pb[i][0]) return pa[i][0] < pb[i][0] ? -1 : 1;
    if (pa[i][1] !== pb[i][1]) return pa[i][1] < pb[i][1] ? -1 : 1;
  }
  return 0;
}
function inRange(version, p) {
  if (p.kind !== 'range') return null;
  if (compare(version, p.introduced) < 0) return false;
  if (p.fixed_in !== undefined) return compare(version, p.fixed_in) < 0;
  if (p.last_affected !== undefined) return compare(version, p.last_affected) <= 0;
  return true;
}

function R(field, op, expected, observed, basis, sources) { return { field: field, op: op, expected: expected, observed: observed === undefined ? null : observed, basis: basis === undefined ? null : basis, sources: sources || [] }; }
function uniq(a) { var o = {}, out = []; a.forEach(function (x) { if (!o[x]) { o[x] = 1; out.push(x); } }); return out; }
function sorted(a) { return a.slice().sort(); }
function normId(s) {
  var u = String(s).trim().toUpperCase();
  if (/^CVE-(19|20)\d{2}-\d{4,}$/.test(u) && parseInt(u.slice(4, 8), 10) >= 1999) return u;
  if (/^EUVD-\d{4}-\d{4,}$/.test(u)) return u;
  var g = String(s).trim().toLowerCase();
  if (/^ghsa(-[23456789cfghjmpqrvwx]{4}){3}$/.test(g)) return 'GHSA' + g.slice(4);
  return null;
}
function days(ms) { return ms / 86400000; }
function parseUtc(s) { return Date.parse(s.replace('Z', '.000Z')); }

function leaf(n, a, ctx) {
  var f = n.field, op = n.op, val = n.value, aff = a.affected || [], h, i;
  switch (f) {
    case 'region':
      var scopes = (a.region_scope || []).map(function (r) { return r.region; });
      return [val.some(function (w) { return regionMatches(w, scopes); }), [R(f, op, val, scopes.length ? scopes : null, 'source-scope', sorted(uniq((a.region_scope || []).map(function (r) { return r.source; }))))]];
    case 'sector':
      var have = (a.sectors || []).map(function (s) { return s.sector; });
      if (val.some(function (s) { return have.indexOf(s) >= 0; })) return [true, [R(f, op, val, have, 'source-stated')]];
      if (!have.length && n.include_unknown) return [true, [R(f, op, val, null, 'included because the subscription includes alerts with no sector information')]];
      return [false, [R(f, op, val, have.length ? have : null, have.length ? null : 'no sector information')]];
    case 'vendor': case 'product': case 'product_family':
      var want = val.map(slug), key = f === 'vendor' ? 'vendor_slug' : 'product_slug', hits = [];
      aff.forEach(function (r) {
        var t = r[key];
        if (want.some(function (w) { return f === 'product_family' ? (t === w || t.indexOf(w + ' ') === 0) : t === w; })) hits.push((r.vendor + ' ' + r.product).trim());
      });
      var srcs = sorted(uniq([].concat.apply([], aff.map(function (r) { return r.sources; }))));
      return [hits.length > 0, [R(f, op, val, hits.length ? hits : (aff.slice(0, 5).map(function (r) { return (r.vendor + ' ' + r.product).trim(); }).length ? aff.slice(0, 5).map(function (r) { return (r.vendor + ' ' + r.product).trim(); }) : null), aff.length ? 'affected products stated by the sources' : 'no affected product stated', srcs)]];
    case 'version':
      var wv = slug(val.vendor), wp = slug(val.product), ver = val.version, notes = [];
      for (i = 0; i < aff.length; i++) {
        var r = aff[i];
        if (r.vendor_slug !== wv || r.product_slug !== wp) continue;
        for (var j = 0; j < r.versions.length; j++) {
          var v = r.versions[j], p = v.kind === 'range' ? inRange(ver, v) : null;
          if (p === true) return [true, [R(f, op, val, v.raw, 'vendor version text (a range); not a distribution package check', r.sources)]];
          if (v.kind === 'single' && n.include_ambiguous && compare(ver, v.version) === 0) return [true, [R(f, op, val, v.raw, 'a single version the source does not call affected or fixed (included on request)', r.sources)]];
          notes.push(v.raw);
        }
      }
      return [false, [R(f, op, val, notes.length ? notes : null, notes.length ? 'no stated range contains this version' : 'the product has no stated version information')]];
    case 'os':
      var haveOs = sorted(uniq([].concat.apply([], aff.map(function (r) { return r.os; }))));
      return [val.some(function (o) { return haveOs.indexOf(o) >= 0; }), [R(f, op, val, haveOs.length ? haveOs : null, haveOs.length ? MAP_BASIS : 'no operating system could be established from the vendor and product names',
        sorted(uniq([].concat.apply([], aff.filter(function (r) { return r.os.some(function (o) { return val.indexOf(o) >= 0; }); }).map(function (r) { return r.sources; })))))]];
    case 'technology_category':
      var haveC = sorted(uniq([].concat.apply([], aff.map(function (r) { return r.categories; }))));
      return [val.some(function (c) { return haveC.indexOf(c) >= 0; }), [R(f, op, val, haveC.length ? haveC : null, haveC.length ? MAP_BASIS : 'no category in the curated map',
        sorted(uniq([].concat.apply([], aff.filter(function (r) { return r.categories.some(function (c) { return val.indexOf(c) >= 0; }); }).map(function (r) { return r.sources; })))))]];
    case 'service':
      var haveS = sorted(uniq([].concat.apply([], aff.map(function (r) { return r.services; })))), ws = val.map(slug);
      return [ws.some(function (c) { return haveS.indexOf(c) >= 0; }), [R(f, op, val, haveS.length ? haveS : null, haveS.length ? MAP_BASIS : 'no service in the curated map')]];
    case 'ecosystem':
      var haveE = sorted(uniq([].concat.apply([], aff.map(function (r) { return r.ecosystems || []; }))));
      return [val.some(function (c) { return haveE.indexOf(c) >= 0; }), [R(f, op, val, haveE.length ? haveE : null, haveE.length ? 'source-stated' : 'no source of this alert states an ecosystem')]];
    case 'id':
      var mine = [].concat(a.ids.cve || [], a.ids.euvd || [], a.ids.ghsa || []), wantIds = val.map(normId);
      return [wantIds.some(function (w) { return mine.indexOf(w) >= 0; }), [R(f, op, wantIds, mine.length ? mine : null, 'identifiers declared by the sources')]];
    case 'cvss':
      var sc = a.severity.score;
      if (sc === null || sc === undefined) return [false, [R(f, op, val, null, 'no source gives a CVSS score')]];
      return [op === 'gte' ? parseFloat(sc) >= val : parseFloat(sc) <= val, [R(f, op, val, sc, 'CVSS ' + (a.severity.version || '?') + ' rated by ' + a.severity.rated_by.join(', '), a.severity.rated_by)]];
    case 'epss':
      var e = (a.epss || {}).by_source || {}, ks = Object.keys(e);
      if (!ks.length) return [false, [R(f, op, val, null, 'no EPSS value from any source')]];
      var top = Math.max.apply(null, ks.map(function (k) { return parseFloat(e[k]); }));
      return [top >= val, [R(f, op, val, e, 'value as the source gives it; its unit is not documented by the source', sorted(ks))]];
    case 'severity':
      var b = a.severity.band;
      return [bandAtLeast(b, val), [R(f, op, val, b, b !== 'unknown' ? 'band of the highest CVSS base score given' : 'no CVSS score: severity unknown', a.severity.rated_by)]];
    case 'exploited':
      var ex = a.exploitation, stale = ctx.stale || [];
      var asserted = ex.asserted_by.filter(function (s) { return (!n.source || s === n.source) && stale.indexOf(s) < 0; });
      var staleHit = stale.filter(function (s) { return ex.asserted_by.indexOf(s) >= 0; });
      return [(asserted.length > 0) === val, [R(f, op, val, { asserted_by: asserted, since: ex.earliest_since }, 'structured exploitation field of each source' + (n.source ? ' (only ' + n.source + ')' : '') + (staleHit.length ? '; stale sources not counted: ' + sorted(staleHit).join(', ') : ''), asserted)]];
    case 'published': case 'updated':
      var d = a.dates[f];
      if (!d) return [false, [R(f, op, val, null, 'no ' + f + ' date stated')]];
      return [op === 'gte' ? d >= val : d <= val, [R(f, op, val, d, 'source date (UTC calendar day)')]];
    case 'ingested_within_days':
      var t = a.first_ingested_utc;
      if (!t) return [false, [R(f, op, val, null, 'no ingestion time')]];
      return [days(ctx.now - parseUtc(t)) <= val, [R(f, op, val, t, 'first time MacGuard ingested it (UTC)')]];
    case 'has_fix':
      var av = a.fix.available;
      return [val ? av === true : av !== true, [R(f, op, val, av, av ? 'fixed versions in the vendor text' : 'no fixed version stated (unknown, not \'no fix\')')]];
    case 'has_mitigation':
      var hm = !!(a.mitigations && a.mitigations.length);
      return [hm === val, [R(f, op, val, hm, a.mitigation_basis)]];
    case 'exposure':
      var vec = a.attack_vector || 'unknown', allowed = {};
      val.forEach(function (x) { EXPOSURE[x].forEach(function (y) { allowed[y] = 1; }); });
      return [!!allowed[vec], [R(f, op, val, vec, 'attack vector (AV) in the CVSS vector the source gave; exposure itself is set by you, not detected')]];
    case 'source':
      var obs = sorted(Object.keys(a.observations));
      return [val.some(function (s) { return obs.indexOf(s) >= 0; }), [R(f, op, val, obs, 'sources that observed it')]];
    case 'threat_family':
      var tf = sorted(uniq((a.threat_families || []).map(function (x) { return x.family; })));
      return [val.some(function (x) { return tf.indexOf(slug(x)) >= 0; }), [R(f, op, val, tf.length ? tf : null, 'source-stated')]];
    case 'attack_technique':
      var at = sorted(a.attack_techniques || []);
      return [val.some(function (x) { return at.indexOf(x) >= 0; }), [R(f, op, val, at.length ? at : null, at.length ? 'source-stated' : 'no source of this alert states ATT&CK techniques')]];
    case 'alert_type':
      return [val.indexOf(a.alert_type) >= 0, [R(f, op, val, a.alert_type)]];
    case 'change':
      if (ctx.changes === null || ctx.changes === undefined) return [false, [R(f, op, val, null, 'not evaluated: this condition applies to a change event')]];
      return [val.some(function (c) { return ctx.changes.indexOf(c) >= 0; }), [R(f, op, val, ctx.changes, 'kinds of the change that triggered this evaluation')]];
  }
  throw new Error('unknown field ' + f);
}

function ev(node, a, ctx) {
  var i, r, out;
  if (node.all) {
    out = [];
    for (i = 0; i < node.all.length; i++) { r = ev(node.all[i], a, ctx); if (!r[0]) return [false, r[1]]; out = out.concat(r[1]); }
    return [true, out];
  }
  if (node.any) {
    if (!node.any.length) return [false, [R('any', 'any', null, null, 'the list of alternatives is empty')]];
    out = [];
    for (i = 0; i < node.any.length; i++) { r = ev(node.any[i], a, ctx); if (r[0]) return [true, r[1]]; out = out.concat(r[1]); }
    return [false, out];
  }
  if (node.not) { r = ev(node.not, a, ctx); return [!r[0], r[1].map(function (x) { var y = {}; for (var k in x) y[k] = x[k]; y.negated = true; return y; })]; }
  return leaf(node, a, ctx);
}

/* spec: {schema, version, expr}; ctx: {now: epoch ms, changes: [..]|null, stale: [..]}. The spec must have been validated by the server or by the builder (build only from the closed vocabulary). */
function evaluate(spec, alert, ctx) {
  ctx = ctx || {};
  if (JSON.stringify(spec.expr) === '{"all":[]}') return { matched: true, reasons: [R('all', 'all', null, null, 'the filter has no conditions')] };
  var r = ev(spec.expr, alert, { now: ctx.now === undefined ? Date.now() : ctx.now, changes: ctx.changes === undefined ? null : ctx.changes, stale: ctx.stale || [] });
  return { matched: r[0], reasons: r[1] };
}

var api = { evaluate: evaluate, compare: compare, regionMatches: regionMatches, normId: normId, slug: slug, EU: EU, BANDS: BANDS };
if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.MGFilter = api;
})(typeof window !== 'undefined' ? window : globalThis);
