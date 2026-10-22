"""The subscription filter language: a CLOSED set of fields and operators combined with all / any / not.

A filter is data, never code: the client sends JSON, the server validates it against the tables below (field names, operators, value shapes, depth,
size) and evaluates it itself. There is no regular expression, no query string, no expression evaluator and nothing the client can name that is
not in LEAVES. The same filter and the same alert give the same answer in `web/alerts/filter.js`; tests/fixtures/alerts/filter-vectors.json is
run by both.

Missing information never matches: a leaf that needs a value the alert does not have (no CVSS score, no sector, no stated version) is false and its
reason says so. The two explicit exceptions are options the subscriber turns on (`include_unknown` for sectors, `include_ambiguous` for versions).
"""
from __future__ import annotations
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from intel.vulns import ids as idmod, versions

from . import SCHEMA_FILTER, taxonomy

MAX_DEPTH = 4
MAX_LEAVES = 40
MAX_LIST = 100
MAX_STR = 200
CHANGE_KINDS = ["new", "exploitation_added", "exploitation_source_added", "fix_available", "severity_up", "severity_down", "scope_added", "affected_changed", "mitigation_added", "other"]
CATEGORIES = ["container-platform", "network-device", "cloud", "service-protocol", "library"]
ALERT_TYPES = ["vulnerability", "advisory", "rule-release"]
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
SLUGISH = re.compile(r"^[a-z0-9][a-z0-9 .+_-]{0,100}$")
SOURCE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,60}$")
ECOSYSTEMS = ["npm", "pypi", "maven", "go", "cargo", "nuget", "rubygems", "packagist", "hex", "pub", "swifturl", "debian", "ubuntu", "alpine", "rpm", "other"]


class FilterError(ValueError):
    def __init__(self, errors: List[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


# ---- leaf table: field -> (allowed ops, value kind) -----------------------------------------------------------------------------
def _in_list(check):
    def v(val, errs, path):
        if not isinstance(val, list) or not val or len(val) > MAX_LIST:
            errs.append(f"{path}: a non-empty list of at most {MAX_LIST} values is required")
            return
        for x in val:
            if not isinstance(x, str) or len(x) > MAX_STR or not check(x):
                errs.append(f"{path}: invalid value {str(x)[:40]!r}")
    return v


def _num(lo, hi):
    def v(val, errs, path):
        if isinstance(val, bool) or not isinstance(val, (int, float)) or not lo <= val <= hi:
            errs.append(f"{path}: a number between {lo} and {hi} is required")
    return v


def _bool(val, errs, path):
    if not isinstance(val, bool):
        errs.append(f"{path}: true or false is required")


def _date(val, errs, path):
    if not isinstance(val, str) or not DATE.match(val):
        errs.append(f"{path}: a date YYYY-MM-DD is required")
        return
    try:
        datetime.strptime(val, "%Y-%m-%d")
    except ValueError:
        errs.append(f"{path}: not a real date")


def _band(val, errs, path):
    if val not in taxonomy.BANDS[1:]:
        errs.append(f"{path}: one of {taxonomy.BANDS[1:]}")


def _version(val, errs, path):
    if not isinstance(val, dict) or set(val) != {"vendor", "product", "version"} or not all(isinstance(val[k], str) and 0 < len(val[k]) <= MAX_STR for k in val):
        errs.append(f"{path}: an object with vendor, product and version (text) is required")
    elif not re.match(r"^[0-9][0-9A-Za-z.\-_+~]*$", val["version"]):
        errs.append(f"{path}: the version must start with a digit and contain only letters, digits and . - _ + ~")


def _ident(x):
    return idmod.normalise(x) is not None


LEAVES: Dict[str, Tuple[Tuple[str, ...], Any, Tuple[str, ...]]] = {
    # field: (ops, value validator, allowed extra keys)
    "region": (("in",), _in_list(taxonomy.valid_region), ()),
    "sector": (("in",), _in_list(lambda x: x in taxonomy.ids("sectors")), ("include_unknown",)),
    "vendor": (("in",), _in_list(lambda x: bool(SLUGISH.match(taxonomy.slug(x)))), ()),
    "product": (("in",), _in_list(lambda x: bool(SLUGISH.match(taxonomy.slug(x)))), ()),
    "product_family": (("in",), _in_list(lambda x: bool(SLUGISH.match(taxonomy.slug(x)))), ()),
    "version": (("affects",), _version, ("include_ambiguous",)),
    "os": (("in",), _in_list(lambda x: x in taxonomy.ids("os-families")), ()),
    "technology_category": (("in",), _in_list(lambda x: x in CATEGORIES), ()),
    "service": (("in",), _in_list(lambda x: bool(SLUGISH.match(taxonomy.slug(x)))), ()),
    "ecosystem": (("in",), _in_list(lambda x: x in ECOSYSTEMS), ()),
    "id": (("in",), _in_list(_ident), ()),
    "cvss": (("gte", "lte"), _num(0, 10), ()),
    "epss": (("gte",), _num(0, 100), ()),
    "severity": (("gte",), _band, ()),
    "exploited": (("is",), _bool, ("source",)),
    "published": (("gte", "lte"), _date, ()),
    "updated": (("gte", "lte"), _date, ()),
    "ingested_within_days": (("lte",), _num(0, 3650), ()),
    "has_fix": (("is",), _bool, ()),
    "has_mitigation": (("is",), _bool, ()),
    "exposure": (("in",), _in_list(lambda x: x in taxonomy.ids("exposure")), ()),
    "source": (("in",), _in_list(lambda x: bool(SOURCE_ID.match(x))), ()),
    "threat_family": (("in",), _in_list(lambda x: bool(SLUGISH.match(taxonomy.slug(x)))), ()),
    "attack_technique": (("in",), _in_list(lambda x: bool(TECHNIQUE.match(x))), ()),
    "alert_type": (("in",), _in_list(lambda x: x in ALERT_TYPES), ()),
    "change": (("any",), _in_list(lambda x: x in CHANGE_KINDS), ()),
}


def _walk(node: Any, errs: List[str], path: str, depth: int, counter: List[int]) -> None:
    if depth > MAX_DEPTH:
        errs.append(f"{path}: nested deeper than {MAX_DEPTH}")
        return
    if not isinstance(node, dict):
        errs.append(f"{path}: an object is required")
        return
    keys = set(node)
    for combiner in ("all", "any"):
        if combiner in keys:
            if keys != {combiner} or not isinstance(node[combiner], list) or len(node[combiner]) > MAX_LEAVES:
                errs.append(f"{path}: '{combiner}' takes only a list of at most {MAX_LEAVES} expressions")
                return
            for i, c in enumerate(node[combiner]):
                _walk(c, errs, f"{path}.{combiner}[{i}]", depth + 1, counter)
            return
    if "not" in keys:
        if keys != {"not"}:
            errs.append(f"{path}: 'not' takes only one expression")
            return
        _walk(node["not"], errs, f"{path}.not", depth + 1, counter)
        return
    counter[0] += 1
    if counter[0] > MAX_LEAVES:
        errs.append(f"{path}: more than {MAX_LEAVES} conditions")
        return
    field = node.get("field")
    if field not in LEAVES:
        errs.append(f"{path}: unknown field {str(field)[:40]!r}")
        return
    ops, check, extras = LEAVES[field]
    if node.get("op") not in ops:
        errs.append(f"{path}: operator for '{field}' must be one of {list(ops)}")
        return
    allowed = {"field", "op", "value"} | set(extras)
    if not set(node) <= allowed or "value" not in node:
        errs.append(f"{path}: allowed keys for '{field}' are {sorted(allowed)}")
        return
    check(node["value"], errs, f"{path}.value")
    for x in extras:
        if x in node:
            if x == "source":
                if not isinstance(node[x], str) or not SOURCE_ID.match(node[x]):
                    errs.append(f"{path}.{x}: a source id is required")
            elif not isinstance(node[x], bool):
                errs.append(f"{path}.{x}: true or false is required")


def validate(spec: Any) -> List[str]:
    """Empty list = valid."""
    errs: List[str] = []
    if not isinstance(spec, dict) or spec.get("schema") != SCHEMA_FILTER or spec.get("version") != 1 or set(spec) != {"schema", "version", "expr"}:
        return [f"a filter is an object with schema {SCHEMA_FILTER}, version 1 and expr"]
    _walk(spec["expr"], errs, "expr", 1, [0])
    return errs


def parse(spec: Any) -> Dict[str, Any]:
    errs = validate(spec)
    if errs:
        raise FilterError(errs)
    return spec


def match_all() -> Dict[str, Any]:
    return {"schema": SCHEMA_FILTER, "version": 1, "expr": {"all": []}}


# ---- evaluation -----------------------------------------------------------------------------------------------------------------
class Ctx:
    """What the evaluation needs besides the alert: the clock (UTC date) and, when matching a change, the kinds of that change."""

    def __init__(self, now: datetime, changes: Optional[List[str]] = None, stale: Optional[List[str]] = None):
        self.now = now
        self.changes = changes
        self.stale = list(stale or [])          # sources whose snapshot is older than their limit: their exploitation statements are not counted


def _reason(field, op, expected, observed, basis=None, sources=None):
    return {"field": field, "op": op, "expected": expected, "observed": observed, "basis": basis, "sources": sources or []}


def _word_prefix(text: str, prefix: str) -> bool:
    return text == prefix or text.startswith(prefix + " ")


def _leaf(node: Dict[str, Any], a: Dict[str, Any], ctx: Ctx) -> Tuple[bool, List[Dict[str, Any]]]:
    f, op, val = node["field"], node["op"], node["value"]
    aff = a.get("affected", [])
    if f == "region":
        scopes = [r["region"] for r in a.get("region_scope", [])]
        hit = [w for w in val if taxonomy.region_matches(w, scopes)]
        return bool(hit), [_reason(f, op, val, scopes or None, "source-scope", sorted({r["source"] for r in a.get("region_scope", [])}))]
    if f == "sector":
        have = [s["sector"] for s in a.get("sectors", [])]
        hit = [s for s in val if s in have]
        if hit:
            return True, [_reason(f, op, val, have, "source-stated")]
        if not have and node.get("include_unknown"):
            return True, [_reason(f, op, val, None, "included because the subscription includes alerts with no sector information")]
        return False, [_reason(f, op, val, have or None, "no sector information" if not have else None)]
    if f in ("vendor", "product", "product_family"):
        want = [taxonomy.slug(v) for v in val]
        key = "vendor_slug" if f == "vendor" else "product_slug"
        hits = []
        for r in aff:
            t = r[key]
            if any((t == w) if f != "product_family" else _word_prefix(t, w) for w in want):
                hits.append(f"{r['vendor']} {r['product']}".strip())
        return bool(hits), [_reason(f, op, val, hits or [f"{r['vendor']} {r['product']}".strip() for r in aff][:5] or None, "affected products stated by the sources" if aff else "no affected product stated",
                                    sorted({s for r in aff for s in r["sources"]}))]
    if f == "version":
        want_v, want_p, ver = taxonomy.slug(val["vendor"]), taxonomy.slug(val["product"]), val["version"]
        notes = []
        for r in aff:
            if r["vendor_slug"] != want_v or r["product_slug"] != want_p:
                continue
            for v in r["versions"]:
                p = versions.in_range(ver, v) if v.get("kind") == "range" else None
                if p is True:
                    return True, [_reason(f, op, val, v["raw"], "vendor version text (a range); not a distribution package check", r["sources"])]
                if v.get("kind") == "single" and node.get("include_ambiguous") and versions.compare(ver, v["version"]) == 0:
                    return True, [_reason(f, op, val, v["raw"], "a single version the source does not call affected or fixed (included on request)", r["sources"])]
                notes.append(v["raw"])
        return False, [_reason(f, op, val, notes or None, "no stated range contains this version" if notes else "the product has no stated version information")]
    if f == "os":
        have = sorted({o for r in aff for o in r["os"]})
        hit = [o for o in val if o in have]
        return bool(hit), [_reason(f, op, val, have or None, taxonomy.MAP_BASIS if have else "no operating system could be established from the vendor and product names",
                                   sorted({s for r in aff if any(o in val for o in r["os"]) for s in r["sources"]}))]
    if f == "technology_category":
        have = sorted({c for r in aff for c in r["categories"]})
        return any(c in have for c in val), [_reason(f, op, val, have or None, taxonomy.MAP_BASIS if have else "no category in the curated map",
                                                     sorted({s for r in aff if any(c in val for c in r["categories"]) for s in r["sources"]}))]
    if f == "service":
        have = sorted({c for r in aff for c in r["services"]})
        w = [taxonomy.slug(x) for x in val]
        return any(c in have for c in w), [_reason(f, op, val, have or None, taxonomy.MAP_BASIS if have else "no service in the curated map")]
    if f == "ecosystem":
        have = sorted({e for r in aff for e in r.get("ecosystems", [])})
        return any(c in have for c in val), [_reason(f, op, val, have or None, "no source of this alert states an ecosystem" if not have else "source-stated")]
    if f == "id":
        mine = [x for k in ("cve", "euvd", "ghsa") for x in a["ids"].get(k, [])]
        want = [idmod.normalise(v)[1] for v in val]
        hit = [w for w in want if w in mine]
        return bool(hit), [_reason(f, op, want, mine or None, "identifiers declared by the sources")]
    if f == "cvss":
        s = a["severity"]["score"]
        if s is None:
            return False, [_reason(f, op, val, None, "no source gives a CVSS score")]
        ok = float(s) >= val if op == "gte" else float(s) <= val
        return ok, [_reason(f, op, val, s, f"CVSS {a['severity'].get('version') or '?'} rated by {', '.join(a['severity']['rated_by'])}", a["severity"]["rated_by"])]
    if f == "epss":
        e = (a.get("epss") or {}).get("by_source", {})
        nums = {s: float(x) for s, x in e.items()}
        if not nums:
            return False, [_reason(f, op, val, None, "no EPSS value from any source")]
        top = max(nums.values())
        return top >= val, [_reason(f, op, val, {s: e[s] for s in sorted(e)}, "value as the source gives it; its unit is not documented by the source", sorted(nums))]
    if f == "severity":
        b = a["severity"]["band"]
        return taxonomy.band_at_least(b, val), [_reason(f, op, val, b, "band of the highest CVSS base score given" if b != "unknown" else "no CVSS score: severity unknown", a["severity"]["rated_by"])]
    if f == "exploited":
        ex = a["exploitation"]
        src = node.get("source")
        asserted = [s for s in ex["asserted_by"] if (not src or s == src) and s not in ctx.stale]
        status = bool(asserted)
        basis = "structured exploitation field of each source" + ("" if not src else f" (only {src})") + (f"; stale sources not counted: {', '.join(sorted(set(ctx.stale) & set(ex['asserted_by'])))}" if set(ctx.stale) & set(ex["asserted_by"]) else "")
        return status == val, [_reason(f, op, val, {"asserted_by": asserted, "since": ex.get("earliest_since")}, basis, asserted)]
    if f in ("published", "updated"):
        d = a["dates"].get(f)
        if not d:
            return False, [_reason(f, op, val, None, f"no {f} date stated")]
        ok = d >= val if op == "gte" else d <= val
        return ok, [_reason(f, op, val, d, "source date (UTC calendar day)")]
    if f == "ingested_within_days":
        t = a.get("first_ingested_utc")
        if not t:
            return False, [_reason(f, op, val, None, "no ingestion time")]
        age = ctx.now - datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=ctx.now.tzinfo)
        return age <= timedelta(days=val), [_reason(f, op, val, t, "first time MacGuard ingested it (UTC)")]
    if f == "has_fix":
        av = a["fix"]["available"]
        return (av is True) == val if val else av is not True, [_reason(f, op, val, av, "fixed versions in the vendor text" if av else "no fixed version stated (unknown, not 'no fix')")]
    if f == "has_mitigation":
        have = bool(a.get("mitigations"))
        return have == val, [_reason(f, op, val, have, a.get("mitigation_basis"))]
    if f == "exposure":
        av = a.get("attack_vector", "unknown")
        allowed = taxonomy.exposure_vectors(val)
        return av in allowed, [_reason(f, op, val, av, "attack vector (AV) in the CVSS vector the source gave; exposure itself is set by you, not detected")]
    if f == "source":
        have = sorted(a["observations"])
        return any(s in have for s in val), [_reason(f, op, val, have, "sources that observed it")]
    if f == "threat_family":
        have = sorted({t["family"] for t in a.get("threat_families", [])})
        return any(taxonomy.slug(v) in have for v in val), [_reason(f, op, val, have or None, "source-stated")]
    if f == "attack_technique":
        have = sorted(a.get("attack_techniques", []))
        return any(v in have for v in val), [_reason(f, op, val, have or None, "no source of this alert states ATT&CK techniques" if not have else "source-stated")]
    if f == "alert_type":
        return a["alert_type"] in val, [_reason(f, op, val, a["alert_type"])]
    if f == "change":
        if ctx.changes is None:
            return False, [_reason(f, op, val, None, "not evaluated: this condition applies to a change event")]
        hit = [c for c in val if c in ctx.changes]
        return bool(hit), [_reason(f, op, val, ctx.changes, "kinds of the change that triggered this evaluation")]
    raise AssertionError(f)


def _eval(node: Dict[str, Any], a: Dict[str, Any], ctx: Ctx) -> Tuple[bool, List[Dict[str, Any]]]:
    if "all" in node:
        reasons: List[Dict[str, Any]] = []
        for c in node["all"]:
            ok, r = _eval(c, a, ctx)
            if not ok:
                return False, r
            reasons += r
        return True, reasons
    if "any" in node:
        if not node["any"]:
            return False, [_reason("any", "any", None, None, "the list of alternatives is empty")]
        last: List[Dict[str, Any]] = []
        for c in node["any"]:
            ok, r = _eval(c, a, ctx)
            if ok:
                return True, r
            last += r
        return False, last
    if "not" in node:
        ok, r = _eval(node["not"], a, ctx)
        return (not ok), [dict(x, negated=True) for x in r]
    return _leaf(node, a, ctx)


def evaluate(spec: Dict[str, Any], alert: Dict[str, Any], ctx: Ctx) -> Tuple[bool, List[Dict[str, Any]]]:
    """(matched, reasons). `alert` is a PUBLISH VIEW (see alerts.model.publish_view). The spec must have been validated."""
    expr = spec["expr"]
    if expr == {"all": []}:
        return True, [_reason("all", "all", None, None, "the filter has no conditions")]
    return _eval(expr, alert, ctx)
