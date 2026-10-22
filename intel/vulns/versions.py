"""Affected-version text and version comparison.

EUVD gives the affected versions of a product as free text. Only the shapes below are understood; anything else is kept verbatim as
'unparsed' and is never turned into a statement about being affected or fixed:

  "A <B"      affected from A up to, not including, B        -> range, fixed_in = B (the vendor says B is the first version without it)
  "A ≤B"      affected from A up to and including B          -> range, last_affected = B (no fixed version is stated)
  "A <publication"  open ended on the right                  -> range with no upper bound
  "patch: X"  a version the vendor text labels as a patch    -> fixed marker, no range
  "X"         one version number                             -> single (AMBIGUOUS: affected version or fixed version is not stated)
  "n/a", "unspecified", ...                                   -> unspecified

Comparison is numeric on dotted components; a component with letters is compared as text after its numeric prefix. Debian-style versions
(epoch:upstream-revision, ~ sorts before everything) have their own comparator because Linux package versions follow those rules, not semver.
"""
from __future__ import annotations
import re
from typing import Any, Dict, List, Optional, Tuple

_NUM = r"[0-9][0-9A-Za-z.\-_+~]*"
_RANGE = re.compile(rf"^\s*({_NUM})\s*(<|≤|<=)\s*({_NUM}|publication)\s*$")
_PATCH = re.compile(rf"^\s*patch:\s*({_NUM})\s*$", re.IGNORECASE)
_SINGLE = re.compile(rf"^\s*({_NUM})\s*$")
_UNSPEC = {"n/a", "na", "unspecified", "unknown", "none", "*", "-", ""}


def parse_affected(raw: object) -> Dict[str, Any]:
    """Never raises. Always returns {raw, kind, ...}; kind is one of range, fixed-marker, single, unspecified, unparsed."""
    if not isinstance(raw, str):
        return {"raw": None, "kind": "unspecified"}
    s = raw.strip()
    out: Dict[str, Any] = {"raw": s[:200]}
    if s.lower() in _UNSPEC:
        out["kind"] = "unspecified"
        return out
    m = _RANGE.match(s)
    if m:
        lo, op, hi = m.group(1), m.group(2), m.group(3)
        out.update(kind="range", introduced=lo)
        if hi.lower() == "publication":
            out["upper_bound"] = "open"
        elif op == "<":
            out["fixed_in"] = hi
        else:
            out["last_affected"] = hi
        if "upper_bound" not in out and compare(lo, hi) > 0:
            return {"raw": out["raw"], "kind": "unparsed", "note": "the lower bound is above the upper bound"}
        return out
    m = _PATCH.match(s)
    if m:
        out.update(kind="fixed-marker", fixed_in=m.group(1))
        return out
    if _SINGLE.match(s):
        out.update(kind="single", version=s, note="a single version: the source does not say whether it is affected or the fix")
        return out
    out["kind"] = "unparsed"
    return out


def _split(v: str) -> List[Any]:
    parts: List[Any] = []
    for tok in re.split(r"[.\-_+]", v):
        m = re.match(r"^(\d*)(.*)$", tok)
        n, rest = m.group(1), m.group(2)
        parts.append((int(n) if n else -1, rest))
    return parts


def compare(a: str, b: str) -> int:
    """Generic dotted-version comparison (-1, 0, 1). Numeric components compare as numbers; trailing zeros are insignificant (1.0 == 1.0.0)."""
    pa, pb = _split(a), _split(b)
    n = max(len(pa), len(pb))
    pa += [(0, "")] * (n - len(pa))
    pb += [(0, "")] * (n - len(pb))
    for x, y in zip(pa, pb):
        if x != y:
            return -1 if x < y else 1
    return 0


def in_range(version: str, parsed: Dict[str, Any]) -> Optional[bool]:
    """True/False for a parsed 'range'; None when the entry cannot answer (not a range)."""
    if parsed.get("kind") != "range":
        return None
    if compare(version, parsed["introduced"]) < 0:
        return False
    if "fixed_in" in parsed:
        return compare(version, parsed["fixed_in"]) < 0
    if "last_affected" in parsed:
        return compare(version, parsed["last_affected"]) <= 0
    return True


# --- Debian / dpkg version order (Debian Policy 5.6.12) ---
def _dpkg_order(c: str) -> int:
    if c == "~":
        return -1
    if c == "":
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _dpkg_cmp_part(a: str, b: str) -> int:
    while a or b:
        pa = re.match(r"^\D*", a).group(0)
        pb = re.match(r"^\D*", b).group(0)
        a, b = a[len(pa):], b[len(pb):]
        for i in range(max(len(pa), len(pb))):
            ca = pa[i] if i < len(pa) else ""
            cb = pb[i] if i < len(pb) else ""
            oa, ob = _dpkg_order(ca), _dpkg_order(cb)
            if oa != ob:
                return -1 if oa < ob else 1
        na = re.match(r"^\d*", a).group(0)
        nb = re.match(r"^\d*", b).group(0)
        a, b = a[len(na):], b[len(nb):]
        ia, ib = int(na or 0), int(nb or 0)
        if ia != ib:
            return -1 if ia < ib else 1
    return 0


def dpkg_split(v: str) -> Tuple[int, str, str]:
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        if not e.isdigit():
            raise ValueError("bad epoch")
        epoch = int(e)
    rev = ""
    if "-" in v:
        v, rev = v.rsplit("-", 1)
    if not v or not v[0].isdigit():
        raise ValueError("a Debian upstream version must start with a digit")
    return epoch, v, rev


def dpkg_compare(a: str, b: str) -> int:
    """Debian version order. Raises ValueError for text that is not a Debian version."""
    ea, ua, ra = dpkg_split(a)
    eb, ub, rb = dpkg_split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    c = _dpkg_cmp_part(ua, ub)
    return c if c else _dpkg_cmp_part(ra, rb)
