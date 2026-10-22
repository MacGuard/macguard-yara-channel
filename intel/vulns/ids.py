"""Vulnerability identifiers: CVE, EUVD (ENISA) and GHSA (GitHub advisories). One canonical spelling per kind, strict syntax, no guessing.

  CVE-YYYY-NNNN+      upper case, year >= 1999, at least 4 digits
  EUVD-YYYY-NNNN+     upper case (ENISA)
  GHSA-xxxx-xxxx-xxxx prefix upper case, the rest lower case (GitHub's own spelling), the 20-letter GitHub alphabet
"""
from __future__ import annotations
import re
from typing import List, Optional, Tuple

CVE = re.compile(r"^CVE-(\d{4})-(\d{4,})$")
EUVD = re.compile(r"^EUVD-(\d{4})-(\d{4,})$")
GHSA = re.compile(r"^ghsa(-[23456789cfghjmpqrvwx]{4}){3}$")
_FIND = re.compile(r"(?<![A-Za-z0-9])(CVE-\d{4}-\d{4,}|EUVD-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})(?![A-Za-z0-9])", re.IGNORECASE)


def normalise(raw: object) -> Optional[Tuple[str, str]]:
    """('cve'|'euvd'|'ghsa', canonical id), or None when the text is not a well-formed identifier."""
    if not isinstance(raw, str):
        return None
    s = raw.strip()
    if not s or len(s) > 40:
        return None
    u = s.upper()
    m = CVE.match(u)
    if m and int(m.group(1)) >= 1999:
        return "cve", u
    if EUVD.match(u):
        return "euvd", u
    g = s.lower()
    if GHSA.match(g):
        return "ghsa", "GHSA" + g[4:]
    return None


def split_aliases(raw: object) -> Tuple[List[Tuple[str, str]], List[str]]:
    """Splits a free 'aliases' field (newline, comma or space separated). Returns (valid ids, de-duplicated, in order; rejected tokens)."""
    if raw is None:
        return [], []
    if isinstance(raw, (list, tuple)):
        tokens = [str(x) for x in raw]
    else:
        tokens = [t for t in re.split(r"[\s,;]+", str(raw)) if t]
    ok: List[Tuple[str, str]] = []
    bad: List[str] = []
    for t in tokens:
        n = normalise(t)
        if n is None:
            bad.append(t[:40])
        elif n not in ok:
            ok.append(n)
    return ok, bad


def mentions(text: object) -> List[Tuple[str, str]]:
    """Identifiers that appear inside free text. A MENTION is not an alias: an advisory about X may name Y without Y being X."""
    if not isinstance(text, str):
        return []
    out: List[Tuple[str, str]] = []
    for m in _FIND.finditer(text):
        n = normalise(m.group(1))
        if n and n not in out:
            out.append(n)
    return out
