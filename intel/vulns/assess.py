"""Is THIS Linux package vulnerable? Only a distribution's own data can say so.

An upstream advisory (CISA, ENISA, CERT-EU) gives upstream version ranges. A distribution backports fixes without changing the upstream version
(2.4.52-1+deb12u1 can contain the fix for a bug 'fixed in 2.4.58'), so comparing an installed package version with an upstream range gives wrong
answers in both directions. This module therefore never answers from upstream ranges. It answers only from a distribution-fixes table
(macguard.distro-fixes/1) for the same distro, release, package and CVE; without such a row the verdict is NOT_ASSESSED.

  PATCHED               the distribution lists a fixed version and the installed version is at or above it (dpkg order)
  AFFECTED_UNPATCHED    the distribution lists the package as vulnerable, or a fixed version above the installed one
  NOT_AFFECTED          the distribution says this package/release is not affected
  UNDER_INVESTIGATION   the distribution has not decided
  NOT_ASSESSED          no distribution row, or the version scheme cannot be compared here (only dpkg is implemented; rpm is not)

None of these says the package IS being exploited. That is a different field (exploitation, per source).
"""
from __future__ import annotations
import json
from typing import Any, Dict, List, Optional

from . import ids as idmod, versions

SCHEMA_DISTRO = "macguard.distro-fixes/1"
STATUSES = ("fixed", "vulnerable", "not-affected", "under-investigation")


def load_rows(raw: bytes) -> List[Dict[str, Any]]:
    doc = json.loads(raw.decode("utf-8"))
    if doc.get("schema") != SCHEMA_DISTRO or not isinstance(doc.get("rows"), list):
        raise ValueError(f"not a {SCHEMA_DISTRO} document")
    rows = []
    for r in doc["rows"]:
        if not isinstance(r, dict) or r.get("status") not in STATUSES:
            raise ValueError(f"bad distro row: {str(r)[:80]}")
        n = idmod.normalise(r.get("cve"))
        if n is None or n[0] != "cve":
            raise ValueError(f"bad CVE in distro row: {str(r.get('cve'))[:40]}")
        rows.append(dict(r, cve=n[1]))
    return rows


def assess_package(cve: str, package: str, installed_version: str, distro: str, release: str, rows: List[Dict[str, Any]], scheme: str = "dpkg") -> Dict[str, Any]:
    n = idmod.normalise(cve)
    if n is None or n[0] != "cve":
        raise ValueError("a CVE id is required")
    cve = n[1]
    base = {"cve": cve, "package": package, "installed": installed_version, "distro": distro, "release": release, "exploited_is_not_decided_here": True}
    match = [r for r in rows if r["cve"] == cve and r.get("package") == package and r.get("distro") == distro and r.get("release") == release]
    if not match:
        return dict(base, verdict="NOT_ASSESSED", reason="no row for this distribution, release, package and CVE; upstream version ranges do not apply to distribution packages (backported fixes)")
    if len(match) > 1:
        sts = {m["status"] for m in match}
        if len(sts) > 1:
            return dict(base, verdict="NOT_ASSESSED", reason=f"the distribution data contradicts itself for this package ({', '.join(sorted(sts))})")
    row = sorted(match, key=lambda m: m["status"])[0]
    ev = {"distro_evidence": row.get("evidence")}
    if row["status"] == "not-affected":
        return dict(base, verdict="NOT_AFFECTED", **ev)
    if row["status"] == "under-investigation":
        return dict(base, verdict="UNDER_INVESTIGATION", **ev)
    if row["status"] == "vulnerable":
        return dict(base, verdict="AFFECTED_UNPATCHED", reason="the distribution lists the package as vulnerable", **ev)
    fixed: Optional[str] = row.get("fixed_version")
    if not fixed:
        return dict(base, verdict="NOT_ASSESSED", reason="the distribution row says 'fixed' without a version", **ev)
    if scheme != "dpkg":
        return dict(base, verdict="NOT_ASSESSED", reason=f"version scheme '{scheme}' cannot be compared here (only dpkg is implemented)", fixed_version=fixed, **ev)
    try:
        c = versions.dpkg_compare(installed_version, fixed)
    except ValueError as e:
        return dict(base, verdict="NOT_ASSESSED", reason=f"a version is not a valid Debian version: {e}", fixed_version=fixed, **ev)
    return dict(base, verdict="PATCHED" if c >= 0 else "AFFECTED_UNPATCHED", fixed_version=fixed, **ev)
