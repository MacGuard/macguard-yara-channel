"""AssetExposureMatch v1: the contract between an alert and an inventory of assets (the MacGuard Cloud side, PLANNED), plus a conservative reference matcher so the
contract is executable and tested. Nothing here talks to Cloud, an agent or a customer inventory: assets are passed in as data.

States (and when each may be used):
  CONFIRMED_AFFECTED   the asset has the exact package identity AND the evidence is decisive: a distribution advisory that says the installed version is unpatched
                       (dpkg order), or a version inside a vendor range for a non-distribution package whose identity is exact (same vendor and product)
  POTENTIALLY_AFFECTED the identity matches exactly but the evidence is not decisive (an ambiguous single version, a range with no upper bound, a distribution
                       package with no distribution data: backports make upstream ranges unreliable)
  NOT_AFFECTED         the distribution says not affected or patched, or the installed version is outside the vendor range
  UNKNOWN              not enough information to decide (no version, no distribution data, name-only similarity)
  NOT_EVALUATED        the asset was not looked at (no inventory, excluded, or the alert type is not applicable)

A name that merely looks similar is never a match. A fleet summary always says how many assets were evaluated and how many had insufficient information.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional

from intel.vulns import assess, versions

from . import SCHEMA_EXPOSURE_MATCH, taxonomy

STATES = ("CONFIRMED_AFFECTED", "POTENTIALLY_AFFECTED", "NOT_AFFECTED", "UNKNOWN", "NOT_EVALUATED")
EVIDENCE_KINDS = ("distribution-advisory", "vendor-version-range", "vendor-single-version", "open-ended-range", "no-distribution-data", "no-version", "name-only", "not-looked-at")


def _match(alert_id: str, asset_id: str, state: str, evidence: List[Dict[str, Any]], reason: str, cve: Optional[str] = None) -> Dict[str, Any]:
    return {"schema": SCHEMA_EXPOSURE_MATCH, "alert_id": alert_id, "asset_id": asset_id, "cve": cve, "state": state, "evidence": evidence, "reason": reason}


def validate_match(m: Dict[str, Any]) -> List[str]:
    """Invariants a producer must keep (and a consumer may check)."""
    errs = []
    if m.get("schema") != SCHEMA_EXPOSURE_MATCH or m.get("state") not in STATES:
        return ["not an AssetExposureMatch v1 document"]
    kinds = [e.get("kind") for e in m.get("evidence", [])]
    if any(k not in EVIDENCE_KINDS for k in kinds):
        errs.append("unknown evidence kind")
    if m["state"] == "CONFIRMED_AFFECTED" and not ({"distribution-advisory", "vendor-version-range"} & set(kinds)):
        errs.append("CONFIRMED_AFFECTED needs a distribution advisory or a vendor version range")
    if m["state"] == "CONFIRMED_AFFECTED" and "name-only" in kinds:
        errs.append("a name match alone never confirms")
    if m["state"] == "NOT_EVALUATED" and kinds not in ([], ["not-looked-at"]):
        errs.append("NOT_EVALUATED carries no evidence of evaluation")
    if m["state"] in ("NOT_AFFECTED", "CONFIRMED_AFFECTED", "POTENTIALLY_AFFECTED") and not m.get("evidence"):
        errs.append("a verdict needs evidence")
    return errs


def evaluate_asset(alert: Dict[str, Any], asset: Dict[str, Any], distro_rows: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """asset = {asset_id, evaluated: bool?, distro?: {id, release, scheme}, packages: [{vendor?, name, version, source: 'distribution'|'vendor'}]}"""
    aid, sid = alert["alert_id"], asset["asset_id"]
    cves = alert["ids"].get("cve", [])
    cve = cves[0] if cves else None
    if asset.get("evaluated") is False or alert["alert_type"] not in ("vulnerability",):
        return _match(aid, sid, "NOT_EVALUATED", [{"kind": "not-looked-at"}], "the asset was not evaluated or the alert is not a vulnerability", cve)
    best: Optional[Dict[str, Any]] = None
    rank = {"CONFIRMED_AFFECTED": 4, "POTENTIALLY_AFFECTED": 3, "NOT_AFFECTED": 2, "UNKNOWN": 1}
    for pkg in asset.get("packages", []):
        pname = taxonomy.slug(pkg.get("name"))
        for row in alert.get("affected", []):
            same_product = row["product_slug"] == pname
            same_vendor = pkg.get("vendor") is not None and row["vendor_slug"] == taxonomy.slug(pkg["vendor"])
            if not same_product:
                continue
            if not same_vendor and pkg.get("source") != "distribution":
                cand = _match(aid, sid, "UNKNOWN", [{"kind": "name-only", "package": pkg.get("name")}], "same product name, different or unstated vendor: not a match", cve)
            elif pkg.get("source") == "distribution":
                d = asset.get("distro") or {}
                if not cve or not distro_rows:
                    cand = _match(aid, sid, "POTENTIALLY_AFFECTED" if same_product else "UNKNOWN", [{"kind": "no-distribution-data", "package": pkg.get("name")}],
                                  "a distribution package: upstream ranges are not used (backported fixes); no distribution data was given", cve)
                else:
                    r = assess.assess_package(cve, pkg["name"], pkg["version"], d.get("id", ""), d.get("release", ""), distro_rows, d.get("scheme", "dpkg"))
                    v = r["verdict"]
                    if v == "AFFECTED_UNPATCHED":
                        cand = _match(aid, sid, "CONFIRMED_AFFECTED", [{"kind": "distribution-advisory", "package": pkg["name"], "installed": pkg["version"], "fixed": r.get("fixed_version"), "reference": r.get("distro_evidence")}], "the distribution says it is unpatched", cve)
                    elif v in ("PATCHED", "NOT_AFFECTED"):
                        cand = _match(aid, sid, "NOT_AFFECTED", [{"kind": "distribution-advisory", "package": pkg["name"], "installed": pkg["version"], "fixed": r.get("fixed_version"), "reference": r.get("distro_evidence")}], "the distribution says it is patched or not affected", cve)
                    else:
                        cand = _match(aid, sid, "UNKNOWN", [{"kind": "no-distribution-data", "package": pkg["name"]}], r.get("reason") or "no decisive distribution data", cve)
            else:
                ver = pkg.get("version")
                if not ver:
                    cand = _match(aid, sid, "UNKNOWN", [{"kind": "no-version", "package": pkg["name"]}], "the inventory gives no version", cve)
                else:
                    cand = None
                    for v in row["versions"]:
                        p = versions.in_range(ver, v) if v.get("kind") == "range" else None
                        if p is True and (v.get("upper_bound") == "open"):
                            cand = _match(aid, sid, "POTENTIALLY_AFFECTED", [{"kind": "open-ended-range", "range": v["raw"], "installed": ver}], "inside a range with no upper bound: not decisive", cve)
                        elif p is True:
                            cand = _match(aid, sid, "CONFIRMED_AFFECTED", [{"kind": "vendor-version-range", "range": v["raw"], "installed": ver, "sources": row["sources"]}], "exact vendor and product, version inside the vendor range", cve)
                        elif v.get("kind") == "single" and versions.compare(ver, v["version"]) == 0:
                            cand = _match(aid, sid, "POTENTIALLY_AFFECTED", [{"kind": "vendor-single-version", "version": v["raw"]}], "the source names this version without saying affected or fixed", cve)
                        if cand:
                            break
                    if cand is None:
                        known = [v for v in row["versions"] if v.get("kind") == "range"]
                        cand = (_match(aid, sid, "NOT_AFFECTED", [{"kind": "vendor-version-range", "range": known[0]["raw"], "installed": ver}], "outside every stated vendor range", cve) if known
                                else _match(aid, sid, "UNKNOWN", [{"kind": "no-version", "package": pkg["name"]}], "the alert states no usable version range for this product", cve))
            if best is None or rank[cand["state"]] > rank[best["state"]]:
                best = cand
    return best or _match(aid, sid, "UNKNOWN", [{"kind": "no-version"}], "no package of the asset matches a product of the alert", cve)


def fleet_summary(matches: List[Dict[str, Any]], assets_total: int) -> Dict[str, Any]:
    c = {s: 0 for s in STATES}
    for m in matches:
        c[m["state"]] += 1
    evaluated = c["CONFIRMED_AFFECTED"] + c["POTENTIALLY_AFFECTED"] + c["NOT_AFFECTED"] + c["UNKNOWN"]
    return {"assets_total": assets_total, "assets_evaluated": evaluated, "not_evaluated": assets_total - evaluated, "counts": c, "insufficient_information": c["UNKNOWN"],
            "note": "UNKNOWN and NOT_EVALUATED are never counted as unaffected"}
