"""IntelligenceAlert v1: the common shape of one alert, built from what the sources say.

An alert keeps EVERY source's observation (its evidence, dates, severity, references) side by side; the fields at the top level are derived from
the observations by `derive`, and the same function builds the public view from only the observations whose source may be redistributed
(`publish_view`), so nothing that came from a source that is not cleared can reach a feed, a page, an e-mail or a webhook.

Volatile data (how old a snapshot is) is NOT part of the hashed content: a source going stale is not a new version of the alert.
"""
from __future__ import annotations
import hashlib
from typing import Any, Dict, List, Optional, Tuple

from intel import registry as reg
from intel.canonical import canonical_bytes
from intel.vulns import ids as idmod

from . import SCHEMA_ALERT, taxonomy

# who supplies the title and the description first (a source we trust to name things; the order is not a quality ranking of the data)
TEXT_PRECEDENCE = ["cisa-kev", "enisa-euvd-exploited", "enisa-euvd", "cert-eu-advisories", "macguard-yara-releases"]
REGION_OF_SOURCE = {"US": "country:US", "EU": "EU", "ES": "ES", "global": "GLOBAL"}


def alert_id_for(first_key: str) -> str:
    return "MGA-" + hashlib.sha256(("macguard-alert-v1|" + first_key).encode()).hexdigest()[:20]


def _rank(sid: str) -> int:
    return TEXT_PRECEDENCE.index(sid) if sid in TEXT_PRECEDENCE else len(TEXT_PRECEDENCE)


def _num(s: Any) -> Optional[float]:
    try:
        return float(s)
    except (TypeError, ValueError):
        return None


def derive(key: str, alert_type: str, observations: Dict[str, Dict[str, Any]], exploitation: Dict[str, Dict[str, Any]], registry: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """The top-level fields of an alert, computed from a set of observations (all of them, or only the cleared ones)."""
    srcs = sorted(observations, key=lambda s: (_rank(s), s))
    ids: Dict[str, List[str]] = {"cve": [], "euvd": [], "ghsa": []}
    for s in srcs:
        for k in ids:
            for v in observations[s].get("ids", {}).get(k, []):
                if v not in ids[k]:
                    ids[k].append(v)
    for k in ids:
        ids[k].sort()
    texts = [(s, observations[s].get("title") or observations[s].get("summary") or "") for s in srcs]
    texts = [(s, t) for s, t in texts if t]
    desc_src = next(((s, observations[s].get("summary")) for s in srcs if observations[s].get("summary")), None)
    title_body = texts[0][1] if texts else ""
    title = (key + (": " + title_body[:140] if title_body and title_body != key else "")).strip()
    # severity: the highest score any source gives; the others stay in `all` and a difference is reported as a discrepancy
    scores = {s: _num(observations[s]["severity"]["score"]) for s in srcs if observations[s].get("severity")}
    top = max(scores, key=lambda s: (scores[s], -_rank(s))) if scores else None
    sev: Dict[str, Any] = {"score": None, "version": None, "vector": None, "band": "unknown", "rated_by": [], "all": {}}
    if top:
        o = observations[top]["severity"]
        sev.update(score=o["score"], version=o.get("version"), vector=o.get("vector"), band=taxonomy.band_of(scores[top]), rated_by=sorted(s for s in scores if scores[s] == scores[top]),
                   all={s: observations[s]["severity"]["score"] for s in sorted(scores)})
    epss = {s: observations[s]["epss"] for s in srcs if observations[s].get("epss") is not None}
    discrepancies = []
    if len({v for v in sev["all"].values()}) > 1:
        discrepancies.append({"field": "severity.score", "values": sev["all"]})
    pub = {s: observations[s]["dates"].get("published") for s in srcs if observations[s]["dates"].get("published")}
    if len(set(pub.values())) > 1:
        discrepancies.append({"field": "dates.published", "values": dict(sorted(pub.items()))})
    since = {s: exploitation[s]["since"] for s in srcs if exploitation.get(s, {}).get("asserted") and exploitation[s].get("since")}
    if len(set(since.values())) > 1:
        discrepancies.append({"field": "exploitation.since", "values": dict(sorted(since.items()))})
    asserted = sorted(s for s in srcs if exploitation.get(s, {}).get("asserted"))
    # affected products: one row per vendor+product, with every distinct version statement and who made it
    rows: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for s in srcs:
        for a in observations[s].get("affected", []):
            k = (taxonomy.slug(a["vendor"]), taxonomy.slug(a["product"]))
            r = rows.setdefault(k, {"vendor": a["vendor"], "product": a["product"], "vendor_slug": k[0], "product_slug": k[1], "versions": [], "sources": []})
            if s not in r["sources"]:
                r["sources"].append(s)
            if a["version"] not in r["versions"]:
                r["versions"].append(a["version"])
    affected = []
    for k in sorted(rows):
        r = rows[k]
        c = taxonomy.classify(r["vendor"], r["product"])
        r.update(os=c["os"], categories=c["categories"], services=c["services"], classification_basis=c["basis"])
        affected.append(r)
    fixes = []
    for s in srcs:
        for f in observations[s].get("fixes", []):
            fixes.append({"vendor": f.get("vendor"), "product": f.get("product"), "fixed_in": f.get("fixed_in"), "source": s, "basis": f.get("basis")})
    refs: List[str] = []
    for s in srcs:
        for u in observations[s].get("references", []):
            if u not in refs:
                refs.append(u)
    regions = []
    for s in srcs:
        r = REGION_OF_SOURCE.get(str(registry.get(s, {}).get("region")))
        if r and {"region": r, "source": s} not in regions:
            regions.append({"region": r, "basis": "source-scope", "source": s})
    threat = []
    for s in srcs:
        extra = observations[s].get("extra") or {}
        if extra.get("ransomware_use") == "Known":
            threat.append({"family": "ransomware", "source": s, "basis": "CISA KEV knownRansomwareCampaignUse = Known"})
    dates = {"published": min(pub.values()) if pub else None,
             "updated": max([observations[s]["dates"]["updated"] for s in srcs if observations[s]["dates"].get("updated")] or [None]) if any(observations[s]["dates"].get("updated") for s in srcs) else None,
             "listed": {s: observations[s]["dates"]["listed"] for s in srcs if observations[s]["dates"].get("listed")}}
    return {
        "key": key, "alert_type": alert_type, "ids": ids, "title": title, "description": (desc_src[1] if desc_src else "")[:500], "description_source": desc_src[0] if desc_src else None,
        "severity": sev, "epss": {"by_source": epss} if epss else None, "attack_vector": taxonomy.attack_vector(sev["vector"]),
        "exploitation": {"status": "exploited" if asserted else "not-asserted", "asserted_by": asserted, "earliest_since": min(since.values()) if since else None,
                         "independent_confirmation": "unknown" if len(asserted) > 1 else "not-applicable",
                         "per_source": {s: {"asserted": bool(exploitation.get(s, {}).get("asserted")), "since": exploitation.get(s, {}).get("since"), "basis": exploitation.get(s, {}).get("basis")} for s in srcs},
                         "note": "a severity score is not evidence of exploitation; each source's statement is kept apart"},
        "affected": affected, "fix": {"available": True if fixes else None, "details": fixes, "note": "vendor text; says nothing about a Linux distribution package"},
        "mitigations": [], "mitigation_basis": "no source of this alert states mitigations in a structured field",
        "region_scope": regions, "sectors": [], "sector_basis": "no source states a sector; sector filters only match what a source or the curated map states",
        "threat_families": threat, "attack_techniques": [], "references": refs, "dates": dates, "discrepancies": discrepancies,
    }


def validate_content(content: Dict[str, Any], observations: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    problems = []
    for k, vs in content["ids"].items():
        for v in vs:
            n = idmod.normalise(v)
            if n is None or n[0] != k:
                problems.append(f"malformed {k} identifier {v!r}")
    if not content["alert_type"] == "rule-release" and not any(content["ids"].values()) and content["alert_type"] == "vulnerability":
        problems.append("a vulnerability alert without any identifier")
    for s, o in observations.items():
        ev = o.get("evidence") or {}
        if not (ev.get("file") and ev.get("file_sha256") and ev.get("locator")):
            problems.append(f"{s}: no evidence reference")
    if not observations:
        problems.append("no observation")
    return {"state": "validated" if not problems else "partial", "problems": problems}


def build_content(key: str, alert_type: str, observations: Dict[str, Dict[str, Any]], exploitation: Dict[str, Dict[str, Any]], flags: List[str],
                  registry: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    c = derive(key, alert_type, observations, exploitation, registry)
    c["schema"] = SCHEMA_ALERT
    c["observations"] = {s: observations[s] for s in sorted(observations)}
    c["flags"] = sorted(set(flags))
    c["validation"] = validate_content(c, observations)
    lic = {}
    for s in sorted(observations):
        src = registry.get(s, {})
        ok, _why = reg.clearance(registry, [s]) if s in registry else (False, ["not in the registry"])
        lic[s] = {"license": src.get("license", {}).get("name"), "redistribution_status": src.get("redistribution_status", "not-evaluated"), "owner_confirmed": bool(src.get("owner_confirmed")),
                  "publishable": ok, "attribution": src.get("attribution")}
    c["license"] = {"sources": lic, "redistributable": all(v["publishable"] for v in lic.values()) if lic else False}
    c["taxonomies"] = {n: v["version"] for n, v in taxonomy.versions().items()}
    return c


def content_hash(content: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(content)).hexdigest()


def from_merged_entry(entry: Dict[str, Any], registry: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """A merged vulnerability entry (intel.vulns.merge) -> alert content. Entries without any identifier are advisories (CERT-EU)."""
    has_id = any(entry["ids"].values())
    obs = {}
    for sid, o in entry["sources"].items():
        obs[sid] = {"record": o["record"], "ids": o.get("ids") or {"cve": [], "euvd": [], "ghsa": []}, "evidence": o["evidence"], "dates": o["dates"], "severity": o.get("severity"), "epss": o.get("epss"),
                    "affected": o.get("affected", []), "fixes": o.get("fixes", []), "references": o.get("references", []), "summary": o.get("summary"), "title": o.get("title"), "extra": o.get("extra"),
                    "mentions": o.get("mentions") or []}
    expl = {sid: {k: e.get(k) for k in ("asserted", "since", "basis")} for sid, e in entry["exploitation"].items()}
    key = entry["key"] if has_id else sorted(obs.values(), key=lambda o: o["record"])[0]["record"]          # an advisory is keyed by its own number, not by 'source:record'
    return build_content(key, "vulnerability" if has_id else "advisory", obs, expl, entry.get("flags", []), registry)


def new_alert_id(content: Dict[str, Any]) -> str:
    return alert_id_for(content["key"])


def cleared_sources(content: Dict[str, Any], registry: Dict[str, Dict[str, Any]]) -> List[str]:
    return [s for s in content["observations"] if s in registry and reg.clearance(registry, [s])[0]]


def publish_view(alert: Dict[str, Any], registry: Dict[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The only shape that may leave the system: derived from the cleared observations alone. None when no contributing source is cleared."""
    keep = cleared_sources(alert, registry)
    if not keep:
        return None
    obs = {s: alert["observations"][s] for s in keep}
    expl = {s: alert["exploitation"]["per_source"][s] for s in keep}
    d = derive(alert["key"], alert["alert_type"], obs, expl, registry)
    d.update({
        "schema": SCHEMA_ALERT, "alert_id": alert["alert_id"], "record_version": alert["record_version"], "record_hash": alert["record_hash"], "observations": obs,
        "first_ingested_utc": alert.get("first_ingested_utc"), "last_changed_utc": alert.get("last_changed_utc"),
        "license": {"sources": {s: alert["license"]["sources"][s] for s in keep}, "withheld_sources": len(alert["observations"]) - len(keep), "redistributable": True},
        "taxonomies": alert["taxonomies"],
        "flags": [f for f in alert["flags"] if not any(w in f for w in alert["observations"] if w not in keep)],        # a flag may name a source that is withheld
    })
    d["validation"] = validate_content(d, obs)
    return d
