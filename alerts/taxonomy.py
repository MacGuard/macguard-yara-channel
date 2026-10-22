"""Versioned taxonomies (config/alerts/taxonomies/*.json): sectors, regions, OS families, exposure, severity bands and a small curated
vendor/product map. A taxonomy file carries its name and version; a record or a match always says which it used."""
from __future__ import annotations
import functools
import hashlib
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "alerts", "taxonomies")
MAP_BASIS = "curated-mapping:technology-map@1"


@functools.lru_cache(maxsize=None)
def load(name: str) -> Dict[str, Any]:
    with open(os.path.join(DIR, name + ".json"), "rb") as f:
        raw = f.read()
    doc = json.loads(raw)
    if doc.get("schema") != "macguard.taxonomy/1" or doc.get("name") != name:
        raise ValueError(f"{name}: not a macguard.taxonomy/1 file named {name}")
    doc["sha256"] = hashlib.sha256(raw).hexdigest()
    return doc


def versions() -> Dict[str, Dict[str, Any]]:
    return {n: {"version": load(n)["version"], "sha256": load(n)["sha256"]} for n in ("sectors", "regions", "os-families", "exposure", "severity", "technology-map")}


def ids(name: str) -> List[str]:
    return [i["id"] for i in load(name)["items"]]


def slug(text: Any) -> str:
    """Lower case, accents kept out of the way, runs of anything that is not a letter or digit collapsed to one space."""
    return re.sub(r"[^a-z0-9.+]+", " ", str(text or "").lower()).strip()


# ---- regions -------------------------------------------------------------------------------------------------------------------
_COUNTRY = re.compile(r"^country:[A-Z]{2}$")


def valid_region(r: Any) -> bool:
    return isinstance(r, str) and (r in ids("regions") or bool(_COUNTRY.match(r)))


def region_matches(wanted: str, scopes: List[str]) -> bool:
    """A scope of ES also satisfies EU (a member state); EU does not satisfy ES; country:XX matches itself, and country:XX of an EU state matches EU."""
    eu = set(load("regions")["eu_member_states"])
    for s in scopes:
        if s == wanted:
            return True
        if wanted == "EU" and (s == "ES" or (s.startswith("country:") and s[8:] in eu)):
            return True
        if wanted == "ES" and s == "country:ES":
            return True
        if wanted == "OTHER" and s.startswith("country:") and s[8:] not in eu:
            return True
    return False


# ---- severity ------------------------------------------------------------------------------------------------------------------
BANDS = ["unknown", "none", "low", "medium", "high", "critical"]      # ascending; 'unknown' never satisfies a minimum


def band_of(score: Optional[float]) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def band_at_least(band: str, minimum: str) -> bool:
    return band != "unknown" and BANDS.index(band) >= BANDS.index(minimum)


# ---- vendor/product -> os, category --------------------------------------------------------------------------------------------
def classify(vendor: str, product: str) -> Dict[str, Any]:
    """{'os': [...], 'categories': [...], 'services': [...], 'basis': ...} from the curated map. Empty when nothing matches: no guessing."""
    v, p = slug(vendor), slug(product)
    os_, cats, services = [], [], []
    for rule in load("technology-map")["rules"]:
        m = rule["match"]
        if "vendor" in m and m["vendor"] != v:
            continue
        if "product_prefix" in m and not (p == m["product_prefix"] or p.startswith(m["product_prefix"] + " ")):
            continue
        if rule.get("os") and rule["os"] not in os_:
            os_.append(rule["os"])
        if rule.get("category") and rule["category"] not in cats:
            cats.append(rule["category"])
        if rule.get("service") and rule["service"] not in services:
            services.append(rule["service"])
    return {"os": os_, "categories": cats, "services": services, "basis": MAP_BASIS if (os_ or cats or services) else None}


# ---- exposure -------------------------------------------------------------------------------------------------------------------
def exposure_vectors(exposure_ids: List[str]) -> List[str]:
    wanted = set()
    items = {i["id"]: i for i in load("exposure")["items"]}
    for e in exposure_ids:
        wanted.update(items[e]["vectors"])
    return sorted(wanted)


def attack_vector(cvss_vector: Optional[str]) -> str:
    """network / adjacent / local / physical / unknown, from the AV metric of a CVSS 3.x or 4.0 vector the source gave."""
    if not cvss_vector:
        return "unknown"
    m = re.search(r"/AV:([NALP])", cvss_vector)
    return {"N": "network", "A": "adjacent", "L": "local", "P": "physical"}.get(m.group(1), "unknown") if m else "unknown"
