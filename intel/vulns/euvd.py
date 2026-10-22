"""ENISA European Vulnerability Database (EUVD): parser and validator for the public JSON API (https://euvdservices.enisa.europa.eu/api/...).

Two registry sources use this parser:
  enisa-euvd          the general database (a bounded recent window; the full database is large and the API is not built for bulk use)
  enisa-euvd-exploited  the EUVD 'exploited' list (the nearest thing to an 'EU KEV'): vulnerabilities carrying an `exploitedSince` date

What the data does and does not say (checked against the live API on 2026-10-22):
  * `exploitedSince` is the only exploitation field. The API does not say WHO observed the exploitation. Public analyses report that the list is largely
    fed by the CISA KEV catalog, so an EUVD exploitation flag is NOT an independent second confirmation of a CISA KEV entry. We record it as this
    source's assertion with basis 'enisa-exploitedSince' and independence 'unknown'.
  * `baseScore`, `epss` and criticality are severity. They never make a record 'exploited'.
  * `product_version` is free text; versions.parse_affected understands a few shapes and keeps the rest verbatim.
"""
from __future__ import annotations
import json
from datetime import datetime
from typing import Any, Dict, List, Tuple

from . import ids, versions
from .records import SCHEMA_VULN, clean_refs, evidence, no_exploitation, number_text, parse_date, severity, today_of
from ..fetch import FetchError

MAX_ITEMS_PER_PAGE = 100


def page_items(raw: bytes) -> Tuple[List[Any], Any]:
    """(items, declared total) of one search page. A list answer (the /last, /exploited, /critical endpoints) has no total."""
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise FetchError("the EUVD answer is not valid JSON")
    if isinstance(doc, list):
        return doc, None
    if isinstance(doc, dict) and isinstance(doc.get("items"), list):
        total = doc.get("total")
        return doc["items"], total if isinstance(total, int) and not isinstance(total, bool) else None
    raise FetchError("the EUVD answer has neither a list nor an 'items' list")


def _affected(item: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for p in item.get("enisaIdProduct") or []:
        if not isinstance(p, dict):
            continue
        prod = p.get("product") if isinstance(p.get("product"), dict) else {}
        vend = prod.get("vendor") if isinstance(prod.get("vendor"), dict) else {}
        out.append({"vendor": str(vend.get("name") or "").strip()[:120], "product": str(prod.get("name") or "").strip()[:160],
                    "version": versions.parse_affected(p.get("product_version"))})
        if len(out) >= 200:
            break
    return out


def parse_page(raw: bytes, source_id: str, file: str, file_sha256: str, retrieved_at: str, now: datetime, *, require_exploited: bool = False,
               locator_prefix: str = "items") -> Tuple[List[Dict[str, Any]], Dict[str, int], Dict[str, Any]]:
    """(records, rejected counts by reason, meta). Every accepted record points back into the original page file."""
    items, total = page_items(raw)
    out: List[Dict[str, Any]] = []
    rejected: Dict[str, int] = {}
    warnings: Dict[str, int] = {}
    seen = set()
    today = today_of(now)

    def rej(r: str) -> None:
        rejected[r] = rejected.get(r, 0) + 1

    def warn(r: str) -> None:
        warnings[r] = warnings.get(r, 0) + 1
    for pos, it in enumerate(items):
        if not isinstance(it, dict):
            rej("not-an-object")
            continue
        own = ids.normalise(it.get("id"))
        if own is None or own[0] != "euvd":
            rej("invalid-euvd-id")
            continue
        if own[1] in seen:
            rej("duplicate-euvd-id")
            continue
        aliases, bad = ids.split_aliases(it.get("aliases"))
        if bad:
            warn("alias-not-an-identifier-dropped")
        published, updated = parse_date(it.get("datePublished")), parse_date(it.get("dateUpdated"))
        if it.get("datePublished") and published is None:
            rej("invalid-date")
            continue
        if published and published > today:
            rej("published-in-the-future")
            continue
        if published and updated and updated < published:
            warn("updated-before-published")
        since_raw = it.get("exploitedSince")
        since = parse_date(since_raw)
        if since_raw not in (None, "") and since is None:
            rej("invalid-exploitedSince")
            continue
        if since and since > today:
            rej("exploitedSince-in-the-future")
            continue
        if require_exploited and not since:
            rej("exploited-list-entry-without-exploitedSince")
            continue
        sev = severity(it.get("baseScore"), it.get("baseScoreVersion"), it.get("baseScoreVector"), "enisa-euvd")
        if it.get("baseScore") is not None and sev is None:
            warn("score-out-of-range-dropped")
        epss = it.get("epss")
        seen.add(own[1])
        by_kind: Dict[str, List[str]] = {"cve": [], "euvd": [own[1]], "ghsa": []}
        for kind, val in aliases:
            if val not in by_kind[kind]:
                by_kind[kind].append(val)
        aff = _affected(it)
        fixes = [{"product": a["product"], "vendor": a["vendor"], "fixed_in": a["version"]["fixed_in"], "basis": "vendor-text-in-enisa-product_version",
                  "scheme": "unknown"} for a in aff if a["version"].get("fixed_in")]
        desc = str(it.get("description") or "")
        out.append({
            "schema": SCHEMA_VULN, "source": source_id, "source_record_id": own[1], "ids": by_kind, "mentions": [],
            "summary": desc[:280], "assigner": str(it.get("assigner") or "")[:80] or None,
            "dates": {"published": published, "updated": updated},
            "severity": sev, "epss": number_text(epss) if isinstance(epss, (int, float)) and not isinstance(epss, bool) and 0 <= epss <= 100 else None,
            "exploitation": ({"asserted": True, "since": since, "basis": "enisa-exploitedSince (the API does not say who observed the exploitation; independence from CISA KEV unknown)"}
                             if since else no_exploitation("the EUVD record has no exploitedSince")),
            "affected": aff, "fixes": fixes, "references": clean_refs(it.get("references")),
            "evidence": evidence(file, file_sha256, f"{locator_prefix}[{pos}]", it, retrieved_at),
        })
    out.sort(key=lambda r: r["source_record_id"])
    meta = {"input_items": len(items), "declared_total": total, "warnings": dict(sorted(warnings.items()))}
    return out, dict(sorted(rejected.items())), meta
