"""CERT-EU security advisories (RSS, https://cert.europa.eu/publications/security-advisories-rss).

The feed carries the latest 10 advisories: title, link, free-text description, date. It has NO structured identifiers, severity or exploitation
fields. So, deliberately:
  * identifiers found in the text are recorded as MENTIONS, not as the advisory's own ids and never as aliases (a text may name several CVEs);
  * exploitation is never read from the prose ('is aware of active exploitation' is a sentence, not a field). `asserted` is always false and the
    basis says why. The advisory is kept as a reference that points at the vendor and at CERT-EU's own page.
"""
from __future__ import annotations
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Tuple

from . import ids
from .records import SCHEMA_VULN, evidence, no_exploitation, today_of
from ..fetch import FetchError

_ADV = re.compile(r"^(\d{4}-\d{3,4})\b")
_LINK = re.compile(r"^https://cert\.europa\.eu/publications/security-advisories/(\d{4}-\d{3,4})/?$")


def _text(el: Any) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", (el.text or "") if el is not None else "")).strip()


def parse_feed(raw: bytes, source_id: str, file: str, file_sha256: str, retrieved_at: str, now: datetime) -> Tuple[List[Dict[str, Any]], Dict[str, int], Dict[str, Any]]:
    try:
        upper = raw.decode("utf-8").upper()
    except UnicodeDecodeError:
        raise FetchError("the CERT-EU feed is not UTF-8: refused (the DTD check would be blind to other encodings)")
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise FetchError("the CERT-EU feed declares a DTD/entity: refused (entity expansion); the standard library parser is not hardened against it")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        raise FetchError("the CERT-EU feed is not valid XML")
    if root.tag != "rss":
        raise FetchError("the CERT-EU feed is not an RSS document")
    items = root.findall("./channel/item")
    out: List[Dict[str, Any]] = []
    rejected: Dict[str, int] = {}
    seen = set()
    today = today_of(now)

    def rej(r: str) -> None:
        rejected[r] = rejected.get(r, 0) + 1
    for pos, it in enumerate(items):
        title, link, desc = _text(it.find("title")), _text(it.find("link")), _text(it.find("description"))
        m = _ADV.match(title)
        lm = _LINK.match(link)
        if not m or not lm or m.group(1) != lm.group(1):
            rej("title-and-link-do-not-agree-on-the-advisory-number")
            continue
        adv = m.group(1)
        if adv in seen:
            rej("duplicate-advisory")
            continue
        try:
            d = parsedate_to_datetime(_text(it.find("pubDate"))).strftime("%Y-%m-%d")
        except (TypeError, ValueError):
            rej("invalid-pubDate")
            continue
        if d > today:
            rej("published-in-the-future")
            continue
        seen.add(adv)
        ment = ids.mentions(title + " " + desc)
        out.append({
            "schema": SCHEMA_VULN, "source": source_id, "source_record_id": f"CERT-EU-{adv}",
            "ids": {"cve": [], "euvd": [], "ghsa": []}, "mentions": [{"kind": k, "id": v} for k, v in ment],
            "title": title[:200], "summary": desc[:280], "assigner": None, "dates": {"published": d, "updated": None},
            "severity": None, "epss": None,
            "exploitation": no_exploitation("CERT-EU advisories have no structured exploitation field; prose is not read as an assertion"),
            "affected": [], "fixes": [], "references": [link], "evidence": evidence(file, file_sha256, f"channel/item[{pos}]", {"title": title, "link": link, "description": desc}, retrieved_at),
        })
    out.sort(key=lambda r: r["source_record_id"])
    return out, dict(sorted(rejected.items())), {"input_items": len(items)}
