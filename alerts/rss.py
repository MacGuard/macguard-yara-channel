"""RSS 2.0 feeds, built with ElementTree (so every character is escaped by the library), plus a structural validator used by the tests and by
`scripts/validate_rss.py`.

Public feeds carry only the PUBLISH VIEW of alerts. Private feeds carry the matches of one subscription, one organisation or one person, behind a secret
token; they are sent with `Cache-Control: private, no-store`, `Referrer-Policy: no-referrer`, `X-Robots-Tag: noindex` so that no shared cache, search
engine or referrer header can leak them. An item's guid is the id of the notification event (match) in private feeds and `alert id + record version` in
public ones: a reader shows a new item when something material happened, not when a feed is re-fetched.
"""
from __future__ import annotations
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import format_datetime, parsedate_to_datetime
from typing import Any, Dict, List, Optional

ATOM = "http://www.w3.org/2005/Atom"
ET.register_namespace("atom", ATOM)
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
DEFAULT_BASE = "https://macguard.github.io/macguard-yara-channel/"
T = {
    "es": {"severity": "Severidad", "exploited": "Explotación conocida según", "not_asserted": "Ninguna fuente afirma explotación", "sources": "Fuentes", "why": "Por qué coincide", "new": "Nueva",
           "update": "Actualizada", "changes": "Cambios", "unknown": "desconocida", "attribution": "Atribución", "region": "Ámbito de la fuente"},
    "en": {"severity": "Severity", "exploited": "Known exploitation according to", "not_asserted": "No source asserts exploitation", "sources": "Sources", "why": "Why it matches", "new": "New",
           "update": "Updated", "changes": "Changes", "unknown": "unknown", "attribution": "Attribution", "region": "Source scope"},
}


def clean(s: Any, limit: int = 2000) -> str:
    return _CTRL.sub("", str(s if s is not None else ""))[:limit]


def reason_text(r: Dict[str, Any]) -> str:
    obs = r.get("observed")
    if isinstance(obs, dict):
        obs = ", ".join(f"{k}={v}" for k, v in obs.items() if v not in (None, [], ""))
    elif isinstance(obs, list):
        obs = ", ".join(map(str, obs[:5]))
    return clean(f"{r['field']} {r['op']} {r['expected']} -> {obs if obs not in (None, '') else '?'}" + (f" [{r['basis']}]" if r.get("basis") else ""), 300)


def alert_text(view: Dict[str, Any], lang: str, reasons: Optional[List[Dict[str, Any]]] = None, changes: Optional[List[str]] = None) -> str:
    t = T[lang]
    sev = view["severity"]
    lines = [clean(view["description"], 500) or clean(view["title"], 300)]
    lines.append(f"{t['severity']}: {sev['band']}" + (f" (CVSS {sev['score']}, {', '.join(sev['rated_by'])})" if sev["score"] else f" ({t['unknown']})"))
    ex = view["exploitation"]
    lines.append((f"{t['exploited']}: {', '.join(ex['asserted_by'])}" + (f" ({ex['earliest_since']})" if ex["earliest_since"] else "")) if ex["status"] == "exploited" else t["not_asserted"])
    lines.append(f"{t['sources']}: {', '.join(sorted(view['observations']))}")
    if view["region_scope"]:
        lines.append(f"{t['region']}: {', '.join(sorted({r['region'] for r in view['region_scope']}))}")
    if changes:
        lines.append(f"{t['changes']}: {', '.join(changes)}")
    if reasons:
        lines.append(t["why"] + ": " + "; ".join(reason_text(r) for r in reasons[:6]))
    att = sorted({a for s in view["license"]["sources"].values() for a in [s.get("attribution")] if a})
    if att:
        lines.append(f"{t['attribution']}: " + " | ".join(att))
    return "\n".join(lines)


def public_item(view: Dict[str, Any], base: str, lang: str) -> Dict[str, Any]:
    when = view.get("last_changed_utc") or view.get("first_ingested_utc")
    return {"guid": f"{view['alert_id']}:{view['record_version']}", "title": view["title"], "link": base.rstrip("/") + "/intelligence/alerts/alert.html?id=" + view["alert_id"],
            "description": alert_text(view, lang), "pub": datetime.strptime(when, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc), "categories": [view["severity"]["band"], view["alert_type"]] + (["exploited"] if view["exploitation"]["status"] == "exploited" else [])}


def match_item(view: Dict[str, Any], match: Dict[str, Any], base: str, lang: str) -> Dict[str, Any]:
    t = T[lang]
    return {"guid": match["match_id"], "title": f"[{t['new'] if match['kind'] == 'new' else t['update']}] {view['title']}", "link": base.rstrip("/") + "/intelligence/alerts/alert.html?id=" + view["alert_id"],
            "description": alert_text(view, lang, match.get("reasons"), match.get("changes")), "pub": datetime.strptime(match["created_utc"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc),
            "categories": [view["severity"]["band"]]}


def render_feed(title: str, description: str, link: str, self_url: Optional[str], items: List[Dict[str, Any]], now: datetime, *, lang: str = "es", ttl_minutes: int = 60) -> bytes:
    rss = ET.Element("rss", {"version": "2.0"})
    ch = ET.SubElement(rss, "channel")
    ET.SubElement(ch, "title").text = clean(title, 200)
    ET.SubElement(ch, "link").text = link
    ET.SubElement(ch, "description").text = clean(description, 1000)
    ET.SubElement(ch, "language").text = lang
    ET.SubElement(ch, "lastBuildDate").text = format_datetime(now.astimezone(timezone.utc), usegmt=True)
    ET.SubElement(ch, "ttl").text = str(ttl_minutes)
    ET.SubElement(ch, "generator").text = "MacGuard alerts 0.1"
    if self_url:
        ET.SubElement(ch, "{%s}link" % ATOM, {"href": self_url, "rel": "self", "type": "application/rss+xml"})
    for it in items:
        e = ET.SubElement(ch, "item")
        ET.SubElement(e, "title").text = clean(it["title"], 300)
        ET.SubElement(e, "link").text = it["link"]
        ET.SubElement(e, "description").text = clean(it["description"], 4000)
        ET.SubElement(e, "guid", {"isPermaLink": "false"}).text = clean(it["guid"], 200)
        ET.SubElement(e, "pubDate").text = format_datetime(it["pub"].astimezone(timezone.utc), usegmt=True)
        for c in it.get("categories", []):
            ET.SubElement(e, "category").text = clean(c, 80)
    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(rss, encoding="utf-8")


def validate_rss(xml: bytes) -> List[str]:
    """Structural problems of an RSS 2.0 document (empty = valid for what MacGuard promises)."""
    errs: List[str] = []
    text = xml.decode("utf-8")           # raises on a non-UTF-8 document
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        return ["a DTD or entity declaration"]
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as e:
        return [f"not well-formed XML: {e}"]
    if root.tag != "rss" or root.get("version") != "2.0":
        return ["the root must be <rss version=\"2.0\">"]
    ch = root.find("channel")
    if ch is None:
        return ["no <channel>"]
    for tag in ("title", "link", "description"):
        if ch.find(tag) is None or not (ch.find(tag).text or "").strip():
            errs.append(f"channel has no {tag}")
    try:
        parsedate_to_datetime(ch.findtext("lastBuildDate") or "")
    except (TypeError, ValueError):
        errs.append("channel lastBuildDate is not an RFC 822 date")
    seen = set()
    for i, it in enumerate(ch.findall("item")):
        g = it.findtext("guid")
        if not g:
            errs.append(f"item {i}: no guid")
        elif g in seen:
            errs.append(f"item {i}: duplicate guid {g}")
        seen.add(g)
        if not (it.findtext("title") or it.findtext("description")):
            errs.append(f"item {i}: neither title nor description")
        try:
            parsedate_to_datetime(it.findtext("pubDate") or "")
        except (TypeError, ValueError):
            errs.append(f"item {i}: pubDate is not an RFC 822 date")
        if not re.match(r"^https?://", it.findtext("link") or ""):
            errs.append(f"item {i}: link is not an http(s) URL")
        if _CTRL.search("".join(it.itertext())):
            errs.append(f"item {i}: control characters")
    return errs
