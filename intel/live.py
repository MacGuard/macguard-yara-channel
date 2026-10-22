"""Real sources, end to end: download -> keep the original -> validate -> build the channel directory and its manifest.

Two sources are wired today, both reachable without credentials and with a licence verdict of 'allowed with conditions' in the matrix:

  abusech-feodo  abuse.ch Feodo Tracker botnet C2 IP list   -> channel 'ioc'   (derived IOC records + the original file)
  cisa-kev       CISA Known Exploited Vulnerabilities       -> channel 'vulns' (derived CVE index + the original file)

Wired means: download, validate, count accepted and rejected, build a manifest. It does NOT mean published: publication needs the owner's
confirmation in the registry and a signing workflow, neither of which exists yet (the manifest says so in approval.blocking_reasons).
"""
from __future__ import annotations
import json
import os
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import ioc, registry as reg
from .canonical import canonical_bytes
from .channel import build_manifest, write_manifest
from .fetch import FetchError, fetch

SOURCES = {
    "abusech-feodo": {"url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json", "filename": "feodo-ipblocklist.json", "channel": "ioc", "family": "ioc"},
    "cisa-kev": {"url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "filename": "known_exploited_vulnerabilities.json", "channel": "vulns", "family": "vulns"},
}
CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def parse_feodo(raw: bytes) -> Iterable[Dict[str, Any]]:
    """Feodo Tracker JSON: a list of {ip_address, port, status, malware, first_seen, last_online, ...}."""
    try:
        rows = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise FetchError("the Feodo file is not valid JSON")
    if not isinstance(rows, list):
        raise FetchError("the Feodo file is not a list")
    for r in rows:
        if not isinstance(r, dict):
            yield {"value": "", "kind": None, "_error": "not an object"}
            continue
        online = str(r.get("status", "")).lower() == "online"
        seen = r.get("last_online") or (r.get("first_seen") or "").split(" ")[0] or None
        yield {"value": str(r.get("ip_address") or ""), "kind": "ip", "seen": (seen + "T00:00:00Z") if seen and "T" not in seen else seen,
               "confidence": 90 if online else 60, "tags": ["c2", "online" if online else "offline", f"port:{r.get('port')}"] if r.get("port") else ["c2"],
               "family": r.get("malware"), "ref": "https://feodotracker.abuse.ch/browse/host/" + str(r.get("ip_address") or "")}


def validate_kev(raw: bytes) -> Tuple[List[Dict[str, Any]], Dict[str, int], Dict[str, Any]]:
    """Returns (accepted records, rejected counts by reason, meta). A record is accepted only if it is complete and its CVE id is unique."""
    try:
        doc = json.loads(raw.decode("utf-8"))
        items = doc["vulnerabilities"]
    except (ValueError, KeyError, UnicodeDecodeError, TypeError):
        raise FetchError("the CISA KEV file is not the expected JSON (no 'vulnerabilities' list)")
    if not isinstance(items, list):
        raise FetchError("'vulnerabilities' is not a list")
    accepted: List[Dict[str, Any]] = []
    rejected: Dict[str, int] = {}
    seen = set()

    def rej(reason: str) -> None:
        rejected[reason] = rejected.get(reason, 0) + 1
    for it in items:
        if not isinstance(it, dict):
            rej("not-an-object")
            continue
        cve = str(it.get("cveID", "")).strip().upper()
        if not CVE.match(cve):
            rej("invalid-cve-id")
            continue
        if cve in seen:
            rej("duplicate-cve-id")
            continue
        try:
            added = datetime.strptime(str(it.get("dateAdded", "")), "%Y-%m-%d").strftime("%Y-%m-%d")
        except ValueError:
            rej("invalid-date-added")
            continue
        vendor, product = str(it.get("vendorProject") or "").strip(), str(it.get("product") or "").strip()
        if not vendor or not product:
            rej("missing-vendor-or-product")
            continue
        seen.add(cve)
        rec = {"cve": cve, "vendor": vendor, "product": product, "name": str(it.get("vulnerabilityName") or "")[:300], "date_added": added,
               "ransomware_use": str(it.get("knownRansomwareCampaignUse") or "Unknown")}
        due = str(it.get("dueDate") or "")
        if due:
            try:
                rec["due_date"] = datetime.strptime(due, "%Y-%m-%d").strftime("%Y-%m-%d")
            except ValueError:
                rej("invalid-due-date-kept-without-it")
        accepted.append(rec)
    accepted.sort(key=lambda r: r["cve"])
    declared = doc.get("count")
    meta = {"catalog_version": str(doc.get("catalogVersion", "")), "date_released": str(doc.get("dateReleased", "")), "declared_count": declared if isinstance(declared, int) else None,
            "input_items": len(items)}
    return accepted, dict(sorted(rejected.items())), meta


def build_live(source_id: str, root: str, version: int, registry: Dict[str, Dict[str, Any]], now: datetime, *, url: Optional[str] = None,
               previous: Optional[Dict[str, Any]] = None, allow_http_localhost: bool = False, timeout: int = 60) -> Dict[str, Any]:
    spec = SOURCES.get(source_id)
    if spec is None:
        raise FetchError(f"no live adapter for '{source_id}' (wired: {', '.join(sorted(SOURCES))})")
    src = registry.get(source_id)
    if src is None:
        raise FetchError(f"{source_id} is not in the source registry")
    out = os.path.join(root, spec["channel"], str(version))
    rec = fetch(url or spec["url"], out, spec["filename"], src, timeout=timeout, allow_http_localhost=allow_http_localhost, now=ioc.iso(now))
    with open(os.path.join(out, spec["filename"]), "rb") as f:
        raw = f.read()
    if source_id == "abusech-feodo":
        records, report = ioc.build([(source_id, it) for it in parse_feodo(raw)], registry, now)
        for t in sorted({r["type"] for r in records}):
            with open(os.path.join(out, f"ioc-{t}.jsonl"), "wb") as f:
                for r in [x for x in records if x["type"] == t]:
                    f.write(canonical_bytes(r) + b"\n")
        accepted, rejected = report["published"], sum(report["dropped"].values())
        stats = dict(report, accepted=accepted, rejected=rejected, rejected_by_reason=report["dropped"])
    else:
        recs, rejected_by, meta = validate_kev(raw)
        with open(os.path.join(out, "kev-index.jsonl"), "wb") as f:
            for r in recs:
                f.write(canonical_bytes(r) + b"\n")
        from .vulns import kev as kev_unified   # additive: the same records in the unified per-source format, for the cross-source merge
        with open(os.path.join(out, "vuln-records.jsonl"), "wb") as f:
            for r in kev_unified.records(raw, spec["filename"], rec["sha256"], rec["retrieved_at"]):
                f.write(canonical_bytes(r) + b"\n")
        stats = {"accepted": len(recs), "rejected": sum(rejected_by.values()), "rejected_by_reason": rejected_by, **meta,
                 "count_matches_declared": meta["declared_count"] == meta["input_items"]}
    with open(os.path.join(out, "build-report.json"), "wb") as f:
        f.write(canonical_bytes(stats) + b"\n")
    manifest = build_manifest(spec["channel"], spec["family"], version, out, [source_id], registry, ioc.iso(now), previous=previous, stats=stats,
                              originals={spec["filename"]})
    write_manifest(manifest, out)
    return {"source": source_id, "channel": spec["channel"], "version": version, "dir": out, "retrieval": rec, "stats": stats,
            "publishable": manifest["approval"]["publishable"], "blocking_reasons": manifest["approval"]["blocking_reasons"]}
