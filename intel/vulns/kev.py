"""CISA KEV in the unified per-source record. Additive: the existing `vulns` channel (kev-index.jsonl, validate_kev) is unchanged; this adds
`vuln-records.jsonl` next to it so KEV can be merged with the European sources."""
from __future__ import annotations
import json
from typing import Any, Dict, List

from .records import SCHEMA_VULN, evidence
from ..live import validate_kev

SOURCE_ID = "cisa-kev"


def records(raw: bytes, file: str, file_sha256: str, retrieved_at: str) -> List[Dict[str, Any]]:
    accepted, _rej, _meta = validate_kev(raw)
    items = json.loads(raw.decode("utf-8"))["vulnerabilities"]
    pos: Dict[str, int] = {}
    for i, it in enumerate(items):
        if isinstance(it, dict):
            pos.setdefault(str(it.get("cveID", "")).strip().upper(), i)
    out = []
    for r in accepted:
        i = pos[r["cve"]]
        out.append({
            "schema": SCHEMA_VULN, "source": SOURCE_ID, "source_record_id": r["cve"],
            "ids": {"cve": [r["cve"]], "euvd": [], "ghsa": []}, "mentions": [], "title": r["name"], "summary": r["name"], "assigner": None,
            "dates": {"published": None, "updated": None, "listed": r["date_added"]},
            "severity": None, "epss": None,
            "exploitation": {"asserted": True, "since": r["date_added"],
                             "basis": "cisa-kev-membership (the date is when CISA listed it, not when exploitation began)"},
            "kev": {"ransomware_use": r["ransomware_use"], "due_date": r.get("due_date")},
            "affected": [{"vendor": r["vendor"], "product": r["product"], "version": {"raw": None, "kind": "unspecified"}}], "fixes": [],
            "references": ["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
            "evidence": evidence(file, file_sha256, f"vulnerabilities[{i}]", items[i], retrieved_at),
        })
    return out
