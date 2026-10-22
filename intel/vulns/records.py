"""The per-source vulnerability record (macguard.vuln-record/1). One record says what ONE source says about one advisory, and where the
evidence is; records from different sources are never overwritten by each other (see merge.py).

Two things are kept apart on purpose:
  severity     how bad the source rates it (CVSS, EPSS). Never evidence of exploitation.
  exploitation whether THIS source asserts that it is exploited, from a structured field of the source (never from the word 'critical',
               never from free text). 'asserted: false' means 'this source does not say', not 'not exploited'.
"""
from __future__ import annotations
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import json

from ..canonical import sha256_hex

SCHEMA_VULN = "macguard.vuln-record/1"
_EN_DATE = ("%b %d, %Y, %I:%M:%S %p", "%b %d, %Y, %I:%M %p")


def parse_date(raw: object) -> Optional[str]:
    """A calendar date 'YYYY-MM-DD' from the shapes the sources use, or None. Time zone is not documented by every source, so only the date is kept."""
    if not isinstance(raw, str):
        return None
    s = raw.strip()
    if not s:
        return None
    for fmt in _EN_DATE:
        try:
            return datetime.strptime(s, fmt).strftime("%Y-%m-%d")
        except ValueError:
            pass
    m = re.match(r"^(\d{4}-\d{2}-\d{2})(?:[T ].*)?$", s)
    if m:
        try:
            return datetime.strptime(m.group(1), "%Y-%m-%d").strftime("%Y-%m-%d")
        except ValueError:
            return None
    return None


def today_of(now: datetime) -> str:
    return now.strftime("%Y-%m-%d")


def clean_refs(raw: object, limit: int = 20) -> List[str]:
    """http(s) references only, de-duplicated, bounded."""
    if isinstance(raw, str):
        toks = re.split(r"[\s]+", raw)
    elif isinstance(raw, list):
        toks = [str(x) for x in raw]
    else:
        return []
    out: List[str] = []
    for t in toks:
        t = t.strip()
        if re.match(r"^https?://[^\s<>\"']{4,500}$", t) and t not in out:
            out.append(t)
        if len(out) >= limit:
            break
    return out


def number_text(x: object) -> Optional[str]:
    """Canonical JSON has no floats, so ratings travel as decimal text ('8.4', '0.76')."""
    if isinstance(x, bool) or not isinstance(x, (int, float)):
        return None
    return str(x)


def severity(score: object, version: object, vector: object, source: str) -> Optional[Dict[str, Any]]:
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= float(score) <= 10:
        return None
    return {"scheme": "cvss", "version": str(version) if version else None, "score": str(round(float(score), 1)),
            "vector": str(vector)[:200] if isinstance(vector, str) and vector.startswith("CVSS:") else None, "rated_by": source,
            "note": "a severity rating is not evidence of exploitation"}


def evidence(file: str, file_sha256: str, locator: str, item: Any, retrieved_at: str) -> Dict[str, Any]:
    """Where the statement can be re-checked: the original file kept byte for byte, the position, and the hash of the raw item."""
    return {"file": file, "file_sha256": file_sha256, "locator": locator, "item_sha256": sha256_hex(json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")), "retrieved_at": retrieved_at}


def no_exploitation(basis: str) -> Dict[str, Any]:
    return {"asserted": False, "since": None, "basis": basis}


def validate_record(rec: Dict[str, Any]) -> List[str]:
    """Structural check used by the tests and by the merge step before it trusts a record read from disk."""
    errs: List[str] = []
    if rec.get("schema") != SCHEMA_VULN:
        errs.append("schema")
    for k in ("source", "source_record_id", "ids", "dates", "exploitation", "evidence"):
        if k not in rec:
            errs.append(f"missing {k}")
    ex = rec.get("exploitation", {})
    if ex.get("asserted") is True and not ex.get("basis"):
        errs.append("an exploitation assertion needs a basis")
    if ex.get("asserted") is True and not ex.get("since"):
        errs.append("an exploitation assertion needs a date")
    if ex.get("asserted") is False and ex.get("since"):
        errs.append("a source that does not assert exploitation cannot carry an exploitation date")
    return errs


def sort_key(rec: Dict[str, Any]) -> Tuple[str, str]:
    return rec["source"], rec["source_record_id"]
