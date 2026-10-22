"""European vulnerability sources, end to end: download -> keep every original byte for byte -> validate -> unified records -> channel manifest.

  enisa-euvd            channel vulns-euvd    EUVD search API, a bounded recent window (default 3 days)
  enisa-euvd-exploited  channel vulns-eukev   EUVD search API with exploited=true: the EU's exploited list ('EU KEV')
  cert-eu-advisories    channel vulns-certeu  CERT-EU security advisories RSS (latest 10)

Downloaded does not mean publishable: the registry (redistribution status AND the owner's confirmation) decides, and an incomplete snapshot
(fewer pages than the API declares) is never publishable.
"""
from __future__ import annotations
import json
import math
import os
import shutil
import time
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlencode

from ..canonical import canonical_bytes, file_sha256
from ..channel import build_manifest, write_manifest
from ..fetch import FetchError, fetch
from . import certeu, euvd

EUVD_BASE = "https://euvdservices.enisa.europa.eu"
CERTEU_URL = "https://cert.europa.eu/publications/security-advisories-rss"
PAGE = 100
SOURCES = {
    "enisa-euvd": {"channel": "vulns-euvd", "kind": "euvd-window"},
    "enisa-euvd-exploited": {"channel": "vulns-eukev", "kind": "euvd-exploited"},
    "cert-eu-advisories": {"channel": "vulns-certeu", "kind": "rss"},
}


def _iso(now: datetime) -> str:
    return now.strftime("%Y-%m-%dT%H:%M:%SZ")


def _page_url(base: str, spec_kind: str, page: int, now: datetime, window_days: int) -> str:
    q: Dict[str, Any] = {"size": PAGE, "page": page}
    if spec_kind == "euvd-exploited":
        q["exploited"] = "true"
    else:
        q["fromDate"] = (now - timedelta(days=window_days)).strftime("%Y-%m-%d")
        q["toDate"] = now.strftime("%Y-%m-%d")
    return f"{base}/api/search?{urlencode(q)}"


def build_eu(source_id: str, root: str, version: int, registry: Dict[str, Dict[str, Any]], now: datetime, *, base_url: Optional[str] = None,
             window_days: int = 3, max_pages: int = 60, pause: float = 1.0, previous: Optional[Dict[str, Any]] = None, allow_http_localhost: bool = False,
             timeout: int = 60, sleep: Callable[[float], None] = time.sleep) -> Dict[str, Any]:
    spec = SOURCES.get(source_id)
    if spec is None:
        raise FetchError(f"no European adapter for '{source_id}' (wired: {', '.join(sorted(SOURCES))})")
    src = registry.get(source_id)
    if src is None:
        raise FetchError(f"{source_id} is not in the source registry")
    out = os.path.join(root, spec["channel"], str(version))
    if os.path.lexists(out):
        raise FetchError(f"{out} already exists: a version directory is never reused")
    retrievals: List[Dict[str, Any]] = []
    originals = set()
    records: List[Dict[str, Any]] = []
    rejected: Dict[str, int] = {}
    warnings: Dict[str, int] = {}
    complete, incomplete_reason, declared_total, pages_got, items_read = True, None, None, 0, 0
    try:
        if spec["kind"] == "rss":
            rec = fetch(base_url or CERTEU_URL, out, "security-advisories.rss.xml", src, timeout=timeout, allow_http_localhost=allow_http_localhost, now=_iso(now))
            retrievals.append(rec)
            originals.add(rec["file"])
            with open(os.path.join(out, rec["file"]), "rb") as f:
                raw = f.read()
            records, rejected, meta = certeu.parse_feed(raw, source_id, rec["file"], rec["sha256"], rec["retrieved_at"], now)
            pages_got, items_read = 1, meta["input_items"]
        else:
            base = base_url or EUVD_BASE
            page, needed = 0, 1
            while page < needed:
                if page >= max_pages:
                    complete, incomplete_reason = False, f"stopped at the {max_pages}-page limit; the API declares {declared_total} records ({needed} pages)"
                    break
                if page:
                    sleep(pause)
                fn = f"euvd-page-{page:04d}.json"
                rec = fetch(_page_url(base, spec["kind"], page, now, window_days), out, fn, src, timeout=timeout, allow_http_localhost=allow_http_localhost, now=_iso(now))
                retrievals.append(rec)
                originals.add(fn)
                with open(os.path.join(out, fn), "rb") as f:
                    raw = f.read()
                recs, rej, meta = euvd.parse_page(raw, source_id, fn, rec["sha256"], rec["retrieved_at"], now, require_exploited=(spec["kind"] == "euvd-exploited"))
                if page == 0:
                    declared_total = meta["declared_total"]
                    if declared_total is None:
                        raise FetchError("the EUVD answer does not declare a total: completeness cannot be checked")
                    needed = max(1, math.ceil(declared_total / PAGE))
                if meta["input_items"] == 0 and page < needed - 1:
                    complete, incomplete_reason = False, f"page {page} was empty before the declared {needed} pages"
                    break
                records += recs
                items_read += meta["input_items"]
                for k, v in rej.items():
                    rejected[k] = rejected.get(k, 0) + v
                for k, v in meta["warnings"].items():
                    warnings[k] = warnings.get(k, 0) + v
                pages_got += 1
                page += 1
            # the same record can show up on two pages when the database changes while we page: keep the most recently updated, count the rest
            best: Dict[str, Dict[str, Any]] = {}
            for r in records:
                k = r["source_record_id"]
                if k in best:
                    rejected["duplicate-across-pages"] = rejected.get("duplicate-across-pages", 0) + 1
                    if (r["dates"]["updated"] or "") <= (best[k]["dates"]["updated"] or ""):
                        continue
                best[k] = r
            records = sorted(best.values(), key=lambda r: r["source_record_id"])
            if complete and declared_total is not None and len(records) + sum(rejected.values()) < declared_total:
                complete, incomplete_reason = False, f"collected {len(records)} accepted and {sum(rejected.values())} rejected records, the API declared {declared_total}"
        with open(os.path.join(out, "vuln-records.jsonl"), "wb") as f:
            for r in records:
                f.write(canonical_bytes(r) + b"\n")
        stats: Dict[str, Any] = {"input_items": items_read, "accepted": len(records), "rejected": sum(rejected.values()), "rejected_by_reason": dict(sorted(rejected.items())), "warnings": dict(sorted(warnings.items())),
                                 "pages": pages_got, "declared_total": declared_total, "complete": complete, "incomplete_reason": incomplete_reason,
                                 "exploitation_asserted": sum(1 for r in records if r["exploitation"]["asserted"]), "window_days": window_days if spec["kind"] == "euvd-window" else None}
        with open(os.path.join(out, "build-report.json"), "wb") as f:
            f.write(canonical_bytes(stats) + b"\n")
        manifest = build_manifest(spec["channel"], "vulns", version, out, [source_id], registry, _iso(now), previous=previous, stats=stats, originals=originals)
    except BaseException:
        shutil.rmtree(out, ignore_errors=True)   # never leave a half-built channel behind
        raise
    if not complete:
        manifest["approval"]["publishable"] = False
        manifest["approval"]["blocking_reasons"].append(f"incomplete snapshot: {incomplete_reason}")
    write_manifest(manifest, out)
    return {"source": source_id, "channel": spec["channel"], "version": version, "dir": out, "retrievals": [{k: r[k] for k in ("url", "bytes", "sha256", "retrieved_at")} for r in retrievals],
            "stats": stats, "publishable": manifest["approval"]["publishable"], "blocking_reasons": manifest["approval"]["blocking_reasons"]}


def load_records(channel_dir: str) -> List[Dict[str, Any]]:
    p = os.path.join(channel_dir, "vuln-records.jsonl")
    out = []
    with open(p, "rb") as f:
        for line in f:
            if line.strip():
                out.append(json.loads(line))
    return out


def snapshot_of(channel_dir: str, source_id: str, max_age_days: Optional[int]) -> Dict[str, Any]:
    """The retrieval time of the newest original in a channel directory: what the merge step uses to decide staleness."""
    newest = None
    for fn in sorted(os.listdir(channel_dir)):
        if fn.endswith(".retrieval.json"):
            with open(os.path.join(channel_dir, fn), "rb") as f:
                t = json.loads(f.read())["retrieved_at"]
            newest = t if newest is None or t > newest else newest
    return {"source": source_id, "retrieved_at": newest, "max_age_days": max_age_days, "manifest_sha256": file_sha256(os.path.join(channel_dir, "manifest.json"))}


__all__ = ["build_eu", "load_records", "snapshot_of", "SOURCES"]
