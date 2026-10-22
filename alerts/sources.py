"""Adapters from MacGuard's own data to alert contents. Two exist:

  vulnerability channels (intel vulns build ...)  ->  merge  ->  one alert per vulnerability (CISA KEV, ENISA EUVD, EUVD exploited list, CERT-EU)
  the YARA release log (logs/log.jsonl)            ->  one 'rule-release' alert per published release (first-party metadata only)

Anything else in the source list of the brief (OSV, NVD, CCN-CERT, Debian/Ubuntu/Red Hat bulletins, ThreatFox/URLhaus/MalwareBazaar, Sigma) has NO adapter
here and is reported as pending by `source_catalog`.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from intel import registry as reg
from intel.canonical import canonical_bytes
from intel.vulns import live_eu, merge as vmerge

from . import model

IMPLEMENTED = {"cisa-kev": "vulnerability channel", "enisa-euvd": "vulnerability channel", "enisa-euvd-exploited": "vulnerability channel", "cert-eu-advisories": "vulnerability channel",
               "macguard-yara-releases": "release log"}
SITE = "https://macguard.github.io/macguard-yara-channel/"


def vulnerability_contents(channel_dirs: List[str], registry: Dict[str, Dict[str, Any]], now: datetime) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """(alert contents, source_runs for engine.ingest, merge result)."""
    recs: List[Dict[str, Any]] = []
    snaps: Dict[str, Dict[str, Any]] = {}
    runs: List[Dict[str, Any]] = []
    for d in channel_dirs:
        d = os.path.abspath(d)
        man = json.load(open(os.path.join(d, "manifest.json"), encoding="utf-8"))
        if man["channel"]["family"] != "vulns":
            raise ValueError(f"{d} is not a vulnerabilities channel")
        rs = live_eu.load_records(d)
        recs += rs
        for s in man["sources"]:
            sid = s["id"]
            snap = live_eu.snapshot_of(d, sid, registry.get(sid, {}).get("max_snapshot_age_days"))
            snaps[sid] = snap
            stats = man.get("stats", {})
            runs.append({"source_id": sid, "retrieved_utc": snap["retrieved_at"], "status": "ok" if stats.get("complete", True) else "partial", "records_in": stats.get("input_items", len(rs)),
                         "accepted": stats.get("accepted", len(rs)), "rejected": stats.get("rejected", 0), "manifest_sha256": snap["manifest_sha256"],
                         "error": None if stats.get("complete", True) else stats.get("incomplete_reason")})
    merged = vmerge.merge(recs, snaps, now, registry)
    return [model.from_merged_entry(e, registry) for e in merged["entries"]], runs, merged


_TAG = re.compile(r"release (rules-\d{8}-\d+)")


def yara_release_contents(log_path: str, registry: Dict[str, Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    sid = "macguard-yara-releases"
    out, newest = [], None
    with open(log_path, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            e = json.loads(line)
            if e.get("event") != "release.published":
                continue
            m = _TAG.search(e.get("message", ""))
            if not m:
                continue
            tag, when = m.group(1), e["time"]
            newest = max(newest or when, when)
            url = (e.get("details") or {}).get("run_url")
            item = {"tag": tag, "time": when, "message": e["message"], "run_url": url}
            obs = {"record": tag, "ids": {"cve": [], "euvd": [], "ghsa": []},
                   "evidence": {"file": "logs/log.jsonl", "file_sha256": hashlib.sha256(canonical_bytes(item)).hexdigest(), "locator": f"seq={e.get('seq')}", "item_sha256": hashlib.sha256(canonical_bytes(item)).hexdigest(),
                                "retrieved_at": when},
                   "dates": {"published": when[:10], "updated": None}, "severity": None, "epss": None, "affected": [], "fixes": [],
                   "references": [SITE + "releases.html"] + ([url] if url else []), "summary": e["message"], "title": f"YARA rules release {tag} published", "extra": None, "mentions": []}
            out.append(model.build_content("YARA-" + tag, "rule-release", {sid: obs}, {sid: {"asserted": False, "since": None, "basis": "not applicable: a release is not a vulnerability"}}, [], registry))
    return out, [{"source_id": sid, "retrieved_utc": newest, "status": "ok", "records_in": len(out), "accepted": len(out), "rejected": 0}]


def source_catalog(registry: Dict[str, Dict[str, Any]], status: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Every source of the brief with what exists today. 'pending' means no adapter; it is never shown as active."""
    wanted = ["cisa-kev", "enisa-euvd", "enisa-euvd-exploited", "osv", "nvd", "cert-eu-advisories", "ccn-cert", "debian-security-tracker", "ubuntu-security-notices", "redhat-security-data",
              "abusech-bulk", "sigmahq", "macguard-yara-releases", "incibe-cert"]
    rows = []
    for sid in wanted:
        s = registry.get(sid)
        if s is None:
            rows.append({"id": sid, "operational_state": "pending", "reason": "not in the source registry"})
            continue
        ok, why = reg.clearance(registry, [sid])
        st = status.get(sid, {})
        implemented = sid in IMPLEMENTED
        if not implemented:
            state = "blocked" if s["redistribution_status"] == "blocked" else "pending"
        else:
            state = {"fresh": "active", "stale": "stale", "never-imported": "implemented-no-data"}.get(st.get("state", "never-imported"), "implemented-no-data")
        rows.append({"id": sid, "name": s["name"], "region": s.get("region"), "endpoint": s["upstream_url"], "operational_state": state, "adapter": IMPLEMENTED.get(sid),
                     "license": s["license"].get("name"), "redistribution_status": s["redistribution_status"], "owner_confirmed": bool(s.get("owner_confirmed")), "publishable": ok,
                     "blocking_reasons": why, "format": {"vulnerability channel": "JSON API / RSS", "release log": "JSON lines"}.get(IMPLEMENTED.get(sid), "not integrated"),
                     "update_expectation_days": s.get("max_snapshot_age_days"), "freshness": {k: st.get(k) for k in ("state", "last_ok_retrieved_utc", "age_days", "failed_runs_since_last_ok", "alerts")} if st else None,
                     "note": s.get("status_note")})
    return rows
