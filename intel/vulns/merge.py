"""Cross-source merge: one entry per vulnerability, with what EACH source says kept side by side (nothing is overwritten or averaged).

Rules (each one has a test):
  * Records are joined only through identifiers a source declares as its OWN (id and aliases): CVE, EUVD, GHSA. Identifiers found in free text
    (mentions), in reference URLs, or implied by a similar product name never join records.
  * A merged entry holds at most one CVE. A record that would bridge two different CVEs (an alias list naming two CVEs, or a GHSA that two records
    attach to different CVEs) is NOT merged: it stays alone, flagged, and appears in `conflicts` for a human to look at.
  * Exploitation is kept per source. `asserted_by` lists the sources that assert it from a structured field; it never counts 'critical' or a high
    score. Two sources asserting it is not called 'independent': that is `unknown` unless the registry declares the sources independent.
  * A source whose snapshot is older than its `max_snapshot_age_days` is stale: its assertions stay visible (with the snapshot date) but are not
    counted in `asserted_by_current`.
"""
from __future__ import annotations
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from .records import validate_record


def _tokens(rec: Dict[str, Any]) -> List[Tuple[str, str]]:
    ids = rec["ids"]
    return [(k, v) for k in ("cve", "euvd", "ghsa") for v in ids.get(k, [])]


class _Groups:
    def __init__(self) -> None:
        self.parent: Dict[Tuple[str, str], Tuple[str, str]] = {}

    def find(self, t: Tuple[str, str]) -> Tuple[str, str]:
        self.parent.setdefault(t, t)
        while self.parent[t] != t:
            self.parent[t] = self.parent[self.parent[t]]
            t = self.parent[t]
        return t

    def members(self, root: Tuple[str, str]) -> List[Tuple[str, str]]:
        return [t for t in self.parent if self.find(t) == root]


def merge(records: List[Dict[str, Any]], snapshots: Optional[Dict[str, Dict[str, Any]]] = None, now: Optional[datetime] = None,
          registry: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
    snapshots = snapshots or {}
    registry = registry or {}
    bad = [(r.get("source"), r.get("source_record_id"), validate_record(r)) for r in records if validate_record(r)]
    if bad:
        raise ValueError(f"invalid records refused: {bad[:3]}")
    stale: Dict[str, str] = {}
    for sid, snap in snapshots.items():
        limit = snap.get("max_age_days")
        got = snap.get("retrieved_at")
        if limit is not None and got and now is not None:
            try:
                taken = datetime.strptime(got, "%Y-%m-%dT%H:%M:%SZ")
                age = now - (taken.replace(tzinfo=now.tzinfo) if now.tzinfo else taken)
            except ValueError:
                stale[sid] = "snapshot date unreadable"
                continue
            if age > timedelta(days=limit):
                stale[sid] = f"snapshot is {age.days} days old, the limit is {limit}"
    ordered = sorted(records, key=lambda r: (r["source"], r["source_record_id"]))
    g = _Groups()
    placement: Dict[int, Tuple[str, str]] = {}
    conflicts: List[Dict[str, Any]] = []
    solo: List[int] = []
    conflicted_tokens: set = set()
    for i, r in enumerate(ordered):
        toks = _tokens(r)
        cves = [t for t in toks if t[0] == "cve"]
        if len(cves) > 1:
            conflicts.append({"source": r["source"], "record": r["source_record_id"], "reason": "the record names more than one CVE: not merged", "ids": [c[1] for c in cves]})
            solo.append(i)
            continue
        if not toks:
            solo.append(i)
            continue
        roots = {g.find(t) for t in toks}
        cve_in_roots = {t[1] for root in roots for t in g.members(root) if t[0] == "cve"} | {c[1] for c in cves}
        if len(cve_in_roots) > 1:
            conflicts.append({"source": r["source"], "record": r["source_record_id"], "reason": "joining would put two different CVEs in one entry: not merged", "ids": sorted(cve_in_roots)})
            conflicted_tokens.update(t for t in toks)
            solo.append(i)
            continue
        first = toks[0]
        for t in toks[1:]:
            a, b = g.find(first), g.find(t)
            if a != b:
                g.parent[b] = a
        placement[i] = g.find(first)
    by_root: Dict[Tuple[str, str], List[int]] = {}
    for i, root in placement.items():
        by_root.setdefault(g.find(root), []).append(i)
    entries: List[Dict[str, Any]] = []
    flagged_solo = {(c["source"], c["record"]) for c in conflicts}

    def build(idx: List[int], key_hint: Optional[Tuple[str, str]], flags: List[str]) -> Dict[str, Any]:
        recs = [ordered[i] for i in idx]
        ids: Dict[str, List[str]] = {"cve": [], "euvd": [], "ghsa": []}
        for r in recs:
            for k in ids:
                for v in r["ids"].get(k, []):
                    if v not in ids[k]:
                        ids[k].append(v)
        for k in ids:
            ids[k].sort()
        key = (ids["cve"] or ids["euvd"] or ids["ghsa"] or [f"{recs[0]['source']}:{recs[0]['source_record_id']}"])[0]
        sources: Dict[str, Any] = {}
        expl: Dict[str, Any] = {}
        for r in recs:
            sid = r["source"]
            if sid in sources:
                flags.append(f"two-records-from-{sid}")
            sources.setdefault(sid, {"record": r["source_record_id"], "region": registry.get(sid, {}).get("region"), "evidence": r["evidence"],
                                     "severity": r.get("severity"), "epss": r.get("epss"), "dates": r["dates"], "affected": r["affected"], "fixes": r["fixes"],
                                     "references": r["references"], "summary": r.get("summary")})
            e = dict(r["exploitation"])
            if sid in stale:
                e["stale"] = True
                e["stale_reason"] = stale[sid]
            expl[sid] = e
        asserted = sorted(s for s, e in expl.items() if e["asserted"])
        current = sorted(s for s in asserted if not expl[s].get("stale"))
        since = sorted(expl[s]["since"] for s in asserted if expl[s].get("since"))
        mention_by = []
        return {
            "key": key, "ids": ids, "sources": dict(sorted(sources.items())), "exploitation": dict(sorted(expl.items())),
            "exploitation_summary": {"asserted_by": asserted, "asserted_by_current": current, "earliest_since": since[0] if since else None,
                                     "independent_confirmation": ("unknown" if len(asserted) > 1 else "not-applicable"),
                                     "note": "per-source statements; more than one source asserting it is not independent confirmation unless the registry says the sources are independent"},
            "regions": sorted({s["region"] for s in sources.values() if s["region"]}), "flags": sorted(set(flags)), "mentioned_by": mention_by,
        }
    for root, idx in sorted(by_root.items()):
        members = set(g.members(g.find(root)))
        entries.append(build(idx, root, ["alias-conflict-with-another-record"] if members & conflicted_tokens else []))
    for i in solo:
        r = ordered[i]
        fl = ["not-merged"] if (r["source"], r["source_record_id"]) in flagged_solo else (["no-identifier"] if not _tokens(r) else [])
        entries.append(build([i], None, fl))
    # mentions: an advisory that names a CVE is linked to the entry, never merged into it
    by_cve = {e["ids"]["cve"][0]: e for e in entries if e["ids"]["cve"]}
    for r in ordered:
        for m in r.get("mentions") or []:
            if m["kind"] == "cve" and m["id"] in by_cve and r["source"] not in by_cve[m["id"]]["sources"]:
                by_cve[m["id"]]["mentioned_by"].append({"source": r["source"], "record": r["source_record_id"]})
    entries.sort(key=lambda e: e["key"])
    return {"schema": "macguard.vuln-merged/1", "entries": entries, "conflicts": conflicts, "stale_sources": dict(sorted(stale.items())),
            "stats": {"records_in": len(records), "entries": len(entries), "multi_source": sum(1 for e in entries if len(e["sources"]) > 1),
                      "exploited_by_any_source": sum(1 for e in entries if e["exploitation_summary"]["asserted_by"]),
                      "exploited_by_current_source": sum(1 for e in entries if e["exploitation_summary"]["asserted_by_current"])}}
