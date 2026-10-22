"""Shared data model: the evidence book (schema 'evidence' objects) and Finding, what one collector returns.

A collector never decides the six fields. It records evidence (with supports/contradicts) and structured facts (owners, integrity
references, origin and installation claims); intel.provenance.combiner applies the policy to all of them."""
from __future__ import annotations
import re
from typing import Any, Dict, List, Optional

from .fileid import iso

FIELDS = ("content_origin", "installation_method", "package_ownership", "integrity_status", "provenance_confidence", "detection_status")
# evidence that, by rule R1/R2/R3, can never support any claim whatever a collector says
NO_SUPPORT_KINDS = ("HASH_ONLY", "PATH_LOCATION", "NAME_COLLISION_NOTE", "TIMESTAMP_CORRELATION", "PROVENANCE_XATTR")
TRUST_RANK = {"CRYPTOGRAPHIC": 4, "SYSTEM_AUTHORITATIVE": 3, "MANAGER_DECLARED": 2, "WRITABLE_METADATA": 1, "HEURISTIC": 0}
ORIGIN_BASIS_RANK = {"VERIFIED_BINDING": 3, "DECLARED_BY_MANAGER": 2, "DECLARED_BY_WRITABLE_METADATA": 1, "INFERRED": 0}


def claim(field: str, value: str, weight: str = "MODERATE") -> Dict[str, str]:
    return {"field": field, "value": value, "weight": weight}


class EvidenceBook:
    """Append-only list of evidence with unique ids (ev-<slug>[-n])."""

    def __init__(self, now: Optional[str] = None):
        self.items: List[Dict[str, Any]] = []
        self.now = now or iso()
        self._ids: set = set()

    def add(self, slug: str, kind: str, source_type: str, command: str, trust: str, group: str, *, present: bool = True, supports=None, contradicts=None,
            summary: str = "", exit_status: Optional[int] = None, needs_root: bool = False, scope: Optional[str] = None, raw_digest: Optional[str] = None,
            sensitive: Optional[str] = None) -> str:
        slug = re.sub(r"[^0-9a-z]+", "-", slug.lower()).strip("-") or "x"
        eid, n = "ev-" + slug, 1
        while eid in self._ids:
            n += 1
            eid = f"ev-{slug}-{n}"
        self._ids.add(eid)
        src: Dict[str, Any] = {"type": source_type, "command_or_api": command, "needs_root": needs_root, "needs_network": False}
        if exit_status is not None:
            src["exit_status"] = exit_status
        if scope:
            src["scope"] = scope
        ev: Dict[str, Any] = {"id": eid, "kind": kind, "present": present, "source": src, "observed_at": self.now, "trust": trust, "independence_group": group}
        if supports and present and kind not in NO_SUPPORT_KINDS:
            ev["supports"] = list(supports)
        if contradicts:
            ev["contradicts"] = list(contradicts)
        if summary:
            ev["summary"] = summary
        if raw_digest:
            ev["raw_digest"] = raw_digest
        if sensitive:
            ev["_sensitive"] = sensitive          # private: rendered (redacted) by intel.provenance.render, never stored raw in the output
        self.items.append(ev)
        return eid


class Finding:
    """What one collector concluded about one file. All lists hold plain dicts so the combiner is easy to test with synthetic data."""

    def __init__(self, name: str):
        self.name = name
        self.applicable = True
        self.queried: List[str] = []              # managers whose database was read successfully (conclusive)
        self.unqueryable: List[str] = []          # managers that apply but could not be read
        self.owners: List[Dict[str, Any]] = []    # {manager, name, version, arch, evidence_id, repository?}
        self.no_owner_ev: List[str] = []          # evidence ids of 'looked for an owner, found none' (present=false)
        self.ownership_inconclusive: List[str] = []   # reasons why "no owner found" cannot be read as NOT_OWNED
        self.integrity: List[Dict[str, Any]] = []     # {kind, authority, strength, scope, writable, outcome MATCH|MISMATCH, evidence_id, note}
        self.integrity_failed: List[str] = []         # probes that could have given a reference and failed
        self.origins: List[Dict[str, Any]] = []       # {value, basis, evidence_id, source{...}}
        self.installs: List[Dict[str, Any]] = []      # {value, manager, installer_version, installed_at, installed_at_basis, evidence_id}
        self.missing: Dict[str, List[str]] = {}
        self.reasons: Dict[str, List[str]] = {}
        self.history: List[Dict[str, Any]] = []
        self.attestations: List[Dict[str, Any]] = []
        self.chain: List[Dict[str, Any]] = []
        self.limits: List[str] = []
        self.coverage_state = "IMPLEMENTED"
        self.historical = "PARTIAL"
        self.signature_summary: Optional[Dict[str, Any]] = None

    def miss(self, field: str, text: str) -> None:
        self.missing.setdefault(field, []).append(text)

    def why(self, field: str, text: str) -> None:
        self.reasons.setdefault(field, []).append(text)
