"""Channel manifests: one manifest per channel and version, listing the exact artifacts (SHA-256, bytes), their Merkle root, the sources and
their licence status, compatibility, approval state and the link to the previous version. Nothing is signed here: the manifest is the byte
sequence that a publishing workflow signs (canonical JSON, see intel.canonical)."""
from __future__ import annotations
import os
from typing import Any, Dict, List, Optional

from . import FAMILIES, SCHEMA_CHANNEL
from .canonical import canonical_bytes, doc_sha256, file_sha256
from .merkle import artifacts_root
from .registry import clearance, public_view

APPROVAL_STATES = ("draft", "approved", "revoked")
MEDIA = {".jsonl": "application/x-ndjson", ".json": "application/json", ".txt": "text/plain", ".yar": "text/plain", ".yara": "text/plain"}


class ChannelError(Exception):
    pass


def _artifact_entries(artifact_dir: str, originals: Optional[set] = None) -> List[Dict[str, Any]]:
    out = []
    for base, dirs, files in os.walk(artifact_dir):
        dirs.sort()
        for fn in sorted(files):
            full = os.path.join(base, fn)
            if os.path.islink(full):
                raise ChannelError(f"symbolic links are not allowed in a channel: {full}")
            rel = os.path.relpath(full, artifact_dir).replace(os.sep, "/")
            if rel in ("manifest.json",) or rel.endswith(".sigstore.json"):
                continue
            out.append({"path": rel, "sha256": file_sha256(full), "bytes": os.path.getsize(full),
                        "media_type": MEDIA.get(os.path.splitext(fn)[1], "application/octet-stream"), "origin": "original" if rel in (originals or set()) else "derived",
                        "original_signature": {"present": False}})
    return out


def build_manifest(channel_id: str, family: str, version: int, artifact_dir: str, source_ids: List[str], registry: Dict[str, Dict[str, Any]],
                   created_at: str, compatibility: Optional[Dict[str, Any]] = None, previous: Optional[Dict[str, Any]] = None,
                   validation: Optional[Dict[str, Any]] = None, stats: Optional[Dict[str, Any]] = None, approval_state: str = "draft", originals: Optional[set] = None) -> Dict[str, Any]:
    if family not in FAMILIES:
        raise ChannelError(f"unknown family '{family}' (known: {', '.join(FAMILIES)})")
    if not isinstance(version, int) or version < 1:
        raise ChannelError("version must be an integer >= 1")
    if approval_state not in APPROVAL_STATES:
        raise ChannelError(f"approval state must be one of {APPROVAL_STATES}")
    if previous is not None:
        if previous.get("channel", {}).get("id") != channel_id:
            raise ChannelError("the previous manifest belongs to another channel")
        if int(previous["channel"]["version"]) >= version:
            raise ChannelError("version must increase: a channel never reuses or lowers a version (rollback is a catalog decision)")
    arts = _artifact_entries(artifact_dir, originals)
    if not arts:
        raise ChannelError("the channel has no artifacts")
    ok, reasons = clearance(registry, source_ids)
    state = approval_state
    if state == "approved" and not ok:
        raise ChannelError("cannot approve: " + "; ".join(reasons))
    doc: Dict[str, Any] = {
        "schema": SCHEMA_CHANNEL,
        "channel": {"id": channel_id, "family": family, "version": version, "created_at": created_at},
        "sources": [public_view(registry[s]) if s in registry else {"id": s, "redistribution_status": "not-evaluated"} for s in sorted(set(source_ids))],
        "artifacts": arts,
        "artifacts_root": artifacts_root([{"path": a["path"], "sha256": a["sha256"]} for a in arts]),
        "compatibility": compatibility or {"platforms": ["macos", "linux"], "engines": [{"name": "mgctl", "min_version": "0.1.0"}]},
        "approval": {"state": state, "publishable": bool(ok), "blocking_reasons": reasons, "approved_by": [], "approved_at": None},
        "validation": validation or {"gates": [], "attestation": None},
        "revocation": {"policy": "a revoked version is listed in the catalog; clients refuse it and keep the last approved version", "revoked": False},
        "previous": {"version": None, "manifest_sha256": None},
        "stats": stats or {},
    }
    if previous is not None:
        doc["previous"] = {"version": int(previous["channel"]["version"]), "manifest_sha256": doc_sha256(previous)}
    return doc


def write_manifest(doc: Dict[str, Any], artifact_dir: str) -> str:
    path = os.path.join(artifact_dir, "manifest.json")
    if os.path.lexists(path):
        raise ChannelError("manifest.json already exists: a published version is never overwritten")
    with open(path, "wb") as f:
        f.write(canonical_bytes(doc) + b"\n")
    return path
