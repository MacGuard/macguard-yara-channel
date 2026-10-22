"""The artifacts root of a channel uses the SAME Merkle construction as the legacy YARA channel (scripts/tlog.py: RFC 6962 hashing, leaf = path NUL sha256).
This module loads that one implementation instead of copying it, when the repository checkout is present; otherwise it carries a faithful minimal copy."""
from __future__ import annotations
import hashlib
import importlib.util
import os
from typing import Dict, List

_TLOG = None
_here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_cand = os.path.join(_here, "scripts", "tlog.py")
if os.path.isfile(_cand):
    _spec = importlib.util.spec_from_file_location("macguard_tlog", _cand)
    if _spec and _spec.loader:
        _TLOG = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(_TLOG)


def _leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _mth(leaves: List[bytes]) -> bytes:
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    k = 1
    while k * 2 < n:
        k *= 2
    return _node(_mth(leaves[:k]), _mth(leaves[k:]))


def artifacts_root(files: List[Dict[str, str]]) -> str:
    """files: [{'path': str, 'sha256': hex}]; order does not matter (sorted by UTF-8 path bytes)."""
    if _TLOG is not None:
        return _TLOG.rules_root(files)
    ordered = sorted(files, key=lambda f: f["path"].encode("utf-8"))
    return _mth([_leaf(f"{f['path']}\0{f['sha256']}".encode("utf-8")) for f in ordered]).hex()


def uses_shared_implementation() -> bool:
    return _TLOG is not None
