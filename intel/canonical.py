"""Canonical JSON and digests. One byte sequence per document, so a hash and a signature mean the same thing everywhere.

Rules: UTF-8, object keys sorted, no insignificant whitespace, no NaN/Infinity, no floats (use integers or strings), one trailing newline is NOT part of the canonical form.
"""
from __future__ import annotations
import hashlib
import json
from typing import Any


def _check(o: Any, path: str = "$") -> None:
    if isinstance(o, float):
        raise ValueError(f"{path}: floats are not allowed in canonical documents (use an integer or a string)")
    if isinstance(o, dict):
        for k, v in o.items():
            if not isinstance(k, str):
                raise ValueError(f"{path}: object keys must be strings")
            _check(v, f"{path}.{k}")
    elif isinstance(o, (list, tuple)):
        for i, v in enumerate(o):
            _check(v, f"{path}[{i}]")
    elif o is not None and not isinstance(o, (str, int, bool)):
        raise ValueError(f"{path}: unsupported type {type(o).__name__}")


def canonical_bytes(doc: Any) -> bytes:
    _check(doc)
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def doc_sha256(doc: Any) -> str:
    return sha256_hex(canonical_bytes(doc))


def file_sha256(path: str, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()
