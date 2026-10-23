"""File digests. The Installer Auditor engine only computes SHA-256, so SHA-512 lives here; SHA-256 is cross-checked against the engine's value."""
from __future__ import annotations
import hashlib
import threading
from typing import Dict, Optional

CHUNK = 1024 * 1024


def digests(path: str, cancel: Optional[threading.Event] = None) -> Dict[str, str]:
    """Streams the file once and returns both digests. A cancelled run raises InterruptedError and never reports a digest."""
    h256, h512 = hashlib.sha256(), hashlib.sha512()
    with open(path, "rb") as f:
        while True:
            if cancel is not None and cancel.is_set():
                raise InterruptedError("cancelled")
            b = f.read(CHUNK)
            if not b:
                break
            h256.update(b)
            h512.update(b)
    return {"sha256": h256.hexdigest(), "sha512": h512.hexdigest()}
