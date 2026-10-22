"""Downloading upstream sources. This is the ONLY module of the package that uses the network, and it is deliberately small:

  * HTTPS only (a redirect to http is refused); no credentials of any kind are ever sent (a source whose registry record says it needs one
    cannot be fetched by this code); a hard size limit; a timeout; a fixed User-Agent.
  * The raw bytes are kept exactly as received (origin: original) together with a retrieval record (URL, time, status, size, SHA-256, ETag).
  * Downloading is NOT permission to republish: the registry decides that (see intel.registry.clearance).
"""
from __future__ import annotations
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

from .canonical import canonical_bytes, sha256_hex

USER_AGENT = "macguard-intel/0.1 (+https://github.com/MacGuard/macguard-yara-channel)"
DEFAULT_MAX_BYTES = 64 * 1024 * 1024
DEFAULT_TIMEOUT = 60


class FetchError(Exception):
    pass


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    allow_http_localhost = False

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        u = urllib.parse.urlsplit(newurl)
        if u.scheme != "https" and not (self.allow_http_localhost and u.hostname in ("127.0.0.1", "localhost")):
            raise FetchError(f"refusing a redirect to a non-HTTPS address: {u.scheme}://{u.hostname}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url: str, dest_dir: str, filename: str, source: Optional[Dict[str, Any]] = None, *, max_bytes: int = DEFAULT_MAX_BYTES,
          timeout: int = DEFAULT_TIMEOUT, allow_http_localhost: bool = False, now: Optional[str] = None) -> Dict[str, Any]:
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" and not (allow_http_localhost and u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost")):
        raise FetchError("only HTTPS URLs are fetched")
    if u.username or u.password:
        raise FetchError("URLs with credentials are refused")
    if source is not None and source.get("access", {}).get("credential_required"):
        raise FetchError(f"{source.get('id')}: this source needs a credential and mgctl/intel never uses one")
    if os.sep in filename or filename.startswith(".") or not filename:
        raise FetchError("unsafe file name")
    os.makedirs(dest_dir, exist_ok=True)
    path = os.path.join(dest_dir, filename)
    if os.path.lexists(path):
        raise FetchError(f"{filename} already exists: a retrieval is never overwritten")
    handler = _HttpsOnlyRedirect()
    handler.allow_http_localhost = allow_http_localhost
    opener = urllib.request.build_opener(handler)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    try:
        with opener.open(req, timeout=timeout) as r:
            status = r.status
            declared = r.headers.get("Content-Length")
            if declared and declared.isdigit() and int(declared) > max_bytes:
                raise FetchError(f"the server announces {declared} bytes, above the {max_bytes} byte limit")
            data = bytearray()
            while True:
                chunk = r.read(1024 * 1024)
                if not chunk:
                    break
                data += chunk
                if len(data) > max_bytes:
                    raise FetchError(f"the download exceeded the {max_bytes} byte limit and was discarded")
            etag, last_mod, final = r.headers.get("ETag"), r.headers.get("Last-Modified"), r.geturl()
    except urllib.error.HTTPError as e:
        raise FetchError(f"HTTP {e.code} from {u.hostname}")
    except urllib.error.URLError as e:
        raise FetchError(f"network error: {e.reason}")
    except TimeoutError:
        raise FetchError("the download timed out")
    if status != 200 or not data:
        raise FetchError(f"unexpected answer: status {status}, {len(data)} bytes")
    with open(path, "wb") as f:
        f.write(bytes(data))
    record = {"url": url, "final_url": final, "status": status, "bytes": len(data), "sha256": sha256_hex(bytes(data)), "etag": etag, "last_modified": last_mod,
              "retrieved_at": now or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "file": filename,
              "source_id": (source or {}).get("id"), "redistribution_status_at_retrieval": (source or {}).get("redistribution_status", "unknown")}
    with open(path + ".retrieval.json", "wb") as f:
        f.write(canonical_bytes(record) + b"\n")
    return record
