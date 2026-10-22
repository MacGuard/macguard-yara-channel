"""The IOC channel: indicators of compromise (hashes, IP addresses, domains, URLs) from local input files.

Pipeline per indicator: parse -> normalise -> validate -> drop false-positive candidates (allowlist, reserved names, non-global addresses)
-> merge duplicates keeping every source -> apply TTL (expired indicators are not published) -> compute confidence.
Every dropped indicator is counted with its reason in the build report: nothing disappears silently.

No network. Input is a file you already hold; the source registry says whether you may republish it.
"""
from __future__ import annotations
import csv
import ipaddress
import json
import re
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import SCHEMA_IOC

HASH_LEN = {32: "md5", 40: "sha1", 64: "sha256"}
HEX = re.compile(r"^[0-9a-f]+$")
LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
RESERVED_TLDS = {"local", "localhost", "internal", "intranet", "lan", "home", "corp", "test", "example", "invalid", "arpa", "onion", "localdomain", "private"}
EMPTY_HASHES = {   # hashes of the empty file: never an indicator
    "d41d8cd98f00b204e9800998ecf8427e", "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}
MAX_URL = 2048
DEFAULT_TTL_DAYS = 30
TYPES = ("sha256", "sha1", "md5", "ipv4", "ipv6", "domain", "url")


class Drop(Exception):
    """An indicator that is not published; the message is the reason code."""


def _defang(s: str) -> str:
    s = s.strip().strip("'\"<>")
    s = re.sub(r"^hxxp", "http", s, flags=re.I)
    s = s.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("[://]", "://").replace("[dot]", ".")
    return s


def norm_hash(v: str) -> Tuple[str, str]:
    h = _defang(v).lower()
    if not HEX.match(h) or len(h) not in HASH_LEN:
        raise Drop("invalid-hash")
    if h in EMPTY_HASHES or len(set(h)) == 1:
        raise Drop("non-indicator-hash")
    return HASH_LEN[len(h)], h


def norm_ip(v: str) -> Tuple[str, str]:
    s = _defang(v)
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        raise Drop("invalid-ip")
    if not ip.is_global or ip.is_multicast:
        raise Drop("non-global-ip")
    return ("ipv4" if ip.version == 4 else "ipv6"), ip.compressed


def norm_domain(v: str) -> Tuple[str, str]:
    d = _defang(v).lower().rstrip(".")
    if not d or " " in d or "/" in d or "@" in d or ":" in d:
        raise Drop("invalid-domain")
    try:
        ipaddress.ip_address(d)
        raise Drop("ip-as-domain")
    except ValueError:
        pass
    try:
        d = d.encode("idna").decode("ascii")
    except UnicodeError:
        raise Drop("invalid-domain")
    labels = d.split(".")
    if len(d) > 253 or len(labels) < 2 or not all(LABEL.match(x) for x in labels):
        raise Drop("invalid-domain")
    tld = labels[-1]
    if tld in RESERVED_TLDS:
        raise Drop("reserved-tld")
    if not (tld.isalpha() or tld.startswith("xn--")):
        raise Drop("invalid-domain")
    return "domain", d


def norm_url(v: str) -> Tuple[str, str]:
    s = _defang(v)
    if len(s) > MAX_URL:
        raise Drop("url-too-long")
    try:
        u = urllib.parse.urlsplit(s)
        port = u.port
    except ValueError:
        raise Drop("invalid-url")
    if u.scheme.lower() not in ("http", "https", "ftp"):
        raise Drop("unsupported-scheme")
    if u.username is not None or u.password is not None:
        raise Drop("url-with-credentials")          # may carry a secret: never republished
    host = (u.hostname or "").lower()
    try:
        ipaddress.ip_address(host)
        kind, host = norm_ip(host)
        if kind == "ipv6":
            host = f"[{host}]"
    except ValueError:
        kind, host = norm_domain(host)
    except Drop:
        raise
    default = {"http": 80, "https": 443, "ftp": 21}[u.scheme.lower()]
    netloc = host if port in (None, default) else f"{host}:{port}"
    path = re.sub(r"%[0-9a-fA-F]{2}", lambda m: m.group(0).upper(), u.path or "/")
    query = re.sub(r"%[0-9a-fA-F]{2}", lambda m: m.group(0).upper(), u.query)
    return "url", urllib.parse.urlunsplit((u.scheme.lower(), netloc, path, query, ""))


def normalise(kind_hint: Optional[str], raw: str) -> Tuple[str, str]:
    """kind_hint: one of TYPES, 'hash', 'ip' or None (autodetect)."""
    s = _defang(raw)
    if not s:
        raise Drop("empty")
    k = (kind_hint or "").lower()
    if k in ("sha256", "sha1", "md5", "hash"):
        t, v = norm_hash(s)
        if k in ("sha256", "sha1", "md5") and t != k:
            raise Drop("hash-type-mismatch")
        return t, v
    if k in ("ip", "ipv4", "ipv6"):
        return norm_ip(s)
    if k == "domain":
        return norm_domain(s)
    if k == "url":
        return norm_url(s)
    if "://" in s:
        return norm_url(s)
    if HEX.match(s.lower()) and len(s) in HASH_LEN:
        return norm_hash(s)
    try:
        ipaddress.ip_address(s)
        return norm_ip(s)
    except ValueError:
        return norm_domain(s)


def parse_time(s: str) -> datetime:
    d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def iso(d: datetime) -> str:
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---- input adapters (local files only) -------------------------------------------------------------------------------
def read_plain(path: str) -> Iterable[Dict[str, Any]]:
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith(("#", ";", "//")):
                yield {"value": line.split()[0], "kind": None}


def read_csv(path: str, column: str, kind: Optional[str], seen_column: Optional[str] = None, confidence_column: Optional[str] = None) -> Iterable[Dict[str, Any]]:
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        rows = (ln for ln in f if ln.strip() and not ln.lstrip().startswith("#"))
        for r in csv.DictReader(rows, skipinitialspace=True):
            if column not in r:
                raise ValueError(f"column '{column}' not in the file (columns: {sorted(r)})")
            item: Dict[str, Any] = {"value": r[column], "kind": kind}
            if seen_column and r.get(seen_column):
                item["seen"] = r[seen_column]
            if confidence_column and r.get(confidence_column, "").strip().isdigit():
                item["confidence"] = int(r[confidence_column])
            yield item


def read_jsonl(path: str) -> Iterable[Dict[str, Any]]:
    with open(path, encoding="utf-8", errors="replace") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except ValueError:
                yield {"value": "", "kind": None, "_error": f"line {n}: not JSON"}
                continue
            yield {"value": str(o.get("value", "")), "kind": o.get("type"), "seen": o.get("seen"), "confidence": o.get("confidence"), "tags": o.get("tags"), "family": o.get("family"), "ref": o.get("ref")}


# ---- the build -----------------------------------------------------------------------------------------------------------
def build(items: Iterable[Tuple[str, Dict[str, Any]]], registry: Dict[str, Dict[str, Any]], now: datetime, allowlist: Optional[Dict[str, Any]] = None) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """items: (source_id, item). Returns (records sorted by type/value, report)."""
    allow = {(a["type"], a["value"].lower()) for a in (allowlist or {}).get("entries", [])}
    merged: Dict[Tuple[str, str], Dict[str, Any]] = {}
    dropped: Dict[str, int] = {}
    seen_n = 0
    for sid, it in items:
        seen_n += 1
        src = registry.get(sid, {})
        trust = int(src.get("trust", 50))
        ttl = int(src.get("default_ttl_days", DEFAULT_TTL_DAYS))
        try:
            if it.get("_error"):
                raise Drop("unreadable-line")
            t, v = normalise(it.get("kind"), it.get("value", ""))
            if (t, v) in allow:
                raise Drop("allowlisted")
        except Drop as d:
            dropped[str(d)] = dropped.get(str(d), 0) + 1
            continue
        try:
            first = parse_time(it["seen"]) if it.get("seen") else now
        except ValueError:
            dropped["bad-timestamp"] = dropped.get("bad-timestamp", 0) + 1
            continue
        if first > now + timedelta(days=1):
            dropped["future-timestamp"] = dropped.get("future-timestamp", 0) + 1
            continue
        conf_in = it.get("confidence")
        conf = 50 if not isinstance(conf_in, int) or not 0 <= conf_in <= 100 else conf_in
        rec = merged.setdefault((t, v), {"schema": SCHEMA_IOC, "type": t, "value": v, "sources": [], "tags": [], "family": None})
        entry = {"id": sid, "first_seen": iso(first), "last_seen": iso(first), "confidence": conf, "ttl_days": ttl}
        if it.get("ref"):
            entry["ref"] = str(it["ref"])[:200]
        same = [s for s in rec["sources"] if s["id"] == sid]
        if same:                                   # same source again: widen the window, keep the highest confidence
            s0 = same[0]
            s0["first_seen"], s0["last_seen"] = min(s0["first_seen"], entry["first_seen"]), max(s0["last_seen"], entry["last_seen"])
            s0["confidence"] = max(s0["confidence"], conf)
        else:
            rec["sources"].append(entry)
        for tag in (it.get("tags") or []):
            if isinstance(tag, str) and tag and tag not in rec["tags"]:
                rec["tags"].append(tag[:64])
        if it.get("family") and not rec["family"]:
            rec["family"] = str(it["family"])[:64]
    out: List[Dict[str, Any]] = []
    expired = 0
    for (t, v), rec in merged.items():
        rec["sources"].sort(key=lambda s: s["id"])
        exp = max(parse_time(s["last_seen"]) + timedelta(days=s["ttl_days"]) for s in rec["sources"])
        if exp <= now:
            expired += 1
            continue
        eff = max(s["confidence"] * int(registry.get(s["id"], {}).get("trust", 50)) // 100 for s in rec["sources"])
        rec["confidence"] = min(100, eff + 10 * (len(rec["sources"]) - 1))
        rec["first_seen"] = min(s["first_seen"] for s in rec["sources"])
        rec["last_seen"] = max(s["last_seen"] for s in rec["sources"])
        rec["expires_at"] = iso(exp)
        rec["tags"].sort()
        out.append(rec)
    out.sort(key=lambda r: (TYPES.index(r["type"]), r["value"]))
    report = {"input_items": seen_n, "published": len(out), "expired": expired, "dropped": dict(sorted(dropped.items())),
              "by_type": {t: sum(1 for r in out if r["type"] == t) for t in TYPES if any(r["type"] == t for r in out)}, "built_at": iso(now)}
    return out, report
