"""Webhook delivery with SSRF protection, signed payloads and bounded retries.

Destination rules (checked when the webhook is created AND again on every send, because DNS can change):
  * https only, no credentials in the URL, a normal public host NAME (no IP literal in any notation, no 'localhost', '.local', '.internal', cloud
    metadata names), port 443 or 8443, no fragment, at most 2000 characters;
  * EVERY address the name resolves to must be a public (global) address: loopback, private, link-local (169.254.169.254 and the other metadata
    addresses), carrier-grade NAT, multicast, reserved, unspecified and IPv4-mapped forms of those are refused;
  * the connection goes to the address that was validated (pinned), with the original name for TLS and the Host header, so a name that resolves
    differently a moment later cannot redirect the request; redirects are never followed; the response body is read up to 64 KB and discarded.

Payloads are signed: header `X-MacGuard-Signature: t=<unix seconds>,v1=<hex hmac-sha256(secret, "<t>.<body>")>` (one v1 per ACTIVE key, so a key can be
rotated without a gap), plus `X-MacGuard-Event-Id` (stable across retries: receivers can de-duplicate) and `X-MacGuard-Delivery-Id`.
"""
from __future__ import annotations
import hashlib
import hmac
import http.client
import ipaddress
import re
import socket
import ssl
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

ALLOWED_PORTS = (443, 8443)
MAX_URL = 2000
MAX_BODY = 256 * 1024
BLOCKED_NAMES = ("localhost", "metadata.google.internal", "metadata", "instance-data", "kubernetes.default", "host.docker.internal")
BLOCKED_SUFFIXES = (".local", ".localhost", ".internal", ".intranet", ".lan", ".home", ".corp", ".private", ".cluster.local", ".svc")
LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
TOLERANCE_SECONDS = 300
RETRY_BACKOFF = (60, 300, 1800, 7200, 21600)          # seconds before attempt 2, 3, 4, 5, 6; after that the delivery goes to the dead-letter state
DISABLE_AFTER = 10                                    # consecutive failed deliveries before the channel is switched off


class UnsafeDestination(ValueError):
    pass


def _is_public(ip: ipaddress._BaseAddress) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast and not ip.is_private and not ip.is_loopback and not ip.is_link_local and not ip.is_reserved and not ip.is_unspecified


def check_url_syntax(url: Any, *, allow_test_http_localhost: bool = False) -> Tuple[str, int, str]:
    """(host, port, path_with_query). Raises UnsafeDestination. `allow_test_http_localhost` exists for tests only and is never reachable from the API."""
    if not isinstance(url, str) or not url or len(url) > MAX_URL or any(c.isspace() or ord(c) < 32 for c in url):
        raise UnsafeDestination("not a usable URL")
    u = urlsplit(url)
    if allow_test_http_localhost and u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost"):
        return u.hostname, u.port or 80, (u.path or "/") + (("?" + u.query) if u.query else "")
    if u.scheme != "https":
        raise UnsafeDestination("only https URLs are accepted")
    if u.username or u.password or "@" in u.netloc:
        raise UnsafeDestination("credentials in the URL are refused")
    if u.fragment:
        raise UnsafeDestination("a fragment is not allowed")
    try:
        port = u.port or 443
    except ValueError:
        raise UnsafeDestination("invalid port")
    if port not in ALLOWED_PORTS:
        raise UnsafeDestination(f"port {port} is not allowed (443 or 8443)")
    host = (u.hostname or "").rstrip(".").lower()
    if not host or "%" in host or ":" in host or "[" in u.netloc:
        raise UnsafeDestination("an IP address or an unusual host is refused: use a public host name")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise UnsafeDestination("invalid host name")
    labels = host.split(".")
    if len(labels) < 2 or not all(LABEL.match(l) for l in labels) or labels[-1].isdigit() or re.match(r"^(0x[0-9a-f]+|[0-9]+)$", labels[-1]):
        raise UnsafeDestination("an IP address in any notation, or a name without a public top-level domain, is refused")
    if host in BLOCKED_NAMES or host.endswith(BLOCKED_SUFFIXES):
        raise UnsafeDestination("an internal host name is refused")
    return host, port, (u.path or "/") + (("?" + u.query) if u.query else "")


def resolve_public(host: str, port: int, resolver: Callable = socket.getaddrinfo) -> List[str]:
    try:
        infos = resolver(host, port, type=socket.SOCK_STREAM)
    except OSError as e:
        raise UnsafeDestination(f"the host name does not resolve ({e.__class__.__name__})")
    ips: List[str] = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if not _is_public(ip):
            raise UnsafeDestination(f"the name resolves to a non-public address ({ip}): refused")
        if str(ip) not in ips:
            ips.append(str(ip))
    if not ips:
        raise UnsafeDestination("the host name does not resolve")
    return ips


def validate_destination(url: str, resolver: Callable = socket.getaddrinfo) -> Dict[str, Any]:
    host, port, path = check_url_syntax(url)
    return {"host": host, "port": port, "path": path, "ips": resolve_public(host, port, resolver)}


# ---- signatures ------------------------------------------------------------------------------------------------------------------
def sign(secrets_hex: Sequence[str], body: bytes, ts: int) -> str:
    parts = [f"t={ts}"]
    for s in secrets_hex:
        parts.append("v1=" + hmac.new(bytes.fromhex(s), f"{ts}.".encode() + body, hashlib.sha256).hexdigest())
    return ",".join(parts)


def verify_signature(secret_hex: str, body: bytes, header: str, now: Optional[float] = None, tolerance: int = TOLERANCE_SECONDS) -> bool:
    """What a receiver does. Accepts if ANY v1 matches (so rotation overlaps) and the timestamp is within the tolerance (replay window)."""
    try:
        items = dict()
        v1s = []
        for part in header.split(","):
            k, _, v = part.partition("=")
            if k == "v1":
                v1s.append(v)
            else:
                items[k] = v
        ts = int(items["t"])
    except (KeyError, ValueError):
        return False
    if abs((now if now is not None else time.time()) - ts) > tolerance:
        return False
    want = hmac.new(bytes.fromhex(secret_hex), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(want, v) for v in v1s)


# ---- sending ---------------------------------------------------------------------------------------------------------------------
class _Pinned(http.client.HTTPSConnection):
    def __init__(self, host: str, ip: str, port: int, timeout: float, context: ssl.SSLContext):
        super().__init__(host, port, timeout=timeout, context=context)
        self._pinned_ip = ip

    def connect(self) -> None:
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class SendResult:
    def __init__(self, status: Optional[int], error: Optional[str] = None):
        self.status, self.error = status, error

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300

    @property
    def gone(self) -> bool:
        return self.status == 410

    @property
    def retryable(self) -> bool:
        return self.status is None or self.status in (408, 425, 429) or self.status >= 500


def send(url: str, body: bytes, headers: Dict[str, str], *, timeout: float = 10.0, resolver: Callable = socket.getaddrinfo, context: Optional[ssl.SSLContext] = None,
         _test_allow_http_localhost: bool = False) -> SendResult:
    """Validates again, then posts to the pinned address. Never raises for network trouble: the result carries it."""
    if len(body) > MAX_BODY:
        return SendResult(None, "payload too large")
    try:
        host, port, path = check_url_syntax(url, allow_test_http_localhost=_test_allow_http_localhost)
        if _test_allow_http_localhost and host in ("127.0.0.1", "localhost"):
            conn: http.client.HTTPConnection = http.client.HTTPConnection(host, port, timeout=timeout)
        else:
            ips = resolve_public(host, port, resolver)
            conn = _Pinned(host, ips[0], port, timeout, context or ssl.create_default_context())
    except UnsafeDestination as e:
        return SendResult(None, f"destination refused: {e}")
    try:
        h = {"Content-Type": "application/json", "User-Agent": "macguard-alerts/0.1", "Content-Length": str(len(body))}
        h.update(headers)
        conn.request("POST", path, body=body, headers=h)
        r = conn.getresponse()
        r.read(65536)
        return SendResult(r.status)
    except (OSError, http.client.HTTPException, ssl.SSLError) as e:
        return SendResult(None, f"{e.__class__.__name__}")
    finally:
        conn.close()


def backoff_seconds(attempt_just_failed: int) -> Optional[int]:
    """Seconds to wait after the Nth failed attempt (1-based); None = no more attempts, dead-letter."""
    return RETRY_BACKOFF[attempt_just_failed - 1] if attempt_just_failed - 1 < len(RETRY_BACKOFF) else None
