"""What a collector gets: the file identity, an injectable runner, the evidence book and a few safe readers. Collectors never open paths themselves
except through read_small (regular file, no symlink, size cap), so hostile metadata cannot make the engine read outside what it names."""
from __future__ import annotations
import os
import platform
import re
import stat
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlsplit

from .model import EvidenceBook
from .runner import Result, system_runner

MAX_META = 4 * 1024 * 1024


class Ctx:
    def __init__(self, ident: Dict[str, Any], path: str, book: EvidenceBook, *, runner: Optional[Callable[..., Result]] = None, os_family: Optional[str] = None,
                 root: str = "/", brew_prefixes: Optional[List[str]] = None, bundle: Optional[str] = None, given_path: Optional[str] = None,
                 distro_id: Optional[str] = None, timeout: int = 20):
        self.ident = ident                    # schema file_identity (+ private _md5, _head)
        self.path = path                      # resolved absolute path of the file that was hashed
        self.given_path = given_path or path
        self.book = book
        self._runner = runner or (lambda argv: system_runner(argv, timeout))
        self.os_family = os_family or {"Darwin": "macos", "Linux": "linux"}.get(platform.system(), "other")
        self.root = root                      # filesystem root for package databases (tests point it at a fixture tree)
        self.brew_prefixes = brew_prefixes if brew_prefixes is not None else ["/usr/local", "/opt/homebrew", "/home/linuxbrew/.linuxbrew"]
        self.bundle = bundle                  # enclosing .app bundle (resolved) if the file is inside one, or the subject itself
        self.distro_id = distro_id
        self.is_main_exe = False             # True when the hashed file is the main executable of ctx.bundle
        self.timeout = timeout
        self.sha256 = ident["hashes"]["sha256"]
        self.sha512 = ident["hashes"].get("sha512")

    def run(self, argv: List[str]) -> Result:
        return self._runner(list(argv))

    @property
    def logical_path(self) -> str:
        """The path as the host's package databases know it: with root='/' the real path; with a fixture root the path below that root."""
        r = self.root.rstrip("/")
        return self.path[len(r):] if r and self.path.startswith(r + "/") else self.path

    def under_root(self, p: str) -> str:
        return os.path.join(self.root, p.lstrip("/"))


def read_small(path: str, cap: int = MAX_META) -> Optional[bytes]:
    """Reads a regular, non-symlink file up to cap bytes. None if it is absent, a link, special, or larger than cap (the caller records why)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > cap:
            return None
        data = b""
        while len(data) <= cap:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            data += chunk
        return data if len(data) <= cap else None
    except OSError:
        return None
    finally:
        os.close(fd)


def is_real_dir(path: str) -> bool:
    try:
        return stat.S_ISDIR(os.lstat(path).st_mode)
    except OSError:
        return False


def safe_token(s: Any, maxlen: int = 128) -> Optional[str]:
    """A name taken from untrusted metadata is only used if it looks like a package/tap/cask token."""
    if isinstance(s, str) and 0 < len(s) <= maxlen and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+@/:~-]*", s):
        return s
    return None


def url_parts(url: str) -> Dict[str, str]:
    """host and a query-less, credential-less URL. Query strings and userinfo can carry tokens, so they are never kept."""
    try:
        u = urlsplit(url)
    except ValueError:
        return {}
    host = u.hostname or ""
    clean = f"{u.scheme}://{host}{(':' + str(u.port)) if u.port else ''}{u.path}" if u.scheme and host else ""
    return {"host": host, "clean": clean[:512]}
