"""Strict path validation (same semantics as mgctl/paths.py) and TOCTOU-safe file identity: one descriptor opened with O_NOFOLLOW,
stat before and after hashing, SHA-256 and SHA-512 in one pass, a size cap, and a 'stable_during_read' flag that is true only if nothing moved."""
from __future__ import annotations
import hashlib
import os
import stat
import struct
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

MAX_PATH = 4096
MAX_HASH_BYTES = 4 * 1024 * 1024 * 1024
CHUNK = 1024 * 1024


class PathError(Exception):
    """Bad path (exit code 3)."""


class Subject:
    def __init__(self, given: str, resolved: str, st: os.stat_result, was_symlink: bool, is_bundle: bool):
        self.given, self.resolved, self.st, self.was_symlink, self.is_bundle = given, resolved, st, was_symlink, is_bundle


def validate(raw: str, *, follow_symlinks: bool = False, allow_bundle: bool = True) -> Subject:
    if not isinstance(raw, str) or not raw.strip():
        raise PathError("the path is empty")
    if "\x00" in raw:
        raise PathError("the path contains a NUL byte")
    if len(raw) > MAX_PATH:
        raise PathError("the path is too long")
    expanded = os.path.expanduser(raw)
    if not os.path.isabs(expanded):
        expanded = os.path.join(os.getcwd(), expanded)
    given = os.path.abspath(expanded)                                  # what is shown: textually normalised
    # what is opened: parent directories are resolved physically (the kernel's meaning of '..' and of directory links), the last component never is
    parent, base = os.path.split(expanded.rstrip("/") or "/")
    physical = os.path.join(os.path.realpath(parent), base) if base not in ("", ".", "..") else os.path.realpath(expanded)
    try:
        lst = os.lstat(physical)
    except FileNotFoundError:
        raise PathError("path not found")
    except PermissionError:
        raise PathError("permission denied reading the path")
    except OSError as e:
        raise PathError(f"cannot read the path ({e.strerror})")
    resolved, was_link = physical, False
    if stat.S_ISLNK(lst.st_mode):
        if not follow_symlinks:
            raise PathError("the path is a symbolic link; pass --follow-symlinks to assess its target")
        was_link = True
        resolved = os.path.realpath(physical)
        try:
            lst = os.stat(resolved)
        except OSError as e:
            raise PathError(f"the link target cannot be read ({e.strerror})")
    if stat.S_ISREG(lst.st_mode):
        return Subject(given, resolved, lst, was_link, False)
    if stat.S_ISDIR(lst.st_mode) and allow_bundle and resolved.rstrip("/").endswith(".app"):
        return Subject(given, resolved, lst, was_link, True)
    raise PathError("only regular files (and .app bundles) are accepted; this is a " + _kind(lst.st_mode))


def _kind(mode: int) -> str:
    for f, n in ((stat.S_ISDIR, "directory"), (stat.S_ISFIFO, "FIFO"), (stat.S_ISSOCK, "socket"), (stat.S_ISCHR, "character device"), (stat.S_ISBLK, "block device")):
        if f(mode):
            return n
    return "special file"


def _key(s: os.stat_result) -> Tuple[int, int, int, int]:
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)


def iso(ts: Optional[datetime] = None) -> str:
    return (ts or datetime.now(timezone.utc)).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---- file type ---------------------------------------------------------------------------------------------------------
_CPU = {0x07: "i386", 0x01000007: "x86_64", 0x0C: "arm", 0x0100000C: "arm64", 0x0200000C: "arm64_32", 0x12: "ppc", 0x01000012: "ppc64"}
_ELF = {0x03: "x86", 0x3E: "x86_64", 0x28: "arm", 0xB7: "aarch64", 0xF3: "riscv", 0x08: "mips", 0x14: "ppc", 0x15: "ppc64", 0x16: "s390x"}


def detect_type(head: bytes, path: str) -> Tuple[str, Optional[str]]:
    """(file_type, architecture) from the first bytes and the extension. Content decides; the extension only separates archives."""
    low = path.lower()
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        cpu = struct.unpack("<I", head[4:8])[0] if len(head) >= 8 else None
        return "macho", _CPU.get(cpu)
    if head[:4] in (b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
        cpu = struct.unpack(">I", head[4:8])[0] if len(head) >= 8 else None
        return "macho", _CPU.get(cpu)
    if head[:4] == b"\xca\xfe\xba\xbe" and len(head) >= 8 and 0 < struct.unpack(">I", head[4:8])[0] <= 30:
        n, archs = struct.unpack(">I", head[4:8])[0], []
        for i in range(n):
            off = 8 + 20 * i
            if len(head) >= off + 4:
                archs.append(_CPU.get(struct.unpack(">I", head[off:off + 4])[0], "unknown"))
        return "macho_fat", "+".join(archs) or None
    if head[:4] == b"\x7fELF":
        little = len(head) > 5 and head[5] == 1
        m = struct.unpack("<H" if little else ">H", head[18:20])[0] if len(head) >= 20 else None
        return "elf", _ELF.get(m)
    if head[:2] == b"MZ":
        return "pe", None
    if head[:4] == b"xar!":
        return "pkg", None
    if low.endswith(".dmg"):
        return "dmg", None
    if low.endswith(".whl"):
        return "wheel_or_sdist", None
    if low.endswith(".jar"):
        return "jar", None
    if low.endswith(".appimage"):
        return "appimage", None
    if head[:2] == b"#!":
        return "script", None
    if head[:4] == b"PK\x03\x04" or head[:2] == b"\x1f\x8b" or head[:6] == b"\xfd7zXZ\x00" or head[:3] == b"BZh":
        return "archive", None
    if head and b"\x00" not in head:
        try:
            head.decode("utf-8")
            return "text", None
        except UnicodeDecodeError:
            pass
    return ("other" if head else "unknown"), None


def _uid_class(st: os.stat_result) -> str:
    if st.st_uid == 0:
        return "root"
    try:
        if st.st_uid == os.getuid():
            return "user"
    except AttributeError:
        return "unknown"
    return "other"


def identify(path: str, *, was_symlink: bool = False, given_path: Optional[str] = None, want_md5: bool = False, max_bytes: int = MAX_HASH_BYTES) -> Dict[str, Any]:
    """Returns the schema 'file_identity' plus private keys _md5, _head, _stable. Raises PathError on anything that is not a stable regular file."""
    last: Dict[str, Any] = {}
    for attempt in (1, 2):
        try:
            before = os.lstat(path)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
        except OSError as e:
            raise PathError(f"cannot open the file without following links ({e.strerror})")
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise PathError("the path is no longer a regular file")
            head = os.read(fd, 4096)
            os.lseek(fd, 0, os.SEEK_SET)
            h256, h512 = hashlib.sha256(), hashlib.sha512()
            md5 = hashlib.md5(usedforsecurity=False) if want_md5 else None
            total = 0
            while True:
                chunk = os.read(fd, CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise PathError("the file is larger than the hashing limit; nothing was claimed")
                h256.update(chunk)
                h512.update(chunk)
                if md5:
                    md5.update(chunk)
            after_fd = os.fstat(fd)
        finally:
            os.close(fd)
        try:
            after_path = os.lstat(path)
        except OSError:
            after_path = None
        stable = bool(after_path) and _key(before) == _key(st) == _key(after_fd) == _key(after_path) and total == st.st_size
        ftype, arch = detect_type(head, path)
        birth = getattr(st, "st_birthtime", None)
        doc: Dict[str, Any] = {
            "path": given_path or path, "path_was_symlink": was_symlink, "device": st.st_dev, "inode": st.st_ino, "size": st.st_size,
            "mode": "%o" % (st.st_mode & 0o7777), "uid_class": _uid_class(st), "mtime_ns": st.st_mtime_ns, "ctime_ns": st.st_ctime_ns,
            "hashes": {"sha256": h256.hexdigest(), "sha512": h512.hexdigest(), "computed_at": iso(), "stable_during_read": stable},
            "file_type": ftype,
        }
        if len(doc["mode"]) < 3:
            doc["mode"] = doc["mode"].zfill(3)
        if birth is not None:
            doc["birthtime_ns"] = int(birth * 1e9)
        if arch:
            doc["architecture"] = arch
        if path != doc["path"]:
            doc["resolved_path"] = path                                # a link, or a parent directory that is a link: both paths are recorded
        doc["_md5"] = md5.hexdigest() if md5 else None
        doc["_head"] = head
        last = doc
        if stable:
            return doc
    return last          # unstable twice: returned with stable_during_read=false; the combiner makes no integrity claim
