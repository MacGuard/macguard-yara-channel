"""Strict path validation. Paths are data: they are never put into a shell and always reach an engine as absolute paths."""
from __future__ import annotations
import os
import stat
from typing import Tuple

from .core import UsageError

MAX_PATH = 4096


def validate_path(raw: str, *, follow_symlinks: bool = False, allow_dir: bool = False) -> Tuple[str, str, os.stat_result]:
    """Returns (given_absolute, resolved_absolute, stat_of_resolved). Raises UsageError for anything suspicious."""
    if not isinstance(raw, str) or not raw.strip():
        raise UsageError("the path is empty")
    if "\x00" in raw:
        raise UsageError("the path contains a NUL byte")
    if len(raw) > MAX_PATH:
        raise UsageError("the path is too long")
    given = os.path.abspath(os.path.expanduser(raw))
    try:
        lst = os.lstat(given)
    except FileNotFoundError:
        raise UsageError("path not found")
    except PermissionError:
        raise UsageError("permission denied reading the path")
    except OSError as e:
        raise UsageError(f"cannot read the path ({e.strerror})")
    resolved = given
    if stat.S_ISLNK(lst.st_mode):
        if not follow_symlinks:
            raise UsageError("the path is a symbolic link; pass --follow-symlinks to audit its target")
        resolved = os.path.realpath(given)
        try:
            lst = os.stat(resolved)
        except OSError as e:
            raise UsageError(f"the link target cannot be read ({e.strerror})")
    if stat.S_ISREG(lst.st_mode):
        return given, resolved, lst
    if stat.S_ISDIR(lst.st_mode) and allow_dir:
        return given, resolved, lst
    raise UsageError("only regular files are accepted" + (" (or bundles/folders)" if allow_dir else ""))


def prepare_output_dir(path: str) -> str:
    """Creates the directory when absent (mode 0700) and refuses a path that is a file or a symbolic link. Existing report files are never overwritten by the caller."""
    if "\x00" in path:
        raise UsageError("the output path contains a NUL byte")
    p = os.path.abspath(os.path.expanduser(path))
    if os.path.islink(p):
        raise UsageError("the output directory is a symbolic link")
    if os.path.exists(p) and not os.path.isdir(p):
        raise UsageError("the output path exists and is not a directory")
    try:
        os.makedirs(p, mode=0o700, exist_ok=True)
    except OSError as e:
        raise UsageError(f"cannot create the output directory ({e.strerror})")
    if not os.access(p, os.W_OK):
        raise UsageError("the output directory is not writable")
    return p
