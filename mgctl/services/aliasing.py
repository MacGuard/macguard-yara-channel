"""The optional 'mg' alias. 'mg' belongs to other software (the mg editor ships with macOS and Debian), so mgctl treats it as a guest:

  - installation never creates it; only 'mgctl alias enable' does, on explicit request;
  - it never overwrites anything, never edits PATH, never touches files owned by APT, DNF or Homebrew;
  - it refuses when any other 'mg' is on PATH unless --force-conflict, and even then it does not gain priority;
  - 'mgctl alias disable' removes it, and only if it points to mgctl.
"""
from __future__ import annotations
import os
import shutil
import sys
from typing import Any, Dict, List, Optional

from ..core import UNAVAILABLE, UsageError

NAME = "mg"
CANONICAL = "mgctl"


def default_dir() -> str:
    return os.path.expanduser("~/.local/bin")


def launcher() -> Optional[str]:
    """Absolute path of the mgctl executable the alias would point to."""
    env = os.environ.get("MGCTL_LAUNCHER")
    cands = [env] if env else []
    cands += [shutil.which(CANONICAL), sys.argv[0] if os.path.basename(sys.argv[0]) == CANONICAL else None]
    for c in cands:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return os.path.abspath(c)
    return None


def is_ours(path: str) -> bool:
    return os.path.islink(path) and os.path.basename(os.path.realpath(path)) == CANONICAL


def on_path() -> List[Dict[str, Any]]:
    seen, found = set(), []
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if not d:
            continue
        p = os.path.join(d, NAME)
        if os.path.lexists(p) and p not in seen and (os.path.isfile(p) or os.path.islink(p)):
            seen.add(p)
            found.append({"path": p, "ours": is_ours(p), "symlink": os.path.islink(p)})
    return found


def status() -> Dict[str, Any]:
    found = on_path()
    return {"name": NAME, "found": found, "conflict": any(not f["ours"] for f in found), "enabled": any(f["ours"] for f in found), "launcher": launcher()}


def _check_dir(d: str) -> str:
    d = os.path.abspath(os.path.expanduser(d))
    if os.path.islink(d):
        raise UsageError("the target directory is a symbolic link")
    if not os.path.isdir(d):
        raise UsageError(f"the target directory does not exist: create it first ({d})")
    if not os.access(d, os.W_OK):
        raise UsageError("the target directory is not writable by you (mgctl never asks for root)")
    return d


def enable(directory: Optional[str], force_conflict: bool) -> Dict[str, Any]:
    d = _check_dir(directory or default_dir())
    target = launcher()
    if not target:
        return {"ok": False, "code": UNAVAILABLE, "message": "cannot find the mgctl executable to link to (put mgctl on PATH or set MGCTL_LAUNCHER)"}
    link = os.path.join(d, NAME)
    if os.path.lexists(link):
        return {"ok": False, "code": UNAVAILABLE, "message": f"{link} already exists; mgctl never overwrites it", "link": link}
    others = [f for f in on_path() if not f["ours"]]
    if others and not force_conflict:
        return {"ok": False, "code": UNAVAILABLE, "conflicts": [f["path"] for f in others],
                "message": "another 'mg' is already on PATH (" + ", ".join(f["path"] for f in others) + "); not creating the alias. Use mgctl, or pass --force-conflict to create it anyway (it will not take priority)."}
    os.symlink(target, link)
    on = [f["path"] for f in on_path()]
    shadow = [p for p in on if p != link and os.path.dirname(p) != d]
    msg = f"created {link} -> {target}. Remove it with: mgctl alias disable"
    if shadow:
        msg += ". Warning: another 'mg' exists on PATH and the shell will keep using: " + shadow[0]
    return {"ok": True, "code": 0, "link": link, "target": target, "message": msg, "shadowedBy": shadow}


def disable(directory: Optional[str]) -> Dict[str, Any]:
    d = _check_dir(directory or default_dir())
    link = os.path.join(d, NAME)
    if not os.path.lexists(link):
        return {"ok": True, "code": 0, "message": f"nothing to remove: {link} does not exist"}
    if not is_ours(link):
        return {"ok": False, "code": UNAVAILABLE, "message": f"{link} is not a link to mgctl; mgctl will not touch it", "link": link}
    os.unlink(link)
    return {"ok": True, "code": 0, "message": f"removed {link}", "link": link}
