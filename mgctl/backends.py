"""Locating and calling the engines mgctl delegates to. Arguments always travel as a list: there is no shell and no string interpolation."""
from __future__ import annotations
import os
import platform
import shutil
import subprocess
import sys
import threading
from typing import List, Optional, Tuple

AUDIT_NAME = "macguard-audit"


def _executable_file(p: Optional[str]) -> Optional[str]:
    if p and os.path.isfile(p) and os.access(p, os.X_OK):
        return os.path.abspath(p)
    return None


def audit_bin() -> Optional[str]:
    """macguard-audit: MGCTL_AUDIT_BIN, then the folder of this executable, then PATH. Only macOS builds exist today."""
    env = _executable_file(os.environ.get("MGCTL_AUDIT_BIN"))
    if env:
        return env
    here = os.path.dirname(os.path.abspath(sys.argv[0] or ""))
    return _executable_file(os.path.join(here, AUDIT_NAME)) or _executable_file(shutil.which(AUDIT_NAME))


def verifier_script() -> Optional[str]:
    """scripts/verify_public_release.py: MGCTL_VERIFIER, or the checkout this file lives in."""
    env = os.environ.get("MGCTL_VERIFIER")
    if env:
        return env if os.path.isfile(env) else None
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cand = os.path.join(here, "scripts", "verify_public_release.py")
    return cand if os.path.isfile(cand) else None


def intel_root() -> Optional[str]:
    """The folder that contains the `intel` package: MGCTL_INTEL_DIR, or the folder that contains the mgctl package."""
    env = os.environ.get("MGCTL_INTEL_DIR")
    cand = env if env else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return cand if os.path.isfile(os.path.join(cand, "intel", "__main__.py")) else None


def is_macos() -> bool:
    return platform.system() == "Darwin"


_LIVE: set = set()
_LOCK = threading.Lock()


def terminate_all() -> None:
    """Stops every child still running (used when the user cancels). Only processes started by mgctl are ever touched."""
    with _LOCK:
        procs = list(_LIVE)
    for p in procs:
        try:
            p.terminate()
        except Exception:
            pass
    for p in procs:
        try:
            p.wait(timeout=3)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass


def run(argv: List[str], timeout: int, stdin_null: bool = True, capture: bool = True, env: Optional[dict] = None) -> Tuple[int, str, str, bool]:
    """Returns (returncode, stdout, stderr, timed_out). Never raises for a failing child; a missing executable is returncode 127."""
    try:
        p = subprocess.Popen(argv, shell=False, stdin=subprocess.DEVNULL if stdin_null else None,
                             stdout=subprocess.PIPE if capture else None, stderr=subprocess.PIPE if capture else None, text=True, errors="replace", env=env)
    except FileNotFoundError:
        return 127, "", "executable not found", False
    except PermissionError:
        return 126, "", "permission denied", False
    with _LOCK:
        _LIVE.add(p)
    try:
        out, err = p.communicate(timeout=timeout)
        return p.returncode, out or "", err or "", False
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()
        return 124, out or "", err or "", True
    finally:
        with _LOCK:
            _LIVE.discard(p)
