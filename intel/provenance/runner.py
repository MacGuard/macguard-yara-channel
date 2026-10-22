"""The only place that starts subprocesses. No shell, fixed argument vectors, clean environment, timeout and output cap on every call.

Collectors receive a runner (a callable argv -> Result), so tests inject recorded outputs and never need the real tool."""
from __future__ import annotations
import os
import subprocess
import threading
from collections import namedtuple
from typing import List, Optional

Result = namedtuple("Result", "rc out err timed_out missing")     # missing=True: the executable does not exist or cannot be started

SAFE_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
EXTRA_PATH = ("/usr/local/bin", "/opt/homebrew/bin")             # only used to LOCATE tools that live outside the system dirs
MAX_OUT = 4 * 1024 * 1024
DEFAULT_TIMEOUT = 20


def _drain(stream, cap: int, sink: list) -> None:
    kept = 0
    try:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            if kept < cap:
                sink.append(chunk[: cap - kept])
                kept += len(chunk[: cap - kept])
    except Exception:
        pass


def system_runner(argv: List[str], timeout: int = DEFAULT_TIMEOUT, max_out: int = MAX_OUT) -> Result:
    """Runs argv (a list; argv[0] is an absolute path or a name looked up in the system dirs). Never raises for a failing child."""
    if not argv or any((not isinstance(a, str)) or "\x00" in a for a in argv):
        return Result(127, "", "bad argv", False, True)
    exe = argv[0]
    if not os.path.isabs(exe):
        exe = _which(exe)
        if exe is None:
            return Result(127, "", "executable not found", False, True)
    env = {"PATH": SAFE_PATH, "LC_ALL": "C", "LANG": "C", "HOMEBREW_NO_AUTO_UPDATE": "1", "HOMEBREW_NO_ANALYTICS": "1"}
    try:
        p = subprocess.Popen([exe] + list(argv[1:]), shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, close_fds=True)
    except FileNotFoundError:
        return Result(127, "", "executable not found", False, True)
    except (PermissionError, OSError) as e:
        return Result(126, "", str(e.strerror or e), False, True)
    out_b: list = []
    err_b: list = []
    ts = [threading.Thread(target=_drain, args=(p.stdout, max_out, out_b), daemon=True), threading.Thread(target=_drain, args=(p.stderr, max_out, err_b), daemon=True)]
    for t in ts:
        t.start()
    timed_out = False
    try:
        p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        p.kill()
        p.wait()
    for t in ts:
        t.join(timeout=2)
    dec = lambda bs: b"".join(bs).decode("utf-8", "replace")
    return Result(124 if timed_out else p.returncode, dec(out_b), dec(err_b), timed_out, False)


def _which(name: str) -> Optional[str]:
    for d in SAFE_PATH.split(":") + list(EXTRA_PATH):
        c = os.path.join(d, name)
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None
