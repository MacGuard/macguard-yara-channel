"""python3 -m intel provenance file PATH [--json] [--redact] [--follow-symlinks] [--out FILE]

Exit codes: 0 a document was produced (even if every field is UNKNOWN, which the document says), 3 bad path or arguments, 4 this OS is not supported."""
from __future__ import annotations
import json
import os
import sys

from .engine import Unavailable, assess
from .fileid import PathError
from .render import render_text


def add_parser(sub) -> None:
    pv = sub.add_parser("provenance", help="per-file software provenance (read-only, offline)").add_subparsers(dest="pvcmd", required=True)
    fl = pv.add_parser("file", help="where did this file come from? six separate facts, evidence, absences and limits")
    fl.add_argument("path")
    fl.add_argument("--json", action="store_true", help="print the schema document on standard output")
    fl.add_argument("--redact", action="store_true", help="drop download URLs, quarantine agent/time and command lines from the output")
    fl.add_argument("--follow-symlinks", action="store_true", help="assess the target of a symbolic link (both paths are recorded)")
    fl.add_argument("--out", help="write the JSON document to this new file (never overwrites; mode 0600)")
    fl.add_argument("--timeout", type=int, default=20, help="seconds allowed to each external tool (default 20)")
    fl.set_defaults(fn=cmd_file)


def write_new(path: str, text: str) -> None:
    p = os.path.abspath(os.path.expanduser(path))
    if "\x00" in path:
        raise PathError("the output path contains a NUL byte")
    try:
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        raise PathError("the output file already exists; it is never overwritten")
    except OSError as e:
        raise PathError(f"cannot create the output file ({e.strerror})")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)


def cmd_file(a) -> int:
    if not 1 <= a.timeout <= 600:
        print("error: --timeout must be between 1 and 600", file=sys.stderr)
        return 3
    try:
        out = assess(a.path, follow_symlinks=a.follow_symlinks, timeout=a.timeout, redact=a.redact)
    except PathError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    except Unavailable as e:
        print(f"error: {e}", file=sys.stderr)
        return 4
    text = json.dumps(out, indent=2, sort_keys=True, ensure_ascii=False)
    if a.out:
        try:
            write_new(a.out, text + "\n")
        except PathError as e:
            print(f"error: {e}", file=sys.stderr)
            return 3
    print(text if a.json else render_text(out))
    return 0
