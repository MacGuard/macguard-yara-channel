#!/usr/bin/env python3
"""Builds macguard-mgctl_<version>_all.deb in pure Python (an ar archive: debian-binary, control.tar.gz, data.tar.gz). Needs no dpkg.

  python3 pkg/make_deb.py --out dist/

The package installs /usr/bin/mgctl and /usr/lib/mgctl/. It never ships 'mg' (that name belongs to the mg editor package) and has no
maintainer scripts. Whether dpkg accepts it on a real Debian/Ubuntu system has to be checked there (dpkg-deb --info / lintian)."""
import argparse
import gzip
import hashlib
import io
import os
import sys
import tarfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from mgctl import VERSION  # noqa: E402
from pkg.make_dist import collect  # noqa: E402

PACKAGE = "macguard-mgctl"


def _tar_gz(entries):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for name, data, mode, kind, link in entries:
            ti = tarfile.TarInfo(name)
            ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname, ti.mode = 0, 0, 0, "root", "root", mode
            if kind == "dir":
                ti.type = tarfile.DIRTYPE
                tar.addfile(ti)
            elif kind == "link":
                ti.type, ti.linkname = tarfile.SYMTYPE, link
                tar.addfile(ti)
            else:
                ti.size = len(data)
                tar.addfile(ti, io.BytesIO(data))
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=0) as gz:
        gz.write(raw.getvalue())
    return out.getvalue()


def _ar(members):
    out = b"!<arch>\n"
    for name, data in members:
        out += f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n".encode()
        out += data + (b"\n" if len(data) % 2 else b"")
    return out


def build(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    files, dirs = [], set()
    entries = [("./", b"", 0o755, "dir", None)]
    for d in ("usr", "usr/bin", "usr/lib", "usr/lib/mgctl", "usr/lib/mgctl/bin", "usr/lib/mgctl/mgctl", "usr/lib/mgctl/mgctl/services", "usr/share", "usr/share/doc", f"usr/share/doc/{PACKAGE}"):
        entries.append((f"./{d}/", b"", 0o755, "dir", None))
    for src, dst in collect():
        data = open(os.path.join(ROOT, src), "rb").read()
        if dst.startswith("mgctl/"):
            target = f"usr/lib/mgctl/{dst}"
        elif dst == "bin/mgctl":
            target = "usr/lib/mgctl/bin/mgctl"
        elif dst.startswith("docs/"):
            target = f"usr/share/doc/{PACKAGE}/{os.path.basename(dst)}"
        else:
            continue
        mode = 0o755 if target.endswith("bin/mgctl") else 0o644
        entries.append((f"./{target}", data, mode, "file", None))
        files.append((target, data))
    entries.append(("./usr/bin/mgctl", b"", 0o777, "link", "../lib/mgctl/bin/mgctl"))
    data_tar = _tar_gz(entries)
    size_kb = max(1, sum(len(d) for _t, d in files) // 1024)
    control = (f"Package: {PACKAGE}\nVersion: {VERSION}\nSection: utils\nPriority: optional\nArchitecture: all\nDepends: python3 (>= 3.9)\n"
               f"Installed-Size: {size_kb}\nMaintainer: MacGuard <noreply@invalid.example>\n"
               "Description: mgctl, the canonical command of the MacGuard suite\n"
               " Front end that delegates to the MacGuard engines. It installs only the command 'mgctl';\n"
               " the short alias 'mg' is never created (it belongs to the mg editor).\n").encode()
    md5 = "".join(f"{hashlib.md5(d).hexdigest()}  {t}\n" for t, d in sorted(files)).encode()
    control_tar = _tar_gz([("./", b"", 0o755, "dir", None), ("./control", control, 0o644, "file", None), ("./md5sums", md5, 0o644, "file", None)])
    deb = _ar([("debian-binary", b"2.0\n"), ("control.tar.gz", control_tar), ("data.tar.gz", data_tar)])
    path = os.path.join(out_dir, f"{PACKAGE}_{VERSION}_all.deb")
    open(path, "wb").write(deb)
    return path


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="dist")
    print(build(ap.parse_args().out))
