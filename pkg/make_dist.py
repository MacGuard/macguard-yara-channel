#!/usr/bin/env python3
"""Builds the source distribution of mgctl: mgctl-<version>.tar.gz and SHA256SUMS (deterministic: sorted names, fixed owner and times).

  python3 pkg/make_dist.py --out dist/

Nothing is signed or published here. To sign the checksums use `cosign sign-blob` (see docs/cli/mgctl-install.md)."""
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

# (source path relative to the repository, path inside the archive relative to the top folder)
FILES = [("bin/mgctl", "bin/mgctl"), ("pkg/install.sh", "install.sh"), ("docs/cli/mgctl.md", "docs/mgctl.md"), ("docs/cli/mgctl-install.md", "docs/mgctl-install.md")]


def collect():
    out = list(FILES)
    for d, _dirs, files in os.walk(os.path.join(ROOT, "mgctl")):
        if "__pycache__" in d:
            continue
        for f in files:
            if f.endswith((".py",)):
                rel = os.path.relpath(os.path.join(d, f), ROOT)
                out.append((rel, rel))
    return sorted(out, key=lambda x: x[1])


def build(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    top = f"mgctl-{VERSION}"
    name = os.path.join(out_dir, top + ".tar.gz")
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for src, dst in collect():
            data = open(os.path.join(ROOT, src), "rb").read()
            ti = tarfile.TarInfo(f"{top}/{dst}")
            ti.size, ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname = len(data), 0, 0, 0, "", ""
            ti.mode = 0o755 if dst in ("bin/mgctl", "install.sh") else 0o644
            tar.addfile(ti, io.BytesIO(data))
    with open(name, "wb") as f:
        with gzip.GzipFile(fileobj=f, mode="wb", mtime=0) as gz:
            gz.write(raw.getvalue())
    digest = hashlib.sha256(open(name, "rb").read()).hexdigest()
    sums = os.path.join(out_dir, "SHA256SUMS")
    with open(sums, "w") as f:
        f.write(f"{digest}  {os.path.basename(name)}\n")
    return name, sums, digest


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="dist")
    a = ap.parse_args()
    n, s, d = build(a.out)
    print(n)
    print(s)
    print(d)
