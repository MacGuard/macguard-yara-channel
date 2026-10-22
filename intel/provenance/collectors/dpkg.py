"""APT / DPKG on Linux: ownership (dpkg-query -S), the per-package md5sums reference (dpkg -V semantics), conffile hashes from the status file,
apt history logs and the current apt policy (recorded as a name collision, never as origin).

IMPLEMENTED AGAINST RECORDED FIXTURES ONLY. There was no Linux host when this was written: the parsers follow the documented dpkg-query,
md5sums, status and history.log formats, and the real-host test is PENDING (tests.test_provenance.RealLinuxDpkgPending).

Facts the code relies on, from the dpkg documentation:
  * md5sums files hold 'md5hex  relative/path' (two spaces, no leading slash), one per package: /var/lib/dpkg/info/<pkg>[:<arch>].md5sums
  * the md5 is a weak hash stored on the same disk (root-writable): the best this gives is PARTIALLY_VERIFIED
  * many packages ship no md5sums; configuration files are checked through the Conffiles field of /var/lib/dpkg/status and are modified on purpose
  * Debian records no source repository per install: origin stays UNKNOWN (apt-cache policy shows today's offers, not the install's source)"""
from __future__ import annotations
import gzip
import os
import re
from typing import Dict, List, Optional, Tuple

from ..context import Ctx, read_small, safe_token
from ..model import Finding, claim

DPKG_QUERY = "/usr/bin/dpkg-query"
APT_CACHE = "/usr/bin/apt-cache"
MERGE = (("/bin/", "/usr/bin/"), ("/sbin/", "/usr/sbin/"), ("/lib/", "/usr/lib/"), ("/lib64/", "/usr/lib64/"))
MAX_STATUS = 256 * 1024 * 1024
MAX_LOG = 8 * 1024 * 1024


def glob_escape(p: str) -> str:
    return re.sub(r"([\\*?\[])", r"\\\1", p)


def alt_paths(p: str) -> List[str]:
    out = [p]
    for a, b in MERGE:
        if p.startswith(a):
            out.append(b + p[len(a):])
        elif p.startswith(b):
            out.append(a + p[len(b):])
    return out


def parse_search(out: str, paths: List[str]) -> Tuple[List[str], List[str]]:
    """Returns (package refs, diversion notes) for output lines 'pkg[, pkg2]: /path' and 'diversion by X from|to: /path'."""
    pkgs: List[str] = []
    notes: List[str] = []
    for line in out.splitlines():
        for p in paths:
            if line.endswith(": " + p):
                head = line[: -(len(p) + 2)]
                if head.startswith("diversion by "):
                    notes.append(head)
                else:
                    pkgs += [x.strip() for x in head.split(", ") if x.strip()]
    return list(dict.fromkeys(pkgs)), notes


def split_pkg(ref: str) -> Tuple[str, Optional[str]]:
    name, _, arch = ref.partition(":")
    return name, (arch or None)


def read_md5sums(ctx: Ctx, ref: str) -> Optional[Dict[str, str]]:
    name, arch = split_pkg(ref)
    for cand in dict.fromkeys([ref, name, f"{name}:{arch}" if arch else name]):
        data = read_small(ctx.under_root(f"/var/lib/dpkg/info/{cand}.md5sums"), 64 * 1024 * 1024)
        if data is not None:
            d: Dict[str, str] = {}
            for line in data.decode("utf-8", "replace").splitlines():
                m = re.match(r"^([0-9a-f]{32})  (.+)$", line)
                if m:
                    d["/" + m.group(2)] = m.group(1)
            return d
    return None


def status_stanza(ctx: Ctx, name: str, arch: Optional[str]) -> Optional[Dict[str, object]]:
    """Streams /var/lib/dpkg/status for one package: Version, Architecture, Status and Conffiles (path -> md5). None if unreadable."""
    p = ctx.under_root("/var/lib/dpkg/status")
    try:
        fh = open(p, "rb")
    except OSError:
        return None
    read = 0
    cur: Dict[str, object] = {}
    conf = False
    try:
        for raw in fh:
            read += len(raw)
            if read > MAX_STATUS:
                return None
            line = raw.decode("utf-8", "replace").rstrip("\n")
            if not line.strip():
                if cur.get("Package") == name and (arch is None or cur.get("Architecture") in (arch, "all")):
                    return cur
                cur, conf = {}, False
                continue
            if line[0] in " \t":
                if conf:
                    m = re.match(r"^\s+(\S+) ([0-9a-f]{32})(?: obsolete)?$", line)
                    if m:
                        cur.setdefault("_conf", {})[m.group(1)] = m.group(2)           # type: ignore[index]
                continue
            k, _, v = line.partition(":")
            conf = k == "Conffiles"
            if k in ("Package", "Version", "Architecture", "Status"):
                cur[k] = v.strip()
        if cur.get("Package") == name and (arch is None or cur.get("Architecture") in (arch, "all")):
            return cur
    finally:
        fh.close()
    return {}


def _read_log(path: str) -> Optional[str]:
    if path.endswith(".gz"):
        try:
            with gzip.open(path, "rb") as g:
                data = g.read(MAX_LOG + 1)
        except (OSError, EOFError):
            return None
        return data[:MAX_LOG].decode("utf-8", "replace")
    raw = read_small(path, MAX_LOG)
    return raw.decode("utf-8", "replace") if raw is not None else None


def apt_history(ctx: Ctx, name: str) -> Optional[Dict[str, str]]:
    """Newest history.log stanza that installed or upgraded the package: {date, action, commandline}. Logs rotate; absence says nothing."""
    base = ctx.under_root("/var/log/apt")
    try:
        files = sorted([x for x in os.listdir(base) if x.startswith("history.log")], key=lambda x: (x != "history.log", x))[:12]
    except OSError:
        return None
    best: Optional[Dict[str, str]] = None
    for fn in files:
        text = _read_log(os.path.join(base, fn))
        if not text:
            continue
        for stanza in text.split("\n\n"):
            fields = dict(re.findall(r"^([A-Za-z-]+): (.*)$", stanza, re.M))
            for action in ("Install", "Upgrade"):
                lst = fields.get(action, "")
                if re.search(r"(^|, )" + re.escape(name) + r"(:[a-z0-9-]+)? \(", lst):
                    d = fields.get("Start-Date", "")[:10]
                    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", d) and (best is None or d >= best["date"]):
                        best = {"date": d, "action": action, "commandline": fields.get("Commandline", "")[:200]}
    return best


def collect_dpkg(ctx: Ctx) -> Finding:
    f = Finding("dpkg")
    if ctx.os_family != "linux" or not os.path.isdir(ctx.under_root("/var/lib/dpkg")):
        f.applicable = False
        return f
    f.coverage_state = "DESIGNED"
    f.limits.append("dpkg support is implemented and tested against recorded fixtures only; the real-host test is PENDING (no Linux host was available)")
    paths = alt_paths(ctx.logical_path)
    cmd = "dpkg-query -S <escaped path>"
    r = ctx.run([DPKG_QUERY, "-S", glob_escape(paths[0])])
    pkgs, notes = parse_search(r.out, paths)
    if not pkgs and not r.missing and not r.timed_out and r.rc == 1 and len(paths) > 1:
        for alt in paths[1:]:
            r = ctx.run([DPKG_QUERY, "-S", glob_escape(alt)])
            pkgs, notes = parse_search(r.out, paths)
            if pkgs:
                break
    if r.missing or r.timed_out or (r.rc not in (0, 1)) or not os.access(ctx.under_root("/var/lib/dpkg/status"), os.R_OK):
        f.unqueryable.append("dpkg")
        ctx.book.add("dpkg-unreadable", "PACKAGE_DB_OWNER", "PACKAGE_DB", cmd, "SYSTEM_AUTHORITATIVE", "dpkg-db", present=False, exit_status=r.rc,
                     summary="the dpkg database could not be queried (tool missing, timeout, error or no read permission); 'no owner' is not concluded")
        f.miss("package_ownership", "dpkg database unreadable")
        return f
    if not pkgs:
        eid = ctx.book.add("dpkg-no-owner", "PACKAGE_DB_OWNER", "PACKAGE_DB", cmd, "SYSTEM_AUTHORITATIVE", "dpkg-db", present=False, exit_status=r.rc,
                           summary="dpkg-query -S read its database successfully and no package lists this path (files made by maintainer scripts, such as alternatives, are not listed either).")
        f.queried.append("dpkg")
        f.no_owner_ev.append(eid)
        return f
    f.queried.append("dpkg")
    if notes:
        f.why("package_ownership", "dpkg reports a diversion for this path: " + "; ".join(notes[:2]))
    for ref in pkgs[:4]:
        name, arch = split_pkg(ref)
        if not safe_token(name):
            continue
        st = status_stanza(ctx, name, arch)
        version = safe_token(str(st.get("Version"))) if st else None
        real_arch = arch or (str(st.get("Architecture")) if st and st.get("Architecture") else None)
        eid = ctx.book.add("dpkg-owner-" + name, "PACKAGE_DB_OWNER", "PACKAGE_DB", cmd, "SYSTEM_AUTHORITATIVE", "dpkg-db",
                           supports=[claim("package_ownership", "OWNED_BY_PACKAGE", "STRONG"), claim("installation_method", "SYSTEM_PACKAGE_MANAGER", "MODERATE")], exit_status=r.rc,
                           summary=f"dpkg database: package {name}" + (f" {version}" if version else "") + " lists this path. A replaced file keeps its owner entry.")
        f.owners.append({"manager": "dpkg", "name": name, "version": version or "", "arch": real_arch, "evidence_id": eid})
        f.installs.append({"value": "SYSTEM_PACKAGE_MANAGER", "manager": "dpkg", "evidence_id": eid})
        # integrity reference: md5sums, else Conffiles
        md5 = ctx.ident.get("_md5")
        sums = read_md5sums(ctx, ref)
        expected, source = None, None
        if sums is not None:
            for p in paths:
                if p in sums:
                    expected, source = sums[p], "md5sums"
                    break
        if expected is None and st and isinstance(st.get("_conf"), dict):
            for p in paths:
                if p in st["_conf"]:                                   # type: ignore[operator]
                    expected, source = st["_conf"][p], "conffile"      # type: ignore[index]
                    break
        if expected is None:
            f.miss("integrity_status", f"package {name} ships no md5sums entry for this file" if sums is not None else f"package {name} ships no md5sums file")
        elif not md5:
            f.integrity_failed.append("md5 of the file was not computed")
        else:
            ok = md5 == expected
            ev = ctx.book.add("dpkg-md5-" + name, "PACKAGE_DB_CHECKSUM_MATCH" if ok else "PACKAGE_DB_CHECKSUM_MISMATCH", "PACKAGE_DB",
                              "compare MD5 of the file with /var/lib/dpkg/info/<pkg>.md5sums" if source == "md5sums" else "compare MD5 with Conffiles in /var/lib/dpkg/status",
                              "SYSTEM_AUTHORITATIVE", "dpkg-db", contradicts=None if ok else [claim("integrity_status", "VERIFIED_INTACT", "MODERATE")],
                              summary=(f"MD5 {'equals' if ok else 'differs from'} the value dpkg recorded at install ({source}). MD5 is a weak hash kept on the same root-writable disk."
                                       + ("" if ok or source != "conffile" else " Configuration files are edited on purpose; a difference is expected.")))
            f.integrity.append({"kind": "PACKAGE_DB_CHECKSUM", "authority": f"dpkg {source} ({name})", "strength": "WEAK_HASH", "scope": "WHOLE_FILE_CONTENT", "writable": True,
                                "outcome": "MATCH" if ok else "MISMATCH", "evidence_id": ev,
                                "note": "dpkg verifies with MD5 stored beside the file; this never rises above PARTIALLY_VERIFIED."})
        h = apt_history(ctx, name)
        if h:
            hid = ctx.book.add("apt-history-" + name, "MANAGER_HISTORY_ENTRY", "LOG", "read /var/log/apt/history.log*", "MANAGER_DECLARED", "apt-log",
                               supports=[claim("installation_method", "SYSTEM_PACKAGE_MANAGER", "MODERATE")],
                               summary=f"apt history.log: {h['action'].lower()} of {name} on {h['date']}. Logs rotate and can be edited by root; the repository is not recorded.",
                               sensitive="commandline: " + h["commandline"] if h.get("commandline") else None)
            f.history.append({"at": h["date"] + "T00:00:00Z", "at_precision": "DAY", "change": "PACKAGE_INSTALLED" if h["action"] == "Install" else "PACKAGE_UPGRADED",
                              "known_via": "PACKAGE_MANAGER_LOG", "reliability": "MEDIUM", "evidence_ids": [hid], "detail": "date from apt history.log; the install source is not recorded there"})
            f.installs.append({"value": "SYSTEM_PACKAGE_MANAGER", "manager": "dpkg", "installed_at": h["date"] + "T00:00:00Z", "installed_at_basis": "LOG", "evidence_id": hid})
        pol = ctx.run([APT_CACHE, "policy", name])
        if not pol.missing and pol.rc == 0 and pol.out.strip():
            cand = re.search(r"Candidate: (\S+)", pol.out)
            inst = re.search(r"Installed: (\S+)", pol.out)
            ctx.book.add("apt-policy-" + name, "NAME_COLLISION_NOTE", "MANAGER_METADATA", "apt-cache policy <pkg>", "HEURISTIC", "catalog",
                         summary=f"apt-cache policy today: installed {inst.group(1) if inst else '?'}, candidate {cand.group(1) if cand else '?'}. These are today's offers; "
                                 "a repository offering the same name or version now does not show where the installed bytes came from. Ignored for origin.")
    f.miss("content_origin", "Debian/Ubuntu record no source repository per install; apt-cache policy shows today's offers only")
    f.miss("content_origin", "no deb or repository signature kept for the installed file")
    f.attestations.append({"kind": "APT_RELEASE_SIGNATURE", "availability": "NOT_CHECKED"})
    f.historical = "PARTIAL"
    return f
