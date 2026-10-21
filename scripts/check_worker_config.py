#!/usr/bin/env python3
"""Refuses a Worker config that must not be deployed: placeholders, a wrong host, incomplete bindings.

    check_worker_config.py --config <effective wrangler.toml>      what `wrangler deploy` is about to use
    check_worker_config.py --template <admin/worker/wrangler.toml>   the tracked template: only the known placeholders may remain

Exit 0 when the config is deployable, 1 with every problem listed, 2 on usage or unreadable input. Secret values are never read (they are not in the file).
"""
import argparse
import re
import sys
import tomllib

HOST = "panel.mac-guard.com"
URL = f"https://{HOST}"
KNOWN_PLACEHOLDERS = {"REPLACE-WITH-ADMIN-HOSTNAME", "REPLACE-WITH-D1-ID"}
PLACEHOLDER = re.compile(r"REPLACE|EXAMPLE|CHANGEME|TODO|<[^>]*>|YOUR[-_]", re.I)
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
REQUIRED_VARS = {"REPO": "MacGuard/macguard-yara-channel", "PIPELINE_WORKFLOWS": "daily.yml,publish.yml"}


def strings(node, path=""):
    if isinstance(node, str):
        yield path, node
    elif isinstance(node, dict):
        for k, v in node.items():
            yield from strings(v, f"{path}.{k}" if path else k)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from strings(v, f"{path}[{i}]")


def problems(cfg, template):
    out = []
    for path, value in strings(cfg):
        left = value
        for known in KNOWN_PLACEHOLDERS if template else ():
            left = left.replace(known, "")
        if PLACEHOLDER.search(left):
            out.append(f"placeholder or example value in {path}")
    if cfg.get("name") != "macguard-quarantine":
        out.append("name is not macguard-quarantine")
    if not cfg.get("main"):
        out.append("main is missing")
    if cfg.get("workers_dev") is not False:
        out.append("workers_dev must be false")
    v = cfg.get("vars", {})
    if not template:
        for key in ("PUBLIC_URL", "OIDC_AUDIENCE"):
            if v.get(key) != URL:
                out.append(f"{key} must be exactly {URL} (no trailing slash)")
        routes = cfg.get("routes", [])
        if not any(isinstance(r, dict) and r.get("pattern") == HOST and r.get("custom_domain") is True for r in routes):
            out.append(f"routes must contain the custom domain {HOST}")
    for key, want in REQUIRED_VARS.items():
        if v.get(key) != want:
            out.append(f"{key} must be {want}")
    d1 = [d for d in cfg.get("d1_databases", []) if d.get("binding") == "DB"]
    if len(d1) != 1:
        out.append("exactly one D1 binding named DB is required")
    elif d1[0].get("database_name") != "macguard-quarantine":
        out.append("D1 database_name must be macguard-quarantine")
    elif not template and not UUID.match(str(d1[0].get("database_id", ""))):
        out.append("D1 database_id is not a UUID")
    if cfg.get("assets", {}).get("binding") != "ASSETS" or not cfg.get("assets", {}).get("directory"):
        out.append("the ASSETS binding with its directory is required")
    return out


def main(argv):
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--config")
    g.add_argument("--template")
    args = ap.parse_args(argv)
    path, template = (args.config, False) if args.config else (args.template, True)
    try:
        with open(path, "rb") as f:
            cfg = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as e:
        print(f"cannot read {path}: {e}", file=sys.stderr)
        return 2
    found = problems(cfg, template)
    for p in found:
        print(f"REFUSED: {p}")
    if not found:
        print(f"OK: {path} is deployable" if not template else f"OK: {path} keeps only the known placeholders")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
