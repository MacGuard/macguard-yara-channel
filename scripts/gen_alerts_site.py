#!/usr/bin/env python3
"""Regenerates the static alert data of the site from what this repository can reproduce on its own: the YARA release log (logs/log.jsonl, first-party data)
and the source registry. Vulnerability alerts need downloaded channels and a cleared source, so they appear here only when the registry says they may.

Writes web/feeds/*, web/feeds/public/*.xml and web/intelligence/alerts/data/*.json. The generation time is the time of the newest release event (deterministic).
usage: gen_alerts_site.py [--check]     --check compares with the committed files and exits 1 on a difference"""
import argparse, json, os, pathlib, shutil, sys, tempfile
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from intel import registry as reg  # noqa: E402
from alerts import engine, sitegen, sources, store  # noqa: E402


def build(out: pathlib.Path, vuln_channels=()):
    registry = reg.load()
    log = ROOT / 'logs' / 'log.jsonl'
    last = max((json.loads(l)['time'] for l in log.read_text(encoding='utf-8').splitlines() if l.strip() and '"release.published"' in l), default='1970-01-01T00:00:00Z')
    now = datetime.strptime(last, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    tmp = tempfile.mkdtemp(prefix='alerts-site-')
    try:
        db_path = os.path.join(tmp, 'a.db')
        db = store.connect(db_path)
        contents, runs = [], []
        c, r = sources.yara_release_contents(str(log), registry)
        contents += c; runs += r
        if vuln_channels:
            c, r, _m = sources.vulnerability_contents(list(vuln_channels), registry, now)
            contents += c; runs += r
        engine.ingest(db, contents, store.utc(now), runs)
        db.close()
        return sitegen.generate(db_path, registry, str(out), now)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def files(root: pathlib.Path):
    out = {}
    for rel in ('feeds', 'intelligence/alerts/data'):
        for p in sorted((root / rel).rglob('*')):
            if p.is_file():
                out[p.relative_to(root).as_posix()] = p.read_bytes()
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--check', action='store_true'); ap.add_argument('--vuln-channel', action='append', default=[], help='built vulnerability channel directories (local runs; the committed data uses none)')
    a = ap.parse_args(argv)
    web = ROOT / 'web'
    if a.check:
        t = pathlib.Path(tempfile.mkdtemp(prefix='alerts-site-check-'))
        try:
            build(t)
            fresh, have = files(t), files(web)
            bad = sorted(k for k in fresh if have.get(k) != fresh[k]) + sorted(k for k in have if k not in fresh)
            for k in bad: print('DIFFERS', k)
            print('gen_alerts_site: committed data', 'differs' if bad else 'matches the sources')
            return 1 if bad else 0
        finally:
            shutil.rmtree(t, ignore_errors=True)
    for rel in ('feeds', 'intelligence/alerts/data'):
        shutil.rmtree(web / rel, ignore_errors=True)
    n_feeds, n_alerts = build(web, a.vuln_channel)
    print(f'wrote {n_feeds} feed files and {n_alerts} alerts under web/')
    return 0


if __name__ == '__main__':
    sys.exit(main())
