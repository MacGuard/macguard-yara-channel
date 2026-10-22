"""Command line for the archive toolset. Every command prints one JSON report on stdout and exits 0 only when that report is ok.
Provider configuration is a JSON file (no secrets in it: the rclone/aws tool finds its credentials in its own environment):
  {"providers": [{"name": "r2", "type": "s3", "kind": "rclone", "cli": ["rclone"], "remote": "r2", "bucket": "..."},
                 {"name": "b2", "type": "s3", "kind": "aws", "cli": ["aws", "--endpoint-url", "https://s3.<region>.backblazeb2.com"], "bucket": "..."},
                 {"name": "local", "type": "local", "root": "/some/dir"}]}"""
import argparse, datetime, json, os, pathlib, sys

from . import manifest as man, monthly
from .canon import GENESIS, seal_bytes, seal_sha256
from .crypto import AgeCli
from .prune import check_period
from .providers import LocalDirectory, S3Cli
from .restore import list_periods, rehearse_period, restore_audit, restore_release, default_verifier
from .segment import SegmentError, build_segments, read_export, verify_archive
from .store import ArchiveError, archive_audit_period, archive_logs_segment, archive_release, make_receipt, read_unit


def provider_from_env(name) -> S3Cli:
    """One S3-compatible provider through rclone; its rclone remote is always called `archive` and is configured by RCLONE_CONFIG_ARCHIVE_* variables set by the workflow. Only the bucket name is read here."""
    bucket = os.environ.get('ARCHIVE_BUCKET')
    if not bucket: raise ArchiveError('ARCHIVE_BUCKET is not set')
    return S3Cli(name, 'rclone', ['rclone'], bucket, remote='archive')


def load_providers(path, only=None, from_env=None) -> list:
    if from_env: return [provider_from_env(from_env)]
    cfg = json.loads(pathlib.Path(path).read_text())['providers']
    out = []
    for c in cfg:
        if only and c['name'] not in only: continue
        if c['type'] == 'local': out.append(LocalDirectory(c['root'], c['name']))
        elif c['type'] == 's3': out.append(S3Cli(c['name'], c['kind'], c['cli'], c['bucket'], c.get('remote'), timeout=c.get('timeout', 120)))
        else: raise ArchiveError(f'unknown provider type {c["type"]!r}')
    if not out: raise ArchiveError('no provider selected')
    return out


def crypto_from(a) -> AgeCli: return AgeCli(a.recipient, binary=a.age.split() if a.age else ('age',))
def emit(rep) -> int:
    print(json.dumps(rep, indent=1, sort_keys=True)); return 0 if rep.get('ok', rep.get('complete', rep.get('ready', True))) else 1
def jload(p): return json.loads(pathlib.Path(p).read_text())


def cmd_segment(a):
    rows = read_export(a.export)
    prev = jload(a.prev_seal) if a.prev_seal else None
    segs = build_segments(rows, a.start_hash, prev)
    if not a.include_last and segs: segs = segs[:-1]   # the newest month is still open
    out = pathlib.Path(a.out_dir); out.mkdir(parents=True, exist_ok=True)
    for s in segs:
        (out / f'segment-{s["period"]}.jsonl').write_bytes(s['segment']); (out / f'seal-{s["period"]}.json').write_bytes(seal_bytes(s['seal']))
    return {'ok': True, 'sealed': [s['period'] for s in segs], 'out_dir': str(out)}


def cmd_verify_local(a):
    d = pathlib.Path(a.dir)
    pairs = [(json.loads(p.read_text()), (d / p.name.replace('seal-', 'segment-').replace('.json', '.jsonl')).read_bytes()) for p in sorted(d.glob('seal-*.json'))]
    r = verify_archive(pairs, a.start_hash, a.expected_head); return {'ok': True, **r}


def cmd_archive_audit(a):
    provs = load_providers(a.providers); seal = jload(a.seal)
    rep = archive_audit_period(provs, seal, pathlib.Path(a.segment).read_bytes(), crypto_from(a)); rep['ok'] = rep['complete']; return rep


def cmd_archive_release(a):
    provs = load_providers(a.providers)
    pre = None if a.skip_precheck else (lambda d: _precheck(d, a.tag))
    res = archive_release(provs, a.dir, a.tag, pre); return {'ok': all('error' not in r for r in res) and len(res) >= 1, 'results': res}


def _precheck(d, tag):
    import subprocess
    r = subprocess.run(default_verifier(d, tag), capture_output=True, text=True, timeout=600)
    if r.returncode != 0: raise ArchiveError('release failed verify_public_release.py; nothing was uploaded')


def cmd_archive_logs(a):
    provs = load_providers(a.providers); d = pathlib.Path(a.dir)
    res = archive_logs_segment(provs, a.name, {p.name: p.read_bytes() for p in sorted(d.iterdir()) if p.is_file()}); return {'ok': all('error' not in r for r in res), 'results': res}


def pick(a):
    if a.from_env: return provider_from_env(a.from_env)
    if not (a.providers and a.provider): raise ArchiveError('give --from-env <name> or --providers file --provider name')
    return load_providers(a.providers, [a.provider])[0]


def cmd_restore(a):
    prov = pick(a)
    if a.tag: return restore_release(prov, a.tag, a.out_dir, previous_checkpoint=a.previous_checkpoint)
    return restore_audit(prov, crypto_from(a) if a.identity else None, a.identity, a.period or None, a.start_hash, a.expected_head)


def cmd_rehearse(a):
    prov = pick(a); return rehearse_period(prov, a.period, crypto_from(a), a.identity)


def cmd_receipt(a):
    rec = make_receipt(jload(a.archive_report), jload(a.rehearsal)); pathlib.Path(a.out).write_text(json.dumps(rec, indent=1, sort_keys=True) + '\n'); return {'ok': True, 'receipt': a.out}


def cmd_manifest(a):
    provs = load_providers(a.providers, None, a.from_env); prev = pathlib.Path(a.prev).read_bytes() if a.prev else None
    if a.prev_latest:
        import re
        older = sorted(k for k in provs[0].list('manifests/') if re.fullmatch(r'manifests/archive-manifest-\d{4}-\d{2}-\d{2}\.json', k) and k < f'manifests/archive-manifest-{a.date}.json')
        prev = provs[0].get(older[-1]) if older else None
    data = man.build(provs, a.date, prev, jload(a.extra) if a.extra else None); pathlib.Path(a.out).write_bytes(data)
    rep = {'ok': True, 'out': a.out, **man.verify(data, None, prev)}
    if a.store: rep['stored'] = man.store(provs, a.date, data)
    return rep


def cmd_prune_check(a):
    provs = load_providers(a.providers)
    return check_period(provs, a.period, jload(a.rehearsal) if a.rehearsal else None, jload(a.d1_anchors) if a.d1_anchors else [],
                        jload(a.authorization) if a.authorization else None, list_periods(provs[0]))


def one(a): return load_providers(getattr(a, 'providers', None), None, a.from_env)[0]


def cmd_prepare_month(a):
    if a.export_file: rows, anchors = [json.loads(l) for l in pathlib.Path(a.export_file).read_text().splitlines() if l.strip()], []
    else: rows, anchors = monthly.fetch_audit(a.d1_database)
    period = a.current_period or datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m')
    return monthly.prepare(rows, anchors, crypto_from(a), a.out_dir, period)


def cmd_pack_prepared(a): return {'ok': True, 'file': a.out, 'sha256': monthly.pack(a.dir, a.out)}
def cmd_unpack_prepared(a): return monthly.unpack(a.file, a.dir)
def cmd_publish_prepared(a): return monthly.publish(one(a), a.dir)
def cmd_verify_prepared(a): return monthly.verify(one(a), a.dir)


def cmd_put_manifest(a):
    prov = one(a); out = []
    for suffix, src in (('json', a.file), ('sigstore.json', a.bundle)):
        from .store import put_verified
        out.append({'key': f'manifests/archive-manifest-{a.date}.{suffix}', 'status': put_verified(prov, f'manifests/archive-manifest-{a.date}.{suffix}', pathlib.Path(src).read_bytes())})
    return {'ok': True, 'provider': prov.name, 'stored': out}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog='archivectl', description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    def P(name, fn, **kw):
        p = sub.add_parser(name, **kw); p.set_defaults(fn=fn); return p
    def crypto_args(p): p.add_argument('--recipient', action='append', default=[], help='public age recipient (repeat)'); p.add_argument('--age', help='age command, default: age')
    p = P('segment', cmd_segment, help='cut an audit export into monthly segments and seals'); p.add_argument('--export', required=True); p.add_argument('--out-dir', required=True)
    p.add_argument('--start-hash', default=GENESIS); p.add_argument('--prev-seal'); p.add_argument('--include-last', action='store_true', help='also seal the newest (possibly open) month')
    p = P('verify-local', cmd_verify_local, help='verify plaintext segments + seals in a directory'); p.add_argument('--dir', required=True); p.add_argument('--start-hash', default=GENESIS); p.add_argument('--expected-head')
    p = P('archive-audit', cmd_archive_audit, help='encrypt one sealed segment and write it to every provider'); p.add_argument('--providers', required=True); p.add_argument('--seal', required=True); p.add_argument('--segment', required=True); crypto_args(p)
    p = P('archive-release', cmd_archive_release, help='archive a release bundle directory'); p.add_argument('--providers', required=True); p.add_argument('--dir', required=True); p.add_argument('--tag', required=True)
    p.add_argument('--skip-precheck', action='store_true', help='skip verify_public_release.py (tests only)')
    p = P('archive-logs', cmd_archive_logs, help='archive public log files/checkpoints/proofs'); p.add_argument('--providers', required=True); p.add_argument('--dir', required=True); p.add_argument('--name', required=True)
    p = P('restore', cmd_restore, help='restore and verify from ONE provider'); p.add_argument('--providers'); p.add_argument('--provider'); p.add_argument('--from-env')
    p.add_argument('--tag'); p.add_argument('--out-dir'); p.add_argument('--previous-checkpoint'); p.add_argument('--identity'); p.add_argument('--period', action='append'); p.add_argument('--start-hash'); p.add_argument('--expected-head'); crypto_args(p)
    p = P('rehearse', cmd_rehearse, help='restore rehearsal of one sealed period (evidence for the anchor)'); p.add_argument('--providers'); p.add_argument('--provider'); p.add_argument('--from-env'); p.add_argument('--period', required=True); p.add_argument('--identity', required=True); crypto_args(p)
    p = P('receipt', cmd_receipt, help='build the receipt that the Worker anchor guard demands'); p.add_argument('--archive-report', required=True); p.add_argument('--rehearsal', required=True); p.add_argument('--out', required=True)
    p = P('manifest', cmd_manifest, help='build the archive manifest-of-manifests'); p.add_argument('--providers'); p.add_argument('--from-env'); p.add_argument('--date', required=True); p.add_argument('--out', required=True); p.add_argument('--prev'); p.add_argument('--prev-latest', action='store_true', help='chain to the newest earlier manifest held by the (first) provider'); p.add_argument('--extra'); p.add_argument('--store', action='store_true')
    p = P('prune-check', cmd_prune_check, help='DRY RUN: is this period ready to be pruned? (never deletes)'); p.add_argument('--providers', required=True); p.add_argument('--period', required=True); p.add_argument('--rehearsal'); p.add_argument('--d1-anchors'); p.add_argument('--authorization')
    def env_arg(p): p.add_argument('--from-env', required=True, help='provider name (r2, b2, scaleway): display name of the provider; rclone remote `archive` configured through RCLONE_CONFIG_ARCHIVE_* and ARCHIVE_BUCKET')
    p = P('prepare-month', cmd_prepare_month, help='workflow step: read the audit, seal complete months, encrypt'); p.add_argument('--out-dir', required=True); p.add_argument('--d1-database'); p.add_argument('--export-file'); p.add_argument('--current-period'); crypto_args(p)
    p = P('pack-prepared', cmd_pack_prepared, help='owner step: bundle a prepared directory and print its SHA-256'); p.add_argument('--dir', required=True); p.add_argument('--out', required=True)
    p = P('unpack-prepared', cmd_unpack_prepared, help='workflow step: safely unpack and check a prepared bundle'); p.add_argument('--file', required=True); p.add_argument('--dir', required=True)
    p = P('publish-prepared', cmd_publish_prepared, help='workflow step: write prepared months to ONE provider'); env_arg(p); p.add_argument('--dir', required=True)
    p = P('verify-prepared', cmd_verify_prepared, help='workflow step: read ONE provider back and verify'); env_arg(p); p.add_argument('--dir', required=True)
    p = P('put-manifest', cmd_put_manifest, help='workflow step: store the signed manifest of manifests in ONE provider'); env_arg(p); p.add_argument('--file', required=True); p.add_argument('--bundle', required=True); p.add_argument('--date', required=True)
    a = ap.parse_args(argv)
    try: return emit(a.fn(a))
    except (ArchiveError, SegmentError, ValueError, OSError, KeyError) as e:
        print(json.dumps({'ok': False, 'error': f'{type(e).__name__}: {str(e)[:400]}'})); return 2


if __name__ == '__main__': sys.exit(main())
