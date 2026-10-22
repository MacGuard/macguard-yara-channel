"""Steps of the monthly archive workflow (.github/workflows/archive.yml), each a plain function so they can be tested without any provider:

prepare   read the audit (read-only) from D1 through wrangler, cut complete months, seal and ENCRYPT them. Needs only PUBLIC age recipients.
publish   write the prepared months to ONE provider (write-only credentials); a month the provider already holds is never rewritten.
verify    read ONE provider back (read-only credentials) and check seals, continuity and digests against what was prepared.
Seals are deterministic from audit data, which D1 never changes, so preparing the same months again yields identical seals: the whole flow is idempotent."""
import io, json, os, pathlib, re, subprocess, tarfile

from .canon import GENESIS, canonical, seal_bytes, seal_sha256, sha256_hex
from .providers import MissingObject, ProviderError
from .restore import list_periods, restore_audit
from .segment import SegmentError, build_segments
from .store import ArchiveError, archive_unit, read_unit

WRANGLER = ('npx', '--yes', 'wrangler@4.149.0')
COLS = 'seq, at, actor, role, action, target, detail, prev_hash, hash'


def _query(database, sql, wrangler, timeout, run):
    r = run([*wrangler, 'd1', 'execute', database, '--remote', '--json', '--command', sql], capture_output=True, text=True, timeout=timeout)   # token comes from CLOUDFLARE_API_TOKEN in the environment
    if r.returncode != 0: raise ArchiveError('wrangler d1 execute failed: ' + (r.stderr or r.stdout)[-300:].strip())
    try: return json.loads(r.stdout)[0]['results']
    except (ValueError, KeyError, IndexError, TypeError): raise ArchiveError('unexpected wrangler output')


def fetch_audit(database, wrangler=WRANGLER, page=1000, timeout=180, run=subprocess.run):
    """(rows, anchors) read page by page. A database without the anchor table (0004 not applied) has no anchors."""
    rows, last = [], 0
    while True:
        got = _query(database, f'SELECT {COLS} FROM audit WHERE seq > {int(last)} ORDER BY seq ASC LIMIT {int(page)}', wrangler, timeout, run)
        rows += got
        if len(got) < page: break
        last = got[-1]['seq']
    try: anchors = _query(database, 'SELECT seq, hash, rows, seal_sha256 FROM audit_anchor ORDER BY seq ASC', wrangler, timeout, run)
    except ArchiveError as e:
        if 'no such table' not in str(e): raise
        anchors = []
    return rows, anchors


def prepare(rows, anchors, crypto, out_dir, current_period):
    """Seal every complete month (strictly before `current_period`, YYYY-MM, UTC) found in `rows` and write ciphertext + seal per period. Nothing private is written in clear."""
    from .canon import parse_row
    rows = [parse_row(r) for r in rows]
    if not rows: return {'ok': True, 'periods': [], 'note': 'no audit rows'}
    start, prev_digest = rows[0]['prev_hash'], None
    if start != GENESIS:
        a = [x for x in anchors if x['hash'] == start and x['seq'] < rows[0]['seq']]
        if not a: raise ArchiveError('oldest retained audit row links to a hash that is not GENESIS and not an anchor: refusing to seal')
        prev_digest = a[-1]['seal_sha256']
    segs = [s for s in build_segments(rows, start, prev_seal_sha256=prev_digest) if s['period'] < current_period]
    out = pathlib.Path(out_dir); out.mkdir(parents=True, exist_ok=True); listing = []
    for s in segs:
        d = out / s['period']; d.mkdir()
        ct = crypto.encrypt(s['segment'])
        (d / 'seal.json').write_bytes(seal_bytes(s['seal'])); (d / 'segment.jsonl.age').write_bytes(ct)
        listing.append({'period': s['period'], 'seal_sha256': seal_sha256(s['seal']), 'ciphertext_sha256': sha256_hex(ct)})
    (out / 'prepared.json').write_text(canonical({'schema': 'macguard-archive-prepared/1', 'periods': listing}) + '\n')
    return {'ok': True, 'periods': [x['period'] for x in listing]}


def _load_prepared(directory):
    d = pathlib.Path(directory); doc = json.loads((d / 'prepared.json').read_text()); out = []
    for e in doc['periods']:
        if not (isinstance(e.get('period'), str) and re.fullmatch(r'\d{4}-\d{2}', e['period'])): raise ArchiveError('prepared.json: bad period name')
        seal_b, ct = (d / e['period'] / 'seal.json').read_bytes(), (d / e['period'] / 'segment.jsonl.age').read_bytes()
        if sha256_hex(seal_b) != e['seal_sha256'] or sha256_hex(ct) != e['ciphertext_sha256']: raise ArchiveError(f'{e["period"]}: prepared files do not match prepared.json')
        out.append((e['period'], json.loads(seal_b), seal_b, ct))
    return out


def publish(provider, directory):
    res = []
    for period, seal, seal_b, ct in _load_prepared(directory):
        try:
            idx, files = read_unit(provider, 'audit', period)
            if files['seal.json'] != seal_b: res.append({'period': period, 'status': 'conflict', 'error': 'provider holds this period with a different seal'}); continue
            res.append({'period': period, 'status': 'already-archived', 'ciphertext_matches_prepared': files['segment.jsonl.age'] == ct}); continue
        except (MissingObject, ProviderError): pass
        meta = {'period': period, 'seal_sha256': seal_sha256(seal), 'segment_sha256': seal['segment_sha256']}
        try: res.append({'period': period, 'status': archive_unit(provider, 'audit', period, {'seal.json': seal_b, 'segment.jsonl.age': ct}, meta)['status']})
        except (ProviderError, ArchiveError) as e: res.append({'period': period, 'status': 'error', 'error': str(e)[:300]})
    return {'provider': provider.name, 'ok': all(r['status'] in ('created', 'exists-identical', 'already-archived') and r.get('ciphertext_matches_prepared', True) for r in res), 'results': res}


def verify(provider, directory):
    rep = {'provider': provider.name, 'ok': False}
    try:
        prepared = _load_prepared(directory); have = list_periods(provider)
        missing = [p for p, *_ in prepared if p not in have]
        if missing: rep['error'] = f'periods missing in {provider.name}: {missing}'; return rep
        rep['ciphertext_sha256'] = {}
        for period, seal, seal_b, ct in prepared:
            idx, files = read_unit(provider, 'audit', period)
            if files['seal.json'] != seal_b: rep['error'] = f'{period}: seal differs from the prepared one'; return rep
            rep['ciphertext_sha256'][period] = sha256_hex(files['segment.jsonl.age'])
        chain = restore_audit(provider)
        rep['ok'] = chain['ok']; rep['chain'] = {k: chain.get(k) for k in ('level', 'head', 'last_seq', 'error')}
    except (MissingObject, ProviderError, ArchiveError, SegmentError, ValueError, KeyError) as e:
        rep['error'] = f'{type(e).__name__}: {str(e)[:300]}'
    return rep


def pack(directory, out_file) -> str:
    """Deterministic tar.gz of a prepared directory (files only, fixed metadata); returns its SHA-256, which the owner types into the workflow dispatch."""
    import gzip
    d = pathlib.Path(directory); files = sorted(p for p in d.rglob('*') if p.is_file())
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w', format=tarfile.PAX_FORMAT) as tf:
        for p in files:
            ti = tarfile.TarInfo(p.relative_to(d).as_posix()); data = p.read_bytes(); ti.size = len(data); ti.mtime = 0; ti.mode = 0o644; ti.uid = ti.gid = 0; ti.uname = ti.gname = ''
            tf.addfile(ti, io.BytesIO(data))
    blob = gzip.compress(raw.getvalue(), mtime=0)
    pathlib.Path(out_file).write_bytes(blob); return sha256_hex(blob)


def unpack(bundle_file, directory, max_files=2000, max_bytes=100 * 1024 * 1024):
    """Extract a prepared bundle without trusting it: only regular files named `prepared.json` or `YYYY-MM/{seal.json,segment.jsonl.age}`, created new with O_EXCL|O_NOFOLLOW."""
    d = pathlib.Path(directory)
    if d.exists() and any(d.iterdir()): raise ArchiveError('output directory is not empty')
    d.mkdir(parents=True, exist_ok=True); total = 0
    with tarfile.open(bundle_file, 'r:gz') as tf:
        members = tf.getmembers()
        if len(members) > max_files: raise ArchiveError('bundle has too many entries')
        for m in members:
            if not m.isfile() or not re.fullmatch(r'prepared\.json|\d{4}-\d{2}/(seal\.json|segment\.jsonl\.age)', m.name): raise ArchiveError(f'unexpected entry in bundle: {m.name!r:.80}')
            total += m.size
            if total > max_bytes: raise ArchiveError('bundle is too large')
            target = d / m.name; target.parent.mkdir(exist_ok=True)
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as f: f.write(tf.extractfile(m).read())
    _load_prepared(d)   # every digest in prepared.json must match
    return {'ok': True}
