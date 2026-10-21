"""Write-once, content-addressed archive layout, upload-then-verify-read-back, and the archiving of audit periods and release bundles.

Layout in every provider (nothing is ever overwritten or deleted):
  objects/sha256/<aa>/<sha256>      every file, named by its own digest
  index/<kind>/<name>.json          one immutable index per unit: kind = releases | audit | logs, name = release tag / YYYY-MM / segment name
  manifests/archive-manifest-<date>.json   the manifest of manifests (see manifest.py)
An index maps logical file names to digests, so a unit is restored by name and every byte is checked against a digest on the way back."""
import pathlib, re

from .canon import canonical, is_hex64, sha256_hex, seal_bytes, seal_sha256
from .providers import MissingObject, ObjectConflict, ProviderError
from .segment import verify_segment

INDEX_SCHEMA = 'macguard-archive-index/1'
RECEIPT_SCHEMA = 'macguard-archive-receipt/1'
KINDS = ('releases', 'audit', 'logs')
NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')


class ArchiveError(Exception): pass


def object_key(sha: str) -> str:
    if not is_hex64(sha): raise ArchiveError('not a SHA-256')
    return f'objects/sha256/{sha[:2]}/{sha}'


def index_key(kind: str, name: str) -> str:
    if kind not in KINDS or not NAME.match(name): raise ArchiveError(f'bad unit {kind!r}/{name!r}')
    return f'index/{kind}/{name}.json'


def put_verified(provider, key: str, data: bytes) -> str:
    """Write once, then read the object back and compare SHA-256. Returns 'created' or 'exists-identical'. Raises on conflict, on a failed write or on a read-back mismatch."""
    status = provider.put_if_absent(key, data)
    back = provider.get(key)
    if sha256_hex(back) != sha256_hex(data): raise ArchiveError(f'{provider.name}: read-back of {key} does not match what was uploaded')
    return status


def put_blob(provider, data: bytes) -> str:
    sha = sha256_hex(data); put_verified(provider, object_key(sha), data); return sha


def make_index(kind, name, files: dict, meta: dict = None) -> bytes:
    doc = {'schema': INDEX_SCHEMA, 'kind': kind, 'name': name, 'files': {n: {'sha256': sha256_hex(b), 'bytes': len(b)} for n, b in sorted(files.items())}, 'meta': meta or {}}
    return (canonical(doc) + '\n').encode('utf-8')


def archive_unit(provider, kind: str, name: str, files: dict, meta: dict = None) -> dict:
    """Store every file by digest, then the index. Idempotent: the same unit again is a no-op; a different unit under the same name is ObjectConflict.
    The index goes last, so an interrupted run leaves unreferenced objects, never an index that points at nothing."""
    if not files: raise ArchiveError('a unit needs at least one file')
    for fname in files:
        if '/' in fname or not NAME.match(fname): raise ArchiveError(f'bad file name {fname!r}')
    idx = make_index(kind, name, files, meta)
    for b in files.values(): put_blob(provider, b)
    status = put_verified(provider, index_key(kind, name), idx)
    return {'provider': provider.name, 'index_sha256': sha256_hex(idx), 'status': status}


def read_unit(provider, kind: str, name: str) -> tuple:
    """(index dict, {logical: bytes}) with every digest and size checked. MissingObject if the index or any object is absent."""
    import json
    raw = provider.get(index_key(kind, name))
    idx = json.loads(raw)
    if idx.get('schema') != INDEX_SCHEMA or idx.get('kind') != kind or idx.get('name') != name: raise ArchiveError(f'{provider.name}: index for {kind}/{name} is not what it claims')
    if raw != (canonical(idx) + '\n').encode('utf-8'): raise ArchiveError(f'{provider.name}: index for {kind}/{name} is not canonical')
    files = {}
    for fname, ent in idx['files'].items():
        b = provider.get(object_key(ent['sha256']))
        if sha256_hex(b) != ent['sha256'] or len(b) != ent['bytes']: raise ArchiveError(f'{provider.name}: object for {kind}/{name}/{fname} is corrupted (digest or size differs)')
        files[fname] = b
    return idx, files


def archive_release(providers, directory, tag: str, precheck=None) -> list:
    """Archive the files of a release bundle (a flat directory: rules-release.tar.gz, manifest.json, *.sigstore.json, checkpoint.*, proofs...). The set of files may vary per
    release; the index records the real inventory. `precheck(directory)` must raise to stop BEFORE anything is written (secret / private-rule scan, verify_public_release)."""
    d = pathlib.Path(directory)
    entries = sorted(d.iterdir())
    files = {}
    for p in entries:
        if p.is_symlink() or not p.is_file(): raise ArchiveError(f'{p.name}: only regular files are archived')
        files[p.name] = p.read_bytes()
    if not files: raise ArchiveError('release directory is empty')
    if precheck: precheck(d)
    return _to_all(providers, lambda pr: archive_unit(pr, 'releases', tag, files, {'tag': tag}))


def archive_logs_segment(providers, name: str, files: dict) -> list:
    """Public logs, checkpoints, Merkle proofs and technical logs (already public, stored in clear)."""
    return _to_all(providers, lambda pr: archive_unit(pr, 'logs', name, files, {}))


def _to_all(providers, fn) -> list:
    out = []
    for pr in providers:
        try: out.append(fn(pr))
        except (ProviderError, ArchiveError) as e: out.append({'provider': pr.name, 'error': str(e)[:300]})
    return out


def archive_audit_period(providers, seal: dict, segment: bytes, crypto) -> dict:
    """Encrypt the plaintext segment (once), then store ciphertext + seal in every provider and verify each by read-back. If any provider already holds this period, its
    ciphertext is reused so all copies stay byte-identical. Returns a report; `copies` has one entry per provider, with readback_verified False and an error when it failed."""
    verify_segment(seal, segment)
    period, sealb = seal['period'], seal_bytes(seal)
    ciphertext = None
    for pr in providers:
        try: idx, files = read_unit(pr, 'audit', period)
        except (MissingObject, ProviderError): continue
        if files.get('seal.json') != sealb: raise ArchiveError(f'{pr.name}: period {period} is already archived with a different seal')
        ciphertext = files['segment.jsonl.age']; break
    if ciphertext is None: ciphertext = crypto.encrypt(segment)
    files = {'seal.json': sealb, 'segment.jsonl.age': ciphertext}
    meta = {'period': period, 'seal_sha256': seal_sha256(seal), 'segment_sha256': seal['segment_sha256']}
    copies = []
    for pr in providers:
        try:
            r = archive_unit(pr, 'audit', period, files, meta)
            read_unit(pr, 'audit', period)          # second, independent read of the whole unit
            copies.append({'provider': pr.name, 'ciphertext_sha256': sha256_hex(ciphertext), 'seal_sha256': seal_sha256(seal), 'readback_verified': True, 'status': r['status']})
        except (ProviderError, ArchiveError) as e:
            copies.append({'provider': pr.name, 'ciphertext_sha256': sha256_hex(ciphertext), 'seal_sha256': seal_sha256(seal), 'readback_verified': False, 'error': str(e)[:300]})
    return {'period': period, 'seal': seal, 'copies': copies, 'complete': all(c['readback_verified'] for c in copies) and len(copies) == 3}


def make_receipt(archive_report: dict, restore_report: dict) -> dict:
    """The document the Worker's writeAnchor() demands. Refuses to exist unless all three copies are verified and a restore of this very seal passed."""
    seal = archive_report['seal']
    if not archive_report.get('complete'): raise ArchiveError('not archived in all three providers with verified read-back')
    s = seal_sha256(seal)
    if not (restore_report.get('ok') and restore_report.get('seal_sha256') == s and restore_report.get('segment_sha256') == seal['segment_sha256']):
        raise ArchiveError('no passing restore rehearsal for this seal')
    return {'schema': RECEIPT_SCHEMA, 'seal_sha256': s, 'segment_sha256': seal['segment_sha256'],
            'copies': [{k: c[k] for k in ('provider', 'ciphertext_sha256', 'seal_sha256', 'readback_verified')} for c in archive_report['copies']],
            'restore': {k: restore_report[k] for k in ('ok', 'provider', 'seal_sha256', 'segment_sha256')}}
