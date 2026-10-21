"""Archive manifest-of-manifests: an ordered, hash-chained, Merkle-rooted list of everything the archive holds. The same builder runs against each provider and refuses to
produce a manifest when the providers disagree. SIGNING IS NOT DONE HERE (see docs/OPERATIONS-archive-setup.md, the Sigstore step runs only in the archive workflow)."""
import json, pathlib, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import tlog   # noqa: E402  (RFC 6962 hashing already used by the public transparency log)

from .canon import canonical, sha256_hex
from .store import ArchiveError, put_verified

SCHEMA = 'macguard-archive-manifest/1'


def inventory(provider) -> list:
    """Every unit file as {path, sha256, bytes}, plus each index file itself; sorted by path. Reads the indexes and checks that each referenced object exists with its size."""
    out = []
    for key in provider.list('index/'):
        raw = provider.get(key)
        idx = json.loads(raw)
        out.append({'path': key, 'sha256': sha256_hex(raw), 'bytes': len(raw)})
        for fname, ent in idx['files'].items():
            obj = provider.get(f'objects/sha256/{ent["sha256"][:2]}/{ent["sha256"]}')
            if sha256_hex(obj) != ent['sha256'] or len(obj) != ent['bytes']: raise ArchiveError(f'{provider.name}: {key}:{fname} object does not match its index')
            out.append({'path': f'{idx["kind"]}/{idx["name"]}/{fname}', 'sha256': ent['sha256'], 'bytes': ent['bytes']})
    return sorted(out, key=lambda e: e['path'])


def merkle_root(entries) -> str:
    return tlog.mth([tlog.leaf_hash(canonical(e).encode('utf-8')) for e in entries]).hex()


def build(providers, date: str, prev_manifest: bytes = None, extra: dict = None) -> bytes:
    """Canonical manifest bytes for `date` (YYYY-MM-DD). `extra` may carry e.g. the newest public checkpoint digest. Every provider must report the same inventory."""
    invs = [(p.name, inventory(p)) for p in providers]
    base = invs[0][1]
    for name, inv in invs[1:]:
        if inv != base:
            a, b = {e['path']: e['sha256'] for e in base}, {e['path']: e['sha256'] for e in inv}
            diff = sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))
            raise ArchiveError(f'providers disagree ({invs[0][0]} vs {name}): {diff[:5]}')
    doc = {'schema': SCHEMA, 'date': date, 'entry_count': len(base), 'merkle_root': merkle_root(base), 'entries': base,
           'prev_manifest_sha256': sha256_hex(prev_manifest) if prev_manifest else None, 'extra': extra or {}}
    return (canonical(doc) + '\n').encode('utf-8')


def store(providers, date: str, data: bytes) -> list:
    """Write-once into every provider at manifests/archive-manifest-<date>.json (read back and compared)."""
    key = f'manifests/archive-manifest-{date}.json'
    return [{'provider': p.name, 'key': key, 'status': put_verified(p, key, data)} for p in providers]


def verify(data: bytes, provider=None, prev_manifest: bytes = None) -> dict:
    doc = json.loads(data)
    if doc.get('schema') != SCHEMA: raise ArchiveError('not an archive manifest')
    if data != (canonical(doc) + '\n').encode('utf-8'): raise ArchiveError('manifest is not canonical')
    if doc['entry_count'] != len(doc['entries']) or doc['merkle_root'] != merkle_root(doc['entries']): raise ArchiveError('manifest root does not match its entries')
    if doc['entries'] != sorted(doc['entries'], key=lambda e: e['path']): raise ArchiveError('manifest entries are not sorted')
    expect_prev = sha256_hex(prev_manifest) if prev_manifest else None
    if doc['prev_manifest_sha256'] != expect_prev: raise ArchiveError('manifest does not chain to the previous manifest')
    if provider is not None:
        have = inventory(provider)
        missing = [e['path'] for e in doc['entries'] if e not in have]
        if missing: raise ArchiveError(f'{provider.name} lacks or differs on {len(missing)} manifest entries, e.g. {missing[:3]}')
    return {'ok': True, 'entries': doc['entry_count'], 'merkle_root': doc['merkle_root']}
