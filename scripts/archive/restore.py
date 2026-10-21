"""Restore-and-verify from ONE provider with read-only access. Everything is checked against digests; releases are re-verified with scripts/verify_public_release.py;
the audit chain is re-verified from the archived segments alone. Never writes to ~/Downloads and never into a non-empty directory."""
import json, os, pathlib, subprocess, sys

from .canon import seal_sha256
from .providers import MissingObject, ProviderError
from .segment import SegmentError, verify_archive, verify_seal_chain
from .store import ArchiveError, read_unit
from .crypto import CryptoError

HERE = pathlib.Path(__file__).resolve().parent
VERIFIER = HERE.parent / 'verify_public_release.py'


def fresh_dir(path) -> pathlib.Path:
    p = pathlib.Path(path).expanduser().resolve()
    downloads = pathlib.Path.home().resolve() / 'Downloads'
    if p == downloads or downloads in p.parents: raise ArchiveError('restores never go to ~/Downloads')
    if p.exists() and (not p.is_dir() or any(p.iterdir())): raise ArchiveError(f'{p} exists and is not an empty directory')
    p.mkdir(parents=True, exist_ok=True)
    return p


def default_verifier(directory, tag, previous_checkpoint=None, extra=()):
    cmd = [sys.executable, '-I', str(VERIFIER), '--directory', str(directory), '--json', '--color', 'never', '--tag-for-directory', tag, *extra]
    if previous_checkpoint: cmd += ['--previous-checkpoint', str(previous_checkpoint)]
    return cmd


def restore_release(provider, tag, out_dir, verifier=default_verifier, previous_checkpoint=None, timeout=600) -> dict:
    """Fetch release `tag` into a fresh directory, check every digest, then run the public verifier on it. ok only if the verifier exits 0."""
    rep = {'provider': provider.name, 'kind': 'release', 'tag': tag, 'ok': False}
    try:
        idx, files = read_unit(provider, 'releases', tag)
    except (MissingObject, ProviderError, ArchiveError, ValueError) as e:
        rep['error'] = str(e)[:300]; return rep
    d = fresh_dir(out_dir)
    for n, b in files.items(): (d / n).write_bytes(b)
    rep['files'] = len(files)
    try: r = subprocess.run(verifier(d, tag, previous_checkpoint), capture_output=True, timeout=timeout, text=True)
    except subprocess.TimeoutExpired: rep['error'] = 'verifier timed out'; return rep
    rep['verifier_exit'] = r.returncode; rep['ok'] = r.returncode == 0
    if r.returncode != 0: rep['error'] = (r.stdout[-300:] or r.stderr[-300:]).strip()
    return rep


def list_periods(provider) -> list:
    return sorted(k[len('index/audit/'):-len('.json')] for k in provider.list('index/audit/') if k.endswith('.json'))


def restore_audit(provider, crypto=None, identity_file=None, periods=None, start_hash=None, expected_head=None) -> dict:
    """Re-verify the archived audit from this provider. With an identity (restore drill machine) each segment is decrypted and the whole chain re-checked;
    without one, only the seals and their continuity are checked (`level` says which). Reports the last seal so the caller can build an anchor receipt."""
    from .canon import GENESIS
    start = GENESIS if start_hash is None else start_hash
    rep = {'provider': provider.name, 'kind': 'audit', 'ok': False, 'level': 'full' if identity_file else 'seals-only'}
    try:
        names = periods or list_periods(provider)
        if not names: rep['error'] = 'no audit periods in this provider'; return rep
        seals, pairs = [], []
        for p in names:
            idx, files = read_unit(provider, 'audit', p)
            seal = json.loads(files['seal.json'])
            if idx['meta'].get('seal_sha256') != seal_sha256(seal): raise ArchiveError(f'{p}: index and seal disagree')
            seals.append(seal)
            if identity_file:
                if crypto is None: raise ArchiveError('an identity file needs the crypto wrapper')
                pairs.append((seal, crypto.decrypt(files['segment.jsonl.age'], identity_file)))
        r = verify_archive(pairs, start, expected_head) if identity_file else verify_seal_chain(seals, start)
        if expected_head is not None and r['head'] != expected_head: raise SegmentError('last sealed head does not equal the expected head')
        last = seals[-1]
        rep.update(ok=True, periods=names, head=r['head'], seal_sha256=seal_sha256(last), segment_sha256=last['segment_sha256'], last_seq=last['last_seq'])
    except (MissingObject, ProviderError, ArchiveError, SegmentError, CryptoError, ValueError, KeyError) as e:
        rep['error'] = f'{type(e).__name__}: {str(e)[:300]}'
    return rep


def rehearse_period(provider, period, crypto, identity_file) -> dict:
    """Restore rehearsal for ONE sealed period (the evidence the anchor guard demands): decrypt it and verify the segment against its seal. The report names the seal."""
    rep = {'provider': provider.name, 'kind': 'rehearsal', 'period': period, 'ok': False}
    try:
        from .segment import verify_segment
        idx, files = read_unit(provider, 'audit', period)
        seal = json.loads(files['seal.json'])
        verify_segment(seal, crypto.decrypt(files['segment.jsonl.age'], identity_file))
        rep.update(ok=True, seal_sha256=seal_sha256(seal), segment_sha256=seal['segment_sha256'])
    except (MissingObject, ProviderError, ArchiveError, SegmentError, CryptoError, ValueError, KeyError) as e:
        rep['error'] = f'{type(e).__name__}: {str(e)[:300]}'
    return rep
