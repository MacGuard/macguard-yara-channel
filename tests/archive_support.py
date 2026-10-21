"""Shared helpers for tests/test_archive_*.py (not a test module)."""
import json, os, pathlib, shutil, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from archive import canon  # noqa: E402

FIX = ROOT / 'tests' / 'fixtures' / 'archive'
FAKE_AGE = [sys.executable, str(FIX / 'fake_age.py')]
FAKE_S3 = [sys.executable, str(FIX / 'fake_s3.py')]
RECIPIENT_A = 'age1' + 'q' * 58
RECIPIENT_B = 'age1' + 'p' * 58


def tmpdir(test):
    d = tempfile.mkdtemp(prefix='archive-test-'); test.addCleanup(shutil.rmtree, d, True); return pathlib.Path(d)


def make_rows(plan, start_hash=canon.GENESIS, start_seq=1):
    """plan: list of ISO timestamps, one per row. Returns a valid chain."""
    rows, prev = [], start_hash
    for i, at in enumerate(plan):
        r = {'seq': start_seq + i, 'at': at, 'actor': 'ada', 'role': 'ADMIN', 'action': 'test.event', 'target': f't{i}', 'detail': json.dumps({'i': i, 'n': 'Ñandú ✓'}), 'prev_hash': prev}
        r['hash'] = canon.chain_hash(prev, r); rows.append(r); prev = r['hash']
    return rows


def months(counts):
    """{'2026-07': 3, '2026-08': 2} -> timestamps"""
    return [f'{m}-{(i % 27) + 1:02d}T10:00:00.000Z' for m, n in counts.items() for i in range(n)]


def identity_file(d, recipient=RECIPIENT_A):
    p = pathlib.Path(d) / f'id-{recipient[-4:]}.txt'; p.write_text(f'FAKE-IDENTITY-FOR {recipient}\n'); return str(p)
