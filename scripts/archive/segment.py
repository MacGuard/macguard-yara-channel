"""Monthly audit segments and their SEAL documents, and verification of the chain of seals from archived segments ALONE.

Segment = the audit rows of one UTC month in canonical JSONL (all columns, prev_hash and hash included), so the link to the previous month travels inside the data.
Seal   = {schema, period, first_seq, last_seq, count, first_prev_hash, head_hash, segment_sha256, prev_seal_sha256}. Deterministic from the segment: building it twice
         gives identical bytes (idempotence). The ciphertext digest is NOT in the seal (age output is not deterministic); it lives in the archive index.
"""
import json

from .canon import GENESIS, canonical, is_hex64, parse_row, parse_segment, row_line, seal_sha256, sha256_hex, verify_chain

SEAL_SCHEMA = 'macguard-audit-seal/1'
SEAL_KEYS = frozenset(('schema', 'period', 'first_seq', 'last_seq', 'count', 'first_prev_hash', 'head_hash', 'segment_sha256', 'prev_seal_sha256'))


class SegmentError(Exception): pass


def read_export(path) -> list:
    """An audit export: one JSON object per line, any key order, exactly the nine audit columns."""
    rows = []
    with open(path, 'r', encoding='utf-8') as f:
        for n, line in enumerate(f, 1):
            if not line.strip(): continue
            try: rows.append(parse_row(json.loads(line)))
            except (ValueError, json.JSONDecodeError) as e: raise SegmentError(f'export line {n}: {e}')
    return rows


def period_of(row) -> str:
    at = row['at']
    if len(at) < 7 or at[4] != '-' or not (at[:4] + at[5:7]).isdigit(): raise SegmentError(f'seq {row["seq"]}: "at" is not an ISO UTC timestamp')
    return at[:7]


def build_segments(rows, start_hash: str = GENESIS, prev_seal: dict = None) -> list:
    """Group `rows` (the continuation of a chain whose head is `start_hash`) into monthly segments. Refuses a broken, reordered or duplicated chain
    and months that go backwards. Returns [{'period', 'segment': bytes, 'seal': dict}]. The caller decides which months are complete (never the current one)."""
    if not rows: return []
    v = verify_chain(rows, start_hash)
    if not v['ok']: raise SegmentError(f'cannot seal a chain that does not verify: seq {v["at"]}: {v["error"]}')
    groups, order = {}, []
    for r in rows:
        p = period_of(r)
        if order and p < order[-1]: raise SegmentError(f'seq {r["seq"]}: month {p} after {order[-1]} (timestamps out of order)')
        if not order or p != order[-1]: order.append(p)
        groups.setdefault(p, []).append(r)
    out, prev_head, prev_sha = [], start_hash, (seal_sha256(prev_seal) if prev_seal else None)
    for p in order:
        rs = groups[p]
        seg = ''.join(row_line(r) for r in rs).encode('utf-8')
        seal = {'schema': SEAL_SCHEMA, 'period': p, 'first_seq': rs[0]['seq'], 'last_seq': rs[-1]['seq'], 'count': len(rs), 'first_prev_hash': prev_head,
                'head_hash': rs[-1]['hash'], 'segment_sha256': sha256_hex(seg), 'prev_seal_sha256': prev_sha}
        out.append({'period': p, 'segment': seg, 'seal': seal})
        prev_head, prev_sha = rs[-1]['hash'], seal_sha256(seal)
    return out


def check_seal_shape(seal) -> None:
    if not isinstance(seal, dict) or set(seal) != SEAL_KEYS or seal['schema'] != SEAL_SCHEMA: raise SegmentError('seal has the wrong shape or schema')
    for k in ('first_prev_hash', 'head_hash', 'segment_sha256'):
        if not is_hex64(seal[k]): raise SegmentError(f'seal {k} is not a SHA-256')
    if seal['prev_seal_sha256'] is not None and not is_hex64(seal['prev_seal_sha256']): raise SegmentError('seal prev_seal_sha256 is not a SHA-256')
    for k in ('first_seq', 'last_seq', 'count'):
        if not (isinstance(seal[k], int) and not isinstance(seal[k], bool) and seal[k] >= 1): raise SegmentError(f'seal {k} must be a positive integer')
    if not (isinstance(seal['period'], str) and len(seal['period']) == 7 and seal['period'][4] == '-' and (seal['period'][:4] + seal['period'][5:]).isdigit()):
        raise SegmentError('seal period must be YYYY-MM')


def verify_segment(seal: dict, segment: bytes) -> list:
    """One seal against its plaintext segment. Returns the rows. Raises SegmentError with the first problem found."""
    check_seal_shape(seal)
    if sha256_hex(segment) != seal['segment_sha256']: raise SegmentError(f'{seal["period"]}: segment bytes do not match segment_sha256 (altered, truncated or wrong object)')
    try: rows = parse_segment(segment)
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as e: raise SegmentError(f'{seal["period"]}: {e}')
    if len(rows) != seal['count']: raise SegmentError(f'{seal["period"]}: {len(rows)} rows, seal says {seal["count"]}')
    if not rows: raise SegmentError(f'{seal["period"]}: empty segment')
    if rows[0]['seq'] != seal['first_seq'] or rows[-1]['seq'] != seal['last_seq']: raise SegmentError(f'{seal["period"]}: seq range does not match the seal')
    if rows[0]['prev_hash'] != seal['first_prev_hash']: raise SegmentError(f'{seal["period"]}: first row does not link to first_prev_hash')
    v = verify_chain(rows, seal['first_prev_hash'])
    if not v['ok']: raise SegmentError(f'{seal["period"]}: seq {v["at"]}: {v["error"]}')
    if v['head'] != seal['head_hash']: raise SegmentError(f'{seal["period"]}: head hash does not match the seal')
    if any(period_of(r) != seal['period'] for r in rows): raise SegmentError(f'{seal["period"]}: contains rows of another month')
    return rows


def verify_seal_chain(seals, start_hash: str = GENESIS) -> dict:
    """Continuity of seals alone (no plaintext, no key needed): periods increase, each first_prev_hash is the previous head_hash, seq moves forward, prev_seal_sha256
    chains. `start_hash` is the head the first seal must continue from (GENESIS, or a trusted anchor)."""
    prev, head = None, start_hash
    for s in seals:
        check_seal_shape(s)
        if prev is not None:
            if s['period'] <= prev['period']: raise SegmentError(f'{s["period"]}: periods are not increasing (duplicate or reordered seal)')
            if s['first_seq'] <= prev['last_seq']: raise SegmentError(f'{s["period"]}: overlaps the previous seal')
            if s['prev_seal_sha256'] != seal_sha256(prev): raise SegmentError(f'{s["period"]}: does not chain to the previous seal (a seal is missing or altered)')
        elif s['prev_seal_sha256'] is not None and start_hash == GENESIS: raise SegmentError(f'{s["period"]}: first seal names a previous seal but the archive starts here')
        if s['first_prev_hash'] != head: raise SegmentError(f'{s["period"]}: first_prev_hash does not continue the chain (a segment is missing or the anchor does not match)')
        prev, head = s, s['head_hash']
    return {'ok': True, 'seals': len(seals), 'head': head, 'last_seq': prev['last_seq'] if prev else None}


def verify_archive(pairs, start_hash: str = GENESIS, expected_head: str = None) -> dict:
    """The full check from archived data alone: every segment against its seal, then the seals against each other. `pairs` = [(seal, segment_bytes)] in period order.
    `expected_head` (optional): the head the live database reports; it must equal the last seal head or be a descendant the caller checks separately."""
    for seal, seg in pairs: verify_segment(seal, seg)
    r = verify_seal_chain([s for s, _ in pairs], start_hash)
    if expected_head is not None and r['head'] != expected_head: raise SegmentError('last sealed head does not equal the expected head')
    return r
