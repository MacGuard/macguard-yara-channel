"""Canonical JSON and the audit hash chain: byte-for-byte the rules of admin/worker/src/core.js (canonical, chainHash, verifyChain)."""
import hashlib, json

GENESIS = '0' * 64
ROW_FIELDS = ('seq', 'at', 'actor', 'role', 'action', 'target', 'detail', 'prev_hash', 'hash')
HEX64 = frozenset('0123456789abcdef')


def is_hex64(s) -> bool: return isinstance(s, str) and len(s) == 64 and set(s) <= HEX64


def _no_floats(o):
    if isinstance(o, float): raise ValueError('floats are not allowed in canonical documents')
    if isinstance(o, dict):
        for v in o.values(): _no_floats(v)
    elif isinstance(o, (list, tuple)):
        for v in o: _no_floats(v)


def canonical(o) -> str:
    """Sorted keys, no whitespace, non-ASCII kept as is: identical to canonical() in core.js for the data used here."""
    _no_floats(o)
    return json.dumps(o, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def sha256_hex(data) -> str:
    return hashlib.sha256(data.encode('utf-8') if isinstance(data, str) else data).hexdigest()


def chain_hash(prev_hash: str, row: dict) -> str:
    return sha256_hex(prev_hash + canonical({k: row[k] for k in ('at', 'actor', 'role', 'action', 'target', 'detail')}))


def verify_chain(rows, start_hash: str = GENESIS) -> dict:
    """Same result shape as verifyChain(rows, startHash). Also requires strictly increasing seq (a reordered export must not pass)."""
    prev, last_seq = start_hash, None
    for r in rows:
        if r['prev_hash'] != prev: return {'ok': False, 'at': r['seq'], 'error': 'chain link broken (entry removed or reordered)'}
        if last_seq is not None and r['seq'] <= last_seq: return {'ok': False, 'at': r['seq'], 'error': 'seq is not increasing (entries reordered or duplicated)'}
        if chain_hash(prev, r) != r['hash']: return {'ok': False, 'at': r['seq'], 'error': 'entry content was altered'}
        prev, last_seq = r['hash'], r['seq']
    return {'ok': True, 'entries': len(rows), 'head': prev}


def seal_bytes(seal: dict) -> bytes: return (canonical(seal) + '\n').encode('utf-8')
def seal_sha256(seal: dict) -> str: return sha256_hex(seal_bytes(seal))


def row_line(row: dict) -> str: return canonical({k: row[k] for k in ROW_FIELDS}) + '\n'


def parse_row(obj) -> dict:
    if not isinstance(obj, dict) or set(obj) != set(ROW_FIELDS): raise ValueError('audit row must have exactly the columns ' + ','.join(ROW_FIELDS))
    if not (isinstance(obj['seq'], int) and not isinstance(obj['seq'], bool) and obj['seq'] >= 1): raise ValueError('seq must be a positive integer')
    for k in ROW_FIELDS[1:7]:
        if not isinstance(obj[k], str): raise ValueError(f'{k} must be a string')
    if not (is_hex64(obj['prev_hash']) and is_hex64(obj['hash'])): raise ValueError('prev_hash/hash must be 64 hex characters')
    return {k: obj[k] for k in ROW_FIELDS}


def parse_segment(data: bytes) -> list:
    """Rows of a segment. Anything not in canonical form (re-serialisation differs) is refused, so a segment has exactly one valid byte string."""
    text = data.decode('utf-8')
    if text and not text.endswith('\n'): raise ValueError('segment must end with a newline')
    rows = []
    for i, line in enumerate(text.split('\n')[:-1] if text else []):
        row = parse_row(json.loads(line))
        if row_line(row) != line + '\n': raise ValueError(f'line {i + 1} is not canonical')
        rows.append(row)
    return rows
