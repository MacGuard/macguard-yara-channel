#!/usr/bin/env python3
"""Append-only transparency log for MacGuard rule releases.

Merkle tree per RFC 6962 (hashing) with the verification algorithms of RFC 9162.
logs/log.jsonl              one canonical JSON entry per line; leaf = SHA-256(0x00 || line)
logs/checkpoints/NNNNNNNN.txt  signed tree head: origin, size, root (base64)
logs/checkpoints/NNNNNNNN.sigstore.json  Sigstore bundle (keyless signature by the publish workflow) over the exact bytes of the .txt
logs/checkpoint.txt / .sigstore.json  copy of the latest checkpoint
The log only grows. `verify` recomputes every root from the entries and checks that each checkpoint is
signed and consistent with the previous one, so rewriting or dropping history is detectable.
"""
import argparse, base64, hashlib, json, os, pathlib, re, sys
from datetime import datetime, timezone

ORIGIN = 'macguard-rules-log v1'
ROOT = pathlib.Path(__file__).resolve().parents[1]


# ---- Merkle tree (RFC 6962 section 2.1) -------------------------------------------------------
def leaf_hash(data: bytes) -> bytes: return hashlib.sha256(b'\x00' + data).digest()
def node_hash(left: bytes, right: bytes) -> bytes: return hashlib.sha256(b'\x01' + left + right).digest()
EMPTY_ROOT = hashlib.sha256(b'').digest()

def _split(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    k = 1
    while k * 2 < n: k *= 2
    return k

def mth(leaves):
    n = len(leaves)
    if n == 0: return EMPTY_ROOT
    if n == 1: return leaves[0]
    k = _split(n)
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))

def inclusion_proof(index: int, leaves):
    n = len(leaves)
    if not 0 <= index < n: raise ValueError('leaf index out of range')
    if n == 1: return []
    k = _split(n)
    if index < k: return inclusion_proof(index, leaves[:k]) + [mth(leaves[k:])]
    return inclusion_proof(index - k, leaves[k:]) + [mth(leaves[:k])]

def verify_inclusion(index: int, size: int, leaf: bytes, proof, root: bytes) -> bool:
    if not 0 <= index < size: return False
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0: return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0: fn >>= 1; sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1; sn >>= 1
    return sn == 0 and r == root

def consistency_proof(first: int, leaves):
    second = len(leaves)
    if not 0 < first <= second: raise ValueError('invalid tree sizes')
    def sub(m, d, complete):
        n = len(d)
        if m == n: return [] if complete else [mth(d)]
        k = _split(n)
        if m <= k: return sub(m, d[:k], complete) + [mth(d[k:])]
        return sub(m - k, d[k:], False) + [mth(d[:k])]
    return sub(first, leaves, True)

def verify_consistency(first: int, second: int, first_root: bytes, second_root: bytes, proof) -> bool:
    if first > second or first < 0: return False
    if first == second: return not proof and first_root == second_root
    if first == 0: return not proof
    proof = list(proof)
    if first & (first - 1) == 0: proof.insert(0, first_root)
    if not proof: return False
    fn, sn = first - 1, second - 1
    while fn & 1: fn >>= 1; sn >>= 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0: return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr); sr = node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0: fn >>= 1; sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1; sn >>= 1
    return sn == 0 and fr == first_root and sr == second_root


# ---- Rules root: Merkle root over the file inventory ------------------------------------------
_HEX64 = re.compile(r'[0-9a-f]{64}')
_PATH = re.compile(r'[A-Za-z0-9._\-/ +@()\[\]]{1,400}')
def check_inventory(files):
    """Reject an inventory the root could be ambiguous or unsafe for: duplicate paths, absolute or `..` paths, NUL/control characters
    (the leaf joins path and hash with NUL), and anything that is not a lowercase SHA-256. Returns an error string or None."""
    if not isinstance(files, list) or not files: return 'the inventory must be a non-empty list'
    seen = set()
    for f in files:
        if not isinstance(f, dict) or not isinstance(f.get('path'), str) or not isinstance(f.get('sha256'), str): return 'every entry needs a string path and sha256'
        p = f['path']
        if not _PATH.fullmatch(p) or p.startswith('/') or any(seg in ('', '.', '..') for seg in p.split('/')): return f'unsafe path {p[:80]!r}'
        if not _HEX64.fullmatch(f['sha256']): return f'sha256 of {p} is not 64 lowercase hex characters'
        if p in seen: return f'duplicate path {p}'
        seen.add(p)
    return None

def rules_root(files) -> str:
    leaves = [leaf_hash(f"{f['path']}\0{f['sha256']}".encode()) for f in sorted(files, key=lambda f: f['path'])]
    return mth(leaves).hex()


# ---- Log storage ------------------------------------------------------------------------------
def canonical(entry: dict) -> bytes:
    return json.dumps(entry, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()

class Log:
    def __init__(self, folder: pathlib.Path):
        self.folder = folder
        self.entries_file = folder / 'log.jsonl'
        self.checkpoints = folder / 'checkpoints'

    def lines(self):
        if not self.entries_file.exists(): return []
        raw = self.entries_file.read_bytes()
        if raw and not raw.endswith(b'\n'): raise ValueError('log.jsonl does not end with a newline')
        return raw.split(b'\n')[:-1]

    def leaves(self): return [leaf_hash(line) for line in self.lines()]

    def append(self, entry: dict) -> int:
        self.folder.mkdir(parents=True, exist_ok=True)
        entry = dict(entry); entry['seq'] = len(self.lines())
        with self.entries_file.open('ab') as f: f.write(canonical(entry) + b'\n')
        return entry['seq']

    def checkpoint_bytes(self, size: int, root: bytes) -> bytes:
        return f'{ORIGIN}\n{size}\n{base64.b64encode(root).decode()}\n'.encode()

    def checkpoint_files(self):
        if not self.checkpoints.exists(): return []
        return sorted(p for p in self.checkpoints.glob('*.txt'))

    @staticmethod
    def parse_checkpoint(body: bytes):
        try: parts = body.decode('ascii').split('\n')
        except UnicodeDecodeError: raise ValueError('malformed checkpoint')
        if len(parts) != 4 or parts[3] != '' or parts[0] != ORIGIN: raise ValueError('malformed checkpoint')
        # one canonical encoding only: int() would also accept '+5', ' 5', '5_0' and non-ASCII digits, base64 would accept loose padding bits
        if not re.fullmatch(r'0|[1-9][0-9]{0,15}', parts[1]): raise ValueError('malformed checkpoint size')
        root = base64.b64decode(parts[2], validate=True)
        if len(root) != 32 or base64.b64encode(root).decode() != parts[2]: raise ValueError('malformed checkpoint root')
        return int(parts[1]), root

    def write_checkpoint(self) -> int:
        """Write the unsigned tree head; the publish workflow signs it with Sigstore right after."""
        leaves = self.leaves(); size = len(leaves)
        previous = self.checkpoint_files()
        if previous:
            old_size, old_root = self.parse_checkpoint(previous[-1].read_bytes())
            if size < old_size: raise ValueError('log is shorter than the last checkpoint')
            if size == old_size: raise ValueError('no new entries since the last checkpoint')
            proof = consistency_proof(old_size, leaves)
            if not verify_consistency(old_size, size, old_root, mth(leaves), proof):
                raise ValueError('log is not consistent with the last checkpoint')
        body = self.checkpoint_bytes(size, mth(leaves))
        self.checkpoints.mkdir(parents=True, exist_ok=True)
        for txt in (self.checkpoints / f'{size:08d}.txt', self.folder / 'checkpoint.txt'): txt.write_bytes(body)
        return size

    @staticmethod
    def bundle_for(txt: pathlib.Path) -> pathlib.Path: return txt.with_name(txt.stem + '.sigstore.json')

    def verify(self, verifier=None):
        """Return a list of problems; empty means the log and all checkpoints are sound.

        `verifier(checkpoint_txt, bundle)` returns None when the Sigstore bundle is valid for that file
        and an error string otherwise. Without a verifier only the structure is checked."""
        problems = []
        try: leaves = self.leaves()
        except ValueError as e: return [str(e)]
        for i, line in enumerate(self.lines()):
            try: entry = json.loads(line)
            except ValueError: problems.append(f'entry {i}: not valid JSON'); continue
            if canonical(entry) != line: problems.append(f'entry {i}: not canonical JSON')
            if entry.get('seq') != i: problems.append(f'entry {i}: seq is {entry.get("seq")}')
        previous = None
        for txt in self.checkpoint_files():
            body = txt.read_bytes()
            try: size, root = self.parse_checkpoint(body)
            except ValueError as e: problems.append(f'{txt.name}: {e}'); continue
            if verifier:
                bundle = self.bundle_for(txt)
                err = verifier(txt, bundle) if bundle.exists() else 'signature bundle is missing'
                if err: problems.append(f'{txt.name}: {err}'); continue
            if size > len(leaves): problems.append(f'{txt.name}: covers {size} entries but log has {len(leaves)}'); continue
            if mth(leaves[:size]) != root: problems.append(f'{txt.name}: root does not match the entries')
            if previous:
                psize, proot = previous
                if not verify_consistency(psize, size, proot, root, consistency_proof(psize, leaves[:size])):
                    problems.append(f'{txt.name}: not consistent with the previous checkpoint')
            previous = (size, root)
        # the copies clients read (checkpoint.txt and its bundle) must be the newest signed checkpoint, not a stale or different one
        files = self.checkpoint_files()
        if files:
            for name, newest in (('checkpoint.txt', files[-1]), ('checkpoint.sigstore.json', self.bundle_for(files[-1]))):
                copy = self.folder / name
                if not copy.exists(): problems.append(f'{name} is missing')
                elif not newest.exists() or copy.read_bytes() != newest.read_bytes(): problems.append(f'{name} is not the newest signed checkpoint ({files[-1].name})')
        return problems

    def release_proof(self, run_id: str, manifest_rules_root: str, checkpoint_size: int) -> dict:
        """Inclusion proof that the accepted candidate of `run_id` is in the tree the checkpoint signs."""
        lines = self.lines(); leaves = self.leaves()[:checkpoint_size]
        for i, line in enumerate(lines[:checkpoint_size]):
            e = json.loads(line)
            if e.get('event') == 'candidate.accepted' and e.get('run_id') == run_id and e.get('details', {}).get('rules_root') == manifest_rules_root:
                proof = inclusion_proof(i, leaves)
                root = mth(leaves)
                if not verify_inclusion(i, checkpoint_size, leaves[i], proof, root): raise ValueError('inclusion proof does not verify')
                return {'schema': 1, 'origin': ORIGIN, 'index': i, 'size': checkpoint_size, 'root': root.hex(),
                        'entry': line.decode(), 'proof': [h.hex() for h in proof]}
        raise ValueError(f'no candidate.accepted entry for run {run_id} with rules_root {manifest_rules_root[:16]}... inside the checkpoint')

def check_inclusion_proof(doc: dict, checkpoint_body: bytes, rules_root_expected: str):
    """Client-side check; returns None when valid, else an error string."""
    try:
        size, root = Log.parse_checkpoint(checkpoint_body)
        if doc['size'] != size or bytes.fromhex(doc['root']) != root: return 'proof is for a different checkpoint'
        entry = json.loads(doc['entry'])
        if entry.get('event') != 'candidate.accepted' or entry.get('details', {}).get('rules_root') != rules_root_expected:
            return 'logged entry does not match the manifest rules_root'
        if not verify_inclusion(doc['index'], size, leaf_hash(doc['entry'].encode()), [bytes.fromhex(h) for h in doc['proof']], root):
            return 'inclusion proof does not verify'
    except (KeyError, ValueError, TypeError) as e:
        return f'malformed proof ({type(e).__name__})'
    return None

ISSUER = 'https://token.actions.githubusercontent.com'
def cosign_verifier(identity: str, repo: str):
    import subprocess
    def verify(path, bundle):
        r = subprocess.run(['cosign', 'verify-blob', '--bundle', str(bundle), '--certificate-identity', identity,
                            '--certificate-oidc-issuer', ISSUER, '--certificate-github-workflow-repository', repo, str(path)],
                           capture_output=True, text=True)
        return None if r.returncode == 0 else (r.stderr.strip().splitlines() or ['cosign verification failed'])[-1]
    return verify


# ---- Events -----------------------------------------------------------------------------------
LEVELS = ('INFO', 'WARNING', 'ERROR')
BUILD_PATH = re.compile(r'(?:/[\w.\-]+)*/dist/')

def now_utc() -> str: return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

def event(level: str, code: str, message: str, run_id: str = '', time: str = '', **details) -> dict:
    """One human-readable log record. `code` is a stable machine name such as rule.rejected."""
    if level not in LEVELS: raise ValueError(f'level must be one of {LEVELS}')
    e = {'time': time or now_utc(), 'level': level, 'event': code, 'message': message}
    if run_id: e['run_id'] = run_id
    if details: e['details'] = details
    return e

HINTS = (
    ('undefined identifier', 'The rule uses a name that is not defined: a missing external variable or a rule that lives in another file.'),
    ('syntax error', 'The file is not valid YARA syntax.'),
    ('duplicated identifier', 'Two rules or variables share the same name.'),
    ('unknown module', 'The file imports a YARA module this engine does not provide.'),
    ('timeout', 'Compiling the file took too long.'),
)

def explain_failure(failure: dict) -> str:
    raw = BUILD_PATH.sub('', failure['error']).strip()
    first = next((l for l in raw.splitlines() if 'error' in l.lower()), raw.splitlines()[0] if raw else 'unknown error')
    hint = next((h for key, h in HINTS if key in raw.lower()), '')
    return f"Rule file {failure['file']} was rejected by the YARA compiler: {first.strip()}" + (f' {hint}' if hint else '')

def events_for_candidate(candidate: dict, validation: dict, run_id: str, time: str, gate=None) -> list:
    out = [event('INFO', 'sources.fetched', f"Fetched {len(candidate['sources'])} upstream sources at pinned commits.", run_id, time,
                 sources=[{'repository': x['repository'], 'commit': x['commit']} for x in candidate['sources']])]
    for rejected in candidate.get('rejected', []):
        out.append(event('WARNING', 'file.skipped', f"Skipped {rejected['path']} from {rejected['source']}: {rejected['reason']}.", run_id, time, **rejected))
    failures = validation.get('failures', [])
    for f in failures:
        out.append(event('ERROR', 'rule.rejected', explain_failure(f), run_id, time, file=f['file'], compiler_output=BUILD_PATH.sub('', f['error'])[-300:]))
    for g in (gate or {}).get('rule_errors', []):
        out.append(event('ERROR', 'gate.rule_error', f"Rule file {g['file']} failed when loaded by the app: {g['error']}", run_id, time, **g))
    root = rules_root(candidate['files'])
    if failures:
        out.append(event('ERROR', 'candidate.rejected', f"Release blocked: {len(failures)} of {validation.get('checked', len(candidate['files']))} rule files failed validation. Nothing was signed or published.",
                         run_id, time, rules_root=root, file_count=len(candidate['files'])))
    else:
        out.append(event('INFO', 'candidate.accepted', f"All {len(candidate['files'])} rule files compiled. Candidate rules root is {root[:16]}...",
                         run_id, time, rules_root=root, file_count=len(candidate['files'])))
    return out

def events_for_decision(candidate: dict, decision: dict, run_id: str, time: str, perf: dict = None) -> list:
    """Public-safe events for the autonomous flow: counts only, never the names or findings of quarantined rules."""
    st = decision['public_stats']
    import accounting; accounting.require(st)   # statistics that break the invariant are never logged, so they can never be shown
    out = [event('INFO', 'sources.fetched', f"Fetched {len(candidate['sources'])} upstream sources at pinned commits.", run_id, time,
                 sources=[{'repository': x['repository'], 'commit': x['commit']} for x in candidate['sources']])]
    out.append(event('INFO', 'candidate.classified', f"Examined {st['examined']} rule files: {st['accepted']} accepted, {st['quarantined']} quarantined for review, {st['rejected']} rejected, {st['deprecated']} deprecated; {st['retired']} files of the previous release are no longer upstream.", run_id, time, **st, **(perf or {})))
    if st.get('previously_published_failing'):
        out.append(event('WARNING', 'rules.withheld', f"{st['previously_published_failing']} previously published rule files no longer pass the checks and are withheld until resolved.", run_id, time, count=st['previously_published_failing']))
    if decision['publishable'] or decision['approved']:
        out.append(event('INFO' if decision['publishable'] else 'WARNING', 'candidate.accepted', f"{st['accepted']} rule files passed every mandatory check. Candidate rules root is {decision['rules_root'][:16]}...", run_id, time,
                         rules_root=decision['rules_root'], file_count=st['accepted'], examined=st['examined'], quarantined=st['quarantined'], rejected=st['rejected'], deprecated=st['deprecated']))
    if not decision['publishable']:
        out.append(event('WARNING', 'candidate.not_publishable', 'No release from this run: ' + '; '.join(decision['blockers']), run_id, time, blockers=decision['blockers']))
    return out

# ---- Readable rendering -----------------------------------------------------------------------
def render(log: Log) -> str:
    rows = [json.loads(l) for l in log.lines()]
    counts = {lv: sum(1 for r in rows if r.get('level') == lv) for lv in LEVELS}
    lines = ['# MacGuard rules transparency log', '',
             'Generated from `logs/log.jsonl`; do not edit by hand. Times are UTC. Newest first.', '',
             f"Entries: {len(rows)} (INFO {counts['INFO']}, WARNING {counts['WARNING']}, ERROR {counts['ERROR']})", '']
    cps = log.checkpoint_files()
    if cps:
        size, root = log.parse_checkpoint(cps[-1].read_bytes())
        lines += [f'Latest signed checkpoint: {size} entries, Merkle root `{root.hex()}`.', '']
    else:
        lines += ['No signed checkpoint yet.', '']
    lines += ['| # | Date (UTC) | Level | Event | Message |', '|---|---|---|---|---|']
    for r in reversed(rows):
        msg = str(r.get('message', '')).replace('|', '\\|').replace('\n', ' ')
        lines.append(f"| {r.get('seq')} | {r.get('time', '')} | {r.get('level', '')} | `{r.get('event', '')}` | {msg} |")
    return '\n'.join(lines) + '\n'


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or 'tlog').splitlines()[0])
    ap.add_argument('--logs', default=str(ROOT / 'logs'))
    sub = ap.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('entry', help='append the events of a validated candidate')
    s.add_argument('--dist', default=str(ROOT / 'dist')); s.add_argument('--run-id', required=True); s.add_argument('--time', default=''); s.add_argument('--gate')
    s = sub.add_parser('entry-decision', help='append the public-safe events of an autonomous decision'); s.add_argument('--dist', default=str(ROOT / 'dist')); s.add_argument('--decision', default=''); s.add_argument('--run-id', required=True); s.add_argument('--time', default=''); s.add_argument('--perf', action='append', default=[], help='key=value aggregate measurement, repeatable')
    s = sub.add_parser('event', help='append one event, e.g. a failed step')
    s.add_argument('--level', required=True, choices=LEVELS); s.add_argument('--code', required=True); s.add_argument('--message', required=True)
    s.add_argument('--run-id', default=''); s.add_argument('--time', default='')
    s.add_argument('--detail', action='append', default=[], help='key=value, repeatable')
    sub.add_parser('root'); sub.add_parser('render')
    sub.add_parser('checkpoint', help='write the unsigned tree head; sign it with cosign afterwards')
    s = sub.add_parser('verify'); s.add_argument('--identity', help='expected Sigstore certificate identity (the publish workflow ref)'); s.add_argument('--repo', help='owner/name the workflow ran in')
    s.add_argument('--structure-only', action='store_true', help='skip signature checks (used before the first signed checkpoint exists or for local runs)')
    s = sub.add_parser('release-proof'); s.add_argument('--run-id', required=True); s.add_argument('--manifest', required=True); s.add_argument('--out', required=True)
    s = sub.add_parser('proof'); s.add_argument('index', type=int)
    a = ap.parse_args(argv)
    log = Log(pathlib.Path(a.logs))
    if a.cmd == 'entry':
        dist = pathlib.Path(a.dist)
        gate = json.loads(pathlib.Path(a.gate).read_text()) if a.gate else None
        evs = events_for_candidate(json.loads((dist / 'candidate.json').read_text()), json.loads((dist / 'validation.json').read_text()), a.run_id, a.time or now_utc(), gate)
        for e in evs: log.append(e)
        print(f'appended {len(evs)} events; last: {evs[-1]["event"]}')
    elif a.cmd == 'entry-decision':
        dist = pathlib.Path(a.dist)
        evs = events_for_decision(json.loads((dist / 'candidate.json').read_text()), json.loads(pathlib.Path(a.decision or dist / 'decision.json').read_text()), a.run_id, a.time or now_utc(), {k: (float(v) if v.replace('.', '', 1).isdigit() else v) for k, v in (p.split('=', 1) for p in a.perf)})
        for e in evs: log.append(e)
        print(f'appended {len(evs)} events; last: {evs[-1]["event"]}')
    elif a.cmd == 'event':
        details = dict(d.split('=', 1) for d in a.detail)
        log.append(event(a.level, a.code, a.message, a.run_id, a.time, **details)); print('appended 1 event')
    elif a.cmd == 'render':
        log.folder.mkdir(parents=True, exist_ok=True); (log.folder / 'LOG.md').write_text(render(log)); print('LOG.md written')
    elif a.cmd == 'root':
        leaves = log.leaves(); print(json.dumps({'size': len(leaves), 'root': mth(leaves).hex()}))
    elif a.cmd == 'checkpoint':
        print(f'checkpoint written for {log.write_checkpoint()} entries')
    elif a.cmd == 'release-proof':
        manifest = json.loads(pathlib.Path(a.manifest).read_text())
        doc = log.release_proof(a.run_id, manifest['rules_root'], manifest['log']['size'])
        pathlib.Path(a.out).write_text(json.dumps(doc, indent=2, sort_keys=True) + '\n'); print(f"inclusion proof written (entry {doc['index']} of {doc['size']})")
    elif a.cmd == 'verify':
        verifier = None
        if not a.structure_only:
            if not (a.identity and a.repo): sys.exit('verify needs --identity and --repo, or --structure-only')
            verifier = cosign_verifier(a.identity, a.repo)
        problems = log.verify(verifier)
        readable = log.folder / 'LOG.md'
        if readable.exists() and readable.read_text() != render(log): problems.append('LOG.md does not match log.jsonl; run `tlog.py render`')
        for p in problems: print('PROBLEM:', p)
        if problems: sys.exit(1)
        print(f'log OK: {len(log.lines())} entries, {len(log.checkpoint_files())} checkpoints')
    elif a.cmd == 'proof':
        leaves = log.leaves()
        print(json.dumps({'index': a.index, 'size': len(leaves), 'root': mth(leaves).hex(),
                          'proof': [h.hex() for h in inclusion_proof(a.index, leaves)]}))

if __name__ == '__main__': main()
