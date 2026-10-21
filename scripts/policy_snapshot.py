#!/usr/bin/env python3
"""Pipeline side of the persistent administrative policy (withdrawals) and of the persistent rejections.

Fail safe, not fail open. Whatever fails (service down, slow, 5xx, wrong schema, truncated, regressed, emptied, tampered), no build can add or modify a
file unless the pipeline holds a VERIFIED view of every prohibition; and no failure can remove a prohibition the pipeline has already verified. A removal
can never violate a prohibition, so removals are always allowed. Spec: docs/audit/quarantine-decision-memory-and-withdrawal-spec.md sections 14-15.

mode       when                                                                    what decide() does
normal     the live view of the Worker is accepted (schema, digests, ratchet)      applies live U verified snapshot
snapshot   the live view is unavailable/rejected but a verified fresh snapshot     applies the snapshot only; additions allowed
unknown    neither, or the live view REGRESSED against the verified snapshot        not publishable if anything is added or modified; the
                                                                                   snapshot's blocks (if any) are still applied

The snapshot is the last live view accepted in mode `normal`: signed keylessly by the daily workflow (cosign), pinned by hash in the append-only repository log
(event `policy.snapshot`) and transported through the Actions cache. It is only ever refreshed from a live view, never from another snapshot, so staleness
cannot be laundered. It is verified before use: signature and workflow identity, hash equal to the NEWEST pin in the log (defeats replaying an older, validly
signed snapshot), and age taken from the signature's transparency-log time inside the bundle (not from a field the file controls).

usage: policy_snapshot.py stage --candidate dist/policy-snapshot.candidate.json --out policy-snapshot"""
import argparse, hashlib, json, pathlib, re, subprocess, sys, time, unicodedata

SCHEMA = 1
MAX_AGE_S = 48 * 3600        # the daily cron is once a day; 48 h tolerates one missed run
FUTURE_SKEW_S = 300
SNAPSHOT_FILE, BUNDLE_FILE = 'policy-snapshot.json', 'policy-snapshot.sigstore.json'
ISSUER = 'https://token.actions.githubusercontent.com'
HEX64 = re.compile(r'^[0-9a-f]{64}$')

# ---- identity (the same functions as admin/worker/src/policies.js; tests/test_policy_parity.py pins them to shared vectors) -------------------------
def canonical(o): return json.dumps(o, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
def digest(o): return hashlib.sha256(canonical(o).encode()).hexdigest()
def ascii_lower(s): return re.sub(r'[A-Z]', lambda m: m.group(0).lower(), str(s))

def normalize_path(p):
    if not isinstance(p, str) or not p or len(p) > 400: return None
    parts = [s for s in unicodedata.normalize('NFC', p.replace('\\', '/')).split('/') if s not in ('', '.')]
    if not parts or '..' in parts: return None
    return '/'.join(parts)

def scope_key(scope, source, path, sha256):
    if scope == 'content': return f'content:{sha256}'
    n = normalize_path(path)
    return None if n is None else f'path:{ascii_lower(source)}:{ascii_lower(n)}'

def matches(policy, f):
    """Does this policy prohibit this classified file? A content policy matches the bytes only; a path policy matches (source, normalized path) whatever the bytes."""
    if policy.get('scope') == 'content': return policy.get('sha256') == f.get('sha256')
    return policy.get('scope_key') == scope_key('path', f.get('source', ''), f.get('path'), None)

def policy_for(f, policies):
    """The prohibition that covers file `f` (the lowest id when several do), or None."""
    hits = [p for p in (policies or []) if matches(p, f)]
    return min(hits, key=lambda p: p['id']) if hits else None

# ---- reading what a run was given -------------------------------------------------------------------------------------------------------------------
def load_required(path, name):
    """None when the option was not given; the parsed JSON when it was; the run STOPS when it was given and the file is missing or invalid. (decide used to ignore a
    missing --rejected silently, which made a persistent rejection dead code.)"""
    if not path: return None
    p = pathlib.Path(path)
    if not p.is_file(): sys.exit(f'--{name} {path} was given but the file does not exist: refusing to continue without it')
    try: return json.loads(p.read_text())
    except Exception as e: sys.exit(f'--{name} {path} is not valid JSON ({e}): refusing to continue without it')

def decide_args(doc):
    """Keyword arguments for decide.decide from a dist/policies.json document."""
    if doc is None: return {}
    if not isinstance(doc, dict) or doc.get('schema') != SCHEMA or doc.get('mode') not in ('normal', 'snapshot', 'unknown') or not isinstance(doc.get('policies'), list):
        sys.exit('policies file is not a policy document of schema 1: refusing to continue')
    return {'policies': doc['policies'], 'policy_mode': doc['mode'], 'policy_set_sha256': doc.get('policy_set_sha256')}

# ---- the live view of the Worker ------------------------------------------------------------------------------------------------------------
def validate_view(v):
    """None when the view is well formed and self-consistent, else why not. The digests are recomputed here: a response that does not hash to what it claims is unusable."""
    if not isinstance(v, dict): return 'not a JSON object'
    if v.get('schema') != SCHEMA: return f"unsupported policy schema {v.get('schema')!r}"
    for k in ('audit_head', 'decisions_max_id', 'policies', 'lifted', 'rejected', 'policy_set_sha256', 'rejected_sha256'):
        if k not in v: return f'missing field {k}'
    ah = v['audit_head']
    if not isinstance(ah, dict) or not isinstance(ah.get('seq'), int) or isinstance(ah.get('seq'), bool) or ah['seq'] < 0: return 'bad audit_head'
    if not isinstance(v['decisions_max_id'], int) or isinstance(v['decisions_max_id'], bool) or v['decisions_max_id'] < 0: return 'bad decisions_max_id'
    if not isinstance(v['policies'], list) or not isinstance(v['lifted'], list) or not isinstance(v['rejected'], list): return 'policies, lifted and rejected must be lists'
    ids = set()
    for p in v['policies']:
        if not isinstance(p, dict) or not isinstance(p.get('id'), str) or not isinstance(p.get('version'), int) or p.get('scope') not in ('path', 'content') or p['id'] in ids: return 'bad policy entry'
        ids.add(p['id'])
        if not HEX64.match(str(p.get('sha256', ''))): return 'bad policy sha256'
        if p['scope'] == 'path' and (not isinstance(p.get('source'), str) or p.get('scope_key') != scope_key('path', p['source'], p.get('path'), None)): return 'a path policy whose key is not its source and path'
        if p['scope'] == 'content' and p.get('scope_key') != f"content:{p['sha256']}": return 'a content policy whose key is not its hash'
    for l in v['lifted']:
        if not isinstance(l, dict) or not isinstance(l.get('id'), str) or not isinstance(l.get('version'), int): return 'bad lifted entry'
    if any(not isinstance(h, str) or not HEX64.match(h) for h in v['rejected']): return 'bad rejected hash'
    if v['policy_set_sha256'] != digest(v['policies']): return 'policy_set_sha256 does not match the policies'
    if v['rejected_sha256'] != digest(v['rejected']): return 'rejected_sha256 does not match the rejected list'
    return None

def regressions(live, snap):
    """The ratchet (15.3): the live view must not know LESS than the last verified snapshot. A lift the Worker reports is accepted (Level A of the spec: the Worker is the authority
    for lifts; the file must still pass every technical gate)."""
    if not snap: return []
    out, lifted = [], {l['id'] for l in live['lifted']}
    if live['audit_head']['seq'] < snap['audit_head']['seq']: out.append('audit head went backwards')
    if live['decisions_max_id'] < snap['decisions_max_id']: out.append('decisions went backwards')
    now_by_id = {p['id']: p for p in live['policies']}
    for p in snap['policies']:
        q = now_by_id.get(p['id'])
        if q is None and p['id'] not in lifted: out.append(f"policy {p['id']} disappeared without being lifted")
        elif q is not None and q['version'] < p['version']: out.append(f"policy {p['id']} went back to version {q['version']}")
    for h in snap['rejected']:
        if h not in live['rejected']: out.append(f'a rejected hash ({h[:12]}) disappeared')
    return out

def effective(live, snap):
    """The blocks in force: everything the live view and the verified snapshot know, minus what the live view validly lifted."""
    blocks = {}
    for p in (snap or {}).get('policies', []): blocks[p['id']] = p
    for p in (live or {}).get('policies', []): blocks[p['id']] = p
    for l in (live or {}).get('lifted', []): blocks.pop(l['id'], None)
    rejected = sorted(set((live or {}).get('rejected', [])) | set((snap or {}).get('rejected', [])))
    return sorted(blocks.values(), key=lambda p: p['id']), rejected

# ---- the snapshot ---------------------------------------------------------------------------------------------------------------------------------
def bundle_time(bundle):
    """Seconds since the epoch at which the transparency log integrated the signature (inside the Sigstore bundle), or None."""
    try:
        d = json.loads(pathlib.Path(bundle).read_text()); t = d['verificationMaterial']['tlogEntries'][0]['integratedTime']
        return int(t)
    except Exception: return None

def cosign_verifier(repo):
    """Verifier of the signing workflow: daily.yml or publish.yml of this repository on main, GitHub OIDC issuer. Returns None when valid, else the reason."""
    identity = rf'^https://github\.com/{re.escape(repo)}/\.github/workflows/(daily|publish)\.yml@refs/heads/main$'
    def verify(path, bundle):
        r = subprocess.run(['cosign', 'verify-blob', '--bundle', str(bundle), '--certificate-identity-regexp', identity, '--certificate-oidc-issuer', ISSUER,
                            '--certificate-github-workflow-repository', repo, str(path)], capture_output=True, text=True)
        return None if r.returncode == 0 else (r.stderr.strip().splitlines() or ['cosign verification failed'])[-1]
    return verify

def newest_pin(logs_dir):
    """The snapshot hash pinned by the newest `policy.snapshot` event of the repository log, or None."""
    f = pathlib.Path(logs_dir) / 'log.jsonl'
    if not f.is_file(): return None
    best = None
    for line in f.read_text().splitlines():
        try: e = json.loads(line)
        except Exception: continue
        if e.get('event') == 'policy.snapshot' and isinstance(e.get('seq'), int) and (best is None or e['seq'] > best['seq']): best = e
    h = ((best or {}).get('details') or {}).get('snapshot_sha256')
    return h if isinstance(h, str) and HEX64.match(h) else None

def load_snapshot(snapshot_dir, logs_dir, now, verifier, max_age=MAX_AGE_S):
    """(snapshot, None) when it passes every check, else (None, why). A snapshot that does not verify is the same as no snapshot."""
    d = pathlib.Path(snapshot_dir or '.')
    f, b = d / SNAPSHOT_FILE, d / BUNDLE_FILE
    if not f.is_file() or not b.is_file(): return None, 'no snapshot'
    raw = f.read_bytes()
    try: snap = json.loads(raw)
    except Exception: return None, 'snapshot is not valid JSON'
    bad = validate_view(snap)
    if bad: return None, f'snapshot is not a valid policy view: {bad}'
    why = verifier(f, b)
    if why: return None, f'signature not accepted: {why}'
    pin = newest_pin(logs_dir)
    if pin is None: return None, 'no policy.snapshot pin in the repository log'
    if hashlib.sha256(raw).hexdigest() != pin: return None, 'snapshot is not the one pinned by the newest log entry (replay of an older snapshot?)'
    t = bundle_time(b)
    if t is None: return None, 'the signature has no transparency log time'
    if now - t > max_age: return None, f'snapshot is older than {max_age // 3600} h'
    if t - now > FUTURE_SKEW_S: return None, 'snapshot time is in the future'
    return snap, None

def resolve(status, data, snapshot_dir, logs_dir, now=None, verifier=None, max_age=MAX_AGE_S):
    """Decide the mode of this run. `status`, `data` are what the call to GET /api/pipeline/policy-snapshot returned (status 0 = unreachable).
    Returns (policies document for decide, live view to keep as the next snapshot or None)."""
    now = int(time.time()) if now is None else now
    snap, snap_why = load_snapshot(snapshot_dir, logs_dir, now, verifier or (lambda *_: 'no verifier'), max_age)
    live, live_why = None, None
    if status != 200: live_why = f'service answered {status}: {(data or {}).get("error") if isinstance(data, dict) else ""}'
    else:
        live_why = validate_view(data)
        if live_why is None: live = data
    doc = {'schema': SCHEMA, 'generated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now)), 'regressions': [], 'snapshot': snap_why if snap is None else 'verified',
           'live': live_why or 'accepted'}
    keep = None
    if live is not None:
        reg = regressions(live, snap)
        policies, rejected = effective(live, snap)
        if reg: doc.update(mode='unknown', reason='policy store regressed against the last verified snapshot: a person must reconcile', regressions=reg)
        else: doc.update(mode='normal', reason='live view accepted'); keep = live
    elif snap is not None:
        policies, rejected = effective(None, snap); doc.update(mode='snapshot', reason=f'live view not usable ({live_why}); using the verified snapshot')
    else:
        policies, rejected = [], []; doc.update(mode='unknown', reason=f'no usable live view ({live_why}) and no verified snapshot ({snap_why})')
    doc.update(policies=policies, rejected=rejected, policy_set_sha256=digest(policies), rejected_sha256=digest(rejected))
    return doc, keep

def check_candidate(files, doc, previous_files):
    """Problems that must stop a publication: a file of the final set that a prohibition or a persistent rejection covers, and, unless the live view was accepted, any
    addition or modification. Returns a list of strings (empty = ok)."""
    problems = []
    for f in files:
        p = policy_for(f, doc.get('policies'))
        if p: problems.append(f"{f.get('path')}: covered by administrative prohibition {p['id']}")
        if f.get('sha256') in set(doc.get('rejected') or []): problems.append(f"{f.get('path')}: its content was rejected")
    if doc.get('mode') != 'normal':
        prev = {f['path']: f['sha256'] for f in previous_files}
        changed = [f['path'] for f in files if prev.get(f['path']) != f['sha256']]
        if changed: problems.append(f"policy view not live ({doc.get('mode')}): {len(changed)} file(s) would be added or modified; only removals can be published")
    return problems

def stage(candidate, out_dir):
    """Copy the accepted live view to the folder that is signed and cached. Refuses anything that is not a valid view."""
    view = json.loads(pathlib.Path(candidate).read_text())
    bad = validate_view(view)
    if bad: sys.exit(f'refusing to keep an invalid policy view: {bad}')
    out = pathlib.Path(out_dir); out.mkdir(parents=True, exist_ok=True)
    (out / SNAPSHOT_FILE).write_text(json.dumps(view, sort_keys=True, indent=1) + '\n')
    h = hashlib.sha256((out / SNAPSHOT_FILE).read_bytes()).hexdigest()
    print(f'snapshot_sha256={h}'); print(f"audit_seq={view['audit_head']['seq']}", file=sys.stderr)

if __name__ == '__main__':
    ap = argparse.ArgumentParser(); sub = ap.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('stage'); s.add_argument('--candidate', default='dist/policy-snapshot.candidate.json'); s.add_argument('--out', default='policy-snapshot')
    a = ap.parse_args()
    if a.cmd == 'stage':
        if not pathlib.Path(a.candidate).is_file(): sys.exit('no accepted live view in this run: no snapshot is kept')
        stage(a.candidate, a.out)
