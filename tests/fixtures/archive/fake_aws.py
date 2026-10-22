"""A stand-in for the `aws` CLI that behaves like a versioned bucket (state in $FAKE_AWS_STATE, a JSON file).
FAKE_AWS_LEAK = '' (protected) | 'delete' (version delete succeeds) | 'retention' (retention change succeeds) | 'overwrite' (a new put replaces the old version)
FAKE_AWS_READONLY = '1' refuses put and delete (a read-only key). No network, no credentials."""
import json, os, sys

STATE = os.environ['FAKE_AWS_STATE']
LEAK = os.environ.get('FAKE_AWS_LEAK', '')
READONLY = os.environ.get('FAKE_AWS_READONLY') == '1'
args = sys.argv[1:]
for flag in ('--endpoint-url', '--region', '--output'):
    if flag in args: i = args.index(flag); del args[i:i + 2]
st = json.load(open(STATE)) if os.path.exists(STATE) else {'versions': {}, 'n': 0}


def opt(name): return args[args.index(name) + 1] if name in args else None


def save(): json.dump(st, open(STATE, 'w'))


def refuse(msg='AccessDenied'): print(msg, file=sys.stderr); sys.exit(255)


cmd = args[1]
key = opt('--key')
if cmd == 'put-object':
    if READONLY: refuse()
    st['n'] += 1; vid = f'v{st["n"]}'
    body = open(opt('--body') or os.devnull, 'rb').read().hex()
    if LEAK == 'overwrite':
        for k in [k for k in st['versions'] if st['versions'][k]['key'] == key]: del st['versions'][k]
    st['versions'][vid] = {'key': key, 'body': body}; save(); print(json.dumps({'VersionId': vid}))
elif cmd == 'get-object':
    out = args[-1]; v = opt('--version-id')
    cands = [x for k, x in st['versions'].items() if x['key'] == key and (v is None or k == v)]
    if not cands: refuse('NoSuchKey')
    open(out, 'wb').write(bytes.fromhex(cands[-1]['body'])); print('{}')
elif cmd == 'delete-object':
    if READONLY: refuse()
    v = opt('--version-id')
    if v and LEAK == 'delete': del st['versions'][v]; save(); print('{}')
    elif v: refuse('AccessDenied: object is locked')
    else: print('{}')           # a delete marker only: no version is removed
elif cmd == 'put-object-retention':
    if LEAK == 'retention': print('{}')
    else: refuse('AccessDenied: retention')
else: refuse('unsupported')
