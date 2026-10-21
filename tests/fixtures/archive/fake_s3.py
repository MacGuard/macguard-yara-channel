#!/usr/bin/env python3
"""TEST DOUBLE of the subset of `rclone` and `aws` that scripts/archive/providers.py uses. Objects live under $FAKE_S3_ROOT/<bucket>/<key>.
Every invocation's argv is appended to $FAKE_S3_ROOT/argv.log so tests can prove no secret is ever on a command line. Not a model of real S3 semantics."""
import json, os, pathlib, shutil, sys

root = pathlib.Path(os.environ['FAKE_S3_ROOT'])
args = sys.argv[1:]
with open(root / 'argv.log', 'a') as f: f.write(json.dumps(args) + '\n')
if os.environ.get('FAKE_S3_HANG'): import time; time.sleep(60)
if args[:1] == ['--endpoint-url']: args = args[2:]


def die(code, msg): sys.stderr.write(msg + '\n'); sys.exit(code)


def split(url):   # rclone "remote:bucket/key" or aws "s3://bucket/key"
    rest = url.split(':', 1)[1] if not url.startswith('s3://') else url[5:]
    b, _, k = rest.partition('/'); return b, k


def flag(name):
    return args[args.index(name) + 1] if name in args else None


cmd = args[0]
if cmd == 'lsf':
    target = [a for a in args[1:] if not a.startswith('-')][0]; b, k = split(target)
    base = root / b
    if '-R' in args: files = sorted(p.relative_to(base).as_posix() for p in base.rglob('*') if p.is_file()) if base.exists() else []
    else: files = [k.split('/')[-1]] if (base / k).is_file() else []
    print('\n'.join(files)); sys.exit(0 if files or '-R' in args else 3)
elif cmd == 'copyto':
    pos = [a for a in args[1:] if not a.startswith('-')]; src, dst = pos
    if ':' in dst and not os.path.isabs(dst):
        b, k = split(dst); p = root / b / k
        if p.exists(): die(9, 'immutable: destination exists' if '--immutable' in args else 'exists')
        p.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(src, p)
    else:
        b, k = split(src); p = root / b / k
        if not p.is_file(): die(3, 'directory not found')
        shutil.copyfile(p, dst)
elif cmd == 's3api':
    sub = args[1]; b, k = flag('--bucket'), flag('--key'); p = root / b / k
    if sub == 'head-object': sys.exit(0 if p.is_file() else 254)
    if sub == 'put-object':
        if p.exists(): die(1, 'PreconditionFailed')
        p.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(flag('--body'), p)
elif cmd == 's3':
    sub = args[1]
    if sub == 'cp':
        b, k = split(args[2]); p = root / b / k
        if not p.is_file(): die(1, 'NoSuchKey')
        shutil.copyfile(p, args[3])
    elif sub == 'ls':
        b, _ = split(args[2]); base = root / b
        for p in sorted(base.rglob('*')):
            if p.is_file(): print(f'2026-01-01 00:00:00 {p.stat().st_size} {p.relative_to(base).as_posix()}')
else: die(2, 'unsupported')
