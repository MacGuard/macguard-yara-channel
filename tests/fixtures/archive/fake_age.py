#!/usr/bin/env python3
"""TEST DOUBLE of the subset of `age` that scripts/archive/crypto.py uses (-r R ... encrypt; -d -i IDENTITY decrypt; stdin to stdout).
Authenticated (HMAC) and recipient-bound, so a tampered ciphertext or a wrong identity fails like the real tool, but it is NOT cryptographically meaningful.
Identity file format: one line `FAKE-IDENTITY-FOR <recipient>`."""
import hashlib, hmac, os, sys

MAGIC = b'FAKE-AGE-1\n'
args, data = sys.argv[1:], sys.stdin.buffer.read()
H = lambda *p: hashlib.sha256(b'|'.join(p)).digest()
xor = lambda a, b: bytes(x ^ y for x, y in zip(a, b))
stream = lambda key, n: b''.join(H(key, str(i).encode()) for i in range(n // 32 + 1))[:n]


def die(msg): sys.stderr.write(msg + '\n'); sys.exit(1)


if '-d' in args:
    ident = open(args[args.index('-i') + 1]).read().split()
    if len(ident) != 2 or ident[0] != 'FAKE-IDENTITY-FOR': die('bad identity file')
    me = ident[1].encode()
    if not data.startswith(MAGIC): die('not an age file')
    lines = data[len(MAGIC):].split(b'\n', 1)
    head, body = lines[0].split(b' '), lines[1]
    wraps = dict(w.split(b':') for w in head[1:]); mac = bytes.fromhex(head[0].decode())
    if me not in wraps: die('no identity matched any of the recipients')
    dk = xor(bytes.fromhex(wraps[me].decode()), H(b'wrap', me))
    if not hmac.compare_digest(mac, hmac.new(dk, body, 'sha256').digest()): die('authentication failed: ciphertext was modified')
    sys.stdout.buffer.write(xor(body, stream(dk, len(body))))
else:
    rs = [args[i + 1].encode() for i, a in enumerate(args) if a == '-r']
    if not rs: die('no recipients')
    dk = H(b'dk', data, os.urandom(16))
    body = xor(data, stream(dk, len(data)))
    wraps = b' '.join(r + b':' + xor(dk, H(b'wrap', r)).hex().encode() for r in rs)
    sys.stdout.buffer.write(MAGIC + hmac.new(dk, body, 'sha256').hexdigest().encode() + b' ' + wraps + b'\n' + body)
