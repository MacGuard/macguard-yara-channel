---
title: Merkle trees
summary: How `rules_root` and the log root are computed, with an example you can recompute.
---
## Rules: `rules_root`

Files are sorted by path (UTF-8 bytes). The leaf of each file is `SHA-256(0x00 || path || 0x00 || sha256_hex)` and internal nodes are `SHA-256(0x01 || left || right)`. A tree of n leaves is split at the largest power of two below n (RFC 6962 / RFC 9162). The root is stored in the signed manifest.

{{diagram:rules-merkle}}

Recompute it yourself with the release `manifest.json` (Python standard library only). It must print `True`:

```python
import hashlib, json
m = json.load(open('manifest.json'))
H = hashlib.sha256
leaf = lambda b: H(b'\x00' + b).digest()
node = lambda l, r: H(b'\x01' + l + r).digest()
def mth(xs):
    if len(xs) == 1: return xs[0]
    k = 1
    while k * 2 < len(xs): k *= 2
    return node(mth(xs[:k]), mth(xs[k:]))
files = sorted(m['files'], key=lambda f: f['path'].encode())
root = mth([leaf(f"{f['path']}\0{f['sha256']}".encode()) for f in files]).hex()
print(root, root == m['rules_root'])
```

Practical effect: adding, removing or changing a single byte of one file, or adding an extra file to the package, changes `rules_root` and verification fails.

## Log: log root

Every line of `logs/log.jsonl` is a leaf: `SHA-256(0x00 || exact bytes of the line)`. They are combined with the same rule. The root and the number of entries form the checkpoint (see [Log and checkpoints](page:transparency-log)).

{{diagram:log-merkle}}

## Proofs

- **Inclusion:** `inclusion-proof.json` carries the sibling hashes joining this release's log entry to the checkpoint root.
- **Consistency:** `consistency.json` proves that the log of the earlier size is a prefix of the current one (entries were only appended).

> **LIMIT** The web pages recompute these sums in the browser but **do not verify Sigstore signatures**. Use `cosign`, the public verifier or the app for that.
