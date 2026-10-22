# Technology: Merkle trees

[Home](EN-Home) · [Limits](EN-YARA-Limits) · [Technology: Sigstore](EN-Tech-Sigstore) · [Technology: YARA](EN-Tech-YARA) · [Historical archive](EN-YARA-Archive)

## In 30 seconds

A Merkle tree boils a long list of things down to one number (the **root**). If any item changes, the root changes. It also lets you prove with very little data that an item is in the list (**inclusion proof**) and that a newer version of the list only appended to the older one (**consistency proof**).

## An everyday example

Imagine a logbook where each page carries a summary of the earlier ones and the last page carries a summary of everything. If someone tears out or edits an old page, the final summary no longer matches. It does not say whether what was written on the pages was true.

{{diagram:rules-merkle}}

## Under the hood

- **Problem:** proving that a set of files and a history log were not altered or rewritten.
- **Algorithm (RFC 6962):** leaf = SHA-256(`0x00` + data); node = SHA-256(`0x01` + left + right); the tree splits at the largest power of two smaller than *n*. The different prefixes stop a leaf from passing as a node {{ev:EV-YC-76}}.
- **Implementation:** `scripts/tlog.py` defines `leaf_hash`, `node_hash`, `mth`, `inclusion_proof`, `verify_inclusion`, `consistency_proof` and `verify_consistency` {{ev:EV-YC-68}}.
- **Two trees:** `rules_root` (leaves = path + hash of each rule file, sorted by path; `check_inventory` rejects duplicate, `..` or absolute paths) and the public log `logs/log.jsonl` (one leaf per line) {{ev:EV-YC-68}}.
- **Cost:** a proof is of the order of log₂(*n*) hashes; the RFC gives at most ⌈log₂(*n*)⌉ + 1 nodes for consistency {{ev:EV-YC-76}}.
- **Does not prevent:** legitimately signed false entries being appended; it only makes rewriting detectable.

{{diagram:log-merkle}}

## Who else uses it

No row implies that these projects use MacGuard.

| Who | Classification | Source |
|---|---|---|
| Certificate Transparency (RFC 6962): public certificate logs using Merkle trees with inclusion and consistency proofs | uses a related algorithm (the same tree hash this project implements) | {{ev:EV-YC-76}} |
| Go module checksum database: per its blog, built on a transparent log ("Merkle tree") backed by Trillian, with `go` checking inclusion and consistency proofs | uses a related algorithm | {{ev:EV-YC-77}} |

## Check it yourself

```
python3 -m unittest tests.test_tlog tests.test_tlog_adversarial tests.test_rules_root_vectors
```

The adversarial tests mutate every element of the proofs for all tested tree sizes, and check forked, truncated or reordered histories {{ev:EV-YC-68}}.

## Limits

The root shows integrity of the set, not its quality. The log is only as trustworthy as the signature on its checkpoint ([Sigstore](EN-Tech-Sigstore)). RFC 6962 has been obsoleted by RFC 9162; this project uses the 6962 hash construction {{ev:EV-YC-76}}.

## State

| Capability | State |
|---|---|
| `rules_root` and public log with signed checkpoints | published {{ev:EV-YC-04}} |
| Archive manifest with a Merkle root (local tool) | implemented-not-deployed {{ev:EV-YC-61}} |
