# Transparency log

[Home](EN-Home) · [Quarantine](EN-YARA-Quarantine) · [Publishing](EN-YARA-Publishing) · [Transparency](EN-YARA-Transparency) · [Verify](EN-YARA-Verify)

## In 30 seconds

The channel keeps a **transparency log**: a diary where lines are only meant to be added; if someone deletes or changes one, a verifier detects it (it cannot prevent it). From time to time a "snapshot" of that diary (the **checkpoint**) is signed. Anyone can redo the maths and check that a publication is in the diary and that today's diary contains yesterday's in full. If someone tries to alter an earlier publication, the sums stop adding up. {{ev:EV-YC-04}} {{ev:EV-YC-50}}

## An everyday example

A ledger whose pages are mathematically linked: at the foot of each page a fingerprint is written that depends on everything written before. If somebody tears out or rewrites an old page, the fingerprints of the later pages no longer match the one that was signed (anyone can check that signature). The analogy carries the idea; the real mechanism is a Merkle tree, explained below.

Key words, once:

- **Entry**: one JSON line of `logs/log.jsonl` (an event, for example `candidate.accepted`).
- **Merkle tree**: hashes of hashes; each leaf is an entry and each node summarizes its two children.
- **Root**: the hash at the top; it changes if any leaf changes.
- **Checkpoint**: a three-line text with origin, number of entries and root; it is signed with Sigstore.
- **Inclusion proof**: the sibling hashes that join one entry to the root.
- **Consistency proof**: shows that the log of size *n* is a prefix of the log of size *m > n*.

{{diagram:log-merkle-1-pair-a}}

{{diagram:log-merkle-2-pair-b}}

{{diagram:log-merkle-3-pair-c}}

{{diagram:log-merkle-4-root}}

## Step by step

1. Each event is appended as a line at the end of `logs/log.jsonl`.
2. `tlog.py checkpoint` computes the root of all lines and writes the checkpoint.
3. `publish.yml` signs the checkpoint with Sigstore (`checkpoint.sigstore.json`).
4. The release carries `inclusion-proof.json` (this release's entry is in the checkpoint) and, if a previous release exists, `consistency.json`.
5. The signed manifest copies `log.size` and `log.root`, which must match `checkpoint.txt`.

{{diagram:checkpoint-sequence-1-sign}}

{{diagram:checkpoint-sequence-2-manifest-proof}}

{{diagram:checkpoint-evolution-1-growth}}

{{diagram:checkpoint-evolution-2-refusals}}

## Under the hood

**Algorithm.** Merkle tree of RFC 6962 (hashing) and RFC 9162 (proofs). Input: an ordered list of leaves. Leaf = `SHA-256(0x00 || data)`; node = `SHA-256(0x01 || left || right)`; a tree of *n* leaves splits at the largest power of two below *n*. Output: the 32-byte root. Read in `scripts/tlog.py` (`leaf_hash`, `node_hash`, `mth`) and repeated independently in `scripts/verify_public_release.py`. {{ev:EV-YC-50}}

Two trees, one rule: the **log** (leaf = the exact bytes of the line) and `rules_root` (leaf = `path`, a NUL byte and the file's hexadecimal SHA-256, sorted by path). With `rules_root`, changing one byte of a file, removing one or adding an extra one changes the root.

Tiny example with three entries `E0 E1 E2` (`H` = SHA-256, `||` = concatenate):

```
L0 = H(00 || E0)    L1 = H(00 || E1)    L2 = H(00 || E2)
N01  = H(01 || L0 || L1)
root = H(01 || N01 || L2)
inclusion proof of E2 = [N01]      (one sibling hash)
if E0 changes: L0, N01 and root change; the signed checkpoint no longer matches
```

**Checkpoint.** Three lines: `macguard-rules-log v1`, the size and the root in base64 (`Log.parse_checkpoint`). Sigstore signs it and the manifest repeats the same size and root. {{ev:EV-YC-51}}

**What anyone can check without trusting us.** (1) The signature of the checkpoint and the manifest with the expected identity. (2) `rules_root` recomputed from the files. (3) That the release entry is in the checkpoint (inclusion). (4) That the new checkpoint extends the one you already knew (consistency) and that the size does not shrink. {{ev:EV-YC-52}}

**If someone alters an earlier publication.**

| Attempt | What detects it | How |
|---|---|---|
| Change an old entry | Different root | The new root does not match the signed checkpoint or the inclusion proof. |
| Delete entries (go back) | Verifier with your saved checkpoint | `ROLLBACK`: fewer entries than the ones you already trust. |
| Rewrite and keep the size | Verifier | `FORK`: a different root at the same size. |
| Rewrite and grow | Consistency proof | No valid proof exists that the rewritten history contains the earlier one. |
| Change an already published file | `rules_root` and SHA-256 | The sum stops matching the signed manifest. |

Tests that cover it: `tests/test_tlog.py` (`test_consistency_detects_rewritten_history`), `tests/test_tlog_adversarial.py` (`test_a_rewritten_history_has_no_valid_consistency_proof`, `test_a_checkpoint_for_a_forked_history_or_a_longer_log_is_detected`), `tests/test_verify_public_release.py` (`test_a_fork_at_the_same_size_is_detected`). Also `publish.yml` verifies the existing log before extending it. {{ev:EV-YC-52}}

What it does not prevent: rollback and fork detection needs a checkpoint you saved earlier; a first verification does not establish rollback protection. And the log proves that a publication happened, not that its rules are good. Cost: the log grows one line per event; verification time was not measured for this page.

## Check it yourself

Recompute `rules_root` with the Python standard library (script in [merkle.md](https://github.com/MacGuard/macguard-yara-channel/blob/main/docs-src/en/merkle.md)) or let the verifier do everything, inclusion included: see [Verify](EN-YARA-Verify). Code: [tlog.py](https://github.com/MacGuard/macguard-yara-channel/blob/main/scripts/tlog.py).

## Limits

- The web pages recompute the sums in the browser but **do not verify Sigstore signatures**. {{ev:EV-YC-58}}
- This log is ours; it is not Rekor nor an independent third party. Its strength comes from the checkpoint being signed by the workflow identity and from other people keeping checkpoints.
- The log carries counts and events, not names or findings of quarantined rules.

## State

| Capability | State |
|---|---|
| Log, signed checkpoints, inclusion and consistency proofs in each release | published {{ev:EV-YC-04}} |
| Third-party verification with a public script and tests | operational {{ev:EV-YC-52}} |
| Independent external monitor watching the log | not verified: none found in the repository |
