# MacCoreGuard

[Home](EN-Home) · [Ecosystem](EN-Ecosystem) · [Global roadmap](EN-Roadmap) · [MacUSBGuard](EN-App-USB)

## In 30 seconds

MacCoreGuard (the code and package are named **MacCore**; only the private repository name uses "maccore-guard") aims to be the shared "minutes book" of the MacGuard applications: each one proposes security events ("a USB device was blocked") and only MacCoreGuard decides to record them permanently and in a tamper-evident way {{ev:EV-EC-27}}.

**State: one-commit prototype** (b0b0f07, 2026-10-09) on a candidate branch that its own message declares "not authoritative" and not pushed. Today the **data formats** and the **hash mathematics** exist; the on-disk ledger, signing, ingest and verifier are **placeholders** {{ev:EV-EC-28}} {{ev:EV-EC-06}}.

It guarantees nothing to a user yet: no service is running and no application imports it today.

## An everyday example

Think of a notebook where each page carries the "fingerprint" of the previous page: if someone tears out or alters a sheet, the following fingerprints stop matching. A summary of the whole notebook also lets you prove one particular page was in it, without showing the whole notebook. The analogy describes the mathematics, not a notebook that is already working.

## Diagram

{{diagram:maccore-chain-merkle}}

## Step by step (design)

1. A producer (a closed set of MacGuard applications; it cannot declare itself) proposes an event.
2. MacCore serializes it as canonical JSON (sorted keys, no floating-point numbers, so the hash is identical on any Mac).
3. MacCore, and only MacCore, assigns a gap-free sequence number from 0 and computes the chain link.
4. Periodically the Merkle tree root is computed and a checkpoint would be signed.
5. An independent verifier, not trusting the writer process, would check chain, proofs and signature.

**Not implemented**: the intake of step 1, the numbering of step 3, the signing of step 4 and step 5. **Implemented**: the closed producer list (step 1), canonical JSON (2), the link formula (3) and the root and proofs (4) {{ev:EV-EC-28}}.

## Under the hood

**Hash chain.** Problem: detect that an intermediate record was altered or deleted. Input: previous hash, sequence number and canonical event bytes. Computation: `recordHash = SHA-256(0x02 || previousHash || 64-bit big-endian sequence || eventBytes)`. Output: 32 bytes. It detects changes to any earlier link; it does **not** stop someone who controls all storage from rewriting the whole chain from the start: signing and an external witness address that, and neither is implemented. Code: `CanonicalHashing.recordHash`, `Sources/MacCoreCrypto/CanonicalHashing.swift` {{ev:EV-EC-27}}.

**RFC 9162 Merkle tree.** Problem: summarize thousands of records in one hash and prove things about it. Input: leaf hashes. Computation (RFC 9162, section 2.1): leaf = `SHA-256(0x00 || data)`, node = `SHA-256(0x01 || left || right)`, splitting at the largest power of two below n; the empty tree is the SHA-256 of the empty string. The `0x00`, `0x01` and `0x02` prefixes separate domains so a leaf, node or record hash is never confused with another. It is the same kind of tree used by Certificate Transparency.

- **Inclusion proof** (`inclusionProof` / `verifyInclusionProof`): shows leaf number *m* is in a tree of size *n* with a path of sibling hashes.
- **Consistency proof** (`consistencyProof` / `verifyConsistencyProof`): shows an old tree is a prefix of the new one (entries were only appended, nothing rewritten).

Cost stated in the code itself: recomputing the root is O(n) per checkpoint, acceptable because it is not done per event. Code: `Sources/MacCoreCrypto/MerkleTree.swift` {{ev:EV-EC-27}}.

**What is a placeholder.** `MacCoreLedger`, `MacCoreSigning`, `MacCoreIngest` and `MacCoreWitness` each hold a one-line file; `maccorectl` only prints "not yet implemented" {{ev:EV-EC-28}}. P-256 signatures, Secure Enclave or keychain keys, key rotation, atomic writes with crash recovery and a witness client appear only in the design contract or comments, with no code.

## Tests

In-house harness `maccore-tests` (executable, three files) with known-answer vectors (KAT), including inclusion proofs for trees of 1 to 6 leaves, derived per the code from a separately written Python/hashlib reference. The commit message claims "147/147 tests" for Protocol and Crypto: self-reported, **not run by me**. No tests are possible for the placeholder parts {{ev:EV-EC-29}}.

## Check it yourself

The repository is private. Its README names `swift build` and `swift run maccore-tests` as the gate of each wave; they were not run here. To validate the algorithm without the repository, read section 2.1 of RFC 9162.

## Limits

- No service, no durable storage, no signing and no offline verifier.
- One candidate branch, no tags, and an unresolved split of responsibilities between parties according to the commit; I did not verify whether another implementation exists on another branch or team.
- MacFirewallGuard has a MacCoreGuard client tested only against a mock; MacUSBGuard does not import it {{ev:EV-EC-04}}. MacGuardDesignKit is forbidden from depending on it.

## State

| Capability | State |
|---|---|
| Event format and identifiers | Implemented, not deployed |
| Hash chain and Merkle tree with proofs | Implemented with test vectors, not deployed |
| Durable ledger, signing, ingest, witness, verifier | Planned (placeholders) |

Named work waves TL-0 to TL-8, each gated on building and passing its tests; no dates {{ev:EV-EC-06}}.

## Further reading

[MacUSBGuard](EN-App-USB) · [Global roadmap](EN-Roadmap) · [Evidence matrix](EN-Evidence)
