# MacCoreGuard

[Home](EN-Home) · [Ecosystem](EN-Ecosystem) · [Global roadmap](EN-Roadmap) · [MacUSBGuard](EN-App-USB)

## In 30 seconds

MacCoreGuard aims to be the shared minutes book of the MacGuard applications, where any change to what was written would be noticed {{ev:EV-EC-27}}. Today it is a prototype: the data formats and the hash mathematics (digital fingerprints of data) exist. No service is running and no application uses it yet {{ev:EV-EC-28}}.

## An everyday example

Think of a notebook where each page carries the "fingerprint" of the previous page (the hash chain). If someone tears out or alters a sheet, the following fingerprints stop matching. A summary of the whole notebook (the Merkle tree) also lets you prove one particular page was in it, without showing the whole notebook. The analogy describes the mathematics, not a notebook that is already working.

## Diagram

{{diagram:maccore-chain-merkle}}

## Step by step (design)

1. A producer (a closed set of MacGuard applications; it cannot declare itself) proposes a security event, for example "a USB device was blocked". Only MacCoreGuard decides to record it.
2. MacCore serializes it in a canonical form, so the hash is identical on any Mac.
3. MacCore, and only MacCore, assigns a gap-free sequence number and computes the chain link.
4. Periodically the Merkle tree root is computed and a checkpoint would be signed.
5. An independent verifier, not trusting the writer process, would check chain, proofs and signature.

**Not implemented**: the intake of step 1, the numbering of step 3, the signing of step 4 and step 5. **Implemented**: the closed producer list (step 1), the canonical form (2), the link computation (3) and the root and proofs (4) {{ev:EV-EC-28}}.

## Under the hood

**Hash chain.** Problem: detect that an intermediate record was altered or deleted. Input: the previous hash, the sequence number and the canonical event. Computation: a SHA-256 hash with domain separation, so a record hash can never be confused with another kind of hash. Output: a 32-byte hash per record. It detects changes to any earlier link; it does **not** stop someone who controls all storage from rewriting the whole chain from the start: signing and an external witness address that, and neither is implemented. Cost: constant per record. {{ev:EV-EC-27}}

**Merkle tree per [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162).** Problem: summarize thousands of records in one hash and prove things about it. Input: the record hashes. Output: a single root hash. The tree follows the public RFC 9162 construction, with domain separation between leaves and inner nodes; it is the same kind of tree used by Certificate Transparency.

- **Inclusion proof**: shows that a given record is in a tree of a given size with a short path of sibling hashes.
- **Consistency proof**: shows an old tree is a prefix of the new one (entries were only appended, nothing rewritten).

What it detects: a record that is not in the tree, or a tree that was rewritten instead of extended. What it does not prevent: anything outside the recorded data. Cost: recomputing the root is linear in the number of records per checkpoint, acceptable because it is not done per event. {{ev:EV-EC-27}}

**What is a placeholder.** Persistent recording, signing, ingestion and verification components remain unimplemented; no operational service exists {{ev:EV-EC-28}}. Digital signatures, hardware-backed or keychain keys, key rotation, atomic writes with crash recovery and a witness client appear only in the design contract or comments, with no code.

## Tests

An in-house test harness with known-answer vectors, including inclusion proofs for small trees, derived per the code from a separately written reference implementation. Internal documentation reports protocol and cryptography tests; **these were not run independently for this review**. No tests are possible for the placeholder parts {{ev:EV-EC-29}}.

## Check it yourself

The repository is private; nothing was run for this page. To validate the algorithm without the repository, read the Merkle tree section of [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162).

## Limits

- No service, no durable storage, no signing and no offline verifier.
- An unpublished prototype was reviewed; the state of other development lines has not been verified.
- MacFirewallGuard has a MacCoreGuard client tested only against a mock; MacUSBGuard does not import it {{ev:EV-EC-04}}. The shared design library has no dependency on it.

## State

The code and package use the shorter name **MacCore**. It is an **unpublished prototype**: the reviewed material is an initial implementation that its own documentation does not present as authoritative. Today the **data formats** and the **hash mathematics** exist; the on-disk ledger, signing, ingest and verifier are **placeholders** {{ev:EV-EC-28}} {{ev:EV-EC-06}}. It guarantees nothing to a user yet.

| Capability | State |
|---|---|
| Event format and identifiers | Implemented, not deployed |
| Hash chain and Merkle tree with proofs | Implemented with test vectors, not deployed |
| Durable ledger, signing, ingest, witness, verifier | Planned (placeholders) |

Work is planned in staged waves, each gated on building and passing its tests; no dates {{ev:EV-EC-06}}.

## Further reading

[MacUSBGuard](EN-App-USB) · [Global roadmap](EN-Roadmap) · [Evidence matrix](EN-Evidence)
