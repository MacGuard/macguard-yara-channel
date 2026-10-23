# MacGuard Security Intelligence: multi-channel architecture

*Resumen: canales separados con versión, manifiesto y hashes propios, un catálogo global firmado que fija la combinación aprobada, y verificadores independientes. Hoy solo el canal YARA (heredado) es operativo; el canal IOC tiene el marco y las pruebas pero ninguna fuente real autorizada.*

## 1. Principles

1. **One channel per kind of intelligence**, never one giant file. Each channel is versioned independently.
2. **Originals are preserved** and third-party signatures are never replaced or claimed. Anything MacGuard derives is labelled `origin: derived`.
3. **Nothing is published without a recorded licence decision** for every source (`config/intel/sources.registry.json`). The code refuses to approve a channel whose sources are not cleared.
4. **Verification is independent**: a client needs only the catalog signature, the manifests and the artifacts. No server, no trust in the transport.
5. **Unknown is not safe, unsigned is not verified, skipped is not passed.**
6. **Compatibility first**: the legacy YARA channel is referenced by the catalog and left exactly as it is.

## 2. Components

```text
sources (registry: licence, access, trust)
   |  local files only; fetching is a separate, licence-gated step that does not exist yet
   v
channel build (ioc today)  ->  artifacts + build-report  ->  channel manifest (canonical JSON)
                                                                   |
                         legacy YARA release (manifest.json) ------+--> global catalog (canonical JSON)  --signed-->  catalog.json + bundle
                                                                   v
                                            verifier: hashes, Merkle roots, states, rollback, signature
```

| Part | Where | Status |
|---|---|---|
| Canonical JSON, digests | `intel/canonical.py` | implemented, tested |
| Artifacts Merkle root (same construction as the YARA channel, shared code) | `intel/merkle.py`, `scripts/tlog.py` | implemented |
| Source registry and clearance gate | `intel/registry.py`, `config/intel/sources.registry.json` | implemented; every source is `pending-legal` or `not-evaluated` |
| IOC normalisation, validation, dedupe, TTL | `intel/ioc.py` | implemented, tested with local files |
| Channel manifest | `intel/channel.py` (`macguard.channel-manifest/1`) | implemented |
| Global catalog | `intel/catalog.py` (`macguard.catalog/1`) | implemented |
| Verifier | `intel/verify.py`, `python3 -m intel catalog verify`, `mgctl intelligence catalog verify` | implemented; signature check needs `cosign` |
| Channel status table | `intel/status.py`, `mgctl intelligence channels` | implemented |
| Signing and publication workflow | none | **not done**: needs a workflow change and the owner's authorisation |
| Live source fetchers | none | **not done**: blocked by licences/access |

## 3. Documents

* **Channel manifest** `macguard.channel-manifest/1`: channel id/family/version/created_at; sources (with licence and redistribution status copied from the registry); artifacts `{path, sha256, bytes, media_type, origin, original_signature}`; `artifacts_root` (Merkle); compatibility (platforms, engines); approval `{state: draft|approved|revoked, publishable, blocking_reasons, approved_by}`; validation (gates and the slot for the signed test attestation, `null` today); revocation policy; `previous {version, manifest_sha256}`; stats.
* **Global catalog** `macguard.catalog/1`: catalog version; one entry per channel (id, family, version, state, manifest SHA-256 and size, artifacts root); the legacy YARA entry (release tag, manifest SHA-256, rules root, signature bundle hash); approved **combinations** (a set of exact channel versions approved together); revocations; `previous {version, catalog_sha256}`.
* **Hash rule:** the SHA-256 of a new manifest or catalog is the hash of its canonical JSON (sorted keys, no whitespace, UTF-8, integers and strings only). The legacy manifest is hashed as the raw file, as published.
* **Signing:** the catalog (and each manifest) is signed as a detached blob by the publishing workflow with keyless Sigstore (same identity model as the YARA channel). The verifier supports identity mode (production) and key mode (offline, tests).
* **Version rules:** versions only increase; a published version is never rewritten; rollback is expressed by a new catalog that pins an older, still-approved channel version, and clients keep a `--min-version` floor.
* **Revocation:** a catalog lists revoked `(channel, version)` pairs; a client refuses them and keeps its last approved version.

## 4. Channels

See `CHANNELS.md` (status of all eight families plus the legacy YARA channel). `mgctl intelligence channels` prints the same table from `intel/status.py`.

## 5. Not decided here

Who signs and approves (roles), where the catalog is hosted, the TSA for trusted timestamps (see `CLOUD-CONTRACTS.md`), and the licence decisions (see `LICENSE-MATRIX.md`).
