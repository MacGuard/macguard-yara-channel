---
title: Publishing and releases
summary: How a complete release is built and which files it contains.
---
## Sequence

{{diagram:release-sequence}}

1. `publish.yml` first checks (`precheck`) that the candidate differs from the latest release; if identical it asks for no approval and publishes nothing.
2. It re-verifies the final set (classification and dynamic evidence) before signing.
3. It signs the checkpoint, seals and signs the manifest, writes the inclusion proof, packages and generates the metadata.
4. It checks the exact artifacts before anything becomes public, creates the release as a **draft**, attaches every file and only then makes it public.

## Files in a release

| File | Content | Mandatory |
|---|---|---|
| `rules-release.tar.gz` | The rules (`rules/`) and `manifest.json`. | yes |
| `manifest.json` | List of files with SHA-256, sources, `rules_root`, log head, statistics and, in releases made after the final audit, `evidence` (review run, workflow commit and dynamic measurement of exactly this set). | yes |
| `manifest.sigstore.json` | Sigstore signature of the manifest. | yes |
| `inclusion-proof.json` | Merkle inclusion proof of the release entry. | yes |
| `checkpoint.txt` | Log checkpoint. | yes |
| `checkpoint.sigstore.json` | Sigstore signature of the checkpoint. | yes |
| `release.json` | Metadata: counts, sources, changes, package. | no |
| `changes.json`, `CHANGELOG.md` | Files added, modified and removed against the previous one. | no |
| `consistency.json` | Consistency proof with the previous release log. | no (if a previous release exists) |

Real example: the latest release `manifest.json` (abridged):

```json
{{manifest_example}}
```

Manifest keys: {{manifest_keys}}.

## Publication rules

- Every release is the complete set, not a patch. A correction is a new release; tags are never reused.
- No effective change, no release.
- Changes to the web or documentation only never create rule releases.
- GitHub immutable releases are not enabled (a repository security setting that needs a person's authorization); the draft → public flow is already the one that setting requires.
