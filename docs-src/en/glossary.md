---
title: Glossary and changes
summary: Terms used in this documentation and the history of the documentation itself.
---
## Glossary

| Term | Meaning |
|---|---|
| YARA | Rule language and engine to identify patterns in files. |
| Fichero de reglas | A `.yar` or `.yara` that may hold several rules; it is the unit that is counted. |
| Candidato | Set of files prepared in a run, before deciding. |
| Release | Complete signed set published on GitHub. |
| Manifiesto | `manifest.json`: files with SHA-256, sources, `rules_root`, log head. |
| `rules_root` | Merkle root of the rule files. |
| Checkpoint | Origin, size and root of the log at a moment, signed. |
| Prueba de inclusión | Sibling hashes tying an entry to the root. |
| Prueba de consistencia | Shows that a smaller log is a prefix of a larger one. |
| Sigstore | Fulcio (certificates), Rekor (public log) and cosign (tool). |
| Cuarentena | State of a file that needs a human decision. |
| ACTUAL / PROPUESTA | Exists and tested / designed but not implemented. |

## Documentation changes

- 2026-10-18: first bilingual version, with 20 pages and 20 Mermaid diagrams, generated from `docs-src/` with `scripts/build_docs.py`.
