---
title: Glosario y cambios
summary: Términos usados en esta documentación y historial de cambios de la propia documentación.
---
## Glosario

| Término | Significado |
|---|---|
| YARA | Lenguaje y motor de reglas para identificar patrones en ficheros. |
| Fichero de reglas | Un `.yar` o `.yara` que puede contener varias reglas; es la unidad que se cuenta. |
| Candidato | Conjunto de ficheros preparado en una ejecución, antes de decidir. |
| Release | Conjunto completo firmado y publicado en GitHub. |
| Manifiesto | `manifest.json`: ficheros con SHA-256, fuentes, `rules_root`, cabeza del registro. |
| `rules_root` | Raíz Merkle de los ficheros de reglas. |
| Checkpoint | Origen, tamaño y raíz del registro en un instante, firmado. |
| Prueba de inclusión | Hashes hermanos que ligan una entrada a la raíz. |
| Prueba de consistencia | Demuestra que un registro menor es prefijo de uno mayor. |
| Sigstore | Fulcio (certificados), Rekor (registro público) y cosign (herramienta). |
| Cuarentena | Estado de un fichero que requiere decisión humana. |
| ACTUAL / PROPUESTA | Existe y probado / diseñado pero no implementado. |

## Cambios de la documentación

- 2026-10-18: primera versión bilingüe, con 20 páginas y 20 diagramas Mermaid, generada desde `docs-src/` con `scripts/build_docs.py`.
