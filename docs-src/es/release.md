---
title: Publicación y releases
summary: Cómo se construye una release completa y qué ficheros contiene.
---
## Secuencia

{{diagram:release-sequence}}

1. `publish.yml` comprueba antes (`precheck`) que el candidato difiere de la última release; si es idéntico no pide aprobación ni publica.
2. Vuelve a verificar el conjunto final (clasificación y evidencia dinámica) antes de firmar.
3. Firma el checkpoint, sella y firma el manifiesto, escribe la prueba de inclusión, empaqueta y genera los metadatos.
4. Comprueba los artefactos exactos antes de que nada sea público, crea la release como **borrador**, adjunta todos los ficheros y solo entonces la hace pública.

## Ficheros de una release

| Fichero | Contenido | Obligatorio |
|---|---|---|
| `rules-release.tar.gz` | Las reglas (`rules/`) y `manifest.json`. | sí |
| `manifest.json` | Lista de ficheros con SHA-256, fuentes, `rules_root`, cabeza del registro, estadísticas y, en las releases posteriores a la auditoría final, `evidence` (ejecución de revisión, commit del workflow y medición dinámica de exactamente este conjunto). | sí |
| `manifest.sigstore.json` | Firma Sigstore del manifiesto. | sí |
| `inclusion-proof.json` | Prueba Merkle de inclusión de la entrada de la release. | sí |
| `checkpoint.txt` | Checkpoint del registro. | sí |
| `checkpoint.sigstore.json` | Firma Sigstore del checkpoint. | sí |
| `release.json` | Metadatos: cifras, fuentes, cambios, paquete. | no |
| `changes.json`, `CHANGELOG.md` | Ficheros añadidos, modificados y quitados respecto a la anterior. | no |
| `consistency.json` | Prueba de consistencia con el registro de la release anterior. | no (si hay anterior) |

Ejemplo real: `manifest.json` de la última release (resumido):

```json
{{manifest_example}}
```

Claves del manifiesto: {{manifest_keys}}.

## Reglas de publicación

- Cada release es el conjunto completo, no un parche. Una corrección es una release nueva; las etiquetas no se reutilizan.
- Sin cambio efectivo no hay release.
- Cambios solo de la web o de la documentación no crean releases de reglas.
- Las releases inmutables de GitHub no están activadas (ajuste de seguridad del repositorio que requiere la autorización de una persona); el flujo borrador → pública ya es el que ese ajuste exige.
