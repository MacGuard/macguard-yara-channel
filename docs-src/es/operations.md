---
title: Operación y pruebas
summary: Cómo se ejecuta el pipeline, qué variables lo controlan y cómo se prueba.
---
## Workflows

| Workflow | Cuándo | Para qué |
|---|---|---|
| `daily.yml` | 03:17 UTC y manual | Revisión del candidato, job de macOS y solicitud de publicación. |
| `publish.yml` | Solicitado por `daily.yml` | Firma y publica. |
| `site.yml` | Tras publicar y al cambiar la web o la documentación | Construye, verifica y despliega el sitio. |
| `chain-test.yml` | Manual y en cambios del pipeline | Cadena sintética de extremo a extremo con 27 comprobaciones. |
| `build-engine.yml` | Manual | Construye el motor YARA universal. |
| `app-tests.yml` | En cambios de la app | Pruebas de la app de macOS. |

## Control de la publicación

- La variable `AUTO_PUBLISH=true` selecciona el entorno `stable-signing-auto` (sin aprobador); sin ella se usa `stable-signing` con aprobador humano. Los controles técnicos, la identidad OIDC y la rama protegida son idénticos en ambos.
- `allow_large_change` en `daily.yml` permite una publicación que supera la guarda anti-anomalía, tras revisión humana.
- `QUARANTINE_URL` apunta al servicio privado cuando exista.

## Qué ejecuta la documentación

Un cambio solo de `docs-src/` o de los ficheros del generador reconstruye y despliega el sitio, pero **no** ejecuta la revisión de reglas ni crea una release. Si las pruebas de la documentación fallan, el sitio no se despliega.

## Pruebas

```bash
python3 -m unittest discover -s tests
python3 scripts/docs_check.py
```

- `tests/test_docs.py`: coherencia entre la documentación, el código y los manifiestos reales, paridad ES/EN y ausencia de datos privados.
- `scripts/docs_check.py`: renderiza las páginas y los diagramas en Chrome sin interfaz, en escritorio y móvil.
- `tests/test_verify_public_release.py`: 29 pruebas del verificador, incluida la manipulación de artefactos.
