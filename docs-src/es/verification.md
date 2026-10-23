---
title: Verificación de reglas, firmas y transparencia
summary: Cómo comprobar tú mismo una release, sin confiar en este sitio: comandos, URLs reales y cómo interpretar los resultados.
---
## A. Qué vas a comprobar

Una release es válida si (1) el manifiesto y el checkpoint están firmados por la identidad del workflow esperado, (2) cada fichero del paquete coincide con el SHA-256 del manifiesto firmado, (3) la raíz Merkle recalculada coincide con `rules_root`, y (4) el checkpoint contiene la entrada de la release y extiende al anterior que ya conocías.

> **LÍMITE** Una firma y unos hashes correctos prueban **quién** publicó exactamente **esos bytes**. No prueban que las reglas sean buenas ni que los ficheros que se escanean sean seguros.

## B. Requisitos

- `cosign` ({{tool.cosign}} o posterior), instalado desde su origen oficial.
- Python 3 para el verificador y el recálculo Merkle; nada más que la biblioteca estándar.
- `shasum` (macOS) o `sha256sum` (Linux).

## C. Artefactos de la última release

Release [`{{release.tag}}`]({{release.url}}). Los artefactos obligatorios se descargan de esta ruta:

```
{{release.download}}/rules-release.tar.gz
{{release.download}}/manifest.json
{{release.download}}/manifest.sigstore.json
{{release.download}}/inclusion-proof.json
{{release.download}}/checkpoint.txt
{{release.download}}/checkpoint.sigstore.json
```

Opcionales: `release.json`, `changes.json`, `CHANGELOG.md` y `consistency.json` (esta última prueba que el registro extiende el de la release anterior). Para descargarlos todos:

```bash
mkdir verify && cd verify
gh release download {{release.tag}} --repo {{repo}}
```

## D. Verificar la firma con cosign

Ejemplo mínimo con la identidad y el emisor esperados:

```bash
cosign verify-blob manifest.json \
  --bundle manifest.sigstore.json \
  --certificate-identity "{{identity}}" \
  --certificate-oidc-issuer "{{issuer}}"
```

Versión completa, que además exige que el certificado nombre este repositorio, para el manifiesto y para el checkpoint:

```bash
cosign verify-blob manifest.json \
  --bundle manifest.sigstore.json \
  --certificate-identity "{{identity}}" \
  --certificate-oidc-issuer "{{issuer}}" \
  --certificate-github-workflow-repository "{{repo}}"

cosign verify-blob checkpoint.txt \
  --bundle checkpoint.sigstore.json \
  --certificate-identity "{{identity}}" \
  --certificate-oidc-issuer "{{issuer}}" \
  --certificate-github-workflow-repository "{{repo}}"
```

Resultado correcto: `Verified OK`. Si la identidad o el emisor no coinciden, cosign falla; no ejecutes nada de esa release.

## E. Verificar los hashes del paquete

SHA-256 del paquete (debe ser `{{release.package_sha256}}` para esta release) y del manifiesto (`{{release.manifest_sha256}}`):

```bash
# macOS
shasum -a 256 rules-release.tar.gz manifest.json
# Linux
sha256sum rules-release.tar.gz manifest.json
```

Los hashes del paquete **no** están firmados por separado; lo que lo ata a la firma es que cada fichero extraído tiene el SHA-256 de `manifest.json`. El verificador lo hace por ti (sección G).

## F. Recalcular `rules_root` e inclusión

El recálculo manual de `rules_root` está en [Árboles Merkle](page:merkle). La prueba de inclusión (`inclusion-proof.json`) la comprueba el verificador: lleva la entrada del registro de la release hasta la raíz del checkpoint y comprueba que esa entrada nombra el `rules_root` firmado.

## G. Verificador público

El script `verify_public_release.py` hace todo lo anterior de una vez (biblioteca estándar de Python y `cosign`). Descárgalo **a un fichero**, léelo y ejecútalo; no lo canalices a un intérprete.

```bash
curl -fsSLo verify_public_release.py https://raw.githubusercontent.com/{{repo}}/<COMMIT_SHA>/scripts/verify_public_release.py
less verify_public_release.py
python3 verify_public_release.py --latest
```

Para verificar sin fiarte de una rama móvil, sustituye `main` por un SHA de commit revisado (`<COMMIT_SHA>`): `main` no es una versión fija. Ninguna etiqueta de release contiene hoy el script; cuando alguna lo contenga, usa esa etiqueta.

Opciones: `--latest`, `--tag TAG`, `--directory DIR` (artefactos ya descargados), `--json`, `--previous-checkpoint FILE` o `--trust-state FILE` (protección contra retroceso), `--token` o la variable `GITHUB_TOKEN` (opcional). Funciona sin token: la API anónima de GitHub admite 60 peticiones por hora y dirección IP; si se agota (HTTP 403 con `X-RateLimit-Remaining: 0`) el verificador lo dice con la hora de reinicio y, sin usar la API, resuelve `latest` con la redirección de `github.com` y descarga los mismos artefactos (se comprueba `Content-Length`, no el tamaño de la API) y lo anota en el informe. Un 403 sin cuota agotada (cortafuegos, proxy) se informa como tal. Salida real, abreviada, sobre la última release:

```
MacGuard release verification — PASS (exit 0)

Release        {{release.tag}}  (latest)
Files          {{release.files}}   individual YARA rules: {{release.yara_rules}}
rules_root     {{release.rules_root}}

  [PASS] signature.manifest
  [PASS] signature.checkpoint
  [PASS] files.sha256
  [PASS] merkle.rules_root
  [PASS] merkle.inclusion
  [n/a ] consistency: no previous checkpoint was given
```

> **ACTUAL** Sin `--previous-checkpoint` ni `--trust-state` el verificador lo dice expresamente: es una primera verificación y **la protección contra retroceso no queda establecida** por esa ejecución.

### Códigos de salida

| Código | Significado |
|---|---|
| 0 | Todas las comprobaciones obligatorias hechas y superadas. |
| 1 | Integridad: un hash no coincide. |
| 2 | Firma o identidad inválidas. |
| 3 | Merkle, inclusión o consistencia. |
| 4 | Descarga incompleta o error de red. |
| 5 | Falta una dependencia (`cosign`). |
| 6 | Formato inválido o conjunto incompleto. |

Si hay varios fallos el informe los lista todos y el código de salida es el primero por esta precedencia: 5, 4, 6, 2, 1, 3.

{{diagram:verifier-flow}}

## H. Cómo saber que el verificador es el correcto

El verificador es código que ejecutas tú: léelo (unas 400 líneas) y compara el commit en GitHub. Descargarlo del mismo sitio que aloja las reglas no es una raíz de confianza independiente.

> **PROPUESTA** Firmar `verify_public_release.py` con Sigstore en `publish.yml` y adjuntarlo a cada release es una mejora **propuesta**: no existe todavía, así que las releases actuales no llevan una copia firmada del verificador.

## I. Qué hacer si falla

- No instales ni uses las reglas de esa release.
- Repite con `--output-dir DIR` y compara los artefactos con los de GitHub Releases (archivo canónico).
- Abre una incidencia en el repositorio con la salida `--json` completa; no contiene secretos.
