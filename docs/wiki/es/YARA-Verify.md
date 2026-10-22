# Verificar una release

[Inicio](ES-Home) · [Cuarentena](ES-YARA-Quarantine) · [Publicación](ES-YARA-Publishing) · [Transparencia](ES-YARA-Transparency) · [Verificar](ES-YARA-Verify)

## En 30 segundos

No tienes que fiarte de nosotros: puedes comprobar tú mismo una release en cuatro pasos. (1) Los hashes: los archivos son los que lista el manifiesto. (2) La firma: el manifiesto lo firmó el workflow `publish.yml` de este repositorio. (3) La raíz Merkle: la lista de archivos produce el `rules_root` firmado. (4) El registro: la publicación consta en el registro de transparencia y extiende el que ya conocías. Un script público lo hace todo de una vez. {{ev:EV-YC-53}}

## Un ejemplo cotidiano

Recibes un paquete por mensajería. Compruebas que el precinto no está roto (hashes), que el remitente es quien dice ser (firma e identidad), que el albarán cuadra con lo que hay dentro (raíz) y que el número de envío es posterior al último que recibiste (registro). Un paquete auténtico y sin abrir puede seguir conteniendo algo inadecuado: la verificación no juzga el contenido.

{{diagram:verifier-flow}}

## Paso a paso

Requisitos: `cosign` instalado desde su origen oficial, Python 3 (solo biblioteca estándar) y `shasum` o `sha256sum`.

1. Descarga el verificador **a un archivo**, léelo y ejecútalo; no lo canalices a un intérprete:

```bash
curl -fsSLo verify_public_release.py https://raw.githubusercontent.com/MacGuard/macguard-yara-channel/main/scripts/verify_public_release.py
less verify_public_release.py
python3 -I verify_public_release.py --latest --trust-state ~/.macguard-trust.json
```

2. Lee el informe. Cada línea es `[PASS]`, `[FAIL]` o `[n/a ]`. El código de salida resume el fallo (tabla en "Por dentro").
3. Para hacerlo a mano, descarga los artefactos y comprueba cada capa:

```bash
gh release download <TAG> --repo MacGuard/macguard-yara-channel
cosign verify-blob manifest.json --bundle manifest.sigstore.json \
  --certificate-identity "https://github.com/MacGuard/macguard-yara-channel/.github/workflows/publish.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-github-workflow-repository "MacGuard/macguard-yara-channel"
shasum -a 256 rules-release.tar.gz manifest.json
```

Lo mismo con `checkpoint.txt` y `checkpoint.sigstore.json`. Resultado correcto: `Verified OK`. Para recalcular `rules_root` a mano, usa el script de [merkle.md](https://github.com/MacGuard/macguard-yara-channel/blob/main/docs-src/en/merkle.md).

## Cómo funciona por dentro

El verificador resuelve la release **una vez** y descarga todo de ese tag. Comprueba, sin fiarse del texto de ninguna orden (solo códigos de retorno y datos): artefactos presentes, firma del manifiesto y del checkpoint, extracción segura del paquete (sin enlaces ni rutas fuera del directorio, con límites), SHA-256 de cada archivo, `rules_root`, recuentos, que el checkpoint coincide con el `log` del manifiesto, la prueba de inclusión y, si le das un checkpoint previo, la consistencia. Identidad y emisor por defecto: los de [Publicación](ES-YARA-Publishing). Código: `scripts/verify_public_release.py`. {{ev:EV-YC-53}}

Salida real, abreviada, de la última release el 2026-10-22 (prueba ejecutada para esta página):

```
MacGuard release verification — PASS (exit 0)
Release   rules-20261021-39541028283  (latest)
Files     1178   individual YARA rules: 10021
  [PASS] signature.manifest
  [PASS] signature.checkpoint
  [PASS] files.sha256: 1178 files match the signed manifest byte for byte
  [PASS] merkle.rules_root
  [PASS] merkle.inclusion: entry 177 of 180 is in the checkpoint ...
  [n/a ] consistency: no previous checkpoint was given ...
```

| Código | Significado |
|---|---|
| 0 | Todas las comprobaciones obligatorias hechas y superadas. |
| 1 | Integridad: un hash no coincide. |
| 2 | Firma o identidad inválida. |
| 3 | Merkle, inclusión o consistencia. |
| 4 | Descarga incompleta o error de red. |
| 5 | Falta una dependencia (`cosign`). |
| 6 | Formato inválido o conjunto incompleto. |

Si fallan varias, el informe las lista todas y el código es el primero según la precedencia 5, 4, 6, 2, 1, 3. {{ev:EV-YC-55}}

**Reconocer una versión nueva legítima (anti-retroceso).** Con `--trust-state FILE` (o `--previous-checkpoint FILE`) el verificador compara con el último checkpoint que verificaste: si el tamaño es menor, falla con `ROLLBACK`; si el tamaño es igual y la raíz distinta, con `FORK`; si es mayor, exige `consistency.json` y una prueba válida que parte exactamente de tu checkpoint. El archivo de estado se escribe solo tras una verificación completa. Probado: una primera ejecución con `--trust-state` dice "n/a"; la segunda sobre la misma release da `[PASS] consistency: same checkpoint as the trusted one (180 entries)`. Una identidad distinta falla con salida 2 (probado con una identidad falsa). {{ev:EV-YC-54}}

**Si la verificación falla** (el mismo criterio que sigue la aplicación): no se instala nada nuevo, las reglas ya instaladas siguen funcionando y se explica el motivo. No uses las reglas de esa release; repite con `--output-dir DIR` y compara con los artefactos de GitHub Releases; abre una incidencia con la salida `--json` (no contiene secretos). La aplicación guarda el estado de confianza en un archivo con permisos 0600 antes de activar las reglas. {{ev:EV-YC-56}}

## Cómo comprobarlo tú

Las órdenes de arriba son las del repositorio. Ejecutadas el 2026-10-22: `--latest` (PASS, salida 0), la verificación manual con `cosign verify-blob` (`Verified OK`) y `shasum`, el segundo paso con `--trust-state` y un intento con identidad falsa (FAIL, salida 2). Pruebas del verificador: `python3 -m unittest tests.test_verify_public_release` (pasaron). Sin token de GitHub la API anónima permite 60 peticiones por hora por IP; el verificador lo avisa y usa la redirección de `github.com`. Más: [verification.md](https://github.com/MacGuard/macguard-yara-channel/blob/main/docs-src/en/verification.md), [client-failures.md](https://github.com/MacGuard/macguard-yara-channel/blob/main/docs-src/en/client-failures.md).

{{diagram:client-update}}

## Límites

- Sin `--previous-checkpoint` ni `--trust-state`, una primera ejecución **no** establece protección contra retroceso. {{ev:EV-YC-54}}
- El verificador es código que ejecutas: léelo. Descargarlo del mismo sitio que las reglas no es una raíz de confianza independiente. Firmarlo con Sigstore y adjuntarlo a cada release es una propuesta, no existe todavía. {{ev:EV-YC-57}}
- Una firma válida y hashes correctos prueban quién publicó esos bytes, no que las reglas sean buenas ni que los archivos analizados sean seguros.
- No existe una prueba de rendimiento de extremo a extremo entre el canal y Installer Auditor. {{ev:EV-YC-10}}

## Estado

| Capacidad | Estado |
|---|---|
| Verificador público independiente con pruebas | operational {{ev:EV-YC-53}} |
| Protección anti-retroceso con estado local | operational {{ev:EV-YC-54}} |
| Verificador firmado y adjunto a cada release | no implementado (propuesta) {{ev:EV-YC-57}} |
