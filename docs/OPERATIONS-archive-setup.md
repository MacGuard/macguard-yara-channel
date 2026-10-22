# Archivo histórico en tres proveedores: configuración que solo puede hacer el propietario

Estado: **nada de esto está hecho**. Este documento es la lista exacta de pasos personales. Hasta completarlo, `.github/workflows/archive.yml` es inerte (termina con un aviso y no escribe nada) y no se puede podar nada de D1. Diseño y medición: `docs/audit/historical-archive-triple-spec.md`. Herramientas: `scripts/archivectl.py` (`--help` de cada orden).

Principios que no se negocian: ninguna clave en el repositorio, en chats ni en informes; las claves del archivo nunca borran; los datos privados se cifran antes de salir del proceso; la clave de descifrado no está en ningún runner; el borrado de D1 no existe como acción automática.

## 0. Hay que decidir antes (decisiones del spec §13 aún abiertas)

D2 región de cada bucket; D3 custodios (§3); D5 retención; D7 base legal de los logins archivados; D8 ventana de D1. Valores propuestos aquí; cámbialos antes de crear nada irreversible.

## 1. Nombres exactos

| Elemento | Valor |
|---|---|
| Variable de repositorio | `ARCHIVE_ENABLED` = `true` (solo cuando todo lo demás esté hecho y probado) |
| Entornos de GitHub (Settings → Environments) | `archive-r2-write`, `archive-r2-read`, `archive-b2-write`, `archive-b2-read`, `archive-scaleway-write`, `archive-scaleway-read` |
| Secretos **de cada entorno** (mismo nombre en los seis) | `ARCHIVE_ACCESS_KEY_ID`, `ARCHIVE_SECRET_ACCESS_KEY` |
| Variables **de cada entorno** | `ARCHIVE_BUCKET` (nombre del bucket de ese proveedor), `ARCHIVE_ENDPOINT` (URL S3), `ARCHIVE_S3_PROVIDER` (valor de `provider` de rclone), `ARCHIVE_REGION` |
| Buckets propuestos | R2 `macguard-archive-r2`; B2 `macguard-archive-b2`; Scaleway `macguard-archive-scw` |
| Reglas de los entornos `*-write` | revisores requeridos = el propietario; ramas permitidas = solo `main` |
| Reglas de los entornos `*-read` | ramas permitidas = solo `main` |

Los entornos solo se crean a mano: el workflow no los referencia mientras `ARCHIVE_ENABLED` no sea `true` (GitHub crearía en silencio un entorno inexistente y sin reglas). Crea primero los entornos con sus reglas y después pon `ARCHIVE_ENABLED`.

No hay ningún secreto de Cloudflare/D1 en el workflow (lo impide `tests/test_workflow_prereqs.py`): la lectura de la auditoría la hace el propietario en su máquina (§7).

Las claves de **escritura** deben poder: listar, comprobar existencia, leer y escribir objetos (el flujo lee de vuelta lo que sube). **No** deben poder borrar, cambiar retención ni administrar el bucket. Las claves de **lectura** solo leen y listan.

## 2. Un proveedor tras otro

Cada proveedor en **una cuenta distinta**, con correo propio, 2FA con llave física y facturación propia. La cuenta Cloudflare del archivo **debería no ser** la del Worker/D1 de producción (spec §4-a); usar la misma cuenta es una decisión del propietario que reduce la independencia de la copia R2 y debe quedar anotada.

**Bloqueo de objetos: qué protege y qué no (corregido 2026-10-22).** Governance no protege frente a identidades autorizadas para saltarse la retención; las reglas de bucket lock de R2 admiten cambios administrativos y **no** equivalen a un Compliance inmutable; solo Compliance (B2, Scaleway) impide a todos borrar o acortar, y **no se activa sin autorización expresa del propietario**. Hasta entonces la retención por defecto es Governance (B2, Scaleway) o una regla de prueba de 30 días (R2). **Ninguna protección contra borrado se da por verificada hasta ejecutar las pruebas negativas de §8** (borrado, sobrescritura, modificación de retención y bypass).

### 2.1 Cloudflare R2
1. Activar R2 en el panel (pide medio de pago: gasto, tu autorización). Preferible cuenta separada; si se usa la de producción, anótalo (ver arriba).
2. Crear el bucket `macguard-archive-r2`; jurisdicción `eu` si D2 lo decide así (no se puede cambiar después).
3. **Bucket lock** (Settings → Bucket lock rules), antes de crear ningún token: regla `macguard-test-30d`, prefijo vacío (todo el bucket), duración fija de 30 días. **No usar «indefinida»** hasta saber si esa regla puede retirarse. Un bucket con reglas no se puede vaciar ni borrar. Las reglas se pueden cambiar o quitar con un token de administración de la cuenta (panel, Wrangler o API): **no es Compliance**.
4. Credenciales S3 de **publicación y lectura** (Manage R2 API Tokens, limitadas al bucket `macguard-archive-r2`): `macguard-r2-write` con `Object Read & Write` y `macguard-r2-read` con `Object Read only`. R2 no ofrece «solo escribir»: el borrado lo impide la regla de bloqueo, no el token. Los tokens **administrativos** de la API (`Admin Read & Write`, que son de cuenta y pueden editar reglas de bloqueo) son otra cosa: **no se crean**, y no entran en GitHub.
5. Entornos: `ARCHIVE_ENDPOINT` = `https://<ID_DE_CUENTA>.r2.cloudflarestorage.com` (añade `.eu` tras `r2` si el bucket es de jurisdicción EU), `ARCHIVE_S3_PROVIDER` = `Cloudflare`, `ARCHIVE_REGION` = `auto`, `ARCHIVE_BUCKET` = `macguard-archive-r2`. Pega Access Key ID y Secret **directamente en el secreto del entorno**, nunca en un chat.

### 2.2 Backblaze B2
1. Crear la cuenta, 2FA con llave física, medio de pago.
2. Crear el bucket `macguard-archive-b2`, privado. **Object Lock se puede activar en un bucket existente** (API nativa, `fileLockEnabled`); una vez activado no se puede desactivar. Estado verificado 2026-10-21: `allPrivate`, SSE-B2, Object Lock activo, **sin retención por defecto**, sin reglas de ciclo de vida.
3. Retención por defecto del bucket en **Governance**: prueba 30 días. Pasar a Compliance (hasta 3 000 días, solo alargable, irreversible) requiere autorización expresa y las tres restauraciones verificadas.
4. Application keys limitadas al bucket (capacidades distintas, no intercambiables): `deleteFiles` borra versiones; `writeFileRetentions` cambia la retención de un objeto; `bypassGovernance` salta Governance.
   - `macguard-b2-write` (entorno `archive-b2-write`): `listBuckets, listFiles, readFiles, writeFiles`. **Sin** `deleteFiles`, `writeFileRetentions` ni `bypassGovernance` (la retención llega de la regla por defecto del bucket).
   - `macguard-b2-read` (entorno `archive-b2-read`): `listBuckets, listFiles, readFiles`.
   - `macguard-b2-admin`: `deleteFiles, writeFileRetentions, readFileRetentions, bypassGovernance`. **Solo en el llavero del propietario, nunca en GitHub, y no se crea hasta que el ensayo muestre qué combinación hace falta.**
5. Entornos: `ARCHIVE_ENDPOINT` = `https://s3.<región>.backblazeb2.com` (la que muestre el bucket), `ARCHIVE_S3_PROVIDER` = `Other`, `ARCHIVE_REGION` = `<región>`, `ARCHIVE_BUCKET` = `macguard-archive-b2`.

### 2.3 Scaleway
Cinco cosas distintas, en este orden:
1. **Proyecto** exclusivo `macguard-archive` (los permisos IAM se aplican al proyecto, no al bucket: con un único bucket dentro, el alcance del proyecto es el del bucket). La prueba gratuita de 750 GB (Standard Multi-AZ y One Zone) dura **90 días** y después se paga por uso; no es una franquicia permanente (§9).
2. **Bucket** `macguard-archive-scw` en `fr-par` (Standard Multi-AZ), privado, con versionado y Object Lock. Object Lock puede habilitarse al crear o después, exige versionado y **no se puede deshabilitar**. Retención por defecto en Governance (prueba 30 días); Compliance solo con autorización expresa.
3. **Aplicaciones IAM**: `macguard-scw-write` y `macguard-scw-read` (identidades, sin permisos propios).
4. **Políticas IAM** (unen aplicación, permisos y proyecto):
   - `macguard-scw-write-policy` → `ObjectStorageObjectsRead` + `ObjectStorageObjectsWrite`, en el proyecto. Nunca `ObjectStorageObjectsDelete` ni `ObjectStorageFullAccess`. **Aviso:** `ObjectsWrite` incluye `PutObjectRetention` y `PutObjectLegalHold`, así que la clave de escritura podría intentar cambiar retenciones; el ensayo (§8) debe probarlo y, si lo logra, se añade una política de bucket que lo deniegue.
   - `macguard-scw-read-policy` → `ObjectStorageReadOnly`.
   - `s3:BypassGovernanceRetention` no figura en la tabla de equivalencias IAM; el procedimiento de bypass **no está documentado en lo leído** y se determina con el ensayo. No se crea ninguna credencial administrativa.
5. **Claves de API**: una por aplicación (en «bearer» se elige la aplicación, no el usuario), proyecto preferido `macguard-archive`.
6. Entornos: `ARCHIVE_ENDPOINT` = `https://s3.fr-par.scw.cloud`, `ARCHIVE_S3_PROVIDER` = `Scaleway`, `ARCHIVE_REGION` = `fr-par`, `ARCHIVE_BUCKET` = `macguard-archive-scw`.

### 2.4 Rotación y caducidad
Claves de larga duración (ningún proveedor ofrece OIDC verificado, D4): rotar cada 90 días, con la anterior revocada al confirmar la nueva. Apunta la fecha de la próxima rotación en el calendario del propietario.

## 3. Ceremonia de custodia de la clave de descifrado

Objetivo: ninguna persona ni soporte único puede descifrar ni perder el archivo; el runner solo tiene claves **públicas**.

1. Máquina sin red (o sesión nueva sin red) con `age` y `ssss`. Genera dos identidades: `age-keygen -o archivo-A.key` y `age-keygen -o archivo-B.key`. Anota solo las líneas `Public key: age1…`: son los dos destinatarios.
2. `archivo-A.key` se divide en 3 partes con umbral 2: `ssss-split -t 2 -n 3 -w macguard-A` sobre el contenido de la línea `AGE-SECRET-KEY-1…`. Cada parte, en papel y sobre sellado, a **un custodio distinto e independiente** (tres personas que no comparten domicilio ni dispositivo; tú puedes ser una). Nadie recibe dos partes. Anota nombre del custodio y fecha, no la parte.
3. `archivo-B.key` se imprime en papel, sobre sellado, **en un lugar físico distinto** (caja de seguridad). Cualquiera de A (2 de 3) o B descifra.
4. Destruye los ficheros `.key` de la máquina (sistema de ficheros en memoria; reinicia). Comprueba que no quedan copias (Time Machine, iCloud, historial del shell).
5. Pon los dos destinatarios públicos, separados por espacio, en `ARCHIVE_AGE_RECIPIENTS` (variable de tu máquina de preparación, §7; el workflow no la usa).
6. **Prueba de recuperación antes del primer uso real y anual después** (el spec §6 exige ensayo con la clave real): con dos custodios presentes reconstruye A (`ssss-combine -t 2`), escribe el resultado a un fichero en un volumen RAM, ejecuta una restauración de ensayo de un mes de **datos sintéticos** (`archivectl.py rehearse …`, §5), confirma `"ok": true`, borra el fichero y registra fecha, custodios y resultado. Repite con B. Si falla, no se archiva datos reales.
7. Rotación (cada 24 meses o ante sospecha): nueva pareja; los meses nuevos se cifran a la nueva y a la vieja durante un año; los antiguos se recifran como objetos nuevos (los viejos quedan protegidos por el bloqueo).

Pérdida de las dos claves: el detalle cifrado es irrecuperable, pero los sellos siguen verificando la continuidad de la cadena (`archivectl.py restore … ` sin `--identity`).

## 4. Qué hace y qué no hace el workflow

`archive.yml` (`workflow_dispatch` con `prepared_url` y `prepared_sha256`; el cron mensual solo avisa): `gate` → `prepare` (descarga el paquete y exige el SHA-256 que tecleaste) → `publish` ×3 (clave de escritura, escritura única, lectura de vuelta) → `verify` ×3 (clave de lectura distinta: sellos, continuidad, digests y manifiesto de ese proveedor) → `sign` → `store-manifest` ×3. Si falta cualquier configuración, el trabajo termina limpio con `::notice::` y **no** se anuncia como archivado.

### Firma Sigstore del manifiesto de manifiestos (descrita, **no ejecutada**)
Trabajo `sign`: `permissions: id-token: write`; exige los tres informes `ok`, el mismo `ciphertext_sha256` en los tres y los tres manifiestos idénticos byte a byte; entonces `cosign sign-blob --yes --bundle archive-manifest-<AAAA-MM-DD>.sigstore.json archive-manifest-<AAAA-MM-DD>.json`. Cada proveedor guarda ambos en `manifests/`. Verificación por un tercero:

```
cosign verify-blob --bundle archive-manifest-<fecha>.sigstore.json \
  --certificate-identity https://github.com/MacGuard/macguard-yara-channel/.github/workflows/archive.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  archive-manifest-<fecha>.json
```
Nota: la identidad es la de `archive.yml`, **distinta** de la de `publish.yml`; hay que publicarla junto a la de los lanzamientos. Sucesión si cambia la cuenta o el repo: decisión D6.

## 5. Ensayo de restauración por proveedor (runbook)

Solo con la clave **de lectura** de ese proveedor, en un directorio nuevo y vacío que **no** sea `~/Downloads`. Credenciales en variables de entorno de la sesión, nunca en la línea de órdenes:

```
export RCLONE_CONFIG_ARCHIVE_TYPE=s3 RCLONE_CONFIG_ARCHIVE_PROVIDER=<ARCHIVE_S3_PROVIDER> RCLONE_CONFIG_ARCHIVE_ENDPOINT=<ARCHIVE_ENDPOINT> RCLONE_CONFIG_ARCHIVE_REGION=<ARCHIVE_REGION>
read -rs RCLONE_CONFIG_ARCHIVE_ACCESS_KEY_ID; read -rs RCLONE_CONFIG_ARCHIVE_SECRET_ACCESS_KEY; export RCLONE_CONFIG_ARCHIVE_ACCESS_KEY_ID RCLONE_CONFIG_ARCHIVE_SECRET_ACCESS_KEY ARCHIVE_BUCKET=<bucket>
```
1. Lanzamientos: `python3 scripts/archivectl.py restore --from-env <r2|b2|scaleway> --tag <tag> --out-dir <dir nuevo>` (descarga, comprueba cada digest y ejecuta `verify_public_release.py -I --directory`). Probar el último, el más antiguo y uno al azar. Añade `--previous-checkpoint` con un `checkpoint.txt` de confianza.
2. Sellos y continuidad sin clave: `… restore --from-env <p>` sin `--tag` ni `--identity`.
3. Completo con descifrado (máquina de la ceremonia, clave en RAM): `… restore --from-env <p> --identity <fichero> --recipient <age1…>` y `… rehearse --from-env <p> --period <AAAA-MM> --identity <fichero> --recipient <age1…>`.
4. Compara los tres proveedores: mismos `head`, `last_seq` y `ciphertext_sha256`; cualquier diferencia se investiga, no se reintenta hasta que pase.
5. Frecuencia: mensual lo ligero de los tres; trimestral hasta el primer sello; anual completo con descifrado real.

(`restore`, `rehearse` y `manifest` aceptan `--from-env <r2|b2|scaleway>` con las variables de arriba, o `--providers fichero.json --provider <nombre>` con un fichero sin secretos.)

## 6. Retención (inicial, revisable)

| Dato | Contiene datos personales | Retención propuesta | Mecanismo |
|---|---|---|---|
| Lanzamientos (paquete, manifiesto, sigstore, checkpoints, pruebas) | No | **20 años** (C9), revisable | Bloqueo del bucket; renovar antes de caducar |
| Sellos mensuales, manifiestos de manifiestos y sus firmas | No (solo hashes y recuentos) | **20 años** | Igual |
| Registros públicos (`logs/`) y registros técnicos | No (públicos) | 20 años | Igual |
| Segmentos de auditoría **cifrados** | **Sí** (logins de GitHub en `detail`) | Propuesta: **6 años**, luego borrado criptográfico (destruir las identidades y partes; el texto cifrado queda ilegible y los sellos siguen válidos). Base legal y plazo: D7, a confirmar con asesoría legal | Los objetos viven bajo el bloqueo largo del bucket (no se pueden borrar antes); lo que caduca es la **clave**, no el objeto |
| Claves de custodia | n/a | Mientras dure el plazo anterior | §3 |

Mientras no se resuelva D7: retención de prueba de 30 días en los buckets de prueba, con **datos sintéticos** (nunca `production`) y sin datos reales de auditoría.

## 7. Cada mes (después de completar todo lo anterior)

1. En tu máquina, con un token de D1 **de solo lectura** en tu entorno (no en GitHub): `python3 scripts/archivectl.py prepare-month --out-dir prepared --d1-database <nombre> --recipient <age1 A> --recipient <age1 B>` — sella solo meses completos y cifra; no escribe texto claro.
2. `python3 scripts/archivectl.py pack-prepared --dir prepared --out bundle.tar.gz` imprime el SHA-256.
3. Sube `bundle.tar.gz` (solo cifrado y sellos) a una URL https accesible sin credenciales durante unos minutos (por ejemplo, una URL firmada de un bucket operativo); la integridad la garantiza el SHA-256 que tecleas.
4. Actions → «Monthly archive» → Run workflow con `prepared_url` y `prepared_sha256`; aprueba los entornos `*-write`.
5. Resultado esperado: `publish` y `verify` verdes en los tres, `sign` y `store-manifest` verdes. Con 2 de 3, alerta y **no se hace nada más**.
6. Ancla: el recibo (`archivectl.py rehearse` + `receipt`) y `writeAnchor` existen como biblioteca y pruebas, pero **no hay todavía una vía administrativa que escriba el ancla en producción** ni aplicar `0004`; es la fase 3 (staging) y requiere tu aprobación. Hasta entonces no se poda nada, y la poda no existe como acción (solo `prune-check`, informe en seco).

## 8. Suposiciones de plataforma que exigen un bucket de prueba (verificar antes de confiar)

1. **R2**: que la regla de bloqueo del bucket impida sobrescribir y borrar objetos con un token `Object Read & Write`, y que `rclone copyto --immutable` más nuestra comprobación de existencia no deje una ventana de carrera aprovechable.
2. **R2**: que no exista modo compliance ni versionado (la documentación leída el 2026-10-21 no los menciona) y si una regla indefinida puede retirarse.
3. **B2**: que la retención por defecto en Governance se aplique a las subidas S3, y que una application key sin `deleteFiles` no pueda ocultar/«borrar» versiones.
4. **B2**: código de salida de `aws s3api head-object` para objeto inexistente (el adaptador asume 254) y soporte de `--if-none-match '*'` en `put-object`; si no existe, la escritura única depende de la comprobación previa y del bloqueo.
5. **Scaleway**: Object Lock en Governance en Standard Multi-AZ, y que una clave con `ObjectsWrite` no pueda acortar la retención (`PutObjectRetention`); qué conjuntos de permisos IAM permiten escribir sin borrar.
6. **rclone** (paquete de Ubuntu 24.04): que `RCLONE_CONFIG_ARCHIVE_*` basta para las tres, y `NO_CHECK_BUCKET` con claves sin permiso de crear buckets.
7. **Todos**: que listar con la clave de lectura funciona sobre el bucket completo y su coste/tiempo sigue siendo razonable con miles de objetos.
8. **D1**: que existe un permiso de token de solo lectura para D1 y que `wrangler d1 execute --json` pagina bien con 1 000 filas por consulta.
9. **GitHub**: que un entorno con revisores requeridos pausa cada trabajo de la matriz por separado, y que `max-filesize` de `curl` respeta el límite.

Ningún punto de esta lista se da por bueno hasta ejecutarlo contra un bucket de prueba autorizado por ti.

## 8.1 Pruebas negativas obligatorias (la protección contra borrado NO está verificada hasta pasarlas)

Con datos sintéticos, retención de prueba de 30 días y por proveedor. Estado inicial de todas: **PENDIENTE**.

| Prueba | Clave | Resultado esperado |
|---|---|---|
| Subida, lectura y comparación SHA-256 | write / read | coinciden |
| Borrado normal (de la versión) | write | rechazado |
| Sobrescritura de un objeto bloqueado | write | rechazada, el original intacto |
| Acortar o quitar la retención | write | rechazado (crítico en Scaleway con `ObjectsWrite`; en R2 con el token de escritura) |
| Borrado desde la lectura | read | rechazado |
| Bypass autorizado | administración (llavero, solo en el ensayo) | borra solo con la combinación documentada; se anota cuál |
| Recuperación y firma | read | `verify_public_release.py` sale 0 |

## 9. Precios (leídos el 2026-10-22; sin garantía de que permanezcan)

| | Almacenamiento | Salida | Operaciones | Gratis |
|---|---|---|---|---|
| R2 | 0,015 USD/GB-mes | gratis | A 4,50 / B 0,36 USD por millón | 10 GB-mes, 1 M A, 10 M B al mes |
| B2 | 6,95 USD/TB-mes | gratis hasta 3× lo almacenado; después 0,01 USD/GB | clases A, B y C gratis | 10 GB |
| Scaleway (Standard Multi-AZ, fr-par) | ≈ 0,01606 EUR/GB-mes | 75 GB/mes gratis; después 0,01 EUR/GB | incluidas | **Prueba de 750 GB durante 90 días** (anunciada en la consola; sus condiciones no constan en la página de tarifas). Después, tarifa normal |

Scaleway **no** tiene franquicia permanente de almacenamiento: los escenarios del spec (§2) ya lo calculan sin capa gratuita de almacenamiento. Con unos 0,8 GB tras un año, el coste de Scaleway tras la prueba es ≈ 0,01 EUR/mes y sigue siendo de céntimos a 5 años. Anota el día 90 para revisar la factura y comprobar que la cuenta y los datos siguen.

## 10. Matriz de aceptación (estado real a 2026-10-22; sin valores secretos)

Tres estados distintos: **CONFIGURADO** (existe, sin probar contra el proveedor), **COMPROBADO** (verificado por una llamada real de solo lectura o por un ensayo) y **PENDIENTE**. Ningún control de protección contra borrado está COMPROBADO: no se ha ejecutado ningún ensayo contra un proveedor real.

| Control | B2 | R2 | Scaleway |
|---|---|---|---|
| Bucket existe, privado | COMPROBADO (API del proveedor) | PENDIENTE (bucket en otra cuenta; no visible desde las herramientas del agente) | PENDIENTE (idem) |
| Región coherente con el endpoint | COMPROBADO (`eu-central-003`) | CONFIGURADO (`auto`) | CONFIGURADO (`fr-par`) |
| Cifrado en reposo | COMPROBADO (SSE-B2) | PENDIENTE | PENDIENTE |
| Versionado | COMPROBADO (B2 versiona siempre) | n/a (R2 no versiona) | PENDIENTE |
| Object Lock / bucket lock | COMPROBADO activo; **sin retención por defecto** (nada protegido aún) | PENDIENTE | PENDIENTE |
| Entornos `-write` / `-read` | CONFIGURADO | CONFIGURADO | CONFIGURADO |
| Rama permitida = solo `main` | COMPROBADO (política de ramas con `main`) | COMPROBADO | COMPROBADO |
| Aprobación obligatoria en `-write` | **FALTA** (0 revisores) | **FALTA** | **FALTA** |
| Secretos = exactamente `ARCHIVE_ACCESS_KEY_ID` y `ARCHIVE_SECRET_ACCESS_KEY` | COMPROBADO (solo nombres) | COMPROBADO | COMPROBADO |
| Variables `ARCHIVE_BUCKET/ENDPOINT/REGION` | COMPROBADO | CONFIGURADO | CONFIGURADO |
| `ARCHIVE_S3_PROVIDER` conforme a §2 | **INCORRECTO** (`b2`; debe ser `Other`) | **INCORRECTO** (`r2`; `Cloudflare`) | **INCORRECTO** (`scaleway`; `Scaleway`) |
| Mínimo privilegio de las claves | **FALLA**: `macguard-b2-write` tiene todas las capacidades (incluidas `deleteFiles`, `bypassGovernance`, `writeKeys`, `deleteKeys`) y no está limitada al bucket; `macguard-b2-read` es de lectura pero de toda la cuenta | PENDIENTE | PENDIENTE |
| Subida, lectura y SHA-256 | PENDIENTE | PENDIENTE | PENDIENTE |
| Borrado de versión rechazado | PENDIENTE | PENDIENTE | PENDIENTE |
| Sobrescritura: original intacto | PENDIENTE | PENDIENTE | PENDIENTE |
| Cambio de retención rechazado | PENDIENTE | PENDIENTE | PENDIENTE |
| Clave de lectura no escribe ni borra | PENDIENTE | PENDIENTE | PENDIENTE |
| Restauración independiente + firma | PENDIENTE | PENDIENTE | PENDIENTE |

**No se ejecutan los ensayos mientras la clave de escritura de B2 conserve `deleteFiles`/`bypassGovernance`, y mientras el bucket no tenga retención por defecto:** el resultado no probaría nada y la clave podría borrar. Orden: corregir claves → fijar retención por defecto Governance de prueba (30 días) → ensayo (`scripts/archive/selftest.py`) → restauración.

`ARCHIVE_ENABLED` sigue sin activar; no hay Compliance; no se ha tocado ninguna release ni D1.
