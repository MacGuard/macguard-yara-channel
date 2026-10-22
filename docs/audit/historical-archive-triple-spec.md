# Archivo histórico en tres proveedores: especificación de diseño y medición

Estado: **diseño y medición solamente**. No se ha creado ninguna cuenta, bucket, clave ni gasto, y no se ha escrito en ningún proveedor. Fecha de medición y de lectura de precios: 2026-10-21. Rama de trabajo: agente A5. Nada de lo descrito aquí está desplegado; todo lo marcado «propuesto» requiere la autorización del propietario (sección 12).

## 1. Medición (solo lectura)

Todas las cifras proceden de las órdenes indicadas; lo que es suposición se rotula así.

### 1.1 Lanzamientos publicados

Fuente: `gh release list --limit 300 --json tagName,publishedAt` y `gh release view <tag> --json assets`.

| Tag | Publicado (UTC) | Activos | Bytes |
|---|---|---|---|
| rules-20261018-39103534527 | 2026-10-18 06:18 | 4 | 2 269 719 |
| rules-20261018-39150886414 | 2026-10-18 17:44 | 10 | 2 273 883 |
| rules-20261021-39541028283 | 2026-10-21 03:57 | 10 | 2 283 988 |
| **Total** | | | **6 827 590 (6,83 MB)** |

- Solo hay **3 lanzamientos**. Media 2,276 MB por lanzamiento; `rules-release.tar.gz` ≈ 2,05-2,06 MB (90 %), `manifest.json` ≈ 194 KB, cada `*.sigstore.json` ≈ 11 KB, pruebas (`inclusion-proof.json`, `consistency.json`) < 1 KB cada una.
- El primer lanzamiento solo tenía 4 activos (sin `checkpoint.*`, `consistency.json`, `release.json`); el esquema de activos cambió entre ellos. El archivo debe aceptar conjuntos de activos variables por lanzamiento y registrar el inventario real en su manifiesto.
- Crecimiento observado por lanzamiento: +4 164 B y +10 105 B (≈ +0,2 % y +0,4 %). **Con 3 muestras no es una tendencia**; se usa solo como cota de partida.

### 1.2 Registros públicos (`logs/`)

Fuente: `git ls-tree -r -l HEAD logs` y `wc -l logs/log.jsonl`.

- 10 ficheros, **143 362 B** en total: `log.jsonl` 60 321 B (187 líneas), `LOG.md` 38 595 B, tres pares `checkpoints/NNNNNNNN.{txt,sigstore.json}` (≈ 11 KB cada `.sigstore.json`), más la copia de `checkpoint.*` vigente (idéntica a `checkpoints/00000180.*`, mismo blob).
- Primer evento del log: 2026-10-18 04:05 UTC; el proyecto tiene ≈ 3,9 días de historia → ≈ 36,8 KB/día de log bruto. **Ese ritmo está dominado por eventos de despliegue del sitio** (`site.github_pages_deployed` 42, `site.live_verified` 30, `site.cloudflare_*` 42 de 187 líneas; recuento con `grep -o '"event":...' | sort | uniq -c`) y es el arranque del proyecto, no un régimen estable.
- Los puntos de control firmados están en tamaños de árbol 20, 75 y 180 (`logs/checkpoints/`).

### 1.3 Cadencia realista de lanzamientos (estimación)

Base: `daily.yml` programa `cron: '17 3 * * *'` (`.github/workflows/daily.yml:6`) y la publicación solo ocurre si el conjunto cambia (`needs.review.outputs.changed == 'true'`, `.github/workflows/daily.yml:221`). Máximo 1 lanzamiento programado al día más disparos manuales (`workflow_dispatch`, `daily.yml:7`). Observado: 3 lanzamientos en 3 días (dos el 18-oct, uno el 21-oct; ninguno el 19 y el 20). El log tiene 12 `candidate.accepted` y 3 `release.published`.

Estimación (suposición explícita, a revisar con 90 días de datos): **bajo 52/año, esperado 120/año, alto 365/año**.

### 1.4 Auditoría privada (cadena en D1)

Fuente: copia local `.../scratchpad/backup2/d1-before.sql` (50 102 B, 103 líneas). Solo recuentos y bytes: tabla `audit` = **10 filas, 3 870 B de sentencias INSERT → ≈ 387 B/fila** (`awk` sobre líneas `INSERT INTO`, sin leer contenido). Es una copia de la fase de pruebas del 21-oct; sirve para tamaño por fila, **no** para ritmo de producción.

Suposición de ritmo anual: bajo 1 200 filas (10 filas en ≈ 3 días extrapolado), esperado 20 000, alto 100 000 (el historial de vistas se audita una vez por ventana de 600 s, `admin/worker/src/store.js` `viewedRecently`). A ≈ 400 B/fila: 0,5 / 8 / 40 MB al año. Es despreciable frente a los lanzamientos.

### 1.5 Volumen anual proyectado (para el coste)

Fórmula: `GB(año y) = [lanz/año × 2,28 MB × (1+g)^y + logs_MB + auditoría_MB] / 1000`, acumulado sin borrar nada (inmutable).

| Escenario | lanz/año | g (tamaño/año) | logs+pruebas MB/año | audit MB/año |
|---|---|---|---|---|
| Bajo | 52 | 0 % | 5 | 0,5 |
| Esperado | 120 | 5 % | 15 | 8 |
| Alto | 365 | 15 % | 50 | 40 |

Acumulado calculado con un script local (`cost.py` en el scratchpad): bajo 0,6 / 1,2 / 2,5 GB; esperado 1,6 / 3,7 / 9,5 GB; alto 6,1 / 17,8 / 87 GB a 5 / 10 / 20 años. Los `logs` se archivan por segmento incremental, no por copia completa en cada lanzamiento.

## 2. Costes (precios públicos leídos el 2026-10-21)

Fuentes: Cloudflare R2 `https://developers.cloudflare.com/r2/pricing/`; Backblaze B2 `https://www.backblaze.com/cloud-storage/pricing`; Scaleway `https://www.scaleway.com/en/pricing/storage/`.

| | Cloudflare R2 (Standard) | Backblaze B2 | Scaleway (Paris, Multi-AZ) |
|---|---|---|---|
| Almacenamiento | 0,015 USD/GB-mes (IA 0,01, mín. 30 d, 0,01/GB recuperación) | 6,95 USD/TB-mes | 0,000022 EUR/GB-hora ≈ 0,01606 EUR/GB-mes (One Zone ≈ 0,00803; Glacier ≈ 0,00254, restauración 0,009 EUR/GB) |
| Salida a Internet | gratis | gratis hasta 3× el almacenamiento medio mensual; después 0,01 USD/GB | 75 GB/mes gratis; después 0,01 EUR/GB |
| Operaciones | A 4,50 / B 0,36 USD por millón | Clases A, B y C gratis; D 0,004 USD/10 000 (2 500/día gratis) | incluidas |
| Duración mínima | ninguna (Standard) | ninguna | no indicada en la página |
| Capa gratuita | 10 GB-mes, 1 M op. A, 10 M op. B al mes (solo Standard) | primeros 10 GB gratis | solo los 75 GB de salida |
| Moneda | USD | USD | EUR |

Notas: la página de R2 no menciona locks (se leyó la página específica, sección 4); la de B2 devolvió la tarifa «desde» 6,95 USD/TB; la de Scaleway no indica duración mínima ni locks (ver 4). **Riesgo de precio**: los tres pueden cambiar sin aviso; las capas gratuitas son por cuenta y pueden desaparecer; Scaleway factura en EUR (se supone 1 EUR = 1,10 USD, **suposición propia, no leída de una fuente**). Impuestos no incluidos. Las operaciones del archivo (≈ 10-20 objetos por lanzamiento, pocos miles al año) quedan muy por debajo de las capas de operación; coste de operaciones ≈ 0 en R2 y B2.

### 2.1 Proyección acumulada (almacenamiento + operaciones, USD)

Fórmula: `Σ_años GB_acumulado × precio × 12`, restando 10 GB gratis en R2 y B2 y sin capa gratuita de almacenamiento en Scaleway (1,10 USD/EUR). Salida: restauración completa anual + verificación completa anual = `2 × GB` por año, en el mismo mes como peor caso.

| Escenario | Años | GB final | R2 | B2 | Scaleway | Total 3 |
|---|---|---|---|---|---|---|
| Bajo | 5 | 0,6 | 0 | 0 | 0,4 | **≈ 0,4** |
| Bajo | 10 | 1,2 | 0 | 0 | 1,4 | **≈ 1,4** |
| Bajo | 20 | 2,5 | 0 | 0 | 5,5 | **≈ 5,5** |
| Esperado | 5 | 1,6 | 0 | 0 | 1,0 | **≈ 1** |
| Esperado | 10 | 3,7 | 0 | 0 | 4,0 | **≈ 4** |
| Esperado | 20 | 9,5 | 0 | 0 | 18 | **≈ 18** |
| Alto | 5 | 6,1 | 0 | 0 | 3,5 | **≈ 3,5** |
| Alto | 10 | 17,8 | 2,6 | 1,2 | 16,7 | **≈ 20,5** |
| Alto | 20 | 87 | 71,5 | 33 | 119 | **≈ 224** |

- Sin capas gratuitas (peor caso) el esperado a 20 años sería ≈ 17 USD en R2 y ≈ 8 USD en B2 (GB medio ≈ 4,75 × tarifa × 12 × 20), es decir, del mismo orden.
- Egreso: en R2 y B2 la restauración + verificación anual (≤ 2 × 87 GB en el peor caso) es gratis (B2 por la regla 3×; R2 sin cargo). Scaleway: gratis hasta 75 GB/mes; solo en el escenario alto a 20 años se pagan ≈ 1,1 USD al año (`(2×87−75) GB × 0,01 EUR`).
- **Conclusión**: el coste es de céntimos a unas decenas de dólares en total en casi todos los escenarios. El coste dominante no es el almacenamiento sino el tiempo humano, la gestión de claves y el riesgo de cuenta. Un proveedor con dos copias independientes da la mayor parte de la protección a menos coste operativo; tres aportan resiliencia jurisdiccional y una tercera opinión para el desempate de integridad. Ambas opciones son baratas; la decisión es operativa (sección 12, D1).

## 3. Contenido del archivo

Por lanzamiento (clave `releases/<tag>/`): `rules-release.tar.gz`, `manifest.json`, `manifest.sigstore.json`, `checkpoint.txt`, `checkpoint.sigstore.json`, `inclusion-proof.json`, `consistency.json`, `release.json`, `changes.json`, `CHANGELOG.md` (lista real de activos medida en 1.1; los que no existan en un lanzamiento antiguo se omiten y se registran como ausentes).

Registros públicos: `logs/` completo en segmentos (`logs/segments/<desde>-<hasta>.tar` con `log.jsonl`, `LOG.md`, `checkpoints/*`), más el commit git de origen.

Auditoría privada: `audit/<YYYY-MM>/segment.jsonl.age` (cifrado, sección 6), `audit/<YYYY-MM>/seal.json` (sellado) y `seal.sigstore.json`.

Cada objeto se direcciona por SHA-256 (`objects/sha256/<aa>/<hash>`) y un índice `index/<fecha>.json` lo enlaza con su nombre lógico. Índices y objetos son inmutables; nada se sobrescribe.

## 4. Independencia y límites

Independencia propuesta: tres cuentas distintas (cuentas de correo y 2FA separadas; claves físicas distintas), tres entidades legales (Cloudflare Inc., Backblaze Inc., Scaleway SAS), jurisdicciones distintas en datos (EEUU, EEUU/UE según región elegida, Francia/UE), sin plano de control compartido, credenciales de escritura distintas, facturación distinta.

Límites reconocidos: (a) R2 y Cloudflare ya alojan el Worker y D1 de producción; la cuenta R2 del archivo debe ser **otra cuenta** de Cloudflare, no un bucket más de la cuenta operativa, o un compromiso de esa cuenta destruiría origen y copia; (b) las tres copias dependen de un único origen de escritura (GitHub Actions) y de un único propietario humano; (c) un mismo DNS, correo o dispositivo comprometido las alcanza todas; (d) Backblaze y Scaleway/Cloudflare usan clouds públicas con posible dependencia de terceros comunes; (e) «independiente» significa que ningún fallo, compromiso o decisión legal de un proveedor basta para perder o falsificar el historial, **no** que sea inmune a un atacante con control del origen de firma.

### Inmutabilidad por proveedor (estado leído el 2026-10-21)

| | Mecanismo | Fuente | Modo |
|---|---|---|---|
| R2 | Bucket locks: reglas de retención por prefijo (duración, fecha o indefinida); impiden sobrescribir y borrar, incluso por lifecycle; el bucket no se puede vaciar mientras existan reglas. **La regla se puede eliminar** con Wrangler, API o panel, y la página no menciona modo compliance ni versionado ni la API S3 Object Lock | `developers.cloudflare.com/r2/buckets/bucket-locks/` | Un atacante con permiso de administración de bucket puede quitar la regla: la protección depende de que la clave de escritura no tenga ese permiso |
| B2 | Object Lock gobernanza o cumplimiento, retención 1-3 000 días, legal hold; debe activarse en el bucket y luego no se puede desactivar; en cumplimiento nadie puede quitarlo | `backblaze.com/docs/cloud-storage-object-lock` | Compliance disponible |
| Scaleway | Object Lock (gobernanza/cumplimiento, legal hold) en Standard Multi-AZ, One Zone y Glacier; exige versionado; no se puede desactivar tras habilitarlo | `scaleway.com/en/docs/object-storage/how-to/use-object-lock/` (resultado de búsqueda; la página de API se truncó, **verificar en un bucket de prueba autorizado**) | Compliance disponible |

Consecuencias de diseño: retención compliance de 3 000 días (≈ 8,2 años) en B2 y de duración equivalente en Scaleway, renovada por extensión (solo se puede alargar); en R2, regla indefinida más política de que la clave de escritura no tenga permisos de administración y cuenta con 2FA hardware. La escritura **nunca** recibe permiso de borrado (`deleteFiles` en B2; sin `s3:DeleteObject*`/`s3:BypassGovernanceRetention` en Scaleway; token R2 solo `Object Write` sin `Admin`). Una retención compliance irreversible significa que un error de subida (por ejemplo un secreto) **no se puede retirar**: por eso la comprobación previa «sin secretos» (sección 7) es obligatoria antes de escribir.

## 5. Ruta de escritura

Flujo propuesto `archive.yml` (nuevo, no existe aún), disparado por `release: published` y por cron mensual del sellado:

1. Se ejecuta tras `publish.yml`; permisos por trabajo (`permissions: {}` por defecto, como en `publish.yml:8`), `id-token: write` solo donde haga falta.
2. Para cada proveedor, un trabajo propio con su `environment` de GitHub con revisión requerida y secretos propios; la subida usa `rclone`/`aws s3 cp` con **claves por proveedor de solo escritura**: R2 token API «Object Write» limitado al bucket, B2 application key con `writeFiles` y sin `deleteFiles`, Scaleway política IAM con `ObjectStorageObjectsWrite`/`PutObject` sobre un solo bucket.
3. OIDC: ninguno de los tres proveedores ofrece hoy federación OIDC de GitHub verificada por esta investigación; no se asume. Es una decisión abierta (D4). Mientras tanto, claves de larga duración rotadas cada 90 días, nunca impresas, inyectadas por variable de entorno en línea.
4. Antes de escribir: validar que el objeto no contenga nombres de reglas privadas ni secretos (reutilizar la comprobación del candidato público; `scripts/make_public_candidate.py`, `scripts/verify_public_release.py`), y calcular SHA-256.
5. Después de escribir en cada proveedor: lectura de vuelta con una clave **de solo lectura distinta** y comparación de SHA-256. Un trabajo final «verifica-triple» exige 3/3 antes de marcar la ventana como archivada; con 2/3 se emite alerta, sin podar nada.
6. Reintento acotado, `timeout-minutes` en cada trabajo, sin esperas indefinidas.

## 6. Integridad

- Cada objeto: SHA-256 en su clave y en el manifiesto de archivo.
- **Manifiesto de manifiestos** `archive-manifest-<AAAA-MM-DD>.json`: lista ordenada `{ruta lógica, sha256, bytes, proveedor-de-origen}` + hash del manifiesto anterior (cadena) + raíz Merkle de la lista. Se firma con Sigstore keyless con la misma identidad de workflow que los lanzamientos (`cosign sign-blob --bundle`, como en `.github/workflows/publish.yml:102,109`) y se guarda su `.sigstore.json` en los tres proveedores.
- Consistencia con el registro de transparencia del proyecto: cada manifiesto de archivo incluye el último `checkpoint.txt` (tamaño de árbol + raíz) y su `checkpoint.sigstore.json`. El verificador comprueba con `verify_consistency` (`scripts/tlog.py:70`; versión standalone en `scripts/verify_public_release.py:73`) que cada checkpoint archivado extiende al anterior (prueba `consistency.json`) y con `verify_inclusion` (`tlog.py:45`) cada candidato aceptado.
- Anclaje externo de la raíz del archivo: publicar el hash del último manifiesto de archivo en `logs/` del repo (una línea en el log público) para que el historial git y la copia se anclen entre sí.

### Cifrado de la auditoría privada

- Cifrado de sobre en cliente (age: `age -r <recipient>`; o AES-256-GCM con DEK aleatoria por segmento envuelta con clave pública) antes de salir del runner; el proveedor nunca ve texto en claro ni claves.
- **Destinatarios**: (1) clave de archivo pública, cuya privada reside offline (token FIDO2/YubiKey + copia en papel en custodia física) bajo control del propietario; (2) una segunda clave de custodia independiente (persona de confianza o notario/depósito) como *escrow* en un reparto 2-de-3 (Shamir) para que la pérdida de un solo soporte no destruya la auditoría. Decisión del propietario (D3).
- Quién descifra: solo quien reúna el umbral; el workflow solo tiene la clave pública (puede cifrar, no descifrar). Un compromiso de GitHub no expone el pasado.
- **Pérdida de clave**: sin ninguna copia, los segmentos cifrados son irrecuperables, **pero** la cadena sigue verificable a nivel de sellos (cada sello firma `head` y rango, ver 7) porque el sello no contiene datos en claro: se pierde la consulta del detalle, no la prueba de continuidad. Mitigación: ensayo de recuperación anual con la clave real.
- **Rotación**: nueva clave cada 24 meses o ante sospecha; los segmentos nuevos se cifran con ambos destinatarios (vieja y nueva) durante un año; los antiguos se recifran de forma explícita mediante un nuevo objeto (no se sobrescribe; la versión anterior queda protegida por el lock). La clave de firma Sigstore no se gestiona: es efímera/keyless.
- El detalle de auditoría puede contener identidades de usuario (logins GitHub): es dato personal. Retención y base legal (RGPD) del archivo cifrado a revisar por el propietario (D7).

## 7. Auditoría: sellado mensual sin romper la cadena

### 7.1 Estado actual (verificado en el código)

- `admin/worker/schema.sql:50-61`: `audit(seq AUTOINCREMENT, at, actor, role, action, target, detail, prev_hash, hash)`; índice único `audit_prev(prev_hash)` fuerza una cadena lineal (`schema.sql:63`); disparadores `audit_no_update`/`audit_no_delete` abortan cualquier cambio (`schema.sql:72-73`).
- `admin/worker/src/core.js:219-231`: `GENESIS = '0'×64`; `chainHash(prev, entry) = SHA-256(prev + canonical(entry))`; `verifyChain(rows)` **parte siempre de `GENESIS`** y exige `r.prev_hash === prev`.
- `admin/worker/src/store.js:8-20`: `appendAudit` lee `SELECT hash FROM audit ORDER BY seq DESC LIMIT 1` y, **si no hay filas, usa `GENESIS`**.
- `admin/worker/src/index.js:138`: `/api/audit/verify` carga `auditRows(db, 100001)` desde `seq` ascendente y verifica desde `GENESIS`; con más de 100 000 filas **se niega a verificar**.

Dos consecuencias para la poda (hallazgos que el diseño debe resolver, no estaban previstos): (1) si se borran todas las filas, `appendAudit` reiniciaría la cadena en `GENESIS` y rompería la continuidad; (2) si se borran las primeras, `/api/audit/verify` falla por el enlace con `GENESIS`.

### 7.2 Segmentos y sello

- **Segmento** = filas con `seq` en `[a,b]` de un mes natural UTC (por `at`), exportadas como JSONL canónico (`canonical()` de `core.js:213`), con **todas** las columnas incluidos `prev_hash` y `hash`. El primer `prev_hash` del segmento N es el `hash` de la última fila del segmento N-1: **el enlace se transporta dentro de los datos**.
- **Sello mensual** `seal.json` (JSON canónico):
  `{schema, month, first_seq, last_seq, rows, first_prev_hash, head_hash, segment_sha256 (del texto en claro), ciphertext_sha256, prev_seal_sha256, d1_database_id_hash?}`.
  `first_prev_hash` del sello N = `head_hash` del sello N-1 (GENESIS en el primero). `prev_seal_sha256` encadena sellos entre sí. Firmado con Sigstore keyless (identidad del workflow de archivo) y guardado en los tres proveedores. El sello no contiene detalle de auditoría, solo hashes y recuentos, así que puede ser público (propuesto: copia del `head_hash` en `logs/`).
- Mes en curso: se sella solo cuando termina; para el mes actual se publica además un **sello provisional diario** del `head_hash` (misma forma) para acotar el riesgo entre sellos.

### 7.3 Cómo verifica un tercero la continuidad solo con los segmentos

Entradas: los sellos `seal-*.json` + sus `.sigstore.json` y los segmentos descifrados. Pasos:
1. Verificar cada firma Sigstore y la identidad del workflow.
2. Para cada sello: `ciphertext_sha256` coincide con el objeto; descifrar; `segment_sha256` coincide.
3. Verificar el segmento con una variante de `verifyChain` que acepta un `startHash` (`verifyChain(rows, startHash = GENESIS)`): `rows[0].prev_hash === seal.first_prev_hash`, cada fila recalcula `chainHash`, `seq` consecutivos, y la última fila da `head_hash` del sello, recuento = `rows`.
4. Encadenar: `seal[N].first_prev_hash === seal[N-1].head_hash`, `seal[N].first_seq === seal[N-1].last_seq + 1` y `prev_seal_sha256`.
5. Opcional: el `head_hash` actual de D1 (consulta `SELECT hash FROM audit ORDER BY seq DESC LIMIT 1`) es descendiente del último sello.
Un hueco, solapamiento, reordenación o alteración rompe el paso 3 o 4. Sin D1 y sin la privada de cifrado se sigue pudiendo comprobar sellos y encadenado (pasos 1 y 4); con la privada, el contenido (2-3).

### 7.4 Qué queda en D1 y qué se poda

- **12 meses consultables en D1** (ventana móvil: mes en curso + 12 meses sellados completos). `GET /api/audit` y `/api/audit/verify` siguen funcionando sobre esa ventana.
- **Fuera de la ventana**: solo se poda un segmento cuando se cumplen **todas** las condiciones: (a) sello firmado; (b) objeto cifrado + sello + firma presentes y con SHA-256 verificado por lectura de vuelta en **R2, B2 y Scaleway** (3/3); (c) restauración de prueba del segmento desde al menos un proveedor distinto del que se usó para escribir ha pasado; (d) el sello siguiente ya existe; (e) aprobación humana registrada en una fila de auditoría `audit.prune_approved`. Nunca se poda la última fila ni el mes en curso.
- Mecanismo: migración nueva (propuesta, no existe): tabla `audit_anchor(seq, hash, sealed_month, seal_sha256)` con una fila por segmento podado, y `appendAudit` leyendo `audit` o, si está vacía, `audit_anchor` (nunca `GENESIS` salvo en una BD recién creada); `verifyChain(rows, startHash)` y `/api/audit/verify` pasan a verificar desde el ancla más reciente. El `DELETE` requiere retirar el disparador `audit_no_delete`: se hará con una migración controlada y puntual que lo recrea al terminar y deja una fila `audit.pruned` que registra rango, hash de sello y quién lo aprobó. La poda corre con una credencial D1 de migración que no es la del Worker.
- **Por qué podar no debilita la cadena**: el eslabón de continuidad (el `hash` de la última fila podada) sigue presente como `prev_hash` de la primera fila retenida y copiado en `audit_anchor`; el contenido podado existe en tres copias inmutables con sello firmado; cada fila retenida sigue ligada criptográficamente a la anterior, que ya no está en D1 pero sí en el archivo, así que alterar o falsificar el pasado exige reproducir un hash SHA-256 enlazado y un sello Sigstore firmado, no solo editar D1. El borrado no añade capacidad al atacante: quien puede borrar de D1 ya podía alterar D1; la protección real es el sello externo y las copias, que no cambian al podar. Lo que sí se pierde, y se acepta, es la consultabilidad rápida desde D1 más allá de 12 meses (se consulta restaurando segmentos).
- Tamaño en D1 a 12 meses: 0,5-40 MB (1.4), muy lejos de cualquier límite de D1.

## 8. Pruebas de restauración independientes

Script `scripts/archive_restore_drill.py` (propuesto, **no existe**), argumento `--provider {r2,b2,scaleway}` con credencial **de solo lectura de ese proveedor**; no admite el resto:

1. Listar `index/` del proveedor X; descargar el último `archive-manifest` y su `.sigstore.json`; verificar con `cosign verify-blob --certificate-identity … --certificate-oidc-issuer …` (identidad de `publish.yml`).
2. Para N lanzamientos (último, más antiguo y uno aleatorio): descargar a un directorio nuevo y vacío con `--output-dir`; ejecutar `python3 -I scripts/verify_public_release.py --directory <dir>` (parámetro `--directory` en `verify_public_release.py:622`) más `--previous-checkpoint` para la consistencia. Verificar SHA-256 de cada objeto frente al manifiesto de archivo.
3. Descargar los segmentos de auditoría; descifrar con la clave de **prueba de restauración** (custodia offline, conectada solo durante el ensayo); ejecutar `verifyChain(rows, firstPrev)` segmento a segmento y el encadenado de sellos (7.3).
4. Comparar los hashes de cabecera de los tres proveedores y emitir informe JSON.
Criterio de éxito: todos los SHA-256 coinciden, firmas válidas, `verify_public_release.py` sale 0, cadena de sellos continua, sin diferencia entre proveedores. Un fallo se investiga; no se reintenta hasta que pase. **Nunca** descargar a `~/Downloads`. Frecuencia: mensual la restauración ligera de los tres (último lanzamiento + último sello, ≈ 2,3 MB + segmento), trimestral la verificación hasta el primer sello y anual la restauración completa con descifrado real. Coste: ligero ≈ 0 (egreso gratis o dentro de capa); completo anual ≈ `GB × 0,01 USD` solo si se excede la capa gratis, en los datos medidos 0 hasta ≈ 37 GB totales en Scaleway y 0 en R2/B2.

## 9. Fallos y ataques

| Escenario | Efecto | Defensa / recuperación |
|---|---|---|
| Caída de un proveedor | La escritura 3/3 falla; no se poda | Reintento; los otros dos mantienen copia; alerta tras 24 h |
| Compromiso de un proveedor o de su cuenta | Podría borrar o alterar sus copias | Retención (compliance en B2/Scaleway), claves sin borrado, 2FA; los otros dos y el sello Sigstore delatan la divergencia por hash |
| Corrupción silenciosa | Un objeto cambia de bytes | SHA-256 por objeto; scrub trimestral compara los tres |
| Ransomware que borra objetos | Pérdida de objetos | Writer sin borrado; locks; copias en otros proveedores |
| Pérdida de clave de descifrado | Detalle no consultable | Escrow 2-de-3; sellos siguen verificables; ensayo anual |
| Pérdida de la cuenta de GitHub | Se pierde origen de escritura y de la identidad Sigstore | El archivo conserva manifiestos firmados ya emitidos y se verifican offline; la identidad de workflow cambia y habría que anclar la nueva con firma de sucesión del propietario (decisión D6) |
| Compromiso de GitHub Actions / del workflow | Sube datos falsos con firma válida | Entornos con aprobación humana, rama protegida, anclaje del hash en `logs/` y comparación con el historial git independiente |
| Error humano: secreto subido | No retirable con compliance | Comprobación previa; reglas de revisión; ventana corta de retención al principio (30 días) hasta pasar la fase 2 |

> **Nota (2026-10-22): superada en parte.** La mitigación «entornos con aprobación humana» de la fila de compromiso de GitHub Actions está ausente mientras `AUTO_PUBLISH=true` (entorno `stable-signing-auto`, sin revisor obligatorio); siguen vigentes la rama protegida y la identidad OIDC.

## 10. Monitorización

- Verificación diaria ligera: último objeto de cada proveedor existe y coincide con el manifiesto (lectura con clave de solo lectura).
- Alertas: 3/3 no alcanzado en 24 h, divergencia de hash, sello no emitido el día 1-2 del mes, drill fallido, caducidad de claves (<30 días), expiración próxima de retención lock (<180 días).
- Canal: notificaciones (correo/GitLab) probadas antes de activar nada; límites de frecuencia revisados. No activar alertas sin canal verificado.
- Los eventos del archivo van al log público solo como agregados (`archive.sealed`, `archive.verified`), sin contenido de auditoría.

## 11. Fases con go/no-go

| Fase | Contenido | Puerta (go si…) |
|---|---|---|
| 0 | Esta especificación revisada; autorizaciones D1-D8 | El propietario aprueba por escrito |
| 1 | Una cuenta/bucket de prueba por proveedor, retención corta (30 d), subida de un lanzamiento y logs, restauración | Verificación 3/3 y drill por proveedor en verde; confirmación de Object Lock en Scaleway y de las capacidades de claves |
| 2 | Cifrado y escrow de la auditoría; sellado de un mes simulado con datos sintéticos (nunca `production`) | `verifyChain(startHash)` pasa; prueba que falla si se quita/altera/reordena una fila |
| 3 | Migración `audit_anchor` y `verify` por ancla en staging (`admin/worker/STAGING.md`) | Pruebas del Worker y E2E reales en verde; rollback anotado |
| 4 | Archivo en producción solo en modo «añadir», sin poda | 3 meses de 3/3 y drills mensuales verdes |
| 5 | Retención larga (compliance) y primera poda aprobada | 12 meses de sellos o al menos 1 sello + drill desde cada proveedor; aprobación humana |

## 12. Operaciones que requieren autorización del propietario

1. Crear cuentas nuevas en Cloudflare (distinta de la operativa), Backblaze y Scaleway, con medio de pago y 2FA (gasto).
2. Crear un bucket por proveedor, con Object Lock/versionado habilitado (irreversible en B2 y Scaleway) y región/jurisdicción.
3. Emitir claves/tokens: escritura (solo subida), lectura (restauración y verificación), y las claves de cifrado/escrow; cualquier secreto de GitHub Actions (`environment` secrets).
4. Modificar `.github/workflows` (nuevo `archive.yml`) y permisos de repositorio/entornos.
5. Migración D1 `audit_anchor` y cambios en `core.js`/`store.js`/`index.js` (política crítica: aprobación humana); recrear/retirar el disparador de borrado en la poda.
6. Ejecutar la primera poda en producción y cada poda posterior.
7. Fijar retención compliance (irreversible) y cualquier cambio de política.
8. Cualquier restauración con la clave real de descifrado.

## 13. Decisiones abiertas

- D1: ¿Tres proveedores o dos (menos coste operativo y de claves; ver 2.1)?
- D2: Región/jurisdicción de cada bucket (UE/EEUU) y cuenta Cloudflare separada.
- D3: Modelo de escrow (Shamir 2-de-3, custodios) y quién guarda las partes.
- D4: OIDC frente a claves de larga duración (no verificado que alguno de los tres soporte federación con GitHub).
- D5: Periodo de retención de lock (30 d de prueba, luego 3 000 d en B2/Scaleway, indefinida en R2) y política de renovación.
- D6: Sucesión de identidad Sigstore si se pierde la cuenta de GitHub o cambia el repositorio.
- D7: Base legal y retención RGPD de los logins de GitHub en el detalle de auditoría archivado.
- D8: Ventana de D1 (12 meses propuestos), umbral de aprobación para podar y cadencia de drills.
- D9: Tipo de cambio y tolerancia a variaciones de precio; capas gratuitas no garantizadas.
- D10: Cadencia real de lanzamientos (la estimación se basa en 3 muestras; revisar a 90 días).

## 14. Estado de implementación

### Fase 1 (rama `feat/archive-p1`): implementada y probada en local; NADA desplegado, NINGUNA credencial, cuenta, bucket ni gasto

Qué existe (todo aditivo; no cambia lo que publica el pipeline ni ejecuta la migración):

| Pieza | Fichero | Estado |
|---|---|---|
| Migración `audit_anchor` (+ disparadores de solo-añadir y de coincidencia con `audit`) y su rollback | `admin/worker/migrations/0004_audit_anchor.sql`, `0004_rollback.sql`; reflejada entre marcadores `BEGIN/END audit_anchor (0004)` en `schema.sql` (una prueba exige que ambas copias sean idénticas) | SQL exacto, **no ejecutado** |
| `verifyChain(rows, startHash = GENESIS)` | `admin/worker/src/core.js` | Compatible hacia atrás; las pruebas anteriores no cambian |
| Cabeza de la cadena `chainHead(db)`: última fila de `audit`; si la tabla está vacía, la última ancla; GENESIS solo si nunca hubo ninguna | `admin/worker/src/anchor.js`; `store.js` la usa en `appendAudit` y en los tres escritores que insertan en `audit` dentro de un `batch` | Hecho (corrige el hallazgo 7.1-(1)) |
| `writeAnchor` (única vía de escritura de anclas): exige sello válido, recibo con las **tres** copias leídas de vuelta (r2, b2, scaleway), mismo cifrado en las tres, restauración ensayada de ese sello, continuidad con la ancla anterior, autor; el `INSERT` lleva la condición de continuidad (un solo escritor gana) | `anchor.js` | Hecho |
| `/api/audit/verify` verifica desde la ancla, por páginas (1 000 filas, memoria acotada) y sin tope de 100 000; si se detiene antes dice `complete:false` y devuelve un punto de reanudación (`?after=&head=`) | `anchor.js`, ruta en `index.js` | Hecho (corrige 7.1-(2)) |
| Herramientas Python: segmentos mensuales, sellos, verificación solo con segmentos, proveedores (LocalDirectory y adaptador S3 por CLI `rclone`/`aws`), envoltorio de `age`, nombres de escritura única por SHA-256, subida con lectura de vuelta, restauración y verificación (`restore`), manifiesto de manifiestos con raíz Merkle (RFC 6962), informe de poda **en seco** | `scripts/archive/*.py`, entrada `scripts/archivectl.py` | Hecho |
| Poda de filas de D1 | no existe como acción ejecutable | Solo `prune-check` (informe; `executed` siempre `false`) |

Desviaciones deliberadas respecto a las secciones 6-7:
- El sello **no** incluye `ciphertext_sha256` (la salida de `age` no es determinista; el sello debe serlo para ser idempotente). El digest del cifrado vive en el índice de archivo y en el recibo. El sello añade `last_seq` y `prev_seal_sha256` (nulo en el primero).
- Se exige `seq` estrictamente creciente, no contiguo: un hueco de `seq` que no rompa el enlace de hashes no se trata como ataque (el borrado de una fila ya rompe la cadena de hashes).
- El digest del sello es SHA-256 de `canonical(sello) + "\n"`; Python y JS calculan lo mismo (prueba cruzada que ejecuta `node`).
- Objetos direccionados por contenido (`objects/sha256/aa/<hash>`) más un índice inmutable por unidad (`index/{releases,audit,logs}/<nombre>.json`).

Pruebas (rápidas, sin red): `cd admin/worker && node --test test/anchor.test.js` y `npm test`; `python3.12 -m unittest tests.test_archive_segments tests.test_archive_providers tests.test_archive_store`. La prueba del binario `age` real solo se ejecuta con `ARCHIVE_REAL_AGE=1` y **falla** (no se omite) si faltan `age`/`age-keygen`; sin la variable consta como `NOT RUN`.

Rollback: Worker (`wrangler rollback`) y después `migrations/0004_rollback.sql`, que borra solo `audit_anchor` y sus disparadores. **No ejecutarlo tras una poda** (las anclas serían lo único que permite verificar la cadena); en ese caso restaurar antes los segmentos. Mientras no haya poda, revertir es inocuo: el Worker anterior ignora la tabla.

Pendiente para pasar a producción (todo requiere al propietario, sección 12): aplicar 0004, crear cuentas/buckets/claves, ensayo con bucket de prueba de los supuestos de plataforma (fase 2, `docs/OPERATIONS-archive-setup.md`), y primera poda.

Endurecimiento de restauración (revisión de seguridad): los nombres lógicos de un índice son datos no confiables. `store.read_unit` los valida (lista permitida `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`, sin separadores, sin punto inicial, sin colisión por mayúsculas) y `restore.write_files` vuelve a validar, exige que el destino cuelgue directamente del directorio de salida y crea con `O_EXCL|O_NOFOLLOW` (0600). Pruebas negativas en `tests/test_archive_store.py::HostileProvider`.
