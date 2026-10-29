# Evidencia de backups: separación de `evidence/` respecto a `main` (2026-10-28)

**Estado: IMPLEMENTADO EN LA PR, DESACTIVADO EN PRODUCCIÓN.** Con los valores por defecto, los workflows y el Worker se comportan exactamente como antes. Nada se ha creado en el remoto (no existe la rama `evidence`), no hay variable `EVIDENCE_MODE` ni se ha desplegado el Worker. Cada paso de la sección 6 pide autorización expresa.

## 1. Por qué

`evidence/backups.jsonl` se escribe con el `GITHUB_TOKEN` de Actions directamente en `main`. Mientras eso sea así, `main` no puede exigir CI (`docs/operations/MAIN-PROTECTION-DESIGN.md`: ese token no puede ser actor de bypass y no hay reglas de push por ruta) y un bot con `contents: write` podría, en teoría, tocar código. Sacar la evidencia de `main` quita a dos de los cinco escritores.

## 2. Inventario (comprobado con `git grep` sobre `origin/main` `b459634`)

**Productores** (solo dos; ningún otro flujo escribe `evidence/`):

| Productor | Qué escribe | Cómo | Identidad |
|---|---|---|---|
| `backup.yml`, job `record` (cron 03:23 gateway, 03:53 panel, y manual) | registro `backup` de la ejecución | `backup_record.mjs backup` + `commit_evidence.sh`; cola `macguard-log` | `GITHUB_TOKEN`, etiqueta de autor `macguard-evidence[bot]`, `contents: write` |
| `record-restore.yml` (manual, solo administrador) | registro `restore` de un simulacro | `evidence_retry.sh` + `backup_record.mjs restore`; cola por run y proveedor | igual |

`restore_from_run.sh` solo *dispara* `record-restore.yml` en `main`; no escribe.

**Consumidores:**

| Consumidor | Qué lee | Cómo | Impacto de la migración |
|---|---|---|---|
| Worker del panel (`admin/worker/src/restore.js`, pestaña Restauración) | `evidence/backups.jsonl` | `raw.githubusercontent.com/<repo>/main/evidence/backups.jsonl` | **El único consumidor de producción.** Ahora admite `EVIDENCE_REFS` (lista de refs unidas sin duplicados) |
| `backup_record.mjs` (`readRecords`, `append`, `buildRestoreRecord`) | el fichero local | para validar y no duplicar; la restauración se valida contra el `backup` ya registrado | Recibe `--file` hacia la copia de la rama |
| `restore_procedures.js` | solo texto de ayuda («Created workflow_dispatch event for record-restore.yml at main») | no lee la evidencia | Ninguno: el despacho sigue en `main` |
| Pruebas | `commit_evidence`, `evidence_retry`, `record_restore_idempotent`, `backup_record`, `restore` | locales | Siguen verdes sin cambios |

El tipo `checkpoint_confirmed` lo lee el panel, pero **ningún flujo lo escribe** hoy (es para una confirmación manual de copia externa). El diseño de checkpoints de la sección 4 es independiente de él.

## 3. Diseño

**Almacenamiento:** rama huérfana `evidence`, con solo `README.md`, `evidence/backups.jsonl` (mismo formato, mismos lectores) y `evidence/backups.chain`. Sin código ni secretos. Los workflows siguen ejecutando el código de `main` y escriben la rama desde un **segundo checkout** (`evidence-wt`), de modo que un bot que escribe la rama no toca código.

**Historial y referencias:** la siembra (`evidence_seed.sh`) copia el log actual **byte a byte** (las 14 líneas de hoy), de modo que `run_id`, `stamp` y huellas siguen siendo válidos. **`main` conserva su copia y su historial: no se borra ni se reescribe nada.** La copia de `main` queda congelada o se sigue escribiendo mientras dure el modo `dual`.

**Idempotencia:** `backup_record.mjs` ya rechaza un `backup` del mismo `run_id` y una restauración repetida (`sameRestore`). `evidence_write.sh` reutiliza esa lógica en cada lado, así que repetir un job no escribe nada nuevo (probado en Actions: la segunda ejecución no creó ningún commit en ninguna rama).

**Concurrencia:** `evidence_retry.sh` no hace *rebase*: ante un push rechazado regenera el registro sobre la punta actual de la rama (6 intentos). Probado con 6 escritores a la vez.

**Escritura en `dual` y estados explícitos** (`evidence_write.sh`): el registro se construye **una sola vez**, en la rama, y los mismos bytes se copian a `main` (así dos copias nunca difieren solo por la marca de tiempo). Si la rama falla, `main` recibe el registro igualmente (no se pierde). El resultado se imprime como `EVIDENCE_STATUS=` y como anotación de Actions, con código de salida:

| Estado | Salida | Significado |
|---|---|---|
| `CONFIRMED` | 0 | todos los destinos que pide el modo tienen el registro |
| `PENDING_SYNC` | 3 | el registro está en **un solo** destino; hay que reconciliar el otro (el job falla a propósito para que se vea) |
| `ERROR` | 1 | el registro no está en ningún destino, **o** las dos copias se contradicen |

**Reintentos:** solo se reintenta un push rechazado por concurrencia (se regenera sobre la punta actual). Una **negativa por integridad** (cadena que no coincide con el log, o rama inexistente) sale con código 2 y **no se reintenta**: antes de este cambio el reintento descartaba la edición local y seguía como si fuera un conflicto de push, ocultando la negativa.

**Reconciliación:** `evidence_reconcile.mjs` compara dos copias y **solo añade lo que falta**. Si una misma identidad existe con **contenido distinto** (backup o restauración) sale con código 4 y **no escribe nada**, ni siquiera lo que falta: una contradicción no se resuelve eligiendo un lado. Es idempotente y nunca modifica líneas existentes.

**La rama no la crea ningún productor:** `commit_evidence.sh` comprueba que la rama existe en el remoto antes de hacer commit (un push a un nombre inexistente la crearía en silencio).

## 4. Política de integridad verificable

Una rama de Git **no es almacenamiento WORM**: quien pueda empujar con permiso suficiente puede reescribirla. Lo que aporta este diseño es que **una reescritura no pase inadvertida**:

1. **Cadena de hashes** (`evidence/backups.chain`): `chain_n = SHA-256(chain_(n-1) + "\n" + SHA-256(registro_n))`. Cambiar, borrar o reordenar un registro rompe todos los valores posteriores. Se actualiza en el mismo commit que el registro. `evidence_chain.mjs verify` lo comprueba.
2. **Checkpoints anclados fuera del dominio de confianza principal:** `evidence-checkpoint.yml` (solo manual) verifica la cadena, genera `{count, head}` y lo firma con **Sigstore keyless**; la firma y su entrada en **Rekor** viven fuera del repositorio y de GitHub. `evidence_chain.mjs verify --checkpoint F --bundle B` **exige la firma**: ejecuta `cosign verify-blob` con la identidad autorizada (`…/evidence-checkpoint.yml@refs/heads/main`) y el emisor OIDC de Actions, y solo entonces comprueba que los primeros `count` registros son exactamente los firmados, aunque la rama haya sido manipulada después. Sin `--bundle` el checkpoint se rechaza (solo `--allow-unsigned` lo admite, para pruebas locales); si `cosign` no está disponible falla cerrado. Además de `cosign`, el verificador lee el propio bundle y exige (comprobaciones propias, no delegadas): que su digest sea el SHA-256 del fichero, que el SAN del certificado sea **exactamente** la identidad autorizada, que el emisor OIDC de la extensión del certificado sea exactamente el autorizado y que exista una entrada de transparencia con prueba de inclusión. **Validado con firma real de Sigstore en Actions** (`docs/audit/evidence/sigstore-lab-2026-10-29/`): 2 verificaciones correctas y 9 manipulaciones rechazadas (checkpoint alterado, firma alterada, identidad equivocada, emisor no autorizado, otro workflow, sin transparencia, certificado cambiado, sin bundle, `head` falsificado). La identidad de **producción** solo se podrá comprobar cuando `evidence-checkpoint.yml` se ejecute desde `main`. Añadir registros posteriores sigue siendo válido.
3. **Reglas de rama (pendiente de autorización):** sin force-push ni borrado en `evidence`. Sin ellas, la cadena y los checkpoints detectan la reescritura, no la impiden.

**Límites declarados:** los registros posteriores al último checkpoint no están avalados; el artefacto del checkpoint dura 90 días en Actions y el ancla durable es la entrada de Rekor más una **copia de `checkpoint.json` + bundle fuera de GitHub** (B2/Scaleway/R2), que es un paso aparte aún no hecho. Si alguna vez se necesita WORM real, hay que evaluar *Object Lock* en los proveedores (no verificado aquí) en vez de una rama.

## 5. Medido

- Pruebas locales: 12 en `evidence_branch.test.js` (cadena, checkpoints, reconciliación, siembra, 6 escritores, CLI, estructura de los workflows) + **13 adversariales** en `evidence_adversarial.test.js` + 5 del lector del Worker + 5 de comprobación del bundle con bundles reales de Sigstore. Gateway completo 342/342 (0 omitidas), Worker 365/365; las 18 pruebas previas de productores siguen verdes sin cambios.
- **Pruebas adversariales** (registro faltante, duplicado idéntico, duplicado contradictorio de backup y de restauración, tres escritores `dual` concurrentes, fallo de red antes y después de la escritura de la rama, ambos lados caídos, recuperación desde un checkout limpio, truncamiento, checkpoint alterado, firma con identidad ajena, reescritura de un registro histórico, rama inexistente, rollback). **Mutaciones:** se reintrodujeron 7 defectos (registro construido dos veces, conflicto que no detiene `--apply`, sin comprobación de firma, identidad sin fijar, rama autocreada, negativa reintentada, `PENDING_SYNC` con salida 0) y cada uno hizo caer pruebas concretas; los ficheros se verificaron idénticos byte a byte a los previos.
- **Límite declarado:** truncar a la vez el log y la cadena es coherente consigo mismo y **no se detecta sin un checkpoint** (una prueba lo afirma explícitamente); por eso el checkpoint firmado es parte del diseño y no un extra.
- **Laboratorio en Actions** (ramas efímeras `exp/evidence-lab*`, ya borradas, con el `GITHUB_TOKEN` real, dos checkouts y los scripts reales, sembrado desde el `evidence/backups.jsonl` real de `main`): escritura dual correcta en ambas ramas; re-ejecución sin commits nuevos; cadena válida; las 14 líneas de `main` idénticas byte a byte al principio de la rama; ningún fichero de código en la rama de datos.
- Defecto encontrado y corregido durante el trabajo: la guarda «¿soy el CLI?» comparaba la ruta real con una ruta que pasa por un symlink (`/var` → `/private/var`) y la herramienta **no hacía nada sin avisar**; ahora compara rutas reales.

## 6. Plan de activación (cada paso requiere autorización; ninguno está hecho)

| Paso | Acción | Verificación | Reversión |
|---|---|---|---|
| 0 | Fusionar esta PR (defaults = hoy) | CI verde; un ciclo diario y un backup posteriores idénticos a los anteriores | Revertir la PR |
| 1 | Sembrar y empujar la rama `evidence` (`evidence_seed.sh`, empujada por el propietario) | `evidence_chain.mjs verify` sobre un clon; primeras líneas = `main` | Borrar la rama (aún nadie la lee) |
| 2 | Proteger `evidence` (sin force-push ni borrado) | Un push forzado de prueba es rechazado | Quitar la regla |
| 3 | Variable `EVIDENCE_MODE=dual` | Un backup real y un `record-restore` real: ambas copias reciben el registro; `evidence_reconcile` sin diferencias; la cadena válida | `EVIDENCE_MODE` vacío (vuelve a `main`); `evidence_reconcile --apply` si hubiera faltas |
| 4 | Desplegar el Worker con `EVIDENCE_REFS=evidence,main` | La pestaña Restauración muestra los mismos indicadores; `unavailable` vacío | Quitar la variable y redesplegar |
| 5 | Ejecutar `evidence-checkpoint.yml`; copiar `checkpoint.json` y el bundle a los 3 proveedores | `verify --checkpoint` con la copia externa | n/a (solo añade) |
| 6 | `EVIDENCE_MODE=branch` y `EVIDENCE_REFS=evidence` tras un periodo sin diferencias | Igual que 3 | Volver a `dual` |

La copia de `main` **no se borra nunca** en este plan. Retirarla (si se decide) es una decisión posterior y distinta.

## 7. Riesgos de integridad y rollback

| Riesgo | Mitigación | Residual |
|---|---|---|
| Reescritura de la rama por quien tenga permiso | Cadena + checkpoint firmado y anclado; regla de no force-push (paso 2) | Detectable, no impedible; lo posterior al último checkpoint no está avalado |
| El panel lee solo una copia desactualizada | `EVIDENCE_REFS=evidence,main` une ambas | Un ref ilegible se informa en `unavailable` |
| Pérdida de un registro por fallo a mitad | `dual` escribe ambos lados y falla en voz alta; `reconcile` repone | Requiere ejecutar `reconcile` si el job se queda a medias |
| `EVIDENCE_MODE` con valor erróneo | `evidence_write.sh` rechaza cualquier valor que no sea `dual`/`branch`; el camino por defecto ignora todo menos `main` | Ninguno |
| Rama inexistente con `dual` | El checkout es `continue-on-error` en `dual`; `main` se escribe y el job falla | Aviso visible, sin pérdida |
| Hash roto por edición legítima manual | No se edita: solo se añade; una corrección es un registro nuevo | — |

Rollback en cualquier momento: vaciar `EVIDENCE_MODE` (los productores vuelven al camino de hoy) y quitar `EVIDENCE_REFS` (el panel vuelve a leer solo `main`). Los dos son ajustes, no despliegues de código, salvo el redespliegue del Worker.

**Orden obligatorio al volver desde `branch`:** durante `branch` los registros solo existen en la rama, y `main` no los tiene. Antes de vaciar `EVIDENCE_MODE`, ejecutar `evidence_reconcile.mjs --from <rama> --to <main> --apply` (a través de `evidence_retry.sh`, desde un checkout limpio de `main`). Solo añade; el historial de `main` queda como prefijo intacto y la rama conserva todo (probado). Desde `dual` no hace falta: `main` ya tiene todo.
