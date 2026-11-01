# Publicación programada y publicación extraordinaria (diseño y primera entrega)

**Regla:** publicación diaria por defecto; publicación extraordinaria cuando haga falta; **ambas por GitHub Actions, con la misma fábrica de validación, firma y publicación, y jamás directamente desde Cloudflare.**

## Modelo: estado deseado y estado efectivo

Una decisión autorizada cambia el **estado deseado** de un recurso. El **estado efectivo** (lo que está realmente publicado y firmado) solo cambia cuando una release verificada lo recoge. El panel nunca escribe el estado efectivo por su cuenta: lo sincroniza a partir de la release activa.

Tabla `publication_requests` (migración panel 0008) + `publication_request_events` (solo se añade). Una solicitud lleva: modo (`SCHEDULED` por defecto o `EXPEDITED`), acción, criticidad, recurso y **versión exacta**, estado deseado, estado efectivo en el momento de pedirla, motivo, alcance (artefactos, paquetes, fuentes, perfiles), solicitante / aprobador / ejecutor (identidades distintas), `authorization_sha256` (ata la autorización al recurso, versión, acción y solicitud concretos), caducidad, y la evidencia del run (id, commit, release, hashes).

## Dos modos, una fábrica

| | SCHEDULED (por defecto) | EXPEDITED |
|---|---|---|
| Quién | `publication.expedite.propose` o más | `publication.expedite` (PUBLISHER, SECURITY_ADMIN, ADMIN); REVIEWER solo **propone** |
| Efecto inmediato | guarda el estado deseado, audita, no lanza nada | además solicita un run de `publish-expedited.yml` (entradas: `request_id` y `dispatch_id`) |
| Pipeline | la diaria recoge las solicitudes `PENDING` | el run recoge **su** solicitud autorizada; la diaria posterior no la repite |
| Coste | el del ciclo diario | minutos de Actions de un run extra, medidos y registrados |

La UI ofrece «Aplicar en la próxima ejecución diaria» (preseleccionada; muestra la hora prevista y que puede retrasarse) y «Solicitar publicación ahora» (motivo ≥ 20 caracteres, identificador y versión exactos, confirmación escribiendo el identificador, identidad verificada, alcance y gates visibles; sin promesas de inmediatez ni de coste cero; tiempo y coste solo si hay historial real).

## Autorización y separación de funciones

- `publication.expedite.propose`: REVIEWER, PUBLISHER, SECURITY_ADMIN, ADMIN. `publication.expedite`: PUBLISHER, SECURITY_ADMIN (solo acciones de seguridad: cuarentena, retirada, revocación, sustitución de firma), ADMIN. `publication.expedite.approve`: ADMIN, SECURITY_ADMIN. `publication.expedite.breakglass`: ADMIN.
- Acciones **críticas** (poner en cuarentena lo publicado, retirar, revocar, sustituir firma) en **cualquier modo, también SCHEDULED**: las pide quien tiene `publication.expedite` (un REVIEWER no puede ni programarlas) y exigen dos identidades distintas; una solicitud crítica programada queda en `AWAITING_APPROVAL`, la pipeline diaria solo la ve cuando otra identidad la ha autorizado (autorización ligada a la solicitud y con caducidad), y aunque se le reportara no la aplica sin esa autorización (se reutilizan las aprobaciones de segunda identidad). Con un único administrador: el procedimiento de emergencia existente (motivo largo, espera, revisión posterior por otra identidad); no hay bypass permanente.
- Quien aprobó un registro para publicar (`intel.approve`) no puede ser quien solicita su publicación extraordinaria.
- La autorización caduca (24 h) y es de un solo uso: un *replay* de una autorización antigua no hace nada.

## Ejecución solo en GitHub Actions

El Worker **no** tiene un token general de escritura. Dispone, como mucho, de una credencial de alcance mínimo para solicitar `workflow_dispatch` de **un** workflow fijo (`publish-expedited.yml`) con **dos** entradas validadas (`request_id` y el `dispatch_id` de ese despacho). Recomendado: GitHub App limitada a este repositorio y al permiso *Actions: write*; no se guardan tokens personales. Mientras esa credencial no exista, la solicitud queda `BLOCKED` con la causa `dispatcher_not_configured`: el panel lo dice y no simula nada.
El run se autentica con OIDC; lee su solicitud en `/api/pipeline/expedite/:id` (solo el workflow `publish-expedited.yml`) y comprueba la autorización, la versión y el estado actual antes de hacer nada. Una petición del navegador no puede ejecutar un workflow arbitrario ni inyectar parámetros.

## Ejecución incremental (en el workflow, siguiente entrega)

Solicitud autorizada → validar versión y estado actual → paquetes afectados → reutilizar datos fuente ya verificados solo si se acredita integridad y vigencia (si no, volver a obtenerlos) → pruebas del cambio y dependencias → *quality gates* aplicables (no se omite ninguno) → construir los paquetes afectados → firma Sigstore keyless → attestations → verificar → publicar artefactos inmutables → actualizar el catálogo activo → evento de transparencia → sincronizar el estado efectivo.

## Concurrencia

Un único grupo de concurrencia de publicación compartido por SCHEDULED y EXPEDITED, **sin** `cancel-in-progress`: una ejecución urgente espera en cola, nunca cancela una publicación a medias. Antes de activar el catálogo se comprueba que la release activa sigue siendo la esperada; si no, se reconcilia o se aborta. Lo ya aplicado por un run extraordinario no se vuelve a aplicar en el diario.

## Estados

`PENDING`, `AWAITING_APPROVAL`, `AUTHORIZED`, `QUEUED`, `RUNNING`, `VALIDATING`, `SIGNING`, `PUBLISHING`, `VERIFYING`, `APPLIED`, `BLOCKED`, `FAILED`, `CANCELLED` y `SYNC_PENDING` (publicado pero el panel aún no sincronizó). `APPLIED` solo cuando la versión nueva es activa y verificable. Si el run falla se conserva el estado efectivo previo y se registra la causa. Si la sincronización falla se muestra `SYNC_PENDING` y se reconcilia **sin republicar**.

## Control de costes

Predeterminado diario; confirmación y motivo obligatorios; idempotencia por `request_id`; solicitudes equivalentes abiertas se detectan (clave de deduplicación) y no se duplican; límite de extraordinarias abiertas a la vez; presupuesto diario de minutos con aviso. **Nunca se bloquea una acción crítica por presupuesto**: se permite y se marca `over_budget` para su revisión; si se agota, se muestra y se ofrece el procedimiento de emergencia autorizado. Alertas independientes para Actions y Cloudflare. Se registra el coste real de cada run.

## Elegibilidad

Solo recursos cuya familia tiene pipeline real, calidad suficiente y política de distribución autorizada. Hoy: reglas YARA (publicadas por la pipeline actual). Las demás familias (Suricata, Sigma, IOC, hashes, CVE…) devuelven `not_eligible` hasta que existan sus paquetes firmados; las decisiones multifamilia las dejan «aprobadas para una futura release» y no se publican por esta vía.

## Vinculación run ↔ solicitud (F6) y release activa (F3)

**Un run solo ejecuta la solicitud para la que el panel lo despachó.** Cada despacho tiene su propio `dispatch_id`, que se registra (tabla `publication_request_dispatches`, migración 0010) en la misma transacción que el paso a `QUEUED`.
- **Requisito del workflow:** `run-name: publish-expedited ${{ inputs.request_id }} ${{ inputs.dispatch_id }}`. Sin ese nombre, ningún run puede reclamar la solicitud.
- **Al primer informe `RUNNING`, el Worker exige al token OIDC:**
  - que sea de `publish-expedited.yml@refs/heads/main`;
  - `event_name = workflow_dispatch`;
  - `actor_id` = la identidad que despacha (`EXPEDITE_DISPATCHER_ID`, el id del bot de la GitHub App);
  - `run_attempt = 1`.
- **El Worker lee el run en la API de GitHub** (`GET /actions/runs/:id`, con la credencial del despachador) y exige que coincidan:
  - el workflow, la rama y el evento;
  - `triggering_actor` y `actor` = el despachador;
  - el intento;
  - el `display_title` = el run-name del despacho **vigente**;
  - `created_at` posterior al despacho.
- **La reclamación es atómica y queda registrada una sola vez** (tabla `publication_request_claims`, solo de inserción): la clave primaria es el despacho y el run es único. Dos runs no pueden reclamar el mismo despacho y un run no puede reclamar dos solicitudes. La reclamación va en el mismo batch que la transición, su evento y su entrada de auditoría.
- **Re-ejecuciones:**
  - un intento 2 no reclama;
  - tras la reclamación, cualquier otro intento u otro run recibe 403;
  - un nuevo despacho (reintento de una solicitud `BLOCKED`) crea un `dispatch_id` nuevo, y los runs del despacho anterior quedan fuera.
- **Falla cerrado:** si GitHub no responde o no hay despachador configurado, la respuesta es 503 y no se reclama nada. No se registran tokens.

**Release activa.** Una solicitud solo se cierra (`APPLIED`, expedita o diaria) con la release **activa autorizada**: la última release pública o, si una operación autorizada la **fijó**, la release fijada (`POST /api/publication-releases/pins`, permiso `publication.expedite.approve`, sesión reciente).
- **Una release histórica no basta:** aunque liste la misma ruta y el mismo SHA-256, no satisface la solicitud (`release_not_active`).
- **Fijar es el rollback explícito:** solo se puede fijar una release pública verificable (manifiesto y digest). Cada `PIN`/`UNPIN` queda en `publication_release_pins` (solo de inserción) y en la cadena de auditoría con motivo, release anterior y `rollback: true/false`. `expect_seq` impide que dos operadores se pisen.
- **Si no se puede determinar la release activa,** no cambia nada (503) y se vuelve a informar más tarde.
- **Fijar no cambia lo que sirve la web:** solo decide qué release puede cerrar solicitudes.

## Evidencia

Solicitud, actor, motivo, aprobación, identidades, fecha, workflow, run, commit, artefactos, gates, hashes, firmas, attestations, checkpoint, release y estado final quedan en `publication_request_events` y en la cadena de auditoría, enlazados al evento de transparencia cuando exista el log (hoy solo hay una cadena de hashes; no se atribuye más garantía).

## Entrega 1 (esta rama) y siguientes

Hecho aquí: modelo y migración 0008, permisos RBAC, máquina de estados, solicitudes SCHEDULED/EXPEDITED, aprobación de segunda identidad, deduplicación, presupuesto, caducidad y *replay*, despachador de mínimo alcance (inyectable), callbacks OIDC del workflow, reconciliación y pruebas de los 20 escenarios.
Siguiente: diálogo de la UI; `publish-expedited.yml` reutilizando la fábrica diaria (`workflow_call`); GitHub App; sincronización del estado efectivo desde la release activa; extensión progresiva a más familias.
