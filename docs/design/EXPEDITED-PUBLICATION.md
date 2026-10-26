# Publicación programada y publicación extraordinaria (diseño y primera entrega)

**Regla:** publicación diaria por defecto; publicación extraordinaria cuando haga falta; **ambas por GitHub Actions, con la misma fábrica de validación, firma y publicación, y jamás directamente desde Cloudflare.**

## Modelo: estado deseado y estado efectivo

Una decisión autorizada cambia el **estado deseado** de un recurso. El **estado efectivo** (lo que está realmente publicado y firmado) solo cambia cuando una release verificada lo recoge. El panel nunca escribe el estado efectivo por su cuenta: lo sincroniza a partir de la release activa.

Tabla `publication_requests` (migración panel 0008) + `publication_request_events` (solo se añade). Una solicitud lleva: modo (`SCHEDULED` por defecto o `EXPEDITED`), acción, criticidad, recurso y **versión exacta**, estado deseado, estado efectivo en el momento de pedirla, motivo, alcance (artefactos, paquetes, fuentes, perfiles), solicitante / aprobador / ejecutor (identidades distintas), `authorization_sha256` (ata la autorización al recurso, versión, acción y solicitud concretos), caducidad, y la evidencia del run (id, commit, release, hashes).

## Dos modos, una fábrica

| | SCHEDULED (por defecto) | EXPEDITED |
|---|---|---|
| Quién | `publication.expedite.propose` o más | `publication.expedite` (PUBLISHER, SECURITY_ADMIN, ADMIN); REVIEWER solo **propone** |
| Efecto inmediato | guarda el estado deseado, audita, no lanza nada | además solicita un run de `publish-expedited.yml` (solo `request_id` como entrada) |
| Pipeline | la diaria recoge las solicitudes `PENDING` | el run recoge **su** solicitud autorizada; la diaria posterior no la repite |
| Coste | el del ciclo diario | minutos de Actions de un run extra, medidos y registrados |

La UI ofrece «Aplicar en la próxima ejecución diaria» (preseleccionada; muestra la hora prevista y que puede retrasarse) y «Solicitar publicación ahora» (motivo ≥ 20 caracteres, identificador y versión exactos, confirmación escribiendo el identificador, identidad verificada, alcance y gates visibles; sin promesas de inmediatez ni de coste cero; tiempo y coste solo si hay historial real).

## Autorización y separación de funciones

- `publication.expedite.propose`: REVIEWER, PUBLISHER, SECURITY_ADMIN, ADMIN. `publication.expedite`: PUBLISHER, SECURITY_ADMIN (solo acciones de seguridad: cuarentena, retirada, revocación, sustitución de firma), ADMIN. `publication.expedite.approve`: ADMIN, SECURITY_ADMIN. `publication.expedite.breakglass`: ADMIN.
- Acciones **críticas** (poner en cuarentena lo publicado, retirar, revocar, sustituir firma) en **cualquier modo, también SCHEDULED**: las pide quien tiene `publication.expedite` (un REVIEWER no puede ni programarlas) y exigen dos identidades distintas; una solicitud crítica programada queda en `AWAITING_APPROVAL`, la pipeline diaria solo la ve cuando otra identidad la ha autorizado (autorización ligada a la solicitud y con caducidad), y aunque se le reportara no la aplica sin esa autorización (se reutilizan las aprobaciones de segunda identidad). Con un único administrador: el procedimiento de emergencia existente (motivo largo, espera, revisión posterior por otra identidad); no hay bypass permanente.
- Quien aprobó un registro para publicar (`intel.approve`) no puede ser quien solicita su publicación extraordinaria.
- La autorización caduca (24 h) y es de un solo uso: un *replay* de una autorización antigua no hace nada.

## Ejecución solo en GitHub Actions

El Worker **no** tiene un token general de escritura. Dispone, como mucho, de una credencial de alcance mínimo para solicitar `workflow_dispatch` de **un** workflow fijo (`publish-expedited.yml`) con **una** entrada (`request_id`, un UUID validado). Recomendado: GitHub App limitada a este repositorio y al permiso *Actions: write*; no se guardan tokens personales. Mientras esa credencial no exista, la solicitud queda `BLOCKED` con la causa `dispatcher_not_configured`: el panel lo dice y no simula nada.
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

## Evidencia

Solicitud, actor, motivo, aprobación, identidades, fecha, workflow, run, commit, artefactos, gates, hashes, firmas, attestations, checkpoint, release y estado final quedan en `publication_request_events` y en la cadena de auditoría, enlazados al evento de transparencia cuando exista el log (hoy solo hay una cadena de hashes; no se atribuye más garantía).

## Entrega 1 (esta rama) y siguientes

Hecho aquí: modelo y migración 0008, permisos RBAC, máquina de estados, solicitudes SCHEDULED/EXPEDITED, aprobación de segunda identidad, deduplicación, presupuesto, caducidad y *replay*, despachador de mínimo alcance (inyectable), callbacks OIDC del workflow, reconciliación y pruebas de los 20 escenarios.
Siguiente: diálogo de la UI; `publish-expedited.yml` reutilizando la fábrica diaria (`workflow_call`); GitHub App; sincronización del estado efectivo desde la release activa; extensión progresiva a más familias.
