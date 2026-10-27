# Contrato de arquitectura: Cloudflare = plano de control; GitHub Actions = fábrica (2026-10-27)

Sustituye y acota `EXPEDITED-PUBLICATION.md` donde difiera. **Una sola pipeline completa al día** en GitHub Actions (`daily.yml` → `publish.yml`, concurrencia `macguard-log`, sin `cancel-in-progress`). Cloudflare **no** procesa ni publica: autentica, autoriza, registra solicitudes, sirve consultas paginadas e indexadas, recibe resultados autenticados y guarda estados y snapshots finales. Ninguna decisión individual del dashboard lanza una pipeline completa.

## Dos estados independientes por registro

- **`desired_state`** (lo que decide una persona): `REQUEST_QUARANTINE`, `REQUEST_APPROVE`, `REQUEST_PUBLISH`, `REQUEST_WITHDRAW`, `REQUEST_REVOKE`, `REQUEST_SUPERSEDE`, `REQUEST_REJECT`. Se guarda como una **solicitud** inmutable: id, identidad, fecha, recurso y versión exactas, estado efectivo en ese momento, estado deseado, motivo, autorizaciones requeridas, versión optimista, estado de procesamiento y referencia de auditoría.
- **`effective_state`** (lo que la pipeline hizo efectivo y puede demostrar): solo lo cambia un **resultado autenticado** de un lote. Pulsar un botón no lo toca. `PUBLISHED` exige artefacto firmado, distribuido y verificado; una revocación solo es efectiva cuando la política de revocación firmada está publicada. No se afirma «aplicado en todos los clientes» sin confirmación del cliente.

## Estados de la solicitud

`PENDING` (registrada) → `AUTHORIZED` (autorizaciones cumplidas; las críticas exigen segunda identidad) → `SNAPSHOTTED` (incluida en un lote) → `PROCESSING` (la pipeline la trata; `phase` muestra el paso real del workflow) → `APPLIED` | `REJECTED` (**política**: calidad, licencia, compatibilidad, seguridad) | `FAILED` (**procesamiento**: error técnico) | `SUPERSEDED` (otra decisión o una versión nueva de la fuente la anula) | `CANCELLED`. Además `SYNC_PENDING`: publicado y verificado pero D1 aún no recibió el resultado; se reconcilia **sin republicar**. Fallo y rechazo por política nunca se confunden.

## Lotes (el único puente entre el panel y la fábrica)

La pipeline pide un snapshot consistente de las decisiones pendientes con su identidad OIDC. Cada lote lleva `batch_id`, `version`, `sequence` (estrictamente creciente), `snapshot_hash`, `timestamp`, `decision_ids`, `expected_previous_release` y `source_revision`. Lo que llega después del snapshot pasa al siguiente ciclo. El panel **no** tiene credenciales de escritura sobre GitHub.

El resultado del lote lo envía el workflow autorizado y el Worker comprueba: identidad exacta del workflow, issuer, audience, repositorio, referencia del lote, hash del resultado, **idempotencia** (mismo resultado dos veces = mismo efecto), **secuencia** (un resultado antiguo nunca pisa una release más reciente), ausencia de *replay* y transiciones válidas. Los resultados del navegador no existen.

## Publicación coherente

Releases inmutables; se construye un candidato completo, se firma y se verifica **antes** de activar la referencia de versión. Si falla un gate crítico se conserva la última release válida y los clientes nunca ven una mezcla incompatible. La publicación efectiva y la actualización de D1 se concilian de forma idempotente.

## Caso excepcional: solo operaciones protectoras

Existe un workflow extraordinario únicamente para **seguridad**: poner en cuarentena lo publicado, retirar, revocar o sustituir una firma. Mismas firmas, calidad y transparencia que el ciclo ordinario. **No se puede usar para publicar contenido nuevo** ni para saltarse los controles de publicación: `REQUEST_PUBLISH` es siempre diario. Exige permiso explícito, segunda identidad (o la vía de emergencia con reautenticación reforzada, espera, motivo largo y revisión posterior por otra identidad), y queda ligado al recurso, versión, acción y solicitud.

## Observabilidad independiente de D1

Las cuotas y los costes se vigilan desde un workflow de Actions propio (frecuencia mayor que la diaria, dentro de los límites de GitHub) con un token de **solo lectura** de analítica (nunca D1 Write ni Workers Admin): D1 filas leídas/escritas y almacenamiento, Workers, R2, minutos de Actions, B2/Scaleway. Umbrales 50/75/90/100 % con predicción por consumo observado; correo y Telegram sin duplicados; histórico diario; funciona aunque D1 no responda. No se inventan euros donde el proveedor solo da unidades. Ausencia o retraso de la ejecución diaria genera alerta (el cron de GitHub puede retrasarse: no es una garantía).

## Transparencia

Se separan la **decisión** del usuario y el **resultado** de la pipeline, ligados por `decision_id`, `batch_id` y release. Debe poder demostrarse quién pidió qué, cuándo, sobre qué versión, qué ejecución lo trató, qué pruebas superó, qué firma se emitió, qué versión se publicó y cuándo fue efectivo. Las entradas históricas no se modifican. Los compromisos críticos se anclan en el log de transparencia criptográfico (las reglas ya tienen log con prueba de inclusión y checkpoint en cada release) con checkpoints independientes. **Una cadena de hashes en D1 no es transparencia completa y no se presenta como tal.**

## Estado de implementación

| Pieza | Estado |
|---|---|
| Solicitudes de publicación, estados, RBAC, segunda identidad, emergencia, despachador mínimo, callbacks OIDC (PR #53) | IMPLEMENTED (backend); a adaptar a este contrato |
| Lotes con secuencia y resultados autenticados, `effective_state` solo por resultado | PLANNED (siguiente entrega) |
| Restricción del workflow extraordinario a operaciones protectoras | PLANNED (siguiente entrega) |
| UI «estado efectivo / cambio solicitado / próxima ejecución» | PLANNED |
| Vigilancia de cuotas y costes en Actions | PLANNED |
| Snapshots pesados de estadísticas generados en Actions | PLANNED (hoy: instantánea de una pasada en el Worker, ya acotada) |
