---
title: Cuarentena
summary: Qué ocurre con las reglas que no pasan, y cómo se decide su destino.
---
## Idea

Lo que pasa las pruebas se publica automáticamente. Lo que no pasa va a cuarentena y una persona decide: aprobar su despliegue, eliminarla o mantenerla. En la siguiente ejecución diaria el pipeline lee esa decisión y actúa: publica la regla, la elimina o la deja en cuarentena. Aprobar **nunca** salta los controles técnicos: la regla se vuelve a validar.

{{diagram:quarantine-states}}

| Estado | Significado |
|---|---|
| PENDING | Entró en cuarentena; espera revisión. |
| UNDER_REVIEW | Una persona lo ha marcado como en revisión. |
| APPROVED_PENDING_VALIDATION | Aprobada; falta que `publish.yml` la valide de nuevo. |
| REJECTED | Eliminada; ese contenido no vuelve. Una versión editada es un candidato nuevo enlazado. |
| RELEASED | Publicada en una release. |

## Qué sale al público

Los detalles de reglas en cuarentena o rechazadas (nombres, hallazgos, contenido) viajan solo al servicio privado. Los artefactos, el registro y el sitio públicos llevan únicamente recuentos. Un fichero que no está en el manifiesto no aparece en ninguna parte pública.

> **ACTUAL** Persistencia y panel: implementados y probados en local; el servicio no está desplegado en producción (ver [Panel privado](page:admin-panel)). Mientras no lo esté, la cuarentena se calcula en cada ejecución y no hay decisión humana que leer.
