# Cuarentena de reglas

[Inicio](ES-Home) · [Cuarentena](ES-YARA-Quarantine) · [Publicación](ES-YARA-Publishing) · [Transparencia](ES-YARA-Transparency) · [Verificar](ES-YARA-Verify)

## En 30 segundos

Cada archivo de reglas YARA que llega de las fuentes se examina. Los que pasan todas las pruebas se aceptan y se publican solos. Los que no pasan no se publican: quedan **rechazados**, **bloqueados** o **pendientes de revisión**. Una persona con rol de revisor puede aprobar o rechazar solo los pendientes de revisión; **nunca** puede saltarse una prueba técnica, porque tras aprobar el archivo se valida otra vez. Cada decisión queda escrita en un registro encadenado por hashes. {{ev:EV-YC-40}}

## Un ejemplo cotidiano

Piensa en el control de calidad de una panadería. El pan bueno sale a la tienda. El pan quemado o roto se tira (no se puede "aprobar" un pan quemado). El pan con un defecto dudoso, por ejemplo menos dorado de lo normal, lo mira una persona: si dice "vale", se vuelve a pesar y medir antes de venderlo. Y todo lo que decide la persona se apunta en un cuaderno donde cada hoja menciona la anterior. La analogía solo ilustra el flujo; no implica que se detecte todo.

{{diagram:quarantine-lanes-1-outcomes}}

{{diagram:quarantine-lanes-2-pending}}

{{diagram:quarantine-lanes-3-recheck}}

## Paso a paso

1. El pipeline diario clasifica cada archivo (`scripts/rulecheck.py`) y decide (`scripts/decide.py`).
2. Los archivos aceptados (`VALIDATED`) entran en el candidato a release.
3. Los de la cuarentena con hallazgos de criterio se envían al panel privado como candidatos (`PENDING`).
4. Un revisor aprueba, rechaza o retiene. Aprobar no publica nada: el siguiente ciclo valida el archivo de nuevo.
5. `publish.yml` verifica el conjunto final otra vez y, tras publicar, comunica al panel qué se liberó (`RELEASED`).

{{diagram:quarantine-states-1-pending}}

{{diagram:quarantine-states-2-under-review}}

{{diagram:quarantine-states-3-approved}}

{{diagram:quarantine-states-4-released}}

| Estado del candidato | Significado |
|---|---|
| `PENDING` | Entró en cuarentena y espera revisión. |
| `UNDER_REVIEW` | Un revisor lo retiene a propósito. |
| `APPROVED_PENDING_VALIDATION` | Aprobado; falta que el pipeline lo valide otra vez. |
| `REJECTED` | Rechazado; ese contenido (mismo SHA-256) no vuelve. |
| `RELEASED` | Una release pública verificada lista ese contenido exacto. |

## Cómo funciona por dentro

**Cuatro destinos** (`rulecheck.py`, función de clasificación): `REJECTED` si hay un criterio duro (binario, sin reglas, por encima del tope de tamaño, demasiadas reglas o contenido rechazado antes: códigos `binary`, `no-rules`, `oversized`, `too-many-rules`, `previously-rejected`); `QUARANTINED` si hay hallazgos truncados, corruptos o de revisión; `DEPRECATED` si el propio archivo se marca obsoleto; `VALIDATED` si nada de eso aplica. Solo `VALIDATED` se publica. Los topes están en `config/policy.json`: `max_file_bytes` 1000000 y `max_rules_per_file` 3000. {{ev:EV-YC-40}}

**Qué puede decidir una persona.** En el servicio privado de revisión, una persona revisora autorizada puede aprobar, rechazar, retener o enviar un candidato a revisión. Cada decisión exige un motivo registrado, y las peticiones están protegidas contra repeticiones y contra actuar sobre una versión obsoleta. No existe ninguna acción humana que produzca `RELEASED`: solo lo escribe `publish.yml` tras ver el archivo en un manifiesto verificado. {{ev:EV-YC-42}}

**Hallazgos que NO se pueden aprobar.** Una persona puede dispensar los hallazgos de criterio con un motivo registrado; los fallos duros no. Todo lo demás es un control técnico: el panel no deja aprobar y `decide.py` lo vuelve a aplicar al ejecutar las decisiones. Una prueba mantiene idénticas ambas listas. {{ev:EV-YC-41}}

| Código real | Qué significa | Por qué no se aprueba |
|---|---|---|
| `unbalanced-braces`, `unclosed-rule`, `ends-mid-file`, `unterminated-string`, `unterminated-comment`, `unterminated-regex` | Archivo truncado | Faltan bytes; aprobar no los devuelve. |
| `corrupt-encoding`, `no-condition`, `compile-error`, `compile-dependency` | Dañado o no compila | El motor no puede cargarlo ni medirlo. |
| `blocked-module`, `no-engine` | Módulo bloqueado o sin motor | No hay forma segura de ejecutarlo. |
| `license-changed` | La licencia cambió | Es una cuestión legal, no de criterio. |
| `dynamic-failure` | Provocó cuelgue, tiempo agotado o regresión | La prueba dinámica falló: es un hecho medido. |
| `previously-rejected`, `rejected-by-reviewer` | Mismo contenido rechazado antes | La decisión humana se mantiene mientras los bytes sean los mismos. |

Un archivo cambiado es un candidato nuevo (clave `(sha256, path)`) que no hereda aprobaciones; solo se muestra la versión anterior como precedente. {{ev:EV-YC-41}}

**Registro de decisiones.** Cada decisión escribe una entrada de auditoría en la misma operación atómica que la decisión. El hash de cada entrada depende de la entrada anterior y de su propio contenido, de modo que una entrada editada, borrada o reordenada es detectable mediante una verificación autorizada. Refuerzo previsto: anclar periódicamente el registro fuera del servicio (ver Estado). {{ev:EV-YC-42}}

## Cómo comprobarlo tú

El código del pipeline y sus pruebas son públicos. Desde un clon del repositorio:

```bash
python3 -m unittest tests.test_admission tests.test_decide
```

En el momento de la revisión (2026-10-22) estas suites pasaron sobre `main`. El servicio de revisión tiene su propia suite de pruebas, que la CI ejecuta en cada pull request. El número de pruebas cambia con cada commit, así que no se cita ninguno: ejecuta las órdenes para obtener la cifra actual. {{ev:EV-YC-42}} Los códigos se leyeron en `scripts/rulecheck.py` y `scripts/decide.py`. Código: [decide.py](https://github.com/MacGuard/macguard-yara-channel/blob/main/scripts/decide.py), [rulecheck.py](https://github.com/MacGuard/macguard-yara-channel/blob/main/scripts/rulecheck.py).

## Límites

- Un archivo "validado" no es una garantía de calidad de detección ni de ausencia de falsos positivos.
- Los detalles de reglas en cuarentena (nombres, hallazgos, contenido) van solo al servicio privado; lo público lleva recuentos.
- El servicio de revisión solo registra decisiones; la publicación y la firma se hacen en `publish.yml`.

## Estado

| Capacidad | Estado |
|---|---|
| Clasificación, decisión y hallazgos no aprobables en el pipeline | operativo {{ev:EV-YC-41}} |
| Panel privado de revisión: aprobar, rechazar, retener, registro de auditoría | operativo {{ev:EV-YC-05}} |
| Memoria persistente de decisiones y retirada de reglas publicadas | implementado en el repositorio, aún no activo en producción {{ev:EV-YC-43}} |
| Anclaje de la auditoría fuera del servicio | implementado en el repositorio, aún no activo en producción {{ev:EV-YC-44}} |
| Control de admisión de fuentes nuevas | implementado en el repositorio, aún no activo en producción {{ev:EV-YC-07}} |

Las retiradas persistentes, las políticas y el anclaje de auditoría están implementados en el repositorio y aún no están activos en producción; el servicio en vivo tolera que falten. Hasta que lo estén, el pipeline (`decide.py`) todavía no aplica las retiradas registradas a la siguiente release. {{ev:EV-YC-43}} {{ev:EV-YC-06}}
