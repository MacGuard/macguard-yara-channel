# Cuarentena de reglas

[Inicio](ES-Home) · [Cuarentena](ES-YARA-Quarantine) · [Publicación](ES-YARA-Publishing) · [Transparencia](ES-YARA-Transparency) · [Verificar](ES-YARA-Verify)

## En 30 segundos

Cada archivo de reglas YARA que llega de las fuentes se examina. Los que pasan todas las pruebas se aceptan y se publican solos. Los que no pasan no se publican: quedan **rechazados**, **bloqueados** o **pendientes de revisión**. Una persona con rol de revisor puede aprobar o rechazar solo los pendientes de revisión; **nunca** puede saltarse una prueba técnica, porque tras aprobar el archivo se valida otra vez. Cada decisión queda escrita en un registro encadenado por hashes. {{ev:EV-YC-40}}

## Un ejemplo cotidiano

Piensa en el control de calidad de una panadería. El pan bueno sale a la tienda. El pan quemado o roto se tira (no se puede "aprobar" un pan quemado). El pan con un defecto dudoso, por ejemplo menos dorado de lo normal, lo mira una persona: si dice "vale", se vuelve a pesar y medir antes de venderlo. Y todo lo que decide la persona se apunta en un cuaderno donde cada hoja menciona la anterior. La analogía solo ilustra el flujo; no implica que se detecte todo.

{{diagram:quarantine-lanes}}

## Paso a paso

1. El pipeline diario clasifica cada archivo (`scripts/rulecheck.py`) y decide (`scripts/decide.py`).
2. Los archivos aceptados (`VALIDATED`) entran en el candidato a release.
3. Los de la cuarentena con hallazgos de criterio se envían al panel privado como candidatos (`PENDING`).
4. Un revisor aprueba, rechaza o retiene. Aprobar no publica nada: el siguiente ciclo valida el archivo de nuevo.
5. `publish.yml` verifica el conjunto final otra vez y, tras publicar, comunica al panel qué se liberó (`RELEASED`).

{{diagram:quarantine-states}}

| Estado del candidato | Significado |
|---|---|
| `PENDING` | Entró en cuarentena y espera revisión. |
| `UNDER_REVIEW` | Un revisor lo retiene a propósito. |
| `APPROVED_PENDING_VALIDATION` | Aprobado; falta que el pipeline lo valide otra vez. |
| `REJECTED` | Rechazado; ese contenido (mismo SHA-256) no vuelve. |
| `RELEASED` | Una release pública verificada lista ese contenido exacto. |

## Cómo funciona por dentro

**Cuatro destinos** (`rulecheck.py`, función de clasificación): `REJECTED` si hay un criterio duro (binario, sin reglas, por encima del tope de tamaño, demasiadas reglas o contenido rechazado antes: códigos `binary`, `no-rules`, `oversized`, `too-many-rules`, `previously-rejected`); `QUARANTINED` si hay hallazgos truncados, corruptos o de revisión; `DEPRECATED` si el propio archivo se marca obsoleto; `VALIDATED` si nada de eso aplica. Solo `VALIDATED` se publica. Los topes están en `config/policy.json`: `max_file_bytes` 1000000 y `max_rules_per_file` 3000. {{ev:EV-YC-40}}

**Qué puede decidir una persona.** El panel ofrece `approve`, `reject`, `hold`, `review` y `release_review` (`admin/worker/src/core.js`, tabla `HUMAN`). Aprobar, rechazar y retener exigen un motivo de 5 a 2000 caracteres visibles; un lote de varios exige `confirm_count` igual al número real; cada petición lleva un `request_id` idempotente y la versión que el revisor vio (si cambió, se rechaza). No existe ninguna acción humana que produzca `RELEASED`: solo lo escribe `publish.yml` tras ver el archivo en un manifiesto verificado. {{ev:EV-YC-42}}

**Hallazgos que NO se pueden aprobar.** Solo los hallazgos de criterio de la lista `WAIVABLE` se pueden aceptar a mano: `costly-regex`, `filesize-loop`, `many-loops`, `unknown-module`, `include`, `license-unchecked`, `matches-benign-corpus`, `dependency-not-validated`, `new-source`. Todo lo demás es un control técnico: el panel no deja aprobar (`blockingReasons`) y `decide.py` lo vuelve a aplicar al ejecutar las decisiones. Una prueba mantiene idénticas ambas listas (`tests/test_admission.py`). {{ev:EV-YC-41}}

| Código real | Qué significa | Por qué no se aprueba |
|---|---|---|
| `unbalanced-braces`, `unclosed-rule`, `ends-mid-file`, `unterminated-string`, `unterminated-comment`, `unterminated-regex` | Archivo truncado | Faltan bytes; aprobar no los devuelve. |
| `corrupt-encoding`, `no-condition`, `compile-error`, `compile-dependency` | Dañado o no compila | El motor no puede cargarlo ni medirlo. |
| `blocked-module`, `no-engine` | Módulo bloqueado o sin motor | No hay forma segura de ejecutarlo. |
| `license-changed` | La licencia cambió | Es una cuestión legal, no de criterio. |
| `dynamic-failure` | Provocó cuelgue, tiempo agotado o regresión | La prueba dinámica falló: es un hecho medido. |
| `previously-rejected`, `rejected-by-reviewer` | Mismo contenido rechazado antes | La decisión humana se mantiene mientras los bytes sean los mismos. |

Un archivo cambiado es un candidato nuevo (clave `(sha256, path)`) que no hereda aprobaciones; solo se muestra la versión anterior como precedente. {{ev:EV-YC-41}}

**Registro de decisiones.** Cada decisión escribe una entrada de auditoría en el mismo lote atómico de D1. El hash de cada entrada es `SHA-256(hash_anterior + JSON canónico de la entrada)`, empezando por 64 ceros (`chainHash`, `GENESIS` en `core.js`). `verifyChain` falla si se edita, borra o reordena una entrada (`/api/audit/verify`, solo ADMIN). Qué no evita: alguien con control total de la base de datos podría reescribir **toda** la cadena; por eso existe el diseño de anclas (ver Estado). {{ev:EV-YC-42}}

## Cómo comprobarlo tú

El código del panel y sus pruebas son públicos. Desde un clon del repositorio:

```bash
python3 -m unittest tests.test_admission tests.test_decide
cd admin/worker && npm test
```

Ejecutados el 2026-10-22 sobre `main`: las pruebas Python de este tema (112 pruebas, junto con las de firma y registro) pasaron, y `node --test test/service.test.js test/policies.test.js test/anchor.test.js` en `admin/worker` dio 113 correctas y 0 fallos. Los códigos se leyeron en `scripts/rulecheck.py`, `scripts/decide.py` y `admin/worker/src/core.js`. Código: [core.js](https://github.com/MacGuard/macguard-yara-channel/blob/main/admin/worker/src/core.js), [decide.py](https://github.com/MacGuard/macguard-yara-channel/blob/main/scripts/decide.py), [rulecheck.py](https://github.com/MacGuard/macguard-yara-channel/blob/main/scripts/rulecheck.py). Detalle del panel público: [admin-panel](https://github.com/MacGuard/macguard-yara-channel/blob/main/docs-src/en/admin-panel.md).

## Límites

- Un archivo "validado" no es una garantía de calidad de detección ni de ausencia de falsos positivos.
- Los detalles de reglas en cuarentena (nombres, hallazgos, contenido) van solo al servicio privado; lo público lleva recuentos.
- El Worker no verifica firmas Sigstore; las verifica `publish.yml`. El Worker solo recalcula `rules_root` del manifiesto público.

## Estado

| Capacidad | Estado |
|---|---|
| Clasificación, decisión y hallazgos no aprobables en el pipeline | operational {{ev:EV-YC-41}} |
| Panel desplegado: aprobar, rechazar, retener, cadena de auditoría | operational {{ev:EV-YC-05}} |
| Memoria persistente de decisiones, retirada de reglas publicadas (`policies`, migración 0003) | implemented-not-deployed {{ev:EV-YC-43}} |
| Anclas de auditoría (`audit_anchor`, migración 0004) | implemented-not-deployed {{ev:EV-YC-44}} |
| Propuestas de fuentes (migración 0005) | implemented-not-deployed {{ev:EV-YC-07}} |

Las migraciones 0003, 0004 y 0005 no están aplicadas. El Worker de `main` tolera que falten (las lecturas responden "sin políticas"), pero en producción **no existen** retiradas persistentes, políticas ni anclas. Además, en `main` el pipeline (`decide.py`) no lee todavía políticas: no se encontró `blocked-by-policy` en `scripts/`, así que una retirada registrada no se aplicaría aún a la siguiente release. Tampoco existe acción `reopen`: nada saca un candidato de `REJECTED`. Diseño: [especificación](https://github.com/MacGuard/macguard-yara-channel/blob/main/docs/audit/quarantine-decision-memory-and-withdrawal-spec.md) (su cabecera dice "solo diseño"; el código de `policies.js` y `anchor.js` ya está en `main`). {{ev:EV-YC-43}} {{ev:EV-YC-06}}
