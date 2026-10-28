# Protección de `main`: propuesta de diseño (2026-10-28)

**Estado: PROPUESTA. No se ha activado nada sobre `main`.** Hoy `main` tiene la protección clásica (sin force-push, sin borrado, `enforce_admins=false`) y **ningún** check requerido ni ruleset. Este documento recoge lo medido, el diseño y lo que falta decidir.

## 1. Cómo escriben hoy los cinco workflows

La identidad «`macguard-evidence[bot]`» / «`macguard-log[bot]`» es **solo la etiqueta de autor de git** (`git config user.name`). Quien autentica el push es el `GITHUB_TOKEN` del workflow, es decir la app `github-actions`. No existe ninguna app ni PAT propios.

| Workflow | Job que escribe | Permisos del token | Script | Ruta que añade | Cola |
|---|---|---|---|---|---|
| `daily.yml` (cron 03:17) | revisión diaria | `contents: write`, `id-token: write` | `scripts/commit_logs.sh` | `logs/` | `macguard-log` |
| `publish.yml` (manual) | publicación | `contents: write`, `id-token: write` | `scripts/commit_logs.sh` | `logs/` | `macguard-log` |
| `site.yml` (push a `main`) | despliegue del sitio | `contents: write` (sin secretos de Cloudflare) | `scripts/commit_logs.sh` | `logs/` | `macguard-log` |
| `backup.yml` (manual/programado) | `record` | `contents: write`, `actions: read` | `gateway/tools/commit_evidence.sh` | `evidence/backups.jsonl` | `macguard-log` |
| `record-restore.yml` (manual) | registro de restauración | `contents: write` | `gateway/tools/commit_evidence.sh` | `evidence/backups.jsonl` | `record-restore-<run>-<proveedor>` |

El resto de jobs de esos workflows tienen `contents: read` y los permisos por defecto del repositorio son `read`. Los scripts hacen `git add` de **una ruta fija** (`logs` o `evidence/backups.jsonl`), pero eso es una convención del script, no una restricción del servidor.

Volumen observado en `main`: 14 commits de evidencia y 166 rutas de `logs/` firmados por esas dos etiquetas; cero commits de bots fuera de `logs/` y `evidence/`.

## 2. Lo que se midió (laboratorio, no `main`)

Rulesets activos **solo** sobre `exp/ruleset-lab` y `exp/ruleset-del`; un workflow ejecutó los **scripts reales** de producción con el `GITHUB_TOKEN` por defecto. Los rulesets y las ramas se han borrado al terminar (0 rulesets, 0 ramas `exp/`).

| Sonda | Sin reglas | Con reglas (universal + check requerido) |
|---|---|---|
| P1 `commit_logs.sh` | permitido | **bloqueado** (GH013, check `lab-required` esperado) |
| P2 `commit_evidence.sh` | permitido | **bloqueado** |
| P3 commit de código arbitrario | permitido | **bloqueado** |
| P4 force-push real (reescribe el remoto) | permitido | **bloqueado** («Cannot force-push to this branch», también para el administrador) |
| P5 borrar rama protegida | permitido | **bloqueado** |
| P6 mismo token a una rama **sin** proteger | permitido | permitido |
| Push del administrador (humano) | n/a | permitido con «Bypassed rule violations» |
| Recuperación: poner `enforcement=disabled` por API | todo vuelve a pasar | n/a |

Limitaciones de la plataforma comprobadas contra la API real de este repositorio (público, cuenta personal):

1. **`github-actions` no puede ser actor de bypass**: «Actor GitHub Actions integration must be part of the ruleset source or owner organization».
2. **No hay reglas de push** (restricción por ruta): «Source public repos cannot have push rules».
3. Por tanto **un check requerido en `main` bloquearía los cinco workflows** (P1, P2) y no se puede darles una excepción por ruta.

Incidencia de la propia prueba: la primera sonda de force-push era una operación nula (empujaba la punta actual) y daba un falso «permitido». Se corrigió para que reescriba el historial y se añadió una guarda (si el remoto no cambia, no cuenta). La captura del motivo del P4 en el resumen de CI quedó vacía; el motivo se confirmó reproduciéndolo desde local.

## 3. Diseño: tres capas separadas

**Capa U, reglas universales** (ruleset `main-universal`, **sin ningún bypass**): `deletion` y `non_fast_forward`. Se aplica a todos, bots y administradores. La recuperación es editar o deshabilitar el ruleset (sección 6), no saltárselo.

**Capa C, requisitos de CI para cambios de código** (ruleset `main-ci`): `required_status_checks` con `gateway-tests` (nombre estable; el job no tiene `if:` ni `continue-on-error`, y el techo de omisiones `ci-skip-ceiling.txt` hace fallar los saltos silenciosos). Bypass: solo el rol de administrador del repositorio. No se añade revisión obligatoria de PR (el propietario es único) ni se tocan los checks `python-tests` y `quarantine-service` sin decisión expresa.

**Capa E, excepciones mínimas para automatismos.** Es lo que la plataforma no permite resolver con `GITHUB_TOKEN`. Opciones:

| Opción | Qué hace | Cumple «sin bypass general de código» | Coste / riesgo | Estado |
|---|---|---|---|---|
| **B. Sacar las escrituras de `main`** | `evidence/` a una rama `evidence` y `logs/` a la rama `logs` (ya anticipada en `CODEOWNERS` y en la PR #27), sin protección de CI; `main` queda sin ningún bot que pueda escribir | **Sí, totalmente**: ningún bot puede modificar código | Hay que cambiar lectores: ~15 ficheros leen `logs/` (verificadores, sitio, publicación) y 8 leen `evidence/` (centro de restauración, `restore.js`). Toca la pipeline de producción, requiere su propia PR y aceptación | Mecanismo **probado** (P6); migración **no hecha** |
| **A. App de GitHub propia** como único actor de bypass | El token de la app se genera solo en los 5 jobs de escritura; resto sin cambios | **Parcial**: la app puede empujar cualquier cosa a `main`; la limitan su permiso `contents:write` en este repo y que su clave solo viva en un entorno restringido a `main` | El propietario debe crear la app y guardar su clave como secreto. **No probado**: la API podría aceptarla o no como actor | Requiere acción del propietario |
| **C. Sin check requerido** | Solo capa U + control detectivo | Sí, pero no hay prevención de CI | Una PR sin CI verde sigue pudiendo fusionarse | Situación actual, más U |

**Recomendación**: aplicar **U ya** (no afecta a ningún workflow; verificado: ningún flujo hace force-push ni borra `main`), y para C elegir **B por fases**: primero `evidence/` (3 escritores, 8 lectores, el más pequeño), después `logs/`. Hasta entonces, la capa C se queda sin activar. A solo si el propietario prefiere rapidez sobre pureza.

## 4. Control detectivo (para cualquier opción que deje escritura de bots en `main`)

Un job en `site.yml` o un workflow aparte que, en cada push a `main`, liste los ficheros de los commits cuya etiqueta de autor sea `macguard-*[bot]` y **falle y avise** si tocan algo fuera de `logs/**` y `evidence/backups.jsonl`. Es detectivo, no preventivo (la etiqueta de autor se puede falsear con acceso de escritura), y no sustituye a B.

## 5. Permisos mínimos y riesgos

- Los jobs de escritura deben conservar `contents: write` **solo** en su job, nunca a nivel de workflow (ya es así en los cinco).
- Con A, la clave de la app solo en un entorno restringido a `main` y con `contents: write` únicamente.
- **Riesgo residual de A**: cualquier job con acceso a la clave puede publicar código a `main` sin CI. **Riesgo residual de B**: lectores no migrados leen datos obsoletos; hay que migrar con lectura doble y retirarla después.
- **Riesgo de aplicar C sin E**: parada total de la publicación diaria y del registro de evidencias (probado en P1/P2).

## 6. Recuperación administrativa (si una regla bloquea la infraestructura)

1. Un administrador del repositorio ejecuta, sin necesitar ningún workflow:
   `gh api -X PUT repos/MacGuard/macguard-yara-channel/rulesets/<id> -f enforcement=disabled` (probado en el laboratorio: todo vuelve a pasar al instante).
2. Si el fallo es de CI, empujar como administrador pasa por el bypass de `main-ci` («Bypassed rule violations», probado).
3. Reactivar con `-f enforcement=active` y reejecutar el workflow afectado.
4. `main-universal` no tiene bypass: para una operación excepcional (p. ej. reescribir una rama) se deshabilita el ruleset, se opera y se reactiva. Queda registrado en el log de auditoría del repositorio.

## 7. Plan de activación (nada se ejecuta sin aprobación)

| Paso | Acción | Comprobación | Reversión |
|---|---|---|---|
| 1 | Crear `main-universal` en modo `evaluate` | Ninguna infracción registrada tras un ciclo diario completo | Borrar |
| 2 | Pasarlo a `active` | `daily`, `site`, `backup`, `record-restore` siguen verdes | `enforcement=disabled` |
| 3 | Migrar `evidence/` a rama `evidence` (PR propia, lectura doble) | Un backup y un registro de restauración reales | Revertir la PR |
| 4 | Migrar `logs/` (PR propia, sobre #27) | Un ciclo `daily` + `publish` + `site` reales | Revertir la PR |
| 5 | Crear `main-ci` con `gateway-tests` | Un push de bot a `logs`/`evidence` sigue pasando; una PR roja no se fusiona | `enforcement=disabled` |

## 8. Plantillas (no aplicadas)

```json
{"name":"main-universal","target":"branch","enforcement":"evaluate",
 "conditions":{"ref_name":{"include":["refs/heads/main"],"exclude":[]}},
 "rules":[{"type":"deletion"},{"type":"non_fast_forward"}],"bypass_actors":[]}
```

```json
{"name":"main-ci","target":"branch","enforcement":"active",
 "conditions":{"ref_name":{"include":["refs/heads/main"],"exclude":[]}},
 "rules":[{"type":"required_status_checks","parameters":{"strict_required_status_checks_policy":false,
   "required_status_checks":[{"context":"gateway-tests"}]}}],
 "bypass_actors":[{"actor_id":5,"actor_type":"RepositoryRole","bypass_mode":"always"}]}
```

Antes del paso 1 hay que comprobar que el contexto `gateway-tests` es exactamente el que publica `ci.yml` en un push a `main` (hoy `ci.yml` solo se dispara en `pull_request` y a mano: **un push directo de un bot nunca tendría ese check**, otra razón para sacar a los bots de `main`).
