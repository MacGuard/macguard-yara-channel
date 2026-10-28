# Monitor de cuotas y costes: puesta en marcha (2026-10-27)

> **ESTADO ACTUAL: `NOT_CONFIGURED`. NO EXISTE VIGILANCIA ACTIVA DE GASTO NI DE CUOTAS.** Faltan los cuatro secretos del entorno `macguard-monitoring` y la variable `USAGE_MONITOR_ENABLED` no está fijada, así que el monitor y el vigilante se omiten por diseño. Ningún umbral (50/75/90/100 % ni 20/50/100/150 €) avisa a nadie hasta completar esta puesta en marcha: el consumo de Cloudflare, Backblaze y Scaleway debe revisarse a mano. Que el workflow aparezca en verde **no** significa que se esté vigilando nada: lo indica el resumen del job `status`.


Workflow: `.github/workflows/usage-monitor.yml` (cron `17 * * * *`, entorno `macguard-monitoring`, restringido a la rama `main`). Código: `scripts/usage_monitor.mjs`. Límites: `config/usage-limits.json`.

## Estado

| Pieza | Estado |
|---|---|
| Entorno `macguard-monitoring` | CREADO, sin secretos, solo desplegable desde `main` |
| Consultas de analítica (D1, Workers, R2, almacenamiento D1) | VERIFICADAS contra la API real de Cloudflare (7/7, conciliadas con `d1_budget.mjs usage`) usando la sesión de wrangler del propietario, solo lectura, sin consultar D1 |
| Antigüedad de la última pipeline diaria (GitHub API) | Consulta verificada; alerta a 36/54/65 h |
| Telegram | **NO verificado**: faltan `TELEGRAM_BOT_TOKEN` y `TELEGRAM_CHAT_ID` |
| Ejecución del workflow en Actions | **NO realizada**: faltan los secretos y el workflow no está en `main` |
| Euros | **Sin fuente conectada** (véase abajo). No se muestra 0 €: se muestra «sin dato» |

El monitor **no es operativo** hasta que llegue una notificación real a Telegram desde una ejecución de Actions.

## Qué vigila y cómo avisa

- Cuotas D1/Workers/R2 a 50/75/90/100 % y **proyección** del día UTC; **consumo anómalo** (subida ≥ 10 % del límite diario entre dos ejecuciones); antigüedad de la pipeline diaria.
- Una métrica que no se puede leer avisa **una vez al día** como «sin dato … No es 0»; si no se puede leer **ninguna**, el monitor se declara ciego y el job falla.
- Un importe desconocido o mal formado nunca suma 0: la moneda queda «unknown» con el motivo. Sin fuente de importes el informe dice `NO_SOURCE`.
- **Vigilante** (`usage-watchdog.yml`, cron propio cada 2 h): si el monitor no tiene una ejecución correcta en las últimas 3 h avisa por Telegram (una vez al día) y falla el job. Límite: ambos viven en GitHub Actions; una caída de Actions, o que GitHub desactive los workflows programados tras 60 días sin actividad, los silencia a la vez. Solo un latido externo lo cubriría y exige un tercero a elegir por el propietario.
- Respaldo sin secreto: cualquier alerta crítica, no entregable, o el monitor ciego hacen fallar el job y GitHub envía correo a los administradores del repositorio.

## 1. Token de analítica de Cloudflare (solo lectura)

Cloudflare → My Profile → API Tokens → Create Token → Custom token:

- Account · **Account Analytics · Read**
- Account Resources: solo la cuenta de MacGuard. Sin IP ni TTL si se quiere que dure; recomendable caducidad de 1 año.
- **Solo** ese permiso: el tamaño de las bases también sale de la analítica GraphQL. **No** añadir D1 (ni Read ni Edit), Workers Scripts ni Admin.

## 2. Bot de Telegram

1. En Telegram, `@BotFather` → `/newbot` → guarda el token (no lo pegues en el chat de Claude; si lo pegas, hay que rotarlo).
2. Abre una conversación con el bot nuevo y envíale cualquier mensaje.
3. El `chat_id` se obtiene con `getUpdates`. Ejecuta esto tú mismo, sin pegar la salida con el token:
   `! read -rs T; curl -s "https://api.telegram.org/bot$T/getUpdates" | jq '.result[].message.chat | {id, type}'`

## 3. Secretos del entorno

**Recomendado: el ayudante** (`scripts/monitoring_setup.sh`; ningún valor pasa por argumentos, logs ni por el chat de Claude):

```
! sh scripts/monitoring_setup.sh status          # qué secretos existen (solo nombres) y estado de la variable
! sh scripts/monitoring_setup.sh telegram-chat   # pide el token del bot en silencio; imprime SOLO ids de chat y tipos
! sh scripts/monitoring_setup.sh secrets         # crea los que falten (gh pide cada valor y no lo muestra)
! sh scripts/monitoring_setup.sh test            # envía UN mensaje fijo de prueba; comprueba tu móvil
```

El ayudante **no activa** el monitor (nunca fija `USAGE_MONITOR_ENABLED`) y `test` se niega si falta algún secreto. Activarlo es un paso manual y posterior (sección 3b), solo tras ver llegar el mensaje a tu móvil y una ejecución correcta con datos reales.

Manualmente, cada comando pide el valor por la entrada estándar (no queda en el historial ni en pantalla):

```
! gh secret set CLOUDFLARE_ANALYTICS_TOKEN --env macguard-monitoring
! gh secret set CLOUDFLARE_ACCOUNT_ID      --env macguard-monitoring
! gh secret set TELEGRAM_BOT_TOKEN         --env macguard-monitoring
! gh secret set TELEGRAM_CHAT_ID           --env macguard-monitoring
```

`CLOUDFLARE_ACCOUNT_ID` no es secreto, pero se guarda aquí para que no esté en el código.

## 3b. Activar el monitor

Los crons están **omitidos** hasta que exista la variable de repositorio `USAGE_MONITOR_ENABLED=true` (Settings → Secrets and variables → Actions → Variables, o `! gh variable set USAGE_MONITOR_ENABLED --body true`). Ponla **después** de los secretos y de la prueba manual del apartado 4; las ejecuciones manuales (`workflow_dispatch`) funcionan siempre. Para parar el monitor: borra la variable.

| `USAGE_MONITOR_ENABLED` | Ejecución programada | Qué se ve |
|---|---|---|
| ausente, vacía, `false`, `0`, `yes`… | el job `monitor` y el `watchdog` se **omiten**: ni consultas a Cloudflare ni avisos ni correos | el job `status` (sin secretos, no falla) escribe `NOT_CONFIGURED` en el resumen de cada run |
| `true` (GitHub compara sin distinguir mayúsculas) | corren | un fallo es **real**: el job falla y GitHub envía correo. Con secretos que faltan, el error dice `NOT_CONFIGURED: missing <NOMBRES>` (solo nombres, nunca valores) |

Las ejecuciones manuales (`workflow_dispatch`) no dependen de la variable. El vigilante cuenta como latido **solo** los runs programados exitosos: una simulación o un mensaje de prueba manuales no lo engañan.

## 4. Primera ejecución (tras fusionar el PR del monitor)

1. Actions → *Usage and cost monitor* → Run workflow, **sin** `simulate`. No toca D1 (solo analítica) ni escribe en Cloudflare.
2. Con los valores reales la ejecución sale con código 0 y **no envía mensaje** si todo está bajo el 50 %. Para probar el canal, ejecutar con `simulate=tests/fixtures/usage/d1-critical.json`: en simulación el envío es solo un `console.log`. **Prueba real del canal:** `workflow_dispatch` con `simulate` vacío y un umbral temporalmente bajado no es aceptable (cambia la política); usa la entrada `test_message`: envía un mensaje fijo de prueba por el canal real (sin analítica, sin estado).
3. Criterio de operativo: mensaje recibido en el móvil + artefacto `usage-report-<run>` + caché de estado restaurada en la siguiente hora.

## Fuentes de coste (€)

| Fuente | Qué da | Estado |
|---|---|---|
| Cloudflare (plan gratuito) | Cuotas, no importes | No hay euros que leer. Las alertas oficiales de facturación/uso de Cloudflare se configuran en el panel (Notifications → Billing / Usage) y se concilian con GuardOps; **no verificado** |
| GitHub Actions | Minutos y almacenamiento | PLANNED (API de uso de facturación; requiere permiso de facturación) |
| Backblaze B2 | Almacenamiento y descargas (unidades) | PLANNED; el importe lo calcula el proveedor, no se estima sin tarifa del propietario |
| Scaleway | API de facturación (importes en EUR) | PLANNED; es la única fuente con importes confirmados |
| Costes fijos | Dominio, etc. | Los declara el propietario en un fichero; hoy no existen |

Reglas: confirmado (factura) ≠ estimado (cantidad × tarifa aportada) ≠ pendiente de consolidar; moneda e impuestos por separado; un producto sin fuente aparece como «sin dato», nunca como 0 €.

## Contención a 150 €

Solo se **notifica y simula**. No hay medidas automáticas activas. Diseño propuesto (sin activar): un fichero de estado `containment` en un entorno de Actions que los workflows no esenciales (`publish-expedited` no protector, backups extra, barridos) consultan al empezar y rechazan; la distribución de releases firmadas, las alertas y el acceso administrativo no lo consultan nunca. Reactivación: manual, por una identidad con permiso, con motivo registrado. Cloudflare no garantiza un tope de facturación.

## Pendiente

- Fuentes de importes (Scaleway primero).
- Vigilar la propia ausencia del monitor: el cron de GitHub puede saltarse ejecuciones; hoy solo lo detectan los artefactos históricos. Opción: heartbeat externo, que requiere un tercero y la decisión del propietario.
