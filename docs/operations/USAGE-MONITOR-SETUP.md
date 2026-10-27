# Monitor de cuotas y costes: puesta en marcha (2026-10-27)

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

## 1. Token de analítica de Cloudflare (solo lectura)

Cloudflare → My Profile → API Tokens → Create Token → Custom token:

- Account · **Account Analytics · Read**
- Account · **D1 · Read** (solo para el tamaño de las bases; no concede escritura)
- Account Resources: solo la cuenta de MacGuard. Sin IP ni TTL si se quiere que dure; recomendable caducidad de 1 año.
- **No** añadir D1 Edit, Workers Scripts Edit ni Admin.

## 2. Bot de Telegram

1. En Telegram, `@BotFather` → `/newbot` → guarda el token (no lo pegues en el chat de Claude; si lo pegas, hay que rotarlo).
2. Abre una conversación con el bot nuevo y envíale cualquier mensaje.
3. El `chat_id` se obtiene con `getUpdates`. Ejecuta esto tú mismo, sin pegar la salida con el token:
   `! read -rs T; curl -s "https://api.telegram.org/bot$T/getUpdates" | jq '.result[].message.chat | {id, type}'`

## 3. Secretos del entorno

Cada comando pide el valor por la entrada estándar (no queda en el historial ni en pantalla):

```
! gh secret set CLOUDFLARE_ANALYTICS_TOKEN --env macguard-monitoring
! gh secret set CLOUDFLARE_ACCOUNT_ID      --env macguard-monitoring
! gh secret set TELEGRAM_BOT_TOKEN         --env macguard-monitoring
! gh secret set TELEGRAM_CHAT_ID           --env macguard-monitoring
```

`CLOUDFLARE_ACCOUNT_ID` no es secreto, pero se guarda aquí para que no esté en el código.

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
