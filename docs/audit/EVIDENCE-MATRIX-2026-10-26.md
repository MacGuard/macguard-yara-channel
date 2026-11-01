# Matriz de evidencias (2026-10-26)

| Línea | Rama / PR | SHA | Pruebas | Estado | Bloqueo |
|---|---|---|---|---|---|
| Multifamilia + RBAC de cinco roles + migraciones + presupuesto D1 | `integration/multifamily-rbac` · #52 (borrador; contiene #50 y #51) | 1960a0c | Worker 331 pasan; UI Chromium/Firefox/WebKit: intel 30/30, multifamily 24/24, restore 42/42, rbac 15/15 (antes), search/rule/ui principal en verde; CI python-tests y quarantine-service en verde sobre fdcada4 | Sin merge ni despliegue | Cuota D1 hasta 00:00 UTC; matriz RBAC pendiente de revisión del propietario |
| Publicación programada / extraordinaria (entrega 1) | `feat/expedited-publication` · #53 (borrador, apilado en #52) | 4c9b6b4 | Worker 352 pasan (21 escenarios nuevos) | Backend + RBAC + migración 0008 | UI, `publish-expedited.yml`, GitHub App y sincronización del estado efectivo |
| Backup de Inteligencia como tercer recurso | en #52 | 1960a0c | verificador de restauración con tests de daño; estado de recuperación por recurso | Configurado; sin primera ejecución | Primera copia tras el reinicio de cuota |
| Token D1 de backup | Environment `macguard-backup-production` | — | Sonda `d1-token-probe.yml` (run 40358495148): verify 200 (user), lectura 200, SELECT 200, **export 200 con `status: active`** | **D1_EXPORT_TOKEN_VERIFIED** (sobre la base del gateway) | Falta confirmar el export del panel y de Inteligencia con la primera ejecución real |

## Migraciones (ensayadas en D1 temporales, no aplicadas en producción)
Panel 0006, 0007, 0008 · INTEL 0002, 0003 (tabla lateral). Informe: `docs/audit/MIGRATION-TRIAL-0006-0007-INTEL0002-2026-10-26.md`; presupuesto y orden: `docs/operations/DEPLOY-MULTIFAMILY-RBAC.md`.

## Consumo D1 medido (26/10, por base)
Inteligencia producción ≈ 4,98 M lecturas (consultas de pantalla sin límite); bases temporales de ensayo ≈ 1,22 M lecturas y 376 k escrituras; panel ≈ 1,1 k; gateway ≈ 1,4 k lecturas y 435 escrituras. Detalle por consulta en `docs/audit/INCIDENT-D1-QUOTA-2026-10-26.md`.

## Disponibilidad comprobada hoy (16:47 UTC)
Gateway `/v1/health` 200 y `/v1/community/releases/latest` 200. Panel `/public/stats` 500 por cuota agotada (la portada estática responde).

## Backups
Local del panel verificado (`20261026T145514Z`). Nube (B2, Scaleway, R2): **ninguna copia todavía** (los runs programados anteriores fallaron en `export`; el token ya exporta). Restauraciones reales y checkpoint externo: pendientes. **No se declara BACKUP_VERIFIED ni PRODUCTION_VERIFIED.**

## Roadmap pendiente
Inspector universal · registry modular con paquetes firmados por fuente · revocaciones verificables · transparency log con pruebas de inclusión/consistencia y ancla independiente (hoy solo cadena de hashes en el panel; las reglas ya tienen log con prueba de inclusión en la release) · UI y workflow de publicación extraordinaria.
