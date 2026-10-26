# Despliegue controlado del panel multifamilia + RBAC (preparado, NO ejecutado)

Requisitos previos: PR de integración verde y fusionado por el propietario (rama protegida, sin saltarla); la matriz RBAC (`docs/rbac/MATRIX.md`) revisada por el propietario.

| # | Paso | Verificación |
|---|---|---|
| 1 | Anotar la versión activa del Worker (`macguard-quarantine`) para el rollback (hoy `6a198275-dd61-41e7-8d0c-3ca9168d806b`, anterior `3d99e5f9`) | versión anotada en el informe de despliegue |
| 2 | `sh admin/worker/tools/local_backup.sh` **justo antes** (copia nueva, cifrada y releída) | «read-back hash matches: VERIFIED»; guardar la ruta |
| 3 | Comprobar que no hay políticas ni prórrogas (el guardián de 0006 se niega si las hay): `SELECT COUNT(*) FROM policies` y `policy_lifts` | 0 y 0; si no, **parar** y decidir con el propietario |
| 4 | Aplicar al panel `0006_five_roles.sql` y después `0007_source_requests.sql` (`wrangler d1 execute macguard-quarantine --remote --file …`) | recuentos idénticos; `/api/audit/verify` ok |
| 5 | Aplicar a INTEL `migrations-intel/0002_decisions.sql` (la base se puede regenerar con `intel_promote.py`; la 0002 solo añade) | recuento de `intel_records` = 75.148 |
| 6 | Desplegar el Worker: `WRANGLER_CONFIG=wrangler.production.toml npm run deploy` (la copia local de producción, con los enlaces DB e INTEL) | `/readyz` y la versión nueva |
| 7 | Con la sesión del propietario: Panel, Cuarentena/Publicadas (otras familias), Fuentes, Logs (tres pestañas), Administración → Usuarios y permisos | cada pantalla carga; una decisión de prueba en un registro y su entrada de auditoría |
| 8 | Si algo falla: redeploy de la versión anotada en 1 (el Worker anterior funciona con el esquema nuevo: comprobado). Las migraciones **no** se revierten salvo orden expresa (`*_rollback.sql` borra las decisiones y solicitudes: exportarlas antes) | panel anterior operativo |

Orden alternativo seguro: como el Worker nuevo tolera la ausencia de las migraciones (503 que nombra la migración, o estado importado sin decisiones), puede desplegarse antes y aplicarlas después.

No declarar nada como publicado: lo «aprobado» solo queda aprobado para una futura publicación.


## Presupuesto de D1 y orden revisado (tras el incidente del 26/10)

Estimación (filas): backup local del panel ~2.000 lecturas, 0 escrituras; panel 0006 + 0007 < 100 escrituras; INTEL 0002 + 0003 < 100 escrituras y 0 lecturas (la columna nueva y el índice parcial nacen vacíos), más **una** pasada de instantánea de ~75.000 lecturas la primera vez que el Worker nuevo lo pida. Total previsto ≈ 80.000 lecturas (1,6 % de la cuota) y < 300 escrituras (< 0,3 %).

1. Tras las 00:00 UTC, **solo consultas mínimas**: `/public/stats` y una lectura de recuentos del panel. Anotar el consumo con `node admin/worker/tools/d1_budget.mjs usage`.
2. **Desplegar primero el Worker** (no consume D1): el Worker nuevo ya no recorre la tabla en cada pantalla. Hasta entonces, **no abrir Panel ni Inteligencia en el Worker actual**: cada carga cuesta ~400.000 lecturas y la cuota son 5.000.000.
3. `local_backup.sh` (con preflight de presupuesto) y verificación del descifrado.
4. Recuentos reales: miembros, políticas, levantamientos, decisiones.
5. Ensayo con el fixture (`migration_trial2.sh`): medir lo que escribe el `ALTER TABLE` de 0003; si no es independiente del tamaño de la tabla, usar tabla lateral.
6. Aplicar 0006, 0007 (panel) y 0002, 0003 (INTEL), verificando recuentos tras cada una.
7. Si el preflight o el consumo del día no lo permiten, **parar** y reintentar al día siguiente: no se sacrifica la disponibilidad.
