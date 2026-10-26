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
