# Permiso que falta al token de backup (`macguard-backup-production`) — 2026-10-26

**Conclusión:** el token tiene D1 de **solo lectura**. Para exportar hace falta **Account → D1 → Edit** (escritura de D1) sobre la cuenta MacGuard (`9e96e19f…`). No requiere ningún otro permiso.

## Evidencia (sin repetir intentos)

Sonda `d1-token-probe.yml`, ejecución 40243123572 (2026-10-25T23:05Z, contra la base `macguard-gateway`):

| Paso | Resultado |
|---|---|
| Leer la base (`GET /d1/database/<id>`) | HTTP 200 |
| `SELECT 1` (`POST /query`) | HTTP 200 |
| **Una** petición de exportación (`POST /export`, la que hace el backup) | **HTTP 401, código 10000 «Authentication error»** |

Los runs programados de `backup.yml` (2026-10-26T03:57Z gateway y 04:20Z panel) fallan exactamente en el job `export`; los demás jobs se omiten. Ningún proveedor llega a ejecutarse, así que **no se sabe** nada de B2, Scaleway ni R2 más allá de que sus lecturas previas (`fetch`) funcionan.

Contraste: la sesión OAuth del operador (`wrangler`, permisos `d1 (write)`) exporta correctamente las dos bases. Es coherente con que lo que falta es la escritura de D1, pero la causa directa la ha demostrado la sonda, no ese contraste.

## Alcance mínimo y cómo cambiarlo

- Editar el token existente (conserva el valor; no hay que tocar el secreto del Environment): añadir **Account → D1 → Edit**, limitado a la cuenta MacGuard. Nada de Workers, R2 ni DNS.
- Lo hace el propietario en Cloudflare; este trabajo no modifica ese token.
- Después: ejecutar **una** vez `d1-token-probe.yml` (paso 5 debe dar 200) y **una** vez `backup.yml` (`resource` = gateway y panel). No repetir si falla.

## Qué sigue sin estar demostrado

- Copia local del panel: existe y está verificada (`tools/local_backup.sh`, 20261026T145514Z). **No es** una copia de nube.
- Restauraciones reales desde B2, Scaleway y R2, checkpoint externo duradero y Sigstore de punta a punta: pendientes. **No se declara PRODUCTION_VERIFIED.**
