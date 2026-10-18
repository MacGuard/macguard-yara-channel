---
title: Panel privado
summary: El servicio de revisión: roles, autenticación y garantías.
---
## Roles

| Rol | Origen | Puede |
|---|---|---|
| VIEWER | Concesión explícita de un ADMIN. | Leer candidatos, contenido, decisiones y estadísticas. |
| REVIEWER | Permiso `write` o `maintain` en el repositorio de GitHub. | Lo del VIEWER, y aprobar, rechazar, marcar en revisión, pedir nueva prueba y leer la auditoría. |
| ADMIN | Permiso `admin` en el repositorio. | Todo, además de gestionar miembros y verificar la cadena de auditoría. |

Leer un repositorio público no concede ningún rol. El rol se recalcula desde GitHub en cada petición protegida (caché de 60 s); si GitHub no responde durante más de 10 minutos se deniega el acceso. Nadie puede cambiar su propio rol.

## Garantías

- Sesiones en el servidor; el token de GitHub no llega al navegador. Cookie con prefijo `__Host-`, `HttpOnly; Secure; SameSite=Strict`.
- Las acciones que cambian estado exigen el token CSRF de la sesión y un `Origin` del mismo origen.
- Cada decisión lleva un `request_id` idempotente y las versiones que vio quien decide; una vista caducada se rechaza sin cambiar nada.
- Decisión, entrada de auditoría y una guarda que aborta todo si algún cambio no se aplicó son un único lote atómico de D1.
- El registro de auditoría está encadenado por hash: editar, quitar o reordenar una entrada hace fallar `/api/audit/verify`.
- Los workflows se identifican con su token OIDC (`daily.yml` puede enviar candidatos, `publish.yml` puede marcar releases, solo desde `main`); no hay secreto compartido.

> **LÍMITE** El código y las pruebas existen en `admin/worker/`. **No está desplegado**: hace falta una persona con credenciales de Cloudflare (Workers y D1) y crear una aplicación OAuth de GitHub; los pasos están en `docs/OPERATIONS.md`. Hay que confirmar con el tipo de aplicación OAuth que `GET /repos/{repo}` devuelve `permissions` antes de fiarse de los roles.
