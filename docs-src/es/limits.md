---
title: Límites y pendientes
summary: Qué está implementado, qué es solo propuesta, qué está bloqueado y los defectos conocidos.
---
## Estado por componente

| Componente | Estado |
|---|---|
| Recolección, validación estática y dinámica, decisión, firma, publicación, sitio | **ACTUAL**: probado en producción con publicación automática (`AUTO_PUBLISH=true`). |
| Verificador público | **ACTUAL**: 29 pruebas y verificada sobre las releases reales. |
| Servicio de cuarentena y panel | Implementado y probado en local; **no desplegado**. |
| Cloudflare Pages automático | **Bloqueado**: la credencial del repositorio no es válida. |
| Máquina virtual macOS independiente | **No disponible**: requiere un Mac físico propio. |
| Firma Developer ID y notarización de la app | Pendiente. |
| Releases inmutables de GitHub | Desactivadas; requieren autorización. |
| Atestaciones SLSA / in-toto | **No existen.** |
| Verificador firmado y adjunto a cada release | **PROPUESTA** |

## Defectos conocidos

Registrados aparte; esta documentación describe el comportamiento real y no los corrige en silencio.

- Diez ficheros de la primera release están retenidos desde la segunda: 6 no superan la clasificación estática (reproducido fuera de CI) y 4 dependen de un fichero de biblioteca que la revisión en CI excluyó; esa exclusión no se ha podido reproducir en local y el motivo detallado solo existe en el almacén privado, que aún no está desplegado.
- La puerta de Linux usa el YARA de Ubuntu 4.5.0 y la app {{tool.yara}}: la clasificación estática coincide con ambos, así que la diferencia de motor no explica esos 4 ficheros.
- `manifest.rejected` está siempre vacío en las releases nuevas: los rechazos se cuentan en el registro, no en el manifiesto.
- La primera release catalogada no tiene `checkpoint.txt` ni su firma entre los artefactos; el verificador usa el checkpoint del repositorio como alternativa.
- El significado de `expanded` en las estadísticas es el tamaño de los ficheros de reglas descomprimidos, que no coincide con el total de bytes del archivo tar.

## Bloqueado y a la espera de una persona

- Un token de Cloudflare válido (`CLOUDFLARE_API_TOKEN` con Cloudflare Pages: Edit) y `CLOUDFLARE_ACCOUNT_ID` como secretos del repositorio.
- Credenciales de Workers y D1 y una aplicación OAuth de GitHub para desplegar el panel privado; luego la variable `QUARANTINE_URL`.
- Certificado Developer ID y notarización.
- Activar las releases inmutables.
- Un Mac físico propio para la prueba en una máquina virtual independiente.
