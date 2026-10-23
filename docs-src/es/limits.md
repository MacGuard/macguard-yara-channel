---
title: Límites y pendientes
summary: Qué está implementado, qué es solo propuesta, qué está bloqueado y los defectos conocidos.
---
## Estado por componente

| Componente | Estado |
|---|---|
| Recolección, validación estática y dinámica, decisión, firma, publicación, sitio | **ACTUAL**: probado en producción con publicación automática (`AUTO_PUBLISH=true`). |
| Verificador público | **ACTUAL**: 29 pruebas y verificada sobre las releases reales. |
| Servicio de cuarentena y panel | **ACTUAL**: desplegado. Las políticas, los anclajes de auditoría y las propuestas de fuentes (migraciones 0003 a 0005) están en `main` y **no desplegados**. |
| Cloudflare Pages automático | **ACTUAL**: desplegado por el workflow y verificado con `verify_live.py`. |
| Máquina virtual macOS independiente | **No disponible**: requiere un Mac físico propio. |
| Firma Developer ID y notarización de la app | Pendiente. |
| Releases inmutables de GitHub | Desactivadas; requieren autorización. |
| Atestaciones SLSA / in-toto | **No existen.** |
| Verificador firmado y adjunto a cada release | **PROPUESTA** |

## Defectos conocidos

Registrados aparte; esta documentación describe el comportamiento real y no los corrige en silencio.

- Diez ficheros de la primera release están retenidos desde la segunda: 6 no superan la clasificación estática (reproducido fuera de CI) y 4 dependen de un fichero de biblioteca que la revisión en CI excluyó; esa exclusión no se ha podido reproducir en local y el motivo detallado solo existe en el almacén privado.
- La puerta de Linux usa el YARA de Ubuntu 4.5.0 y la app {{tool.yara}}: la clasificación estática coincide con ambos, así que la diferencia de motor no explica esos 4 ficheros.
- `manifest.rejected` está siempre vacío en las releases nuevas: los rechazos se cuentan en el registro, no en el manifiesto.
- La primera release catalogada no tiene `checkpoint.txt` ni su firma entre los artefactos; el verificador usa el checkpoint del repositorio como alternativa.
- El significado de `expanded` en las estadísticas es el tamaño de los ficheros de reglas descomprimidos, que no coincide con el total de bytes del archivo tar.

- `evidence` en el manifiesto es la declaración firmada del workflow de publicación de que la medición dinámica pertenece al conjunto publicado. No es una atestación independiente in-toto ni SLSA de todo el proceso; esas no se producen.

## Bloqueado y a la espera de una persona

- Aplicar las migraciones 0003 a 0005 y desplegar la versión correspondiente del Worker (políticas, anclajes de auditoría, propuestas de fuentes) en el panel privado.
- Certificado Developer ID y notarización.
- Activar las releases inmutables.
- Un Mac físico propio para la prueba en una máquina virtual independiente.
