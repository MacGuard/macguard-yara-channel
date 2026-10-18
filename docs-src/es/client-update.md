---
title: Actualización en MacGuard
summary: Cómo la app descarga, verifica e instala las reglas.
---
## Flujo normal

{{diagram:client-update}}

La app no actualiza sola sin consentimiento. Descarga a una carpeta de staging privada con límites de tamaño por fichero, extrae con límites (sin enlaces ni rutas fuera del directorio) y solo activa las reglas cuando **todas** las comprobaciones han pasado.

## Qué comprueba

- Firma Sigstore del manifiesto y del checkpoint con la identidad y el emisor esperados.
- SHA-256 de cada fichero contra el manifiesto firmado, y que no sobra ni falta ninguno.
- `rules_root`, la prueba de inclusión y que el checkpoint coincide con la cabeza del registro del manifiesto.
- Consistencia con el checkpoint de confianza guardado (protección contra retroceso y bifurcación).

## Orígenes

La app descarga primero de GitHub Pages (`https://macguard.github.io/macguard-yara-channel/`) y, solo si ese origen no responde, del espejo de Cloudflare Pages (`https://macguard-rules.pages.dev/`). Cada intento instala de **un único** origen de principio a fin; nunca mezcla ficheros de los dos. Los dos sirven los mismos bytes firmados y la release se verifica igual en ambos casos. Un fallo de verificación no pasa al siguiente origen.

## Motor YARA

MacGuard distribuye su propio motor YARA {{tool.yara}} (con OpenSSL {{tool.openssl}}) en versión universal Intel/ARM. Antes de usar el motor comprueba los hashes de su manifiesto, su firma de código, su versión, su arquitectura y una autoprueba. Cada fichero de reglas se carga en su propio espacio de nombres con las dependencias firmadas.

> **LÍMITE** Firma con Developer ID y notarización de la app, del motor y del `cosign` incluido son pasos de publicación de la app que aún están pendientes.

## Instalación atómica

{{diagram:client-atomic-install}}
