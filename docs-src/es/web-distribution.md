---
title: Sitio web y distribución
summary: URLs públicas, qué sirve cada sitio y el estado real del despliegue en Cloudflare.
---
## Direcciones públicas

| Qué | GitHub Pages (principal) | Cloudflare Pages (réplica) |
|---|---|---|
| Web | https://macguard.github.io/macguard-yara-channel/ | https://macguard-rules.pages.dev/ |
| Reglas YARA | https://macguard.github.io/macguard-yara-channel/rules.html | https://macguard-rules.pages.dev/rules |
| Transparencia | https://macguard.github.io/macguard-yara-channel/transparency.html | https://macguard-rules.pages.dev/transparency |
| Documentación | https://macguard.github.io/macguard-yara-channel/docs/index.html | https://macguard-rules.pages.dev/docs/index.html |

Ambos sirven los mismos bytes; GitHub Releases es el archivo canónico. Los datos que muestra la web (catálogo, historial, transparencia) se derivan de manifiestos firmados.

## Qué hace `site.yml`

1. Descarga la release y el historial, construye el sitio y verifica la release exactamente como lo haría un cliente (`verify_release.py`).
2. Despliega GitHub Pages y después comprueba la URL pública con `verify_live.py`: paquete, cada fichero de reglas, catálogo, firmas, pruebas y enlaces.
3. Intenta Cloudflare Pages solo si las credenciales existen y pasan una comprobación previa que no imprime secretos.
4. Registra el resultado en el registro de transparencia.

> **LÍMITE** **Cloudflare no está automatizado.** El secreto `CLOUDFLARE_API_TOKEN` del repositorio no es un token de Cloudflare válido y el workflow lo clasifica como `site.cloudflare_blocked`. El sitio de `pages.dev` se ha desplegado **a mano** con la sesión local de `wrangler` de la persona responsable; eso no equivale a un despliegue automático correcto. El problema sigue abierto hasta que se configure una credencial válida (`CLOUDFLARE_API_TOKEN` con permiso Cloudflare Pages: Edit y `CLOUDFLARE_ACCOUNT_ID`).

## Vista previa al compartir

Cada página lleva metadatos Open Graph y de tarjeta de X con una imagen de 1200 × 630 y URLs absolutas del sitio que la sirve; `scripts/og_inject.py` los escribe para GitHub Pages y para la réplica.
