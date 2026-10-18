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
3. Intenta Cloudflare Pages solo si las credenciales existen y pasan una comprobación previa que no imprime secretos, envía allí cabeceras de seguridad reales (`scripts/csp.py`), descarga y verifica el espejo público con el mismo `verify_live.py` y comprueba que ambos servidores sirven la misma release (`compare_mirrors.py`). Un job de despliegue terminado no se da por un espejo que funciona.
4. Registra el resultado en el registro de transparencia.

> **ACTUAL** **Cloudflare Pages se despliega automáticamente desde el workflow** (desde el 2026-10-18, ejecución con `site.cloudflare_deployed` en el registro) con los secretos `CLOUDFLARE_API_TOKEN` y `CLOUDFLARE_ACCOUNT_ID`, sin depender de ningún equipo local. El proyecto `macguard-rules` está en la cuenta cuyo id figura en `config/cloudflare_account_id.txt`. El sitio, la documentación y el verificador de `pages.dev` se comprueban con `verify_live.py` y sirven los mismos bytes que GitHub Pages. Antes de esa fecha el espejo se desplegó a mano con una sesión local de `wrangler`; eso ya no se usa. Si la credencial falla, el preflight lo clasifica, el workflow anota `site.cloudflare_blocked` y no intenta desplegar.

El sitio se reconstruye y se despliega en los dos servicios tras cada release, con cada cambio de la web o de la documentación y cada 24 horas (04:17 UTC).

## Vista previa al compartir

Cada página lleva metadatos Open Graph y de tarjeta de X con una imagen de 1200 × 630 y URLs absolutas del sitio que la sirve; `scripts/og_inject.py` los escribe para GitHub Pages y para la réplica.
