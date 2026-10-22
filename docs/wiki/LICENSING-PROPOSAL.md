# Propuesta de licencias (para decisión del propietario)

Estado: **propuesta**. No se modifica `LICENSE` (no existe) ni se atribuye ningún permiso de reutilización. No es asesoramiento jurídico: conviene una revisión legal antes de fijar nada.

## Situación comprobada
- El repositorio **no tiene fichero de licencia**. Sin licencia, el contenido original queda con todos los derechos reservados; ser público en GitHub permite verlo y bifurcarlo según las condiciones de la plataforma, no reutilizarlo.
- Las reglas YARA de terceros que el canal redistribuye tienen licencia propia, registrada en `config/policy.json` y comprobada por `scripts/licensing.py` en cada ejecución: `Neo23x0/signature-base` bajo Detection Rule License (DRL-1.1, "allowed-with-attribution") y `Yara-Rules/rules` bajo GPL-2.0 ("allowed-with-license-notice").
- Mermaid está incluido en `web/vendor/` con su licencia MIT (`mermaid-LICENSE.txt`).

## Propuesta diferenciada por tipo de material

| Material | Quién tiene los derechos | Opciones a decidir | Nota |
|---|---|---|---|
| Código propio (scripts, panel `admin/worker`, app `DMGTrustAuditor`) | El propietario | MIT, Apache-2.0 u otra | Apache-2.0 añade concesión de patentes; MIT es más simple. Decisión de producto y legal |
| Documentación original y wiki (texto) | El propietario | CC BY 4.0 o CC BY-SA 4.0 | Con CC BY-SA los derivados deben compartirse igual |
| Diagramas Mermaid originales | El propietario | Igual que la documentación | Texto plano, versionado en el repositorio |
| Reglas YARA de terceros | Sus autores | **No relicenciar.** Mantener la licencia y los avisos de origen en cada release | Revisar con asesoría el efecto de redistribuir contenido GPL-2.0 junto a otros materiales en un mismo paquete |
| Dependencias vendorizadas (Mermaid) | Sus autores | Conservar su licencia y su fichero | Ya incluido |
| Imágenes de terceros | No hay | Solo con licencia verificada y atribución | La wiki no incluye ninguna |

## Qué hay que decidir antes de publicar la wiki
1. Licencia del texto y los diagramas de la wiki (hasta entonces, las páginas dicen "licencia pendiente").
2. Licencia del código, para poder añadir `LICENSE`.
3. Revisión legal de la redistribución conjunta de reglas con licencias distintas.

No se ha aplicado ninguna de estas decisiones.
