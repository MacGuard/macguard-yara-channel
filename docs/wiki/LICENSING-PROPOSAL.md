# Propuesta de licencias (para decisión del propietario)

Estado: **propuesta**. No se modifica `LICENSE` (no existe) ni se atribuye ningún permiso de reutilización. No es asesoramiento jurídico: conviene una revisión legal antes de fijar nada.

Los avisos y atribuciones concretos, con su evidencia, están en el borrador `THIRD-PARTY-NOTICES-DRAFT.md` (en inglés, también sin aplicar). Este documento y ese borrador no fijan ninguna licencia.

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

## Cuatro regímenes separados (decisión del propietario)
Se mantienen separados y ninguno se decide aquí: (1) licencia del código propio; (2) licencia de la documentación y los diagramas originales; (3) licencias de las reglas YARA de terceros, que conservan las suyas; (4) licencias de las bibliotecas y componentes que se redistribuyen (Mermaid y lo que lleva dentro, motor YARA, OpenSSL, cosign). Que los paquetes estén firmados no demuestra la propiedad intelectual del proyecto sobre su contenido. La compatibilidad jurídica entre DRL-1.1 y GPL-2.0 sigue **PENDIENTE** de revisión especializada, como riesgo aparte de la documentación pedagógica. Detalle y evidencia: `THIRD-PARTY-NOTICES-DRAFT.md`.

## Cuatro clases de material, cuatro regímenes distintos
1. **Código propio.** Lo escribe el proyecto. Hoy no tiene licencia: todos los derechos reservados. Si se elige una (MIT o Apache-2.0), se aplica solo a este código.
2. **Documentación original (incluida esta wiki).** Texto y diagramas escritos por el proyecto. Se licencia aparte del código (por ejemplo CC BY o CC BY-SA), porque una licencia de software no está pensada para texto.
3. **Reglas de terceros.** Las escriben otras personas u organizaciones y las redistribuye el canal. Cada fuente conserva su licencia y sus avisos. El proyecto **no afirma tener derechos de autor sobre ellas**, ni sobre las de Nextron (Neo23x0/signature-base) ni sobre las de ningún otro proveedor, y no puede relicenciarlas.
4. **Artefactos generados.** Los archivos de una release (paquete, manifiesto, firma, índice) mezclan reglas de terceros con metadatos del proyecto. Qué licencia describe el conjunto y cómo se avisa de la de cada parte está **sin decidir**.

## Pendiente de revisión jurídica (no resuelto)
- Si redistribuir reglas con licencias distintas (DRL-1.1 y GPL-2.0) en un mismo paquete exige avisos separados, un fichero de avisos o una separación en paquetes distintos.
- El alcance de las condiciones de atribución de DRL-1.1 para el uso derivado dentro de los artefactos publicados.
- Si los efectos de GPL-2.0 alcanzan a algo más que a las reglas que la llevan.
- Qué texto de aviso debe acompañar a cada release.
Hasta que una persona cualificada lo revise, la wiki no asegura que la redistribución sea conforme: solo describe lo que el código registra.

## Lo comprobado en la última release (leído el 2026-10-22)
- El paquete `rules-release.tar.gz` de `rules-20261021-39541028283` contiene 1178 ficheros de reglas y `manifest.json`, y **ningún fichero de licencia ni de avisos**. Los assets de la release tampoco incluyen ninguno. No se inspeccionaron releases anteriores.
- Los ficheros de reglas se copian sin modificar (`scripts/prepare.py`) y conservan sus metadatos de autor y licencia. El manifiesto registra repositorio, commit y resultado de la comprobación de licencia, no el texto ni el enlace de la licencia.
- Algunas reglas declaran en sus propios metadatos una licencia distinta de la de su repositorio (por ejemplo CC BY-NC 4.0, Open Government Licence v3, BSD 2-Clause). La comprobación automática del proyecto no lee esas declaraciones. No se ha evaluado su efecto.
- El texto de licencia de `Neo23x0/signature-base` (DRL 1.1) y el de `Yara-Rules/rules` (GPL-2.0) leídos en origen coinciden con los hashes que registra el manifiesto.
- Requisitos resumidos de cada licencia y textos de atribución propuestos (para abogado): `THIRD-PARTY-NOTICES-DRAFT.md`, secciones 2.3 y 3.

## Verificación por fuente y dependencia (estado a 2026-10-22)
Leído en el repositorio. «Comprobado» significa que el dato consta en un archivo; no es una opinión jurídica.

| Elemento | Licencia que consta | Comprobado | Estado |
|---|---|---|---|
| Reglas de `Neo23x0/signature-base` | Detection Rule License 1.1 (el script `licensing.py` busca la marca «Detection Rule License»; `policy.json` la clasifica «allowed-with-attribution») | La marca se busca en cada ejecución | **PENDING**: la clasificación «allowed» es una etiqueta interna del proyecto, no una conclusión legal; falta fijar el texto de atribución de las releases |
| Reglas de `Yara-Rules/rules` | GPL-2.0 (`policy.json`: «allowed-with-license-notice») | La licencia esperada se comprueba en cada ejecución | **PENDING**: efectos de redistribuir contenido GPL-2.0 en un paquete mixto, a revisar con asesoría |
| `VirusTotal/yara-x` (entrada `kind: engine`) | No es fuente de reglas; no se redistribuyen sus reglas | GitHub la indica como BSD-3-Clause (leído 2026-10-22). El paquete de la release no contiene código ni binario de YARA-X | **PENDING** si algún día se redistribuye su binario |
| Motor YARA 4.5.8 de Installer Auditor (construido desde fuente fijada) | BSD-3-Clause según `COPYING` de la etiqueta `v4.5.8` (leído 2026-10-22) | No hay aviso de licencia del motor en la carpeta de la aplicación; una aplicación construida no se ha inspeccionado | **PENDING**: añadir texto de licencia y aviso al distribuir la aplicación |
| OpenSSL 3.5.9 (estático en el motor) y cosign v3.1.1 (binario fijado en `Helpers/`) | Apache-2.0 según GitHub (leído 2026-10-22) | No se encontró fichero de licencia de ninguno bajo `DMGTrustAuditor/` | **PENDING**: añadir texto de licencia a los avisos de la aplicación |
| Mermaid 12.2.0 (`web/vendor`) | MIT del propio Mermaid (`mermaid-LICENSE.txt`) | Archivo presente y hash fijado en `web/vendor/README.md` | **PENDING** parcial: el paquete minificado incluye dependencias propias con sus licencias (DOMPurify 3.4.12, cuya cabecera dice Apache 2.0 y MPL; el resto de paquetes incluidos no se ha identificado); solo se distribuye el aviso de Mermaid |
| Imágenes y diseños externos | Ninguno | La wiki no incluye imágenes | No aplica |
| Texto y diagramas de esta wiki | Sin licencia asignada | No hay `LICENSE` | **PENDING** (decisión del propietario) |

## Lo que la firma no es
La firma Sigstore de una release demuestra la identidad verificable del flujo de publicación y la integridad del archivo firmado, dentro de su modelo de confianza. **No transfiere ni crea derechos de propiedad intelectual** sobre el contenido firmado, y no demuestra quién escribió las reglas de terceros. Que un repositorio de origen sea público tampoco autoriza por sí solo su redistribución: manda la licencia de cada fuente.

## Qué hay que decidir antes de publicar la wiki
1. Licencia del texto y los diagramas de la wiki (hasta entonces, las páginas dicen "licencia pendiente").
2. Licencia del código, para poder añadir `LICENSE`.
3. Revisión legal de la redistribución conjunta de reglas con licencias distintas (DRL-1.1 y GPL-2.0, además de las reglas que declaran otras licencias en sus propios metadatos).
4. Si cada release lleva un fichero de avisos y con qué forma, y si la aplicación incluye los avisos de sus componentes (borrador en `THIRD-PARTY-NOTICES-DRAFT.md`, sección 4).

No se ha aplicado ninguna de estas decisiones.
