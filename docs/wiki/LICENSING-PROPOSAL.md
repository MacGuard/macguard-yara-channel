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

## Verificación por fuente y dependencia (estado a 2026-10-22)
Leído en el repositorio. «Comprobado» significa que el dato consta en un archivo; no es una opinión jurídica.

| Elemento | Licencia que consta | Comprobado | Estado |
|---|---|---|---|
| Reglas de `Neo23x0/signature-base` | Detection Rule License 1.1 (el script `licensing.py` busca la marca «Detection Rule License»; `policy.json` la clasifica «allowed-with-attribution») | La marca se busca en cada ejecución | **PENDING**: la clasificación «allowed» es una etiqueta interna del proyecto, no una conclusión legal; falta fijar el texto de atribución de las releases |
| Reglas de `Yara-Rules/rules` | GPL-2.0 (`policy.json`: «allowed-with-license-notice») | La licencia esperada se comprueba en cada ejecución | **PENDING**: efectos de redistribuir contenido GPL-2.0 en un paquete mixto, a revisar con asesoría |
| `VirusTotal/yara-x` (entrada `kind: engine`) | No es fuente de reglas; no se redistribuyen sus reglas | Su licencia no se ha comprobado en esta revisión | **PENDING** si algún día se redistribuye su binario |
| Motor YARA 4.5.8 de Installer Auditor (construido desde fuente fijada) | La de YARA, no verificada aquí | No hay aviso de licencia del motor en la carpeta de la aplicación | **PENDING**: confirmar texto de licencia y aviso al distribuir la aplicación |
| Mermaid 12.2.0 (`web/vendor`) | MIT del propio Mermaid (`mermaid-LICENSE.txt`) | Archivo presente y hash fijado en `web/vendor/README.md` | **PENDING** parcial: el paquete minificado incluye dependencias propias (por ejemplo DOMPurify) con sus licencias; solo se distribuye el aviso de Mermaid |
| Imágenes y diseños externos | Ninguno | La wiki no incluye imágenes | No aplica |
| Texto y diagramas de esta wiki | Sin licencia asignada | No hay `LICENSE` | **PENDING** (decisión del propietario) |

## Lo que la firma no es
La firma Sigstore de una release demuestra la identidad verificable del flujo de publicación y la integridad del archivo firmado, dentro de su modelo de confianza. **No transfiere ni crea derechos de propiedad intelectual** sobre el contenido firmado, y no demuestra quién escribió las reglas de terceros. Que un repositorio de origen sea público tampoco autoriza por sí solo su redistribución: manda la licencia de cada fuente.

## Qué hay que decidir antes de publicar la wiki
1. Licencia del texto y los diagramas de la wiki (hasta entonces, las páginas dicen "licencia pendiente").
2. Licencia del código, para poder añadir `LICENSE`.
3. Revisión legal de la redistribución conjunta de reglas con licencias distintas.

No se ha aplicado ninguna de estas decisiones.
