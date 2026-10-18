---
title: Visión general
summary: Qué es el canal de reglas YARA de MacGuard, qué garantiza y qué no.
---
## Qué es

El canal recoge reglas YARA públicas, las valida, firma un conjunto **completo** con Sigstore (sin clave guardada), lo publica como GitHub Release, registra cada paso en un registro de transparencia Merkle y sirve el catálogo en GitHub Pages (con Cloudflare Pages como réplica). Las apps de MacGuard (GUI, TUI y CLI) instalan solo releases que pueden verificar.

Es un proyecto independiente: no está afiliado con Nextron Systems, VirusTotal ni con la comunidad de reglas YARA, y esas fuentes no firman ni avalan estas releases.

## La última release

Etiqueta [`{{release.tag}}`]({{release.url}}), publicada el {{release.date}}: {{release.files}} ficheros de reglas y {{release.yara_rules}} reglas YARA. Paquete de {{release.package_bytes}} bytes con SHA-256 `{{release.package_sha256}}`. Raíz Merkle de las reglas (`rules_root`): `{{release.rules_root}}`.

Estas cifras se leen de los ficheros reales de la release cuando se construye esta documentación; si cambian, la página se regenera.

## Qué garantiza

- Todo lo publicado superó la clasificación estática y la prueba dinámica antes de firmarse.
- Cada release es el conjunto completo actual: se instala por sí sola, sin releases anteriores.
- El manifiesto y el checkpoint del registro están firmados con la identidad del workflow `publish.yml` en la rama `main` de este repositorio.
- Cualquiera puede comprobarlo sin confiar en este sitio: ver [Verificación](page:verification).

## Qué no garantiza

- «Validada» significa que el compilador YARA aceptó el fichero y pasó las pruebas descritas; no significa que detecte bien.
- No hay atestaciones SLSA ni in-toto: solo firmas de blobs (`manifest.json` y el checkpoint) con Sigstore.
- La revisión de licencias de las reglas upstream no está automatizada más allá de comprobar el marcador de licencia esperado.
- No hay telemetría de descargas: las gráficas muestran lo que observó el pipeline, no usuarios.

> **NOTA** Cada afirmación de esta documentación se marca como **ACTUAL** (existe y se ha probado) o **PROPUESTA** (diseñada, no implementada). Los defectos conocidos están en [Límites y pendientes](page:limits).
