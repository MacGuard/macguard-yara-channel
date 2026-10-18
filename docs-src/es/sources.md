---
title: Fuentes de reglas
summary: De dónde salen las reglas, cómo se fija cada commit y cuál es el papel de cada fuente.
---
## Qué fuentes cuentan

| Fuente pública | Identificador técnico | Papel real |
|---|---|---|
| Nextron Systems — signature-base | `Neo23x0/signature-base` | **Fuente efectiva de reglas.** Se descarga el directorio `yara`. |
| Comunidad de reglas YARA (Yara-Rules) | `Yara-Rules/rules` | **Fuente efectiva de reglas** (comunidad): `malware`, `packers`, `crypto`, `antidebug_antivm`, `capabilities`, `exploit_kits`, `webshells`. |
| VirusTotal — ecosistema YARA y YARA-X | `VirusTotal/yara-x` | **Motor de referencia, sin reglas.** Se registra en `config/sources.json` con tipo `engine`; hoy no aporta ficheros al canal. |

> **ACTUAL** Un foro o repositorio de la comunidad solo es fuente efectiva si está en la lista permitida `config/sources.json`. Cualquier otra fuente es **PROPUESTA** hasta que se añada con su licencia revisada.

## Cómo se recoge

{{diagram:sources-sequence}}

- Se consulta el último commit de cada fuente y se descarga el tarball de **ese commit exacto**, de modo que el candidato es reproducible.
- Solo se conservan `.yar` y `.yara` bajo las rutas permitidas; se omiten los ficheros de más de 1 MB o con bytes NUL (evento `file.skipped`).
- Se comprueba la licencia contra `config/policy.json`: marcador «Detection Rule License» para Nextron y GPL-2.0 para Yara-Rules. Un cambio de licencia lleva a cuarentena.

## Qué queda registrado

Cada release incluye en `release.json` y en el manifiesto la lista de fuentes con repositorio, commit y resultado de la comprobación de licencia, de modo que se puede reconstruir de dónde salió cada fichero.
