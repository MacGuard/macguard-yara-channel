# Tecnología: YARA

[Inicio](ES-Home) · [Límites](ES-YARA-Limits) · [Tecnología: Sigstore](ES-Tech-Sigstore) · [Tecnología: Merkle](ES-Tech-Merkle) · [Tecnología: copias S3](ES-Tech-S3-Backups)

## En 30 segundos

YARA es un lenguaje para escribir «descripciones de patrones» de archivos y un programa que busca esos patrones. Sus autores lo describen como una herramienta pensada (sin limitarse a ello) para ayudar a investigadores de malware a identificar y clasificar muestras {{ev:EV-YC-70}}.

## Un ejemplo cotidiano

Una regla es como una ficha de «se busca»: «un archivo que contiene esta frase y tiene este tamaño». El motor recorre archivos y avisa de los que encajan con la ficha. Encajar no prueba que sea peligroso; solo que se parece a la ficha.

{{diagram:sources-sequence-1-commit}}

{{diagram:sources-sequence-2-download}}

{{diagram:sources-sequence-3-inventory}}

## YARA frente a YARA-X

**YARA** es el motor clásico. **YARA-X** lo presenta VirusTotal como una «reencarnación» de YARA, escrita en Rust, que busca ser más rápida y segura y afirma una compatibilidad cercana al 99 % con las reglas de YARA {{ev:EV-YC-71}}. En este proyecto las **fuentes de reglas** son solo dos repositorios, `Neo23x0/signature-base` y `Yara-Rules/rules`; `VirusTotal/yara-x` figura en `config/sources.json` como entrada de tipo `engine`, no aporta reglas {{ev:EV-YC-01}}.

## Cómo funciona por dentro

- **Problema:** decidir de forma automática si un archivo de reglas es seguro de publicar.
- **Entrada:** archivos `.yar`/`.yara` de las dos fuentes. **Salida:** una clasificación por archivo (aceptar, cuarentena, rechazar) con motivos.
- **Cómo:** `scripts/rulecheck.py` analiza el texto (riesgo de expresiones regulares, bucles) y compila con `yarac`; la política `config/policy.json` declara una versión mínima del motor y prohíbe los módulos `cuckoo`, `magic` y `androguard` {{ev:EV-YC-67}}. Después `scripts/bench.py` y `scripts/dynamic_gate.py` miden tiempo, memoria y coincidencias contra un corpus benigno {{ev:EV-YC-64}}.
- **Qué no previene:** una regla válida puede ser inútil o dar falsos positivos; ver [Límites](ES-YARA-Limits).
- **Motor distribuido:** la aplicación usa YARA 4.5.8 compilado con la herramienta de `docs/ENGINE.md`.

## Quién más lo usa

Estas filas describen otros proyectos; ninguna implica que usen MacGuard.

| Quién | Clasificación | Fuente |
|---|---|---|
| Empresas de seguridad que el propio README de YARA lista en «Who's using YARA» (entre ellas VirusTotal, ESET, Kaspersky Lab, Trend Micro y Elastic Security) | usa la misma tecnología | {{ev:EV-YC-70}} |
| ClamAV, que procesa reglas YARA con limitaciones (sin módulos, sin reglas globales, sin variables externas, máximo 64 cadenas por regla) | usa la misma tecnología | {{ev:EV-YC-72}} |
| YARA-X (VirusTotal) | implementa una solución similar (otro motor para el mismo lenguaje) | {{ev:EV-YC-71}} |

## Cómo comprobarlo tú

```
python3 -m unittest tests.test_rulecheck tests.test_rulecheck_adversarial
python3 scripts/rulecheck.py --help
```

## Límites

YARA busca patrones, no entiende intención. Los motores difieren entre versiones y plataformas ({{ev:EV-YC-66}}).

## Estado

| Capacidad | Estado |
|---|---|
| Validación estática y dinámica con YARA 4.x en el canal | operativo {{ev:EV-YC-67}} |
| YARA-X como motor del canal | solo figura como entrada de fuente `engine`; no se usa para validar |
