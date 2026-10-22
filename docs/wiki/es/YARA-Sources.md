# YARA Sources: de dónde salen las reglas

[Inicio](ES-Home) · [Canal YARA](ES-YARA-Channel) · [Validación](ES-YARA-Validation) · [Rendimiento](ES-YARA-Performance) · [Cuarentena](ES-YARA-Quarantine)

## En 30 segundos

El canal no escribe reglas: las toma de **dos repositorios públicos** (`Neo23x0/signature-base` y `Yara-Rules/rules`) y, además, registra el motor `VirusTotal/yara-x`, que es un motor y no aporta reglas. Cada día descarga el estado exacto de cada repositorio, guarda de qué commit y con qué licencia salió, y trata todo lo descargado como no fiable hasta validarlo. {{ev:EV-YC-21}}

## Un ejemplo cotidiano

Es como comprar fruta a dos mercados distintos y anotar en el albarán de qué puesto y a qué hora llegó cada caja. Antes de ponerla en la tienda se mira caja por caja; si un puesto cierra o cambia las condiciones, el albarán permite saber qué venía de dónde.

## El camino de la descarga

{{diagram:sources-sequence}}

## Paso a paso

1. `scripts/prepare.py` lee `config/sources.json` y, para cada fuente, pide a la API de GitHub el último commit (`commits/HEAD`).
2. Descarga el tarball **de ese commit exacto** y lo extrae con comprobaciones (ver abajo).
3. Si la fuente es de reglas, lee la licencia y la compara con `config/policy.json`.
4. Conserva solo `.yar` y `.yara` bajo las rutas declaradas, calcula el SHA-256 de cada fichero y escribe el inventario `dist/candidate.json`.
5. `scripts/rulecheck.py` clasifica cada fichero (ver [Validación](ES-YARA-Validation)).

## Cómo funciona por dentro

### Fuentes y procedencia

| Id | Repositorio | Tipo | Rutas |
|---|---|---|---|
| `nextron` | `Neo23x0/signature-base` | `rules` | `yara` |
| `community` | `Yara-Rules/rules` | `rules` | `malware`, `packers`, `crypto`, `antidebug_antivm`, `capabilities`, `exploit_kits`, `webshells` |
| `yara-x` | `VirusTotal/yara-x` | `engine` | ninguna: no aporta ficheros |

- **Commit fijado por ejecución, no en la configuración.** No hay un commit fijo por fuente en `config/sources.json`: se sigue el `HEAD` de cada repositorio cada día y el commit usado queda registrado en `candidate.json` y en la release. Lo «fijado» es que el tarball sale de ese commit y no de «lo último en ese momento». {{ev:EV-YC-22}}
- **Límites de descarga** en `scripts/prepare.py`: 90 000 000 bytes (`MAX_DOWNLOAD`), 25 000 entradas por archivo, 40 s de espera, 3 intentos ante 403/429/500/502/503. Se rechazan enlaces simbólicos y duros, dispositivos, rutas absolutas y `..`. El token de GitHub solo viaja al host `api.github.com`. {{ev:EV-YC-22}}
- **Licencias y metadatos:** `scripts/licensing.py` consulta la licencia y guarda SPDX, resumen SHA-256 del texto y veredicto. La política espera «Detection Rule License» (DRL-1.1) para `Neo23x0/signature-base` y GPL-2.0 para `Yara-Rules/rules`. Si no coincide, **todos** los ficheros de esa fuente van a cuarentena (`license-changed`) y ninguna aprobación humana lo levanta. {{ev:EV-YC-23}}

### Si una fuente falla o desaparece

- Si la API o la descarga fallan tras los reintentos, `prepare.py` termina con error; `daily.yml` registra `run.failed` en el registro de transparencia y **no se pide release**. La release anterior sigue siendo la vigente. {{ev:EV-YC-36}}
- Si solo falla la lectura de la licencia, el texto queda vacío y el veredicto es «no se pudo leer»: la fuente queda en cuarentena, no se publica en silencio.
- Si un fichero deja de existir en origen, `decide.py` lo marca como retirado (`no longer present upstream`). Si desaparece o cambia una fracción grande (más del 15 % retirado o más del 40 % tocado, `anomaly` en `config/policy.json`), el cambio no es publicable hasta que una persona lo revise y relance con `allow_large_change`.

### Normalización y estructura de una regla

La «normalización» **no reescribe reglas**: `prepare.py` copia los bytes tal cual a `dist/rules/<id de fuente>/<ruta>`, saltándose los ficheros de más de 1 000 000 bytes, los que contienen bytes NUL y los de nombre que el inventario firmado no pueda representar sin ambigüedad. `rulecheck.py` solo analiza: quita comentarios y contenido de cadenas para localizar cada `rule nombre { ... }`, comprobar llaves, `condition:`, `import` e `include`. {{ev:EV-YC-24}}

### Reglas inválidas, imports, dependencias y duplicados

- **Inválidas:** comentario, cadena o regex sin cerrar, regla sin cerrar, llaves desequilibradas, fichero que acaba a medias (`truncated`); caracteres de control en el código o regla sin `condition` (`corrupt`); sin reglas, binario, más de 1 000 000 bytes o más de 3000 reglas (`reject`); error del compilador (`compile-error`). Truncadas o corruptas van a cuarentena; las de rechazo duro no se reaprovechan mientras los bytes no cambien.
- **`import`:** módulos permitidos y bloqueados en [Validación](ES-YARA-Validation). Un `include` es un hallazgo de revisión.
- **Dependencias:** si una regla usa el nombre de una regla de otro fichero, se compila junto con él (hasta 6 rondas) y queda en `depends_on`. Un fichero cuya dependencia no esté validada tampoco se valida, de forma transitiva. {{ev:EV-YC-24}}
- **Duplicados:** repositorios distintos repiten nombres de regla. Al compilar el conjunto se usa un espacio de nombres por fichero (`bench.compile_set`), de modo que dos reglas con el mismo nombre en ficheros distintos coexisten. {{ev:EV-YC-38}}

### Cómo se admiten fuentes nuevas

Añadir una fuente exige un cambio revisado de `config/sources.json` y de `config/policy.json` en `main`; sin entrada de licencia en la política, sus ficheros quedan en cuarentena. El diseño de «propuestas de fuentes» (`docs/audit/source-proposals-spec.md`, `admin/worker/src/proposals.js`, migración `0005`) y el control de admisión (`scripts/admission.py`) están **implementados en `main` y no desplegados**: una fuente nueva queda retenida hasta que un ADMIN autorice sus reglas (`new-source`). Se controla porque una fuente nueva introduce código de terceros que llega a los equipos de las personas usuarias; un fallo de licencia o un compromiso del repositorio de origen se propagaría. {{ev:EV-YC-31}}

La retención de fuentes nuevas solo se activa si quien llama pasa las fuentes (opción `--sources` de `decide.py`). La ejecución diaria usa `scripts/dynamic_gate.py`, que no las pasa: **hoy ese control no está activo en la ejecución diaria** (comprobado leyendo `daily.yml` y `dynamic_gate.py`). {{ev:EV-YC-31}}

## Cómo comprobarlo tú

- `python3 -m unittest tests.test_admission tests.test_decide tests.test_licensing`
- Leer [prepare.py](https://github.com/MacGuard/macguard-yara-channel/blob/main/scripts/prepare.py) y [config/sources.json](https://github.com/MacGuard/macguard-yara-channel/blob/main/config/sources.json).

## Límites

- Una fuente en la lista no es una fuente «de confianza»: sus reglas se validan igual.
- El commit no está fijado por configuración; un repositorio puede cambiar entre ejecuciones.
- La licencia se comprueba por SPDX y marcador de texto, no es un dictamen jurídico.

## Estado

| Capacidad | Estado |
|---|---|
| Descarga diaria de dos fuentes de reglas, con commit y licencia registrados | operativo {{ev:EV-YC-01}} |
| Propuestas de fuentes y retención de fuente nueva (`admission.py`) | implementado en `main`, no desplegado {{ev:EV-YC-07}} |
| Fuentes adicionales | planificado (ninguna activa) |
