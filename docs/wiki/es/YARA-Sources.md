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
4. Conserva solo `.yar` y `.yara` bajo las rutas declaradas, calcula el SHA-256 de cada archivo y escribe el inventario `dist/candidate.json`.
5. `scripts/rulecheck.py` clasifica cada archivo (ver [Validación](ES-YARA-Validation)).

## Cómo funciona por dentro

### Fuentes y procedencia

| Id | Repositorio | Tipo | Rutas |
|---|---|---|---|
| `nextron` | `Neo23x0/signature-base` | `rules` | `yara` |
| `community` | `Yara-Rules/rules` | `rules` | `malware`, `packers`, `crypto`, `antidebug_antivm`, `capabilities`, `exploit_kits`, `webshells` |
| `yara-x` | `VirusTotal/yara-x` | `engine` | ninguna: no aporta archivos |

- **Commit fijado por ejecución, no en la configuración.** No hay un commit fijo por fuente en `config/sources.json`: se sigue el `HEAD` de cada repositorio cada día y el commit usado queda registrado en `candidate.json` y en la release. Lo «fijado» es que el tarball sale de ese commit y no de «lo último en ese momento». {{ev:EV-YC-22}}
- **Límites de descarga** en `scripts/prepare.py`: topes de tamaño de descarga, de número de entradas del archivo y de tiempo. Se rechazan enlaces simbólicos y duros, dispositivos, rutas absolutas y `..`. El token de GitHub solo viaja al host `api.github.com`. {{ev:EV-YC-22}}
- **Licencias y metadatos:** `scripts/licensing.py` consulta la licencia y guarda SPDX, resumen SHA-256 del texto y veredicto. La política espera «Detection Rule License» (DRL-1.1) para `Neo23x0/signature-base` y GPL-2.0 para `Yara-Rules/rules`. Si no coincide, **todos** los archivos de esa fuente van a cuarentena (`license-changed`) y ninguna aprobación humana lo levanta. {{ev:EV-YC-23}}

### Si una fuente falla o desaparece

- Si la API o la descarga fallan, `prepare.py` termina con error; `daily.yml` registra `run.failed` en el registro de transparencia y **no se pide release**. La release anterior sigue siendo la vigente. {{ev:EV-YC-36}}
- Si solo falla la lectura de la licencia, el texto queda vacío y el veredicto es «no se pudo leer»: la fuente queda en cuarentena, no se publica en silencio.
- Si un archivo deja de existir en origen, `decide.py` lo marca como retirado (`no longer present upstream`). Si desaparece o cambia una fracción grande (más del 15 % retirado o más del 40 % tocado, `anomaly` en `config/policy.json`; valores de política que pueden cambiar), el cambio no es publicable hasta que una persona lo revise y lo apruebe de forma explícita.

### Normalización y estructura de una regla

La «normalización» **no reescribe reglas**: `prepare.py` copia los bytes tal cual a `dist/rules/<id de fuente>/<ruta>`, saltándose los archivos de más de 1 000 000 bytes, los que contienen bytes NUL y los de nombre que el inventario firmado no pueda representar sin ambigüedad. `rulecheck.py` solo analiza: quita comentarios y contenido de cadenas para localizar cada `rule nombre { ... }`, comprobar llaves, `condition:`, `import` e `include`. {{ev:EV-YC-24}}

### Licencias de las reglas de terceros

Las reglas descargadas de una fuente siguen bajo la licencia de esa fuente; la política registra lo que se espera de cada una. Este proyecto no reclama derechos de autor sobre las reglas descargadas y nada en esta wiki concede derechos sobre ellas. Las releases redistribuyen los archivos de reglas descargados: las condiciones de esa redistribución están pendientes de revisión legal y el repositorio aún no tiene un archivo LICENSE general. La comprobación automática de licencia solo detecta que una licencia cambió; no es asesoría legal. {{ev:EV-YC-85}} {{ev:EV-YC-81}}

### Reglas inválidas, imports, dependencias y duplicados

- **Inválidas:** comentario, cadena o regex sin cerrar, regla sin cerrar, llaves desequilibradas o archivo que acaba a medias (`truncated`). Caracteres de control en el código, o regla sin `condition` (`corrupt`). Sin reglas, binario, más de 1 000 000 bytes o más de 3000 reglas (`reject`). Error del compilador (`compile-error`). Truncadas o corruptas van a cuarentena; las de rechazo duro no se reaprovechan mientras los bytes no cambien.
- **`import`:** módulos permitidos y bloqueados en [Validación](ES-YARA-Validation). Un `include` es un hallazgo de revisión.
- **Dependencias:** si una regla usa el nombre de una regla de otro archivo, se compila junto con él y queda en `depends_on`. Un archivo cuya dependencia no esté validada tampoco se valida, de forma transitiva. {{ev:EV-YC-24}}
- **Duplicados:** repositorios distintos repiten nombres de regla. Al compilar el conjunto se usa un espacio de nombres por archivo (`bench.compile_set`), de modo que dos reglas con el mismo nombre en archivos distintos coexisten. {{ev:EV-YC-38}}

### Cómo se admiten fuentes nuevas

Añadir una fuente exige un cambio revisado de `config/sources.json` y de `config/policy.json` en `main`; sin entrada de licencia en la política, sus archivos quedan en cuarentena. El control de admisión de fuentes nuevas está implementado en el repositorio y aún no está habilitado en producción. Se controla porque una fuente nueva introduce contenido de terceros que llega a los equipos de las personas usuarias; un fallo de licencia o un compromiso del repositorio de origen se propagaría. {{ev:EV-YC-31}}

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
| Descarga diaria de dos fuentes de reglas, con commit y licencia registrados | publicado {{ev:EV-YC-01}} |
| Control de admisión de fuentes nuevas | implementado en el repositorio, aún no habilitado en producción {{ev:EV-YC-07}} |
| Fuentes adicionales | planificado (ninguna activa) |
