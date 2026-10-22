# YARA Validation: qué se comprueba de verdad

[Inicio](ES-Home) · [Canal YARA](ES-YARA-Channel) · [Fuentes](ES-YARA-Sources) · [Rendimiento](ES-YARA-Performance) · [Cuarentena](ES-YARA-Quarantine) · [Publicación](ES-YARA-Publishing)

## En 30 segundos

Antes de publicar, cada fichero de reglas pasa por dos filtros automáticos. El **estático** lo lee como texto y lo compila sin ejecutar nada de él. El **dinámico** carga el conjunto completo en el motor YARA real, lo prueba sobre ficheros inofensivos y lo compara con la versión anterior. Lo dudoso va a cuarentena; solo lo que supera ambos se publica. {{ev:EV-YC-24}} {{ev:EV-YC-28}}

## Un ejemplo cotidiano

Es como revisar un examen antes de entregarlo: primero que esté completo y legible (estático), luego que no tarde tres horas en corregirse y que no suspenda a todo el mundo (dinámico). Aprobar la revisión no demuestra que el examen sea bueno, solo que no tiene los defectos que sabemos buscar.

## Las decisiones

{{diagram:static-decision}}

{{diagram:dynamic-decision}}

## Paso a paso

1. `rulecheck.py` analiza el texto, aplica las heurísticas y compila cada fichero con `yarac` (con sus dependencias).
2. `dynamic_gate.py` mide el conjunto aprobado frente al anterior (5 repeticiones) y, si falla, aísla los ficheros culpables.
3. `decide.py` junta todo: añade el filtro del corpus benigno, aplica decisiones humanas permitidas y decide si el conjunto es publicable.

## Cómo funciona por dentro

### Comprobaciones estáticas (`scripts/rulecheck.py`, `config/policy.json`)

| Comprobación | Valor | Fichero | Resultado |
|---|---|---|---|
| Tamaño máximo de fichero | 1 000 000 bytes | `policy.json` `limits.max_file_bytes` | rechazo duro |
| Máximo de reglas por fichero | 3000 | `limits.max_rules_per_file` | rechazo duro |
| Bytes NUL | cualquiera | `rulecheck.py` | rechazo duro (`binary`) |
| Módulos permitidos | `pe`, `elf`, `macho`, `math`, `hash`, `dotnet`, `time`, `string` | `allowed_modules` | — |
| Módulos bloqueados | `cuckoo`, `magic`, `androguard` | `blocked_modules` | `blocked-module`, revisión (no renunciable) |
| Otro módulo | cualquiera no listado | `rulecheck.py` | `unknown-module`, revisión (renunciable) |
| Riesgo de regex | puntuación ≥ 7 | `regex.max_risk_score` | `costly-regex`, revisión |
| Bucles `for` en una condición | más de 3 | `condition.max_for_loops` | `many-loops`, revisión |
| Bucle sobre todo el fichero (`filesize`) | prohibido | `forbid_filesize_loops` | `filesize-loop`, revisión |
| Tiempo de compilación por fichero | 20 s | `compile_file` (`timeout`) | `compile timeout` → error |
| Rondas de resolución de dependencias | 6 | `compile_file` | `compile-dependency` |

La puntuación de una regex suma: 9 por cuantificadores anidados, 3 si hay dos o más `.*`/`.+`, 2 si es un único `.*` inicial, 4 por cada hueco `{n,m}` con `m` ≥ 1000 (`regex.wide_gap`) y 3 por una repetición abierta `{n,}`. Un cuantificador anidado (9) basta para superar el umbral de 7. Estas heurísticas **solo mandan a cuarentena**; el coste real lo decide la medición dinámica. {{ev:EV-YC-25}} {{ev:EV-YC-26}}

La compatibilidad con el motor se comprueba compilando con el motor `yara`/`yarac` disponible (`-w` y variables externas vacías). `config/policy.json` declara `engines[].min_version` `4.3.0`, pero no se encontró código que lea ese valor; la versión real queda registrada (4.5.0 en el registro público de la ejecución diaria). {{ev:EV-YC-32}}

### Comprobaciones dinámicas (`scripts/dynamic_gate.py`, `scripts/bench.py`)

| Parámetro | Valor | Dónde |
|---|---|---|
| Repeticiones por conjunto | 5 | `dynamic.runs` |
| Mínimo de repeticiones para comparar | 3 (si no, `inconclusive`) | `bench.compare` |
| Límite por fichero escaneado | 10 s | `bench.measure_set` (`timeout_file`) |
| Abortar tras fallos | 3 (cuelgues, caídas o errores) | `bench.measure_set` (`max_failures`) |
| Ruido | umbral = máx(3 × MAD, 25 % de la mediana, suelo absoluto) | `regression.*` |
| Suelos absolutos | CPU 0,5 s; RSS 25 MB; compilación 0,5 s; p95 de escaneo 0,05 s | `policy.json` / `bench.compare` |
| Sin versión previa: p95 de escaneo | 2,0 s | `dynamic.absolute.max_scan_p95_s` |
| Sin versión previa: RSS de escaneo | 1500 MB | `max_scan_rss_mb` |
| Sin versión previa: RSS / tiempo de compilación | 3000 MB / 240 s | `max_compile_rss_mb`, `max_compile_wall_s` |
| Aislamiento de culpables | delta debugging, presupuesto 40; máx. 3 rondas | `culprits`, `run` |

Mediciones: tiempo, CPU y memoria máxima por proceso hijo (`wait4`). {{ev:EV-YC-28}}

**Corpus benigno y falsos positivos.** El corpus es determinista: 40 ficheros aleatorios, 10 de texto y hasta 8 binarios del sistema; más 5 «canarios» con una cadena de prueba. Un fichero de reglas que salte en más del 5 % del corpus limpio (`hit_rate_limit=0.05` en `decide.py`, solo si el corpus tiene ≥ 50 ficheros) se manda a cuarentena como `matches-benign-corpus`. Los 5 canarios deben detectarse todos; si no, no hay publicación («la detección no está demostrada»). Es un corpus pequeño: mide genericidad grosera, no la tasa real de falsos positivos en el mundo. {{ev:EV-YC-29}}

**Política de aceptación (`decide.py`).** Publicable solo si: el conjunto aprobado no está vacío; hay un cambio efectivo respecto a la release anterior; la variación no supera el 15 % retirado ni el 40 % tocado (salvo `allow_large_change`); la medición dinámica se hizo sobre exactamente ese conjunto (`set_root`) con veredicto `ok` o `no-baseline` y todos los canarios; y la contabilidad cuadra. Una aprobación humana solo levanta hallazgos de juicio (`costly-regex`, `many-loops`, `filesize-loop`, `unknown-module`, `include`, `license-unchecked`, `matches-benign-corpus`, `dependency-not-validated`, `new-source`); nunca errores de compilación, truncamiento, corrupción, módulo bloqueado, licencia cambiada ni fallos dinámicos. {{ev:EV-YC-27}}

**Plataformas.** El motor de referencia corre en Linux; un trabajo en `macos-15` repite las mediciones con el motor que envía MacGuard. No hay una máquina virtual macOS independiente (`required_platforms` en la política lo declara «no disponible»). {{ev:EV-YC-28}}

### Pruebas adversariales y de regresión

`tests/test_rulecheck_adversarial.py` corta un fichero válido en cada posición y exige que todo corte dentro de una regla produzca un hallazgo bloqueante, aplica 1500 daños aleatorios de bytes sin que el analizador falle, prueba caracteres Unicode y de control y entradas patológicas de hasta 1 000 000 de caracteres (regex anidadas, llaves sin cerrar, 3000 bucles anidados) con un límite de 8 s que es una cota de recursos contra entradas hostiles, no un criterio de aprobación. `tests/test_bench.py`, `tests/test_dynamic_gate.py` y `tests/test_decide.py` cubren regresiones, aislamiento de culpables con el motor real, canarios y el límite del 5 %. Se ejecutan antes de cada revisión diaria y en cada pull request. {{ev:EV-YC-30}} {{ev:EV-YC-37}}

## Cómo comprobarlo tú

- `python3 -m unittest tests.test_rulecheck tests.test_rulecheck_adversarial tests.test_bench tests.test_dynamic_gate tests.test_decide`
- Leer [rulecheck.py](https://github.com/MacGuard/macguard-yara-channel/blob/main/scripts/rulecheck.py), [decide.py](https://github.com/MacGuard/macguard-yara-channel/blob/main/scripts/decide.py), [dynamic_gate.py](https://github.com/MacGuard/macguard-yara-channel/blob/main/scripts/dynamic_gate.py) y [policy.json](https://github.com/MacGuard/macguard-yara-channel/blob/main/config/policy.json).

## Límites

- Las heurísticas son aproximaciones: pueden dejar pasar una regex lenta o apartar una inofensiva.
- Que una regla compile y no sature el motor no prueba que detecte lo que dice detectar.
- Claves de `policy.json` sin lector en el código revisado: `engines.min_version`, `regex.quarantine_nested_quantifiers`, `dynamic.timeout_seconds_per_file` (el valor efectivo, 10 s, está fijado en `bench.py`).

## Estado

| Capacidad | Estado |
|---|---|
| Clasificación estática, puerta dinámica y política de aceptación | operativo {{ev:EV-YC-02}} |
| Retenciones de política persistentes en el panel | implementado en `main`, no desplegado {{ev:EV-YC-06}} |
| Máquina virtual macOS independiente | no disponible |
