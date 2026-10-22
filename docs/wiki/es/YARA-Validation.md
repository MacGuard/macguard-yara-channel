# YARA Validation: qué se comprueba de verdad

[Inicio](ES-Home) · [Canal YARA](ES-YARA-Channel) · [Fuentes](ES-YARA-Sources) · [Rendimiento](ES-YARA-Performance) · [Cuarentena](ES-YARA-Quarantine) · [Publicación](ES-YARA-Publishing)

## En 30 segundos

Antes de publicar, cada archivo de reglas pasa por dos filtros automáticos. El **estático** lo lee como texto y lo compila sin ejecutar nada de él. El **dinámico** carga el conjunto completo en el motor YARA real, lo prueba sobre archivos inofensivos y lo compara con la versión anterior. Lo dudoso va a cuarentena; solo lo que supera ambos puede publicarse. Un conjunto que cambia se publica únicamente si la validación pasa y el trabajo de medición en macOS termina bien (ver Plataformas más abajo). {{ev:EV-YC-24}} {{ev:EV-YC-28}}

## Un ejemplo cotidiano

Es como revisar un examen antes de entregarlo: primero que esté completo y legible (estático), luego que no tarde tres horas en corregirse y que no suspenda a todo el mundo (dinámico). Aprobar la revisión no demuestra que el examen sea bueno, solo que no tiene los defectos que sabemos buscar.

## Las decisiones

{{diagram:static-decision}}

{{diagram:dynamic-decision}}

## Paso a paso

1. `rulecheck.py` analiza el texto, aplica las heurísticas y compila cada archivo con `yarac` (con sus dependencias).
2. `dynamic_gate.py` mide el conjunto aprobado frente al anterior (5 repeticiones) y, si falla, aísla los archivos culpables.
3. `decide.py` junta todo: añade el filtro del corpus benigno, aplica decisiones humanas permitidas y decide si el conjunto es publicable.

## Cómo funciona por dentro

### Comprobaciones estáticas (`scripts/rulecheck.py`, `config/policy.json`)

| Comprobación | Valor | Archivo | Resultado |
|---|---|---|---|
| Tamaño máximo de archivo | 1 000 000 bytes | `policy.json` `limits.max_file_bytes` | rechazo duro |
| Máximo de reglas por archivo | 3000 | `limits.max_rules_per_file` | rechazo duro |
| Bytes NUL | cualquiera | `rulecheck.py` | rechazo duro (`binary`) |
| Módulos permitidos | `pe`, `elf`, `macho`, `math`, `hash`, `dotnet`, `time`, `string` | `allowed_modules` | — |
| Módulos bloqueados | `cuckoo`, `magic`, `androguard` | `blocked_modules` | `blocked-module`, revisión (no renunciable) |
| Otro módulo | cualquiera no listado | `rulecheck.py` | `unknown-module`, revisión (renunciable) |
| Riesgo de regex | puntuación ≥ 7 | `regex.max_risk_score` | `costly-regex`, revisión |
| Bucles `for` en una condición | más de 3 | `condition.max_for_loops` | `many-loops`, revisión |
| Bucle sobre todo el archivo (`filesize`) | prohibido | `forbid_filesize_loops` | `filesize-loop`, revisión |

La puntuación de riesgo de una regex suma puntos por formas que suelen ser costosas: cuantificadores anidados, tramos abiertos repetidos (`.*`, `.+`), huecos `{n,m}` muy anchos (`regex.wide_gap`, 1000 en la política) y repeticiones abiertas. Una puntuación igual o mayor que `regex.max_risk_score` (7 en la política) manda el archivo a revisión. Los pesos están en `regex_risk` de `scripts/rulecheck.py`. Estas heurísticas **solo mandan a cuarentena**; el coste real lo decide la medición dinámica. Son señales aproximadas para quien revisa, no objetivos. {{ev:EV-YC-25}} {{ev:EV-YC-26}}

La compatibilidad con el motor se comprueba compilando con el motor `yara`/`yarac` disponible (`-w` y variables externas vacías). La versión del motor realmente usada queda registrada (4.5.0 en el registro público de la ejecución diaria). {{ev:EV-YC-32}}

### Comprobaciones dinámicas (`scripts/dynamic_gate.py`, `scripts/bench.py`)

| Parámetro | Valor | Dónde |
|---|---|---|
| Repeticiones por conjunto | 5 | `dynamic.runs` |
| Límite por archivo escaneado | 10 s | `dynamic.timeout_seconds_per_file` |
| Ruido | umbral = máx(3 × MAD, 25 % de la mediana, suelo absoluto) | `dynamic.regression.*` |
| Suelos absolutos | CPU 0,5 s; RSS 25 MB | `policy.json` |
| Sin versión previa: p95 de escaneo | 2,0 s | `dynamic.absolute.max_scan_p95_s` |
| Sin versión previa: RSS de escaneo | 1500 MB | `max_scan_rss_mb` |
| Sin versión previa: RSS / tiempo de compilación | 3000 MB / 240 s | `max_compile_rss_mb`, `max_compile_wall_s` |
| Aislamiento de culpables | delta debugging sobre los archivos que empeoran el conjunto | `scripts/dynamic_gate.py` |

Mediciones: tiempo, CPU y memoria máxima por proceso hijo (`wait4`). {{ev:EV-YC-28}}

Estos valores se leen de `config/policy.json` y de los scripts citados. Pueden cambiar y son límites de revisión, no objetivos: un candidato que los supera se aísla, va a cuarentena o no se publica. Los límites «sin versión previa» son cotas de cordura generosas que solo se aplican cuando no hay nada con lo que comparar.

**Corpus benigno y falsos positivos.** El corpus es determinista y pequeño: archivos sintéticos, algunos archivos de texto y unos pocos binarios del sistema del ejecutor, además de un pequeño conjunto de archivos «canario» inofensivos. Un archivo de reglas que salta en una fracción demasiado grande del corpus limpio (un límite fijado en el código, que puede cambiar) se manda a cuarentena como `matches-benign-corpus`. Todos los canarios deben detectarse; si no, no hay publicación («la detección no está demostrada»). Es un corpus pequeño: mide genericidad grosera, no la tasa real de falsos positivos en el mundo. {{ev:EV-YC-29}}

**Política de aceptación (`decide.py`).** Un conjunto es publicable solo si se cumple todo lo siguiente. El conjunto aprobado no está vacío. Hay un cambio efectivo respecto a la release anterior. La variación no supera los límites de cambio masivo (15 % retirado o 40 % tocado; valores de política) salvo que una persona lo apruebe de forma explícita. La medición dinámica se hizo sobre exactamente ese conjunto (`set_root`), con veredicto `ok` o `no-baseline` y todos los canarios detectados. La contabilidad cuadra. Una aprobación humana solo levanta hallazgos de juicio (`costly-regex`, `many-loops`, `filesize-loop`, `unknown-module`, `include`, `license-unchecked`, `matches-benign-corpus`, `dependency-not-validated`); nunca errores de compilación, truncamiento, corrupción, módulo bloqueado, licencia cambiada ni fallos dinámicos. {{ev:EV-YC-27}}

**Plataformas y qué condiciona la publicación.** El motor de referencia corre en Linux. Si el conjunto es publicable y ha cambiado, un trabajo en `macos-15` (`macos` en `daily.yml`) repite las mediciones con el motor que envía MacGuard. La petición de release (`request-publish`) solo se ejecuta si ese trabajo termina bien, y después `publish.yml` vuelve a verificar el conjunto final antes de firmar. El trabajo `app-compat` también corre tras `macos`, pero solo informa y no condiciona la publicación. No hay una máquina virtual macOS independiente: el ejecutor alojado ya es una máquina virtual y `required_platforms` en la política declara la independiente «no disponible». {{ev:EV-YC-28}} {{ev:EV-YC-89}}

### Pruebas adversariales y de regresión

`tests/test_rulecheck_adversarial.py` corta un archivo válido en cada posición y exige que todo corte dentro de una regla produzca un hallazgo bloqueante, aplica muchos casos de daño aleatorio de bytes sin que el analizador falle, y prueba caracteres Unicode y de control. También prueba entradas patológicas (regex anidadas, llaves sin cerrar, bucles muy anidados) bajo un límite de tiempo, que es una cota de recursos contra entradas hostiles, no un criterio de aprobación. `tests/test_bench.py`, `tests/test_dynamic_gate.py` y `tests/test_decide.py` cubren regresiones, aislamiento de culpables con el motor real, canarios y el límite del corpus. Se ejecutan antes de cada revisión diaria y en cada pull request. {{ev:EV-YC-30}} {{ev:EV-YC-37}}

## Cómo comprobarlo tú

- `python3 -m unittest tests.test_rulecheck tests.test_rulecheck_adversarial tests.test_bench tests.test_dynamic_gate tests.test_decide`
- Leer [rulecheck.py](https://github.com/MacGuard/macguard-yara-channel/blob/main/scripts/rulecheck.py), [decide.py](https://github.com/MacGuard/macguard-yara-channel/blob/main/scripts/decide.py), [dynamic_gate.py](https://github.com/MacGuard/macguard-yara-channel/blob/main/scripts/dynamic_gate.py) y [policy.json](https://github.com/MacGuard/macguard-yara-channel/blob/main/config/policy.json).

## Límites

- Las heurísticas son aproximaciones: pueden dejar pasar una regex lenta o apartar una inofensiva.
- Que una regla compile y no sature el motor no prueba que detecte lo que dice detectar.
- Algunos valores de configuración de `policy.json` están declarados pero el código todavía no los aplica.

## Estado

| Capacidad | Estado |
|---|---|
| Clasificación estática, puerta dinámica y política de aceptación | operativo {{ev:EV-YC-02}} |
| Retenciones de política persistentes en el panel | implementado en el repositorio, aún no activo en producción {{ev:EV-YC-06}} |
| Máquina virtual macOS independiente | no disponible |
