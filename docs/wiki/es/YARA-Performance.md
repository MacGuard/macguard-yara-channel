# YARA Performance: cuando una regla correcta es demasiado lenta

[Inicio](ES-Home) · [Canal YARA](ES-YARA-Channel) · [Fuentes](ES-YARA-Sources) · [Validación](ES-YARA-Validation) · [Cuarentena](ES-YARA-Quarantine) · [Límites](ES-YARA-Limits)

## En 30 segundos

Una regla puede estar bien escrita, compilar sin errores y aun así hacer que escanear un archivo tarde mucho o gaste mucha memoria. El canal mide ese coste con el motor YARA real, regla a regla y conjunto a conjunto, y aparta lo que lo empeora. **No existe** una prueba de rendimiento de extremo a extremo entre Installer Auditor y el canal real (planificada, ver abajo). {{ev:EV-YC-10}} {{ev:EV-YC-35}}

## Un ejemplo cotidiano

Es como pedir a alguien que compare cada página de un libro con una lista de 1000 palabras. Si una de las entradas de la lista dice «busca esta palabra en cualquier sitio y, después, otra, a cualquier distancia», el lector tiene que dar muchas más vueltas. El libro y la lista son correctos; el tiempo total, no tan aceptable.

## Qué se mide

{{diagram:perf-measurement}}

## Paso a paso

1. Se construye un corpus benigno pequeño y sintético.
2. `yarac` compila el conjunto y se mide el coste de compilar.
3. `yara -p 1` escanea cada archivo (límite de 10 s por archivo); se registran tiempo, CPU y memoria máxima de cada proceso.
4. Se repite 5 veces para la release anterior y para la candidata, y se compara la mediana con el ruido de la anterior.
5. Si hay regresión, se aíslan los archivos culpables y se vuelve a medir.

## Cómo funciona por dentro

### Por qué una regla correcta puede ser lenta

Tres patrones inofensivos de ejemplo. Son ilustrativos; no son reglas del canal ni se han medido aquí con un archivo concreto.

```yara
// EJEMPLO 1: cuantificadores anidados
rule Ejemplo_Anidado { strings: $a = /(ab+)+c/ condition: $a }
// EJEMPLO 2: dos tramos abiertos
rule Ejemplo_Abierto { strings: $a = /ab.*cd.*ef/ condition: $a }
// EJEMPLO 3: recorrer todo el archivo
rule Ejemplo_Bucle { condition: for all i in (0..filesize-1) : ( uint8(i) == 0 ) }
```

- **Anidado:** la forma `(x+)+` es la clásica que, en muchos motores de expresiones regulares, provoca un número enorme de combinaciones al fallar. No se ha medido cómo se comporta el motor de YARA; la revisión estática trata esta forma como señal de riesgo y manda el archivo a revisión.
- **Tramos abiertos** `.*` sin ancla: obligan al motor a seguir mirando por todo el archivo tras cada posible inicio. La revisión estática solo ve estas formas como señales aproximadas; la medición dinámica es la que observa el coste real.
- **Bucle sobre todo el archivo:** `filesize` de 100 MB significa cien millones de vueltas por cada archivo escaneado. `rulecheck.py` lo marca como `filesize-loop`.

La revisión estática (`analyse_text` en `rulecheck.py`) convierte formas como estas en señales de riesgo. Es una aproximación y no sustituye a la medición con el motor real. Sus pesos y umbrales son valores del código y de `config/policy.json`; se explican en contexto en [Validación](ES-YARA-Validation), pueden cambiar y no son objetivos. {{ev:EV-YC-26}}

**Riesgo.** Gasto de CPU y memoria en el equipo de quien escanea y, si el escaneo es automático, posibilidad de **denegación de servicio**: un archivo hostil o una regla lenta que bloquea la herramienta. De ahí los tiempos límite, la regresión frente a la versión anterior y el aislamiento de culpables.

### Qué mide realmente el canal

- `scripts/bench.py`: compilación (tiempo, CPU, RSS), escaneo (p50, p95, p99, CPU total, RSS máximo, errores, cuelgues, caídas), comprobación canario y aciertos en el corpus limpio. El corpus es pequeño y sintético (ver [Límites](ES-YARA-Limits)). El informe marca si los percentiles tienen al menos 50 muestras (`min_samples_for_percentiles`, campo `percentiles_reported`). Umbrales en [Validación](ES-YARA-Validation). {{ev:EV-YC-28}}
- `scripts/macguard_smoke.py`: ejecuta la CLI `macguard-audit` sobre el mismo corpus, con las reglas **candidatas** instaladas en un directorio privado, e informa de caídas, cuelgues, errores, p50/p95/p99, memoria máxima y el resultado de la comprobación canario. Se ejecuta en el trabajo `app-compat` de `daily.yml`, que **informa y no decide** la publicación. {{ev:EV-YC-34}}
- **Números guardados en el repositorio:** el registro público (`logs/log.jsonl`) guarda, por cada revisión diaria con medición, `scan_p95_s`, `scan_rss_peak_mb` y `compile_rss_mb`. En las 10 entradas con medición (2026-10-18 a 2026-10-22, motor YARA 4.5.0): p95 de escaneo entre 0,1676 y 0,1988 s; RSS máximo de escaneo entre 84,3 y 86,6 MB; RSS de compilación entre 72,7 y 73,7 MB; duración de la puerta entre 81 y 174 s. Son mediciones en un ejecutor de CI, no promesas de rendimiento en un Mac. {{ev:EV-YC-33}}
- `docs/audit/root-cause-benign-hit-count-2026-10-20.md` guarda una comparación en un contenedor compartido: p95 de escaneo 0,54 s (base) y 0,46 s (candidata); compilación 6,19 s y 4,94 s; los tiempos absolutos eran unas cinco veces peores que en el ejecutor, según el propio documento. {{ev:EV-YC-33}}

### Lo que NO se ha medido

- **No hay prueba de rendimiento de extremo a extremo de Installer Auditor con el canal real.** Estado: planificado. {{ev:EV-YC-10}} {{ev:EV-YC-35}}
- **Una medición de reglas no prueba la ausencia de condiciones de carrera.** El banco escanea un archivo por proceso, de forma secuencial (`-p 1`). Las carreras (actualizar reglas mientras se escanea, dos escaneos a la vez, instalación atómica) requieren pruebas de concurrencia propias. Lo que existe en la app es una prueba unitaria de que una segunda actualización de reglas simultánea se rechaza (`testSecondConcurrentUpdateIsRefused`); no es una prueba de escaneo durante una actualización.

### Cómo debería probarse (propuesta, no implementada)

1. Instalar en un Mac real el último release del canal con el cliente tal como lo usan las personas, no con reglas copiadas a mano.
2. Escanear un conjunto representativo (instaladores, paquetes, archivos grandes, comprimidos) midiendo tiempo, CPU y memoria, con y sin las reglas del canal, y comparar con la versión anterior del canal.
3. Repetir con varios escaneos simultáneos y con una actualización de reglas a mitad de un escaneo, buscando bloqueos, resultados mezclados o archivos a medias.
4. Criterios de fallo basados en caídas, cuelgues, resultados incorrectos y degradación frente a la línea base; un tiempo suelto no se usa como criterio de aprobación.

## Cómo comprobarlo tú

- `python3 -m unittest tests.test_bench tests.test_dynamic_gate` (necesita `yara` y `yarac`; incluye una regla que bloquea el motor y se ve como cuelgue).
- `python3 scripts/bench.py --help` y `python3 scripts/dynamic_gate.py --help`.
- Entradas con medidas en [logs/log.jsonl](https://github.com/MacGuard/macguard-yara-channel/blob/main/logs/log.jsonl).

## Límites

- El corpus es pequeño y sintético y no representa software real.
- Las cifras de CI no se extrapolan a otros equipos.
- Los umbrales del ruido son arranques documentados, no garantías de rendimiento.
- Las puertas existen para proteger los equipos que escanean. Los valores numéricos salen de `config/policy.json`, pueden cambiar y son límites de revisión, no metas para quien escribe reglas.

## Estado

| Capacidad | Estado |
|---|---|
| Medición de reglas con el motor real (compilación, escaneo, regresión, comprobación canario) | operativo {{ev:EV-YC-28}} |
| Prueba de humo de la CLI con las reglas candidatas | operativo (informa, no decide) {{ev:EV-YC-34}} |
| Prueba de rendimiento de extremo a extremo con Installer Auditor y el canal real | planificado {{ev:EV-YC-10}} |
| Pruebas de concurrencia entre escaneo y actualización | planificado {{ev:EV-YC-35}} |
