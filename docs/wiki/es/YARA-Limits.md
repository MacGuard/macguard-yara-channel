# Límites del canal YARA

[Inicio](ES-Home) · [Archivo histórico](ES-YARA-Archive) · [Tecnología: YARA](ES-Tech-YARA) · [Tecnología: Sigstore](ES-Tech-Sigstore) · [Tecnología: Merkle](ES-Tech-Merkle)

## En 30 segundos

Una regla YARA es un detector de patrones. Ningún detector acierta siempre: a veces **da la alarma por un archivo inocente** (falso positivo) y a veces **no ve algo malicioso** (falso negativo). El canal mide y filtra, pero no puede prometer que no haya ni lo uno ni lo otro. Y la firma del canal demuestra *quién publicó y que nada cambió después*, no que las reglas sean buenas.

## Un ejemplo cotidiano

Un detector de metales del aeropuerto suena con unas llaves (falso positivo) y puede no sonar con un objeto que no sea metálico (falso negativo). Ajustar la sensibilidad cambia el equilibrio, no lo elimina. Y el sello de «inspeccionado» no dice que el detector sea perfecto.

{{diagram:dynamic-decision-1-compare}}

{{diagram:dynamic-decision-2-isolate}}

{{diagram:dynamic-decision-3-publish}}

## Falsos positivos y negativos

- **Falsos positivos.** La puerta dinámica ejecuta cada conjunto de reglas contra un **corpus benigno** y pone en cuarentena una regla que acierta en demasiados archivos limpios. El límite es una fracción del corpus fijada en el código (`scripts/decide.py`); es un valor de política que puede cambiar {{ev:EV-YC-65}}.
- **Falsos negativos.** No hay medida de cuántas amenazas reales se escapan. La única comprobación de detección es una comprobación canario que debe acertar siempre; muestra que la medición puede detectar un acierto, no que las reglas cubran el malware real {{ev:EV-YC-64}}.

## Límites del corpus benigno

El corpus benigno es **pequeño y sintético**; mide genericidad grosera, no la tasa real de falsos positivos en el mundo {{ev:EV-YC-64}}. No contiene software real variado (documentos, instaladores, aplicaciones), así que una regla demasiado genérica puede pasar {{ev:EV-YC-65}}. Un defecto real: un archivo benigno se contaba una vez por copia de espacio de nombres y hacía superar el límite a reglas que no lo merecían; se corrigió contando archivos distintos, sin cambiar el límite {{ev:EV-YC-65}}.

## Coste de rendimiento

La política (`config/policy.json`) fija límites de cordura que se aplican cuando no hay una release anterior con la que comparar; un candidato que los supera no se aprueba. Contra una release previa, un aumento cuenta como regresión solo si supera el ruido medido y un mínimo relativo y otro absoluto {{ev:EV-YC-67}}. Los valores exactos están, en contexto, en [Validación](ES-YARA-Validation). Salen de la política, pueden cambiar y son puntos de partida que protegen los equipos que escanean, no garantías de rendimiento en cualquier Mac ni objetivos. No existe prueba de rendimiento de extremo a extremo con la aplicación {{ev:EV-YC-10}}.

## Disponibilidad de las fuentes

Dos repositorios de reglas alimentan el canal (`Neo23x0/signature-base` y `Yara-Rules/rules`) {{ev:EV-YC-01}}. Si cambian, desaparecen o reescriben su historial, el canal depende de esa evolución. La publicación automática se niega a quitar más del 15 % de la release anterior o tocar más del 40 % (`anomaly` en la política) y pide revisión humana {{ev:EV-YC-67}}. La licencia de las reglas solo se revisa de forma automática comprobando que el texto no ha cambiado; la revisión jurídica no se hace {{ev:EV-YC-66}}.

## Confianza en los motores

La política declara una versión mínima del motor; algunos valores de configuración están declarados pero el código todavía no los aplica {{ev:EV-YC-32}}. El motor distribuido es 4.5.8, la puerta de Linux usa el YARA 4.5.0 de Ubuntu y la medición en macOS corre en una máquina virtual, no en un Mac independiente {{ev:EV-YC-66}}. Los motores no son idénticos; un archivo que compila en uno puede no hacerlo en otro, y la aplicación verifica el motor distribuido antes de usarlo ([`docs/ENGINE.md`](https://github.com/MacGuard/macguard-yara-channel/blob/main/docs/ENGINE.md)).

## Qué NO demuestra la firma

La firma Sigstore y la raíz Merkle demuestran que **ese flujo de trabajo publicó esos bytes** y que el registro solo crece {{ev:EV-YC-03}} {{ev:EV-YC-04}}. No demuestran quién escribió las reglas, que detecten bien, que no tengan falsos positivos, ni que el proceso de revisión sea correcto. `manifest.evidence` es la declaración del propio flujo de publicación, no una atestación independiente in-toto/SLSA {{ev:EV-YC-66}}.

## Lo que la auditoría dejó abierto (nivel público)

El proyecto mantiene una auditoría con puntos abiertos {{ev:EV-YC-66}}: no hay atestación independiente de la revisión, el fuzzing es limitado y aún no se han ejecutado algunas herramientas.

## Cómo comprobarlo tú

```
python3 -m unittest tests.test_bench tests.test_dynamic_gate tests.test_rulecheck
```

## Límites

Esta página resume documentos del proyecto a fecha de su última revisión; las cifras citadas son las del código leído, no mediciones nuevas.

## Estado

| Capacidad | Estado |
|---|---|
| Puerta dinámica con corpus benigno y canarios | operativo {{ev:EV-YC-65}} |
| Medición en un macOS independiente | no disponible {{ev:EV-YC-66}} |
| Atestación independiente de la revisión | planificado |
