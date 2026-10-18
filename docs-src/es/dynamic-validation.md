---
title: Validación dinámica
summary: Cómo se mide el conjunto con el motor YARA y cómo se aíslan reglas problemáticas.
---
## Qué se mide

`dynamic_gate.py` construye un corpus seguro (ficheros aleatorios, texto, ficheros de sistema y canarios de detección), compila el conjunto aprobado y lo ejecuta con YARA contra cada fichero del corpus midiendo CPU, memoria máxima y tiempo (en Linux con el YARA de Ubuntu; en el job de macOS con el motor que distribuye MacGuard, {{tool.yara}}). Compara el candidato con la release anterior en el mismo job y alternando ejecuciones.

{{diagram:dynamic-sequence}}

## Decisión

{{diagram:dynamic-decision}}

- Se mide 5 veces cada conjunto y se comparan medianas contra el ruido de la base; una regresión exige subir más de 3 veces el ruido y como mínimo un 25 %, 0,5 s de CPU o 25 MB.
- Sin release anterior se aplican límites absolutos: p95 de escaneo 2,0 s, 1500 MB de memoria al escanear, 3000 MB al compilar y 240 s de compilación.
- Timeout por fichero: 10 s. Todos los canarios deben detectarse.
- Si algo falla, la depuración por deltas (ddmin) aísla los ficheros nuevos o modificados responsables, se mandan a cuarentena y se vuelve a medir, hasta 3 rondas.
- El conjunto medido debe ser exactamente el que se publica (`set_root` coincide con la raíz Merkle); `publish.yml` lo vuelve a comprobar antes de firmar.

## En macOS

Un job en un runner macOS instala el motor que se distribuye con MacGuard y ejecuta `macguard_smoke.py` con el conjunto candidato. Los valores exactos están en `config/policy.json`.

> **LÍMITE** Los runners de macOS de GitHub son máquinas virtuales (Apple M1 Virtual, `hv_vmm_present=1`, sin Hypervisor.framework). **No hay una máquina virtual macOS independiente**: `dynamic.json` lo declara como `not_run: independent-macos-vm`. Hace falta un Mac físico propio para eso.

> **LÍMITE** La puerta en Linux usa el YARA de Ubuntu (4.5.0) y la app distribuye {{tool.yara}}. La clasificación estática del conjunto completo dio el mismo resultado con ambos motores (comprobado el 2026-10-18), pero las mediciones dinámicas pueden diferir entre motores y sistemas; ver [Límites y pendientes](page:limits).

No se ejecuta malware real en ningún punto: el corpus se compone de datos sintéticos, texto y ficheros benignos.
