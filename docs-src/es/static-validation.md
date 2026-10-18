---
title: Validación estática
summary: Cómo se clasifica cada fichero de reglas antes de medirlo.
---
## Estados

`rulecheck.py` asigna a cada fichero examinado uno de cuatro estados finales: **VALIDATED**, **QUARANTINED**, **REJECTED** o **DEPRECATED**. Solo VALIDATED puede publicarse.

{{diagram:static-decision}}

## Criterios

| Resultado | Motivo |
|---|---|
| REJECTED | Criterios duros: binario, vacío, sin reglas, más de 1 MB o contenido ya rechazado antes. |
| QUARANTINED | Truncado, corrupto, error de compilación, módulo bloqueado (`cuckoo`, `magic`, `androguard`) o desconocido, expresión regular costosa, bucle sobre todo el fichero, licencia cambiada o dependencia no validada. |
| DEPRECATED | El fichero se marca como obsoleto en sus propios metadatos. |
| VALIDATED | Ningún criterio anterior se cumple. |

Módulos permitidos: `pe`, `elf`, `macho`, `math`, `hash`, `dotnet`, `time`, `string`. El módulo `cuckoo` necesita un informe de sandbox que MacGuard no genera, por eso no tiene uso en el canal. Los umbrales viven en `config/policy.json`.

## Dependencias entre ficheros

Muchos ficheros usan reglas de otros (`include` o nombres de regla). El candidato conserva esa relación como `depends_on` firmado; cada fichero se compila en su propio espacio de nombres con sus dependencias, porque 227 ficheros repiten nombres de regla y un único espacio de nombres no compilaría.

> **LÍMITE** «Validada» no es una evaluación de calidad de detección. No se mide falsos positivos más allá de las pruebas con un corpus benigno y los canarios.
