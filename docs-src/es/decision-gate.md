---
title: Puerta de decisión y contabilidad
summary: Cómo decide `decide.py` y por qué las cifras siempre cuadran.
---
## La invariante

La unidad es el **fichero de reglas examinado en una ejecución**. Cada uno acaba en un solo estado final y se cumple siempre:

```
examinados = aceptados + en cuarentena + rechazados + obsoletos
```

Si una cifra rompe la invariante, `accounting.py` lanza un error: la ejecución se bloquea, nada se registra y nada se publica. Los ficheros de la release anterior que ya no están upstream se cuentan aparte como `retired`; no son parte de esta suma.

## Qué decide

- Publica el conjunto aprobado solo si todos los controles obligatorios pasaron y hay cambio efectivo.
- Guarda anti-anomalía: no se publica automáticamente un cambio que quite más del 15 % de la release anterior o toque más del 40 %. Una persona lo revisa y repite con `allow_large_change`.
- Las reglas ya publicadas que dejan de pasar se retienen y se registran (`rules.withheld`).
- Una decisión humana aprobada no se salta ningún control técnico.

## Estadísticas públicas

El panel de la web usa la última ejecución de cada día, sin mezclar días distintos; un día sin ejecución es «sin observación», no cero. «Nuevas» de una release son los ficheros añadidos respecto a la anterior (en la primera release son todos), y no es lo mismo que lo examinado en el análisis.
