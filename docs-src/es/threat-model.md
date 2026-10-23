---
title: Modelo de amenazas
summary: Qué ataques se consideran, qué los frena hoy y qué no cubre.
---
| Amenaza | Qué la frena hoy | Qué no cubre |
|---|---|---|
| Fuente upstream comprometida o con force-push | Commit fijado, cuarentena de reglas nuevas con hallazgos, guarda anti-anomalía (15 % quitado / 40 % tocado) y prueba dinámica. | Una regla maliciosa que compila, rinde bien y no usa construcciones marcadas. |
| Regla que cuelga o consume mucha memoria | Medición contra la release anterior, límites absolutos, timeout por fichero y aislamiento del culpable. | Entradas patológicas que el corpus no contiene. |
| Fichero alterado en tránsito o en el sitio | SHA-256 por fichero y `rules_root` firmados; la app y el verificador los comprueban. | Nada si el atacante controla además la identidad del workflow. |
| Sitio que sirve una release antigua (retroceso) o distinta (bifurcación) | Checkpoint verificado y guardado; la app rechaza tamaños menores o raíces distintas con el mismo tamaño. | Un cliente nuevo sin checkpoint previo no tiene protección contra retroceso en su primera verificación. |
| Publicación desde otro workflow o rama | La identidad firmada nombra `publish.yml@refs/heads/main`; rama principal protegida, permisos mínimos. | Un cambio malicioso en `publish.yml` en `main` que pase la revisión. |
| Fuga de reglas en cuarentena | Los artefactos, logs y sitio públicos solo llevan recuentos; los detalles van únicamente al servicio privado. | El servicio privado está desplegado. Su autorización se probó en un arnés local y en el runtime real de Workers con una D1 real; lo que hacen en producción la aplicación OAuth real de GitHub, los tokens de usuarios reales y los límites de tasa de Cloudflare no se ha verificado de forma independiente (a confirmar por el propietario). |
| Archivo malicioso en la extracción | Límites de miembros, tamaños, profundidad; sin enlaces, rutas absolutas ni duplicados. | — |

Rekor y Fulcio son infraestructuras públicas de Sigstore en las que se confía en la verificación; la raíz de confianza se fija en la app y puede rotar.
