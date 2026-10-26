# Incidente: cuota diaria de D1 agotada (2026-10-26)

## Qué pasó
A partir de ~15:00 UTC todas las consultas D1 de la cuenta devolvieron el error 7500 (límite diario de filas leídas del plan gratuito, 5.000.000). El panel devolvió 500 en sus endpoints de datos hasta el reinicio de las 00:00 UTC. Los datos no se pierden por superar la cuota.

## Causa raíz (con las métricas de Cloudflare Analytics, sin consultar D1)

Filas leídas hoy, por base y hora (UTC):

| Hora | Base | Consultas de lectura | Filas leídas | Filas escritas | Qué era |
|---|---|---:|---:|---:|---|
| **06:00** | **macguard-intel (producción)** | **112** | **4.909.588** | 0 | el propio Worker del panel sirviendo pantallas de Inteligencia (≈ 44.000 filas por consulta) |
| 14:00 | base temporal del panel (ensayo) | 12 | 11.331 | 456 | mi ensayo de migraciones |
| 15:00 | macguard-intel (producción) | 1 | 75.264 | 0 | mi exportación de INTEL para el ensayo |
| 15:00 | base temporal de INTEL (ensayo) | 15 | 1.207.426 | 376.012 | mi importación de 75.148 registros y sus comprobaciones |
| todo el día | macguard-gateway | ~290 | ~1.400 | ~435 | tráfico normal, sin anomalía |
| todo el día | macguard-quarantine (panel) | ~177 | ~1.100 | ~34 | tráfico normal |

1. **La causa principal es de diseño, no del ensayo.** A las 06:00 UTC, antes de cualquier prueba mía, el Worker de producción ya había leído 4,9 M de filas de INTEL (98 % de la cuota). Cada pantalla de Inteligencia recorría la tabla completa de 75.148 registros varias veces: `COUNT(*)` del listado, cinco agregados de `/api/intel/stats` y el recuento por fuente de `/api/intel/sources`. Unas 15 cargas de pantalla bastaban para agotar el día.
2. **Lo que hizo cruzar el límite fue mi ensayo**: exportar 75.264 filas de producción y volcar el export en una base temporal (1,2 M de lecturas y 376 k escrituras) sin presupuesto ni comprobación previa del consumo.
3. Sin alerta de consumo ni tope por operación, nada avisó.

## Servicios afectados
- Panel (`macguard-quarantine` y `macguard-intel`): las lecturas D1 fallaron; 500 en `/public/stats` y en las rutas de datos.
- Gateway (`macguard-gateway`): su tráfico de las 14:00 y las 15:00 coincide con su patrón normal (29 consultas / 3 consultas por hora), así que **no hay indicios** de que la ingesta haya dejado de escribir. No lo afirmo: faltan las horas posteriores a las 16:30 UTC y no leí D1 para comprobarlo.

## Cambios de protección (en el PR de integración #52)
- **Lecturas de INTEL acotadas**: una sola pasada por los registros produce una instantánea (tabla `intel_snapshot`, migración INTEL 0003, y memoria del Worker); se reconstruye solo cuando una promoción cambia los datos. Totales, recuentos por familia/fuente/estado y estadísticas salen de ella. Las decisiones se aplican como deltas pequeños.
- Los listados leen por **rango de clave primaria**, en orden de id, sin ordenar; sin `COUNT(*)`; si el total es cero ni se toca la tabla. Un texto que parece identificador se busca por prefijo de clave (índice); una búsqueda por título que tocaría más de 25.000 filas se **rechaza** con el motivo (`search_too_broad`).
- Estado efectivo en una columna (`decided_state`, índice parcial que nace vacío: no escribe filas) en lugar de un `JOIN` por fila.
- Si D1 devuelve el error de cuota, el panel responde **503** con `d1_quota_exhausted` y la hora de reinicio (no un 500 mudo) y no cambia nada.
- Tests que impiden la regresión (`test/d1_budget.test.js`): tras la instantánea, 100 peticiones hacen **una** pasada; ninguna consulta de registros hace *scan* de tabla ni ordenación completa; ninguna cuenta filas; una búsqueda amplia se rechaza.
- **Presupuesto de operaciones** (`tools/d1_budget.mjs`): una operación puede usar como máximo el 10 % de la cuota de lecturas y el 25 % de la de escrituras; el día no puede pasar del 60 % por operaciones planificadas; si el consumo del día no se puede leer, la operación **no** se ejecuta; se registra el coste estimado y el real en `~/macguard-d1-usage.jsonl`; niveles de alerta ok / warn (50 %) / critical (80 %). `local_backup.sh` y `migration_trial2.sh` lo invocan antes de tocar D1 (un test lo exige).
- Los ensayos **ya no exportan ni importan INTEL de producción**: usan un fixture determinista de ~1.500 registros (`tools/intel_trial_fixture.mjs`) y lo pesado se prueba en SQLite local.

## Lo que no está hecho
- Alerta automática de consumo anómalo (necesita un token de solo lectura de Analytics como secreto de CI; decisión del propietario). La herramienta ya da el nivel (`node tools/d1_budget.mjs usage`).
- Medir en un D1 real el coste del `ALTER TABLE … ADD COLUMN` de la migración 0003: se mide con el fixture (≈1.500 filas) antes de aplicarla; si escribe filas en proporción al tamaño, se usa una tabla lateral en lugar de la columna.
