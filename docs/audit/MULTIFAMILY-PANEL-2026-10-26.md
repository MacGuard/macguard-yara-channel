# Panel multifamilia — auditoría, causas raíz, cambios y evidencias (2026-10-26)

Rama `feat/multifamily-panel` (sobre `main` 61e7468, que incluye #49). No toca LifeClock, no borra históricos, no hace force-push, no restaura sobre producción.

## 1. Auditoría inicial: por qué el panel era YARA-céntrico

| # | Síntoma | Causa raíz comprobada en el código |
|---|---|---|
| 1 | Franja de 14 días y gráfica de 7 días solo reflejaban YARA | Salían de `/api/ops/overview`, que lee los runs de `daily.yml` (la pipeline YARA). Ninguna otra familia entraba en el estado del día. |
| 2 | Actividad (calendario, gráficas) solo YARA | Misma fuente (`o.days`); las ejecuciones de ingesta de Intelligence eran una tabla aparte, sin influir en el estado del día. |
| 3 | Cuarentena/Publicadas solo operaban con YARA | Las listas llamaban a `/api/candidates` y `/api/published` (tablas de candidatos YARA). Las otras familias solo tenían una tabla resumen de solo lectura. |
| 4 | No se podía despublicar, retirar ni decidir fuera de YARA | La base INTEL era solo lectura: no existía ningún almacén de decisiones ni de estado efectivo para los registros de otras familias. |
| 5 | Logs solo de ingesta | `/api/intel/events` era el único flujo; la auditoría de personas y la cadena estaban en otra pantalla, sin filtros por familia, fuente ni texto. |
| 6 | Fuentes con formatos desiguales y sin «nueva fuente» | Dos renderizadores distintos (tarjetas YARA y tabla del resto); no había ninguna ruta de alta ni de retirada. |
| 7 | Gráficas de Intelligence ilegibles | Barras verticales con etiquetas truncadas a 9 caracteres y rotuladas en el eje X. |
| 8 | Copias «todas fallidas» | **No es un fallo de UI.** Verificado en GitHub Actions: el job `export` de los runs programados de `backup.yml` falla (token de Cloudflare con D1 solo Lectura); los demás jobs se omiten. Requiere subir el token a D1 Edit. |

## 2. Cambios implementados

- **Agregación multifamilia** (`public/views/families_agg.js`, función pura con pruebas): el estado del día es el peor estado observado entre YARA y las demás familias; una familia sin ejecución ese día no se pinta verde ni cero («no observada»). Matriz familia × día (retenidas / rechazadas). Un VIEWER ve solo YARA y la pantalla lo dice.
- **Panel**: franja de 14 días multifamilia con la familia que requiere atención, matriz de 7 días, KPI de cuarentena con el recuento de las demás familias.
- **Decisiones sobre cualquier familia** (migración INTEL `0002_decisions.sql`, `src/intel_decisions.js`): retener, poner en cuarentena, rechazar y aprobar para la próxima publicación. Tabla *append-only* superpuesta al estado importado (una reimportación no borra decisiones), motivo obligatorio, `request_id` idempotente, lote todo-o-nada, «vista obsoleta» no cambia nada, una entrada de auditoría encadenada por petición y marca `audited` visible si faltara. **Aprobar** explica por qué está bloqueado (puertas de calidad, descarga no publicable, licencia) y nunca publica: PUBLISHED solo lo fija la pipeline firmada.
- **Navegador de registros único** (`public/views/records.js`) usado por Cuarentena, Publicadas e Inteligencia: familias, fuentes, estados, búsqueda sin perder el foco, ficha lateral con contenido, metadatos, evidencia e historial, acciones individuales y por lote con confirmación y motivo.
- **Logs** en tres registros separados: Sistema (filtros por nivel, familia, componente/servicio, fuente y texto), Acciones de personas (la auditoría) y Cadena verificable (cabeza, anclas externas, verificación; dice sin rodeos que **no** hay ancla externa y que una cadena de hashes no es un registro de transparencia público).
- **Actividad**: estado del día multifamilia, detalle por familia de cada día, filtro por familia y tabla de acciones por día y tipo.
- **Fuentes**: una tabla para todas las familias, ficha lateral con metadatos, descargas, errores y gráfica propia; **Nueva fuente** y **Solicitar retirada** como solicitudes (migración panel `0007_source_requests.sql`) que decide un ADMIN con motivo; el Worker nunca descarga la dirección escrita.
- **Gráficas de Intelligence**: barras horizontales con etiquetas completas, color fijo por familia y tabla de datos.
- **Restauración**: tabla «Veredicto de recuperación» (último intento, fase y causa, último backup válido, restauración demostrada) sin tocar el Asistente de emergencia.

## 3. Qué se ha generalizado de YARA al resto

Contadores, estado diario, gráficas, actividad, búsqueda, filtros, ficha, historial, decisiones, logs y fuentes. Familias soportadas por el navegador y las decisiones: Suricata, Sigma, IOC, hashes, CVE, KEV, EPSS, ATT&CK y avisos.

## 4. Qué sigue bloqueado y por qué

- **Publicación firmada de familias no YARA**: no existe pipeline de publicación para ellas (depende de la fábrica modular y del registro por fuente). «Aprobar» las deja aprobadas para la próxima publicación; «sustituir» y «revocar» de lo publicado solo tienen sentido cuando algo se publique.
- **Copias de seguridad reales**: bloqueadas por el token D1 Read.
- **Transparency log con pruebas de inclusión/consistencia y punto de control independiente**: pertenece a Observability V2; hoy solo hay cadena de hashes.
- **Mapamundi y paneles Grafana/SigNoz**: fuera de este alcance.

## 5. Despliegue

Pendiente. La migración INTEL `0002` y la del panel `0007` son aditivas; antes de aplicarlas hay que hacer la prueba sobre copia aislada y, para el panel, la copia cifrada verificada (bloqueada por el token D1).
