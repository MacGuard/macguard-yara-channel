# O1 — Streaming extremo a extremo de backup y restauración (2026-10-27)

Corrección (2026-10-27): una versión anterior de este informe y de la descripción de la PR decía «146 MB de SQL»; 146 MB es el tamaño de la base D1 en disco. El export SQL real pesa 129,6 MB.

Medido en local (macOS, `/usr/bin/time -l`, pico de RSS del proceso más grande), sin tocar la nube ni D1. La máquina estaba cargada (9 agentes activos), así que **los tiempos tienen ruido** (±2–3×); la memoria no.

## Resultados

| Caso | Camino | RAM pico | Tiempo |
|---|---|---|---|
| Fixture 1 MiB | en memoria (`main`) | 39,9 MB | 0,07 s (descifrar+hash+cargar) |
| Fixture 1 MiB | streaming | 39,2 MB | 0,27 s |
| Fixture 100 MiB (133.831 filas, trigger, cadenas multilínea) | en memoria (`main`) | **477,6 MB** | 3,7 s |
| Fixture 100 MiB | streaming | **70,8 MB** (6,7× menos) | 29,0 s |
| **Copia real de Intelligence** (run 40469071822: 129,6 MB de SQL, 129,6 MB cifrado) `restore_verify` completo | `main` | **736 MB** | 11,3 s |
| Ídem | streaming | **75,6 MB** (9,7× menos) | 19,2 s |

La memoria deja de crecer con el tamaño del export (el camino antiguo cuesta ≈4,8× el SQL; una base de 1 GB habría necesitado ≈5 GB, más que un runner estándar de 7 GB con margen). El precio es tiempo: el streaming pasa por disco.

Un primer intento sin pragmas de carga tardó **249 s** en la copia real (un `fsync` por sentencia en autocommit). `journal_mode=OFF` + `synchronous=OFF` (la base es desechable) lo dejó en 19 s. `locking_mode=EXCLUSIVE` y `cache_size` se probaron y no dieron efecto medible sobre la ejecución completa: no se aplican.

## Qué cambia

- `gateway/tools/stream_io.mjs` (nuevo): `ageEncryptFile`, `ageDecryptFile` (descriptores de fichero, `.partial` 0600, código de salida, cabecera, tamaño, cancelación), `shaFile`, `loadExport` (`sqlite3 -safe -bail` desde el fichero; respaldo a memoria si falta el CLI).
- `runBackup`, `restore_verify`, `restore_to_staging`, drill de `backup_objstore`, drill de `backup_offsite`, `rekeyBackup` y los tres verificadores (gateway, panel, Intelligence) dejan de materializar el SQL/ciphertext completo.
- `restore_verify` ahora también compara el SHA-256 del texto plano con el manifiesto.

## Seguridad

- `sqlite3 -safe` rechaza `.shell`, `ATTACH`, `writefile()` (probado). Es **más estricto** que el `db.exec` anterior, que permitía `ATTACH`.
- Un fallo de carga no copia SQL al log: solo la primera línea del error y `near "…"`. (La prueba detectó que el CLI imprime la sentencia fallida bajo el mensaje; corregido.)
- Directorio privado 0700, ficheros 0600; limpieza también ante excepción o salida del proceso (probado).
- Descifrado con identidad errónea, ciphertext truncado o alterado: salida ≠ 0 y **ningún fichero de salida**.

## Pruebas

`gateway/test/stream_io.test.js` (6): equivalencia fichero/memoria con trigger y línea con punto inicial, export hostil, error sin fuga de SQL, CLI ausente, descifrado adverso, **regresión de memoria** a 100 MiB (techo = tamaño del export: si se materializara entero no podría quedar por debajo; con el camino antiguo la prueba falla, 456 MiB). Suites de backup de gateway y admin en verde.

## No cubierto / residual

- **Volumen ≥ 1 GB:** no sintetizado para no saturar el Mac; el caso representativo es la copia real de 129,6 MB. La extrapolación (RAM plana) se apoya en 1 MiB → 100 MiB → 129,6 MB reales.
- **Descarga desde los proveedores:** `backup_objstore` baja el ciphertext a un `Buffer` (129 MB hoy). Pasarlo a streaming exige reescribir el cliente S3. Pendiente.
- `backup_encrypt_legacy.mjs` (herramienta del formato antiguo) conserva `maxBuffer` de 1 GiB.
- La exportación de D1 la hace `wrangler`, que escribe su propio fichero.
- Compatibilidad: verificada con la copia real de hoy y con las fixtures de las suites; **no** con copias de formatos anteriores a `macguard.gateway-backup/2` más allá de lo que cubren esas suites.
- No aplica a producción hasta fusionar y volver a ejecutar un backup real; sin despliegue ni `PRODUCTION_VERIFIED`.
