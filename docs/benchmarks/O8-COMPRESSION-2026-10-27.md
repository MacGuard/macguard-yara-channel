# O8 — Compresión antes de age: evaluación medida (2026-10-27)

**Estado: EVALUADO, no implementado.** Ninguna copia en producción cambia con este documento.

## Datos y método

Export SQL real de Intelligence (run 40469071822): 129 592 714 bytes. `zstd 1.5.7 -T1 | age -r <recipient>`, un solo hilo, macOS, `/usr/bin/time -l` (RAM = pico del proceso más grande de la tubería). La máquina estaba cargada (9 agentes), así que los tiempos tienen ruido; los tamaños son deterministas.

| Variante | Tamaño cifrado | Ratio | Tiempo | RAM pico |
|---|---|---|---|---|
| Sin compresión (`age` solo) | 129 624 546 | 1,0× | 0,4 s | 5,5 MB |
| zstd -3 | 13 694 701 | 9,5× | 1,8 s | 38,5 MB |
| zstd -6 | 12 636 799 | 10,3× | 4,2 s | 40,1 MB |
| zstd -10 | 12 287 068 | 10,5× | 8,3 s | 92,6 MB |

## Lectura

- Comprimir **antes** de cifrar es lo único que tiene sentido: el ciphertext no comprime.
- Ahorro por copia de Intelligence: ≈116 MB (zstd -3) y ≈117 MB (zstd -6). Se replica en 3 proveedores y se descarga en cada drill y en cada restauración: unos **350 MB menos almacenados por backup** y la misma reducción en transferencia.
- De -3 a -6: 7,7 % menos de tamaño por +2,4 s. De -6 a -10: 2,8 % por +4 s y 2,3× de RAM: no compensa.
- **Propuesta:** zstd -6 (un backup no es sensible a la latencia; 4 s sobre 130 MB). zstd -3 si algún día importara el tiempo de runner.
- Limitación del dato: es **un** export (Intelligence, con mucho JSON repetitivo). Gateway y panel pesan ≈0,35 MB y su ahorro absoluto es irrelevante; no se midieron. El resultado de otros datos podría diferir.

## Cómo reproducir la medición

Necesita el export real y la identidad `age` (no están en el repositorio). Con un export SQL descifrado `plain.sql` y un par de claves `age`:

```sh
REC=$(age-keygen -y identity.txt)
/usr/bin/time -l age -r "$REC" -o c_none.age plain.sql                    # sin compresión
for L in 3 6 10; do
  /usr/bin/time -l sh -c "zstd -q -$L -T1 -c plain.sql | age -r $REC -o c_zstd$L.age"
  stat -f %z c_zstd$L.age                                                 # tamaño cifrado (Linux: stat -c %s)
done
```

Los tamaños son deterministas para un mismo `plain.sql`, versión de `zstd` y nivel; los tiempos y la RAM dependen de la máquina. Una sola ejecución por variante, sin repeticiones ni intervalos de confianza: son órdenes de magnitud, no una medición estadística.

## Qué hay que hacer antes de poder desplegarla (nada de esto está hecho)

1. **Formato:** manifiesto con `compression: {algorithm: "zstd", level: 6, version}`, `original_bytes`, `plaintext_sha256` del SQL original y `stored_sha256` del cifrado. La ausencia del campo significa formato antiguo sin compresión.
2. **Compatibilidad hacia atrás:** `restore_verify`, `recover_verify.sh`, `restore_from_run.sh`, los drills de `backup_objstore` y `backup_offsite` y `rekeyBackup` deben leer ambos formatos. Un backup antiguo debe seguir restaurándose con el verificador nuevo (se probaría con la copia real del run 40469071822).
3. **Streaming:** `zstd -c | age` y `age -d | zstd -d` como procesos encadenados sin shell, comprobando el código de salida de **cada** extremo (en una tubería, el fallo de `zstd` no debe quedar oculto por el éxito de `age`), con `.partial`; reutilizando `stream_io.mjs` (introducido por la PR #57; si #57 no estuviera fusionada, este punto no se puede implementar).
4. **Seguridad:** límite de expansión (bomba de descompresión): el verificador aborta si el tamaño descomprimido supera `original_bytes` del manifiesto firmado.
5. **Disponibilidad de la herramienta:** `zstd` debe existir en el runner y en la máquina del propietario. En la máquina del propietario está (`zstd 1.5.7`, comprobado). **En el runner no está comprobado**: hay que ejecutar `zstd --version` en un job antes de depender de ello, o instalarlo explícitamente.
6. **Criterio de salida obligatorio:** backup real comprimido de los tres recursos y restauración aislada desde **B2, Scaleway y R2**, con evidencia, antes de activarlo. Hasta entonces, no desplegar.
7. **Pruebas adversarias:** zstd truncado, ciphertext alterado, manifiesto con `compression` falsificado, bomba de descompresión.

## Riesgo

Moderado: toca la ruta de recuperación, la que no puede fallar. Va después de #57 (streaming) y con la restauración triple como criterio de salida, no solo con pruebas unitarias. Aviso de la lección de #57: la CI no ejecuta las pruebas que requieren `age` (se omiten en Ubuntu), así que cualquier prueba de esta ruta debe poder correr sin `age` o instalarlo en CI.
